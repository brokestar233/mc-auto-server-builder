from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import threading
import time
import traceback
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, fields
from datetime import datetime
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

import psutil
import requests

from .ai import BuilderAIService
from .config import AppConfig
from .defaults import (
    SUPPORTED_JAVA_VERSIONS,
    get_common_jvm_params,
    get_jvm_params_for_java_version,
)
from .input_parser import parse_manifest_from_zip, parse_pack_input
from .models import (
    ActionPreflight,
    AIResult,
    AttemptTrace,
    BisectMoveRecord,
    BisectRoundRecord,
    BisectSession,
    PackInput,
    PackManifest,
    StartResult,
    WorkDirs,
)
from .recognition import (
    RecognitionFallbackPlan,
    choose_java_version,
    choose_latest_lts_java_version,
    infer_java_from_runtime_feedback,
    top_candidate_values,
)
from .rule_db import RuleDB
from .util import (
    ColorPolicy,
    DownloadConfig,
    Downloader,
    DownloadFailure,
    DownloadTask,
    StructuredLogger,
    adoptium_platform_triplet,
    backup_directory,
    extract_archive,
    extract_archive_payload_into,
    extract_start_command_from_line,
    gb_to_mem_str,
    graceful_stop_process,
    http_get_json,
    is_http_url,
    is_local_tcp_port_open,
    merge_overrides_into_base,
    normalize_client_relative_path,
    normalize_java_home_layout,
    normalize_memory_plan,
    oracle_platform_triplet,
    parse_log_level,
    parse_mem_to_gb,
    read_tail_text,
    replace_path,
    safe_unlink,
    terminate_process,
    threaded_pipe_reader,
    verify_hashes,
)
from .workspace import create_workdirs


class ServerBuilder:
    _ALLOWED_MANIFEST_DOWNLOAD_TYPES = {"mod", "plugin", "datapack"}

    def __init__(self, source: str, config: AppConfig | None = None, base_dir: str | Path = "."):
        self.config = config or AppConfig()
        self.pack_input: PackInput = parse_pack_input(source)
        self.base_dir = Path(base_dir).resolve()
        self.workdirs: WorkDirs = create_workdirs(self.base_dir)
        self.rule_db = RuleDB(self.workdirs.db / "rules.sqlite3")
        self.rule_db.seed_defaults()
        for p in self.config.user_blacklist_regex:
            self.rule_db.add_rule(p, "user custom rule")

        self.manifest: PackManifest | None = None
        self.current_java_bin: Path | None = None
        self.current_java_version: int = 21
        self.java_params_mode_by_version: dict[int, str] = {21: "graalvm"}
        self.jvm_xmx = self.config.memory.xmx
        self.jvm_xms = self.config.memory.xms
        self.extra_jvm_flags = list(
            dict.fromkeys(
                [
                    *self._resolve_java_params_for_version(self.current_java_version),
                    *self.config.extra_jvm_flags,
                ]
            )
        )
        self.operations: list[str] = []
        self.removed_mods: list[str] = []
        self.bisect_removed_mods: list[str] = []
        self.known_deleted_client_mods: set[str] = set()
        self.deleted_mod_evidence: dict[str, list[str]] = {}
        self.last_ai_payload: dict[str, object] = {}
        self.last_ai_result: AIResult | None = None
        self.last_ai_manual_report: dict[str, object] = {}
        self.attempt_traces: list[AttemptTrace] = []
        self.bisect_session = BisectSession()
        self.last_bisect_feedback: dict[str, object] = {}
        self.ai_service = BuilderAIService(self)
        self.attempts_used: int = 0
        self.run_success: bool = False
        self.stop_reason: str = ""
        self.server_jar_name: str = "server.jar"
        self.start_command_mode: str = "jar"
        self.start_command_value: str = self.server_jar_name
        self.recognition_attempts: list[dict[str, object]] = []
        self.log_file_path: Path = self.workdirs.logs / "install.log"
        try:
            color_policy = ColorPolicy((self.config.logging.color_policy or "auto").lower())
        except ValueError:
            color_policy = ColorPolicy.AUTO
        self.logger = StructuredLogger(
            log_file_path=self.log_file_path,
            color_policy=color_policy,
            min_level=parse_log_level(self.config.logging.level),
            download_ui_enabled=self.config.download.terminal_ui_enabled,
            download_ui_running_rows=self.config.download.terminal_ui_running_rows,
            download_ui_refresh_interval_sec=self.config.download.terminal_ui_refresh_interval_sec,
        )
        self.downloader = Downloader(
            DownloadConfig(
                enable_parallel_download=self.config.download.enable_parallel_download,
                max_workers=self.config.download.max_workers,
                connect_timeout=self.config.download.connect_timeout,
                read_timeout=self.config.download.read_timeout,
                max_retries=self.config.download.max_retries,
                retry_backoff_sec=self.config.download.retry_backoff_sec,
                chunk_size=self.config.download.chunk_size,
            ),
            logger=self.logger,
        )

    def _log(self, stage: str, message: str, level: str = "INFO") -> None:
        lv = parse_log_level(level)
        self.logger.log(stage, message, lv)

    def _ai_debug_enabled(self) -> bool:
        return self.ai_service._ai_debug_enabled()

    def _ai_debug(self, message: str) -> None:
        self.ai_service._ai_debug(message)

    def _truncate_debug_text(self, value: object, limit: int = 1000) -> str:
        return self.ai_service._truncate_debug_text(value, limit)

    def _serialize_ai_action(self, action: object) -> dict:
        return self.ai_service._serialize_ai_action(action)

    # 文件与mods操作
    def list_mods(self) -> list[str]:
        mods_dir = self.workdirs.server / "mods"
        if not mods_dir.exists():
            return []
        return sorted([p.name for p in mods_dir.glob("*.jar") if p.is_file()])

    def _record_deleted_client_mod(self, mod_name: str, source: str, reason: str) -> None:
        clean = str(mod_name or "").strip()
        if not clean:
            return
        self.known_deleted_client_mods.add(clean)
        evidence = f"{source}:{reason}"
        existing = self.deleted_mod_evidence.setdefault(clean, [])
        if evidence not in existing:
            existing.append(evidence)

    def _record_deleted_mod_detail(self, mod_name: str, category: str, source: str, reason: str) -> None:
        clean = str(mod_name or "").strip()
        if not clean:
            return
        detail_map = getattr(self, "deleted_mod_sources", None)
        if not isinstance(detail_map, dict):
            detail_map = {}
            self.deleted_mod_sources = detail_map
        entry = detail_map.setdefault(
            clean,
            {
                "builtin_rule": [],
                "user_rule": [],
                "ai_suggested": [],
                "dependency_cleanup": [],
                "bisect": [],
                "other": [],
            },
        )
        bucket = category if category in entry else "other"
        payload = f"{source}:{reason}"
        if payload not in entry[bucket]:
            entry[bucket].append(payload)

    def _normalize_mod_token(self, value: str) -> str:
        token = str(value or "").strip().lower()
        token = token.removesuffix(".jar")
        token = re.sub(r"[\s_\-\.]+", "", token)
        return token

    def _resolve_mod_names_to_installed(self, names: list[str], candidates: list[str] | None = None) -> list[str]:
        mods = candidates if candidates is not None else self.list_mods()
        if not mods:
            return []

        exact = {m: m for m in mods}
        lower_map = {m.lower(): m for m in mods}
        token_map = {self._normalize_mod_token(m): m for m in mods}
        resolved: list[str] = []
        for raw in names:
            val = str(raw or "").strip()
            if not val:
                continue
            if val in exact:
                pick = exact[val]
            elif val.lower() in lower_map:
                pick = lower_map[val.lower()]
            else:
                t = self._normalize_mod_token(val)
                pick = token_map.get(t)
                if not pick and t:
                    for tk, mod_name in token_map.items():
                        if t in tk or tk in t:
                            pick = mod_name
                            break
            if pick and pick not in resolved:
                resolved.append(pick)
        return resolved

    def list_current_installed_client_mods(self) -> list[str]:
        mods = self.list_mods()
        if not mods:
            return []

        patterns = self.rule_db.list_rules()
        compiled: list[tuple[str, re.Pattern[str]]] = []
        for pat in patterns:
            try:
                compiled.append((pat, re.compile(pat)))
            except re.error:
                continue

        matched: list[str] = []
        for mod in mods:
            if any(cre.search(mod) for _, cre in compiled):
                matched.append(mod)
        return sorted(dict.fromkeys(matched))

    def remove_mods_by_name(self, names: list[str], source: str = "manual", reason: str = ""):
        mods_dir = self.workdirs.server / "mods"
        for n in names:
            target = mods_dir / n
            if target.exists():
                target.unlink()
                if source == "bisect":
                    self.bisect_removed_mods.append(n)
                else:
                    self.removed_mods.append(n)
                self.operations.append(f"remove_mod_by_name:{n}")
                self._log("install.remove_mod", f"删除mod:{n} 原因:{reason}")
                self._record_deleted_client_mod(n, source=source, reason=reason or "explicit_name")
                category = "other"
                if source == "bisect":
                    category = "bisect"
                elif source == "builtin_rule":
                    category = "builtin_rule"
                elif source in {"regex_rule", "user_rule"}:
                    category = "user_rule"
                elif source == "ai":
                    category = "ai_suggested"
                elif source == "dependency_cleanup":
                    category = "dependency_cleanup"
                self._record_deleted_mod_detail(n, category=category, source=source, reason=reason or "explicit_name")

    def remove_mods_by_regex(self, patterns: list[str], source: str = "regex_rule"):
        for pat in patterns:
            try:
                cre = re.compile(pat)
            except re.error:
                self._log("install.blacklist", f"忽略非法正则规则: {pat}", level="WARN")
                self.operations.append(f"remove_mods_by_regex_invalid:{pat}")
                continue

            mods = self.list_mods()
            if not mods:
                break

            matched = [m for m in mods if cre.search(m)]
            for mod_name in matched:
                self._log("install.blacklist.match", f"命中黑名单规则: pattern={pat} -> mod={mod_name}")
            self.remove_mods_by_name(matched, source=source, reason=f"pattern={pat}")

    def add_remove_regex(self, pattern: str, desc: str = ""):
        self.rule_db.add_rule(pattern, desc)
        self.operations.append(f"add_remove_regex:{pattern}")

    def apply_known_client_blacklist(self):
        patterns = self.rule_db.list_rules()
        self.remove_mods_by_regex(patterns, source="builtin_rule")

    def apply_recognition_based_client_cleanup(self) -> list[str]:
        manifest = getattr(self, "manifest", None)
        if not manifest:
            return []
        mods_dir = self.workdirs.server / "mods"
        if not mods_dir.exists():
            return []

        removal_patterns = (
            (
                re.compile(r"(?:fancymenu|embeddiumplus|oculus|rubidium|sodiumextras|reeses[_\-.]?sodium)", re.IGNORECASE),
                "client_visual_mod",
            ),
            (re.compile(r"(?:xaeros[_\-.]?minimap|journeymap|controlling|notenoughanimations)", re.IGNORECASE), "client_utility_mod"),
            (re.compile(r"(?:presencefootsteps|entityculling|3dskinlayers|skinlayers)", re.IGNORECASE), "client_render_mod"),
        )
        removed: list[str] = []
        for mod_path in sorted(mods_dir.glob("*.jar"), key=lambda p: p.name.lower()):
            for pattern, reason in removal_patterns:
                if pattern.search(mod_path.name):
                    self.remove_mods_by_name(
                        [mod_path.name],
                        source="dependency_cleanup",
                        reason=f"recognition_prior_cleanup:{reason}",
                    )
                    removed.append(mod_path.name)
                    break
        if removed:
            self.operations.append(f"recognition_prior_cleanup:removed={json.dumps(removed, ensure_ascii=False)}")
        return removed

    def backup_mods(self, tag: str):
        mods_dir = self.workdirs.server / "mods"
        if mods_dir.exists():
            backup_directory(mods_dir, self.workdirs.backups, f"mods_{tag}")
            self.operations.append(f"backup_mods:{tag}")

    def rollback_mods(self, tag: str):
        src = self.workdirs.backups / f"mods_{tag}"
        dst = self.workdirs.server / "mods"
        if src.exists():
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(src, dst)
            self.operations.append(f"rollback_mods:{tag}")

    def _split_mods_for_bisect(self, mods: list[str]) -> tuple[list[str], list[str]]:
        clean = sorted({str(x).strip() for x in mods if str(x).strip()}, key=lambda x: x.lower())
        if len(clean) <= 1:
            return clean, []
        pivot = max(1, len(clean) // 2)
        return clean[:pivot], clean[pivot:]

    def _classify_bisect_failure(self, start_res: dict[str, object]) -> tuple[str, str]:
        text_parts = [
            str(start_res.get("reason") or ""),
            str(start_res.get("stdout_tail") or ""),
            str(start_res.get("stderr_tail") or ""),
            json.dumps(start_res.get("readiness_evidence") or [], ensure_ascii=False),
        ]
        text = "\n".join(part for part in text_parts if part).lower()
        dependency_markers = (
            "missing dependency",
            "dependency",
            "depends on",
            "could not find required mod",
            "requires",
            "missing required",
            "no such file",
            "classnotfoundexception",
            "nosuchmethoderror",
        )
        if any(marker in text for marker in dependency_markers):
            return "dependency_failure", text[:400]
        return "general_failure", text[:400]

    def _build_bisect_feedback_payload(
        self,
        *,
        suspects: list[str],
        bisect_mode: str,
        tested_side: str,
        keep_group: list[str],
        test_group: list[str],
        moved_mods: list[str],
        round_result: str,
        startup_success: bool,
        failure_kind: str,
        failure_detail: str,
        reason: str,
        pending_group: list[str],
        continuation_targets: list[str],
        next_allowed_requests: list[str],
        fallback_targets: list[str],
        suspects_invalidated: bool,
    ) -> dict[str, object]:
        return {
            "already_bisected": True,
            "requested_targets": list(suspects),
            "bisect_mode": bisect_mode,
            "tested_side": tested_side,
            "split_strategy": "stable_sorted_halves",
            "keep_group": list(keep_group),
            "test_group": list(test_group),
            "moved_mods": list(moved_mods),
            "result": round_result,
            "startup_success": startup_success,
            "failure_kind": failure_kind,
            "failure_detail": failure_detail,
            "reason": reason,
            "pending_group": list(pending_group),
            "continuation_targets": list(continuation_targets),
            "next_allowed_requests": list(next_allowed_requests),
            "fallback_targets": list(fallback_targets),
            "suspects_invalidated": bool(suspects_invalidated),
            "grouping_explanation": (
                f"系统先按文件名稳定排序，再平分为 keep_group({len(keep_group)}) 和 test_group({len(test_group)})；"
                f"本轮实际验证侧={tested_side}。"
            ),
        }

    def _make_bisect_progress_token(
        self,
        *,
        suspects: list[str],
        bisect_mode: str,
        tested_side: str,
        round_result: str,
        final_suspects: list[str],
        next_allowed_requests: list[str],
    ) -> str:
        payload = {
            "suspects": list(suspects),
            "bisect_mode": bisect_mode,
            "tested_side": tested_side,
            "round_result": round_result,
            "final_suspects": list(final_suspects),
            "next_allowed_requests": list(next_allowed_requests),
        }
        return json.dumps(payload, ensure_ascii=False, sort_keys=True)

    def _log_bisect_event(self, stage: str, payload: dict[str, object]) -> None:
        self._log(stage, json.dumps(payload, ensure_ascii=False, sort_keys=True))

    def _coerce_bisect_round_record(self, round_record: object, fallback_index: int) -> BisectRoundRecord:
        if isinstance(round_record, BisectRoundRecord):
            return round_record

        payload = dict(round_record) if isinstance(round_record, dict) else {}
        moved_mods: list[BisectMoveRecord] = []
        for item in list(payload.get("moved_mods") or []):
            if isinstance(item, BisectMoveRecord):
                moved_mods.append(item)
            elif isinstance(item, dict):
                moved_mods.append(
                    BisectMoveRecord(
                        mod_name=str(item.get("mod_name") or item.get("mod") or "").strip(),
                        from_group=str(item.get("from_group") or item.get("from") or "").strip(),
                        to_group=str(item.get("to_group") or item.get("to") or "").strip(),
                        reason=str(item.get("reason") or "").strip(),
                    )
                )

        allowed_fields = {field.name for field in fields(BisectRoundRecord)}
        normalized_payload = {
            "round_index": int(payload.get("round_index") or fallback_index),
            "requested_targets": list(payload.get("requested_targets") or payload.get("targets") or []),
            "bisect_mode": str(payload.get("bisect_mode") or "initial"),
            "tested_side": str(payload.get("tested_side") or "keep"),
            "kept_group": list(payload.get("kept_group") or payload.get("keep_group") or []),
            "tested_group": list(payload.get("tested_group") or payload.get("test_group") or []),
            "moved_mods": moved_mods,
            "result": str(payload.get("result") or "unknown"),
            "trigger_reason": str(payload.get("trigger_reason") or payload.get("reason") or ""),
            "split_strategy": str(payload.get("split_strategy") or "stable_sorted_halves"),
            "startup_success": bool(payload.get("startup_success", False)),
            "failure_kind": str(payload.get("failure_kind") or ""),
            "failure_detail": str(payload.get("failure_detail") or ""),
            "continuation_targets": list(payload.get("continuation_targets") or []),
            "pending_other_group": list(payload.get("pending_other_group") or payload.get("pending_group") or []),
            "next_allowed_requests": list(payload.get("next_allowed_requests") or []),
            "fallback_targets": list(payload.get("fallback_targets") or []),
            "suspects_invalidated": bool(payload.get("suspects_invalidated", False)),
            "notes": list(payload.get("notes") or []),
        }
        return BisectRoundRecord(**{key: value for key, value in normalized_payload.items() if key in allowed_fields})

    def _coerce_bisect_session(self, session: object | None = None) -> BisectSession:
        source = session if session is not None else getattr(self, "bisect_session", BisectSession())
        if isinstance(source, BisectSession):
            normalized_rounds = [
                self._coerce_bisect_round_record(round_record, index)
                for index, round_record in enumerate(list(getattr(source, "rounds", []) or []), start=1)
            ]
            if normalized_rounds == list(getattr(source, "rounds", []) or []):
                return source
            return BisectSession(**{**asdict(source), "rounds": normalized_rounds})

        payload = dict(source) if isinstance(source, dict) else {}
        normalized_rounds = [
            self._coerce_bisect_round_record(round_record, index)
            for index, round_record in enumerate(list(payload.get("rounds") or []), start=1)
        ]
        allowed_fields = {field.name for field in fields(BisectSession)}
        normalized_payload = {
            "active": bool(payload.get("active", False)),
            "source_mods": list(payload.get("source_mods") or []),
            "suspect_mods": list(payload.get("suspect_mods") or payload.get("final_suspects") or []),
            "safe_mods": list(payload.get("safe_mods") or []),
            "phase": str(payload.get("phase") or "initial"),
            "rounds": normalized_rounds,
            "final_suspects": list(payload.get("final_suspects") or []),
            "stopped_reason": str(payload.get("stopped_reason") or ""),
            "last_round_feedback": dict(payload.get("last_round_feedback") or {}),
            "pending_group": list(payload.get("pending_group") or []),
            "continuation_targets": list(payload.get("continuation_targets") or []),
            "next_allowed_requests": list(payload.get("next_allowed_requests") or []),
            "completed_requests": list(payload.get("completed_requests") or []),
            "completed_request_tokens": list(payload.get("completed_request_tokens") or []),
            "fallback_targets": list(payload.get("fallback_targets") or []),
            "suspects_invalidated": bool(payload.get("suspects_invalidated", False)),
            "progress_token": str(payload.get("progress_token") or ""),
            "stagnant_rounds": int(payload.get("stagnant_rounds", 0) or 0),
            "last_preflight_block_reason": str(payload.get("last_preflight_block_reason") or ""),
            "last_preflight_block_details": list(payload.get("last_preflight_block_details") or []),
            "success_ready": bool(payload.get("success_ready", False)),
            "success_guard_reason": str(payload.get("success_guard_reason") or ""),
            "success_guard_history": list(payload.get("success_guard_history") or []),
            "consecutive_same_issue_on_success": int(payload.get("consecutive_same_issue_on_success", 0) or 0),
        }
        return BisectSession(**{key: value for key, value in normalized_payload.items() if key in allowed_fields})

    def _format_bisect_tree_lines(self) -> list[str]:
        session = self._coerce_bisect_session()
        if not getattr(session, "rounds", []):
            return ["- none"]

        lines: list[str] = []
        for index, raw_round_record in enumerate(session.rounds, start=1):
            round_record = self._coerce_bisect_round_record(raw_round_record, index)
            moved = [
                {
                    "mod": item.mod_name,
                    "from": item.from_group,
                    "to": item.to_group,
                    "reason": item.reason,
                }
                for item in round_record.moved_mods
            ]
            lines.extend(
                [
                    (
                        f"- Round {round_record.round_index}: mode={round_record.bisect_mode}, "
                        f"tested_side={round_record.tested_side}, result={round_record.result}, "
                        f"startup_success={round_record.startup_success}"
                    ),
                    f"  requested_targets={json.dumps(round_record.requested_targets, ensure_ascii=False)}",
                    f"  keep_group={json.dumps(round_record.kept_group, ensure_ascii=False)}",
                    f"  test_group={json.dumps(round_record.tested_group, ensure_ascii=False)}",
                    f"  moved_mods={json.dumps(moved, ensure_ascii=False)}",
                    f"  continuation_targets={json.dumps(round_record.continuation_targets, ensure_ascii=False)}",
                    f"  pending_other_group={json.dumps(round_record.pending_other_group, ensure_ascii=False)}",
                    f"  next_allowed_requests={json.dumps(round_record.next_allowed_requests, ensure_ascii=False)}",
                    f"  fallback_targets={json.dumps(round_record.fallback_targets, ensure_ascii=False)}",
                    f"  suspects_invalidated={round_record.suspects_invalidated}",
                    f"  failure_kind={round_record.failure_kind or 'none'}",
                    f"  failure_detail={round_record.failure_detail or 'none'}",
                    f"  notes={json.dumps(round_record.notes, ensure_ascii=False)}",
                ]
            )
        lines.extend(
            [
                f"- session.phase={getattr(session, 'phase', 'initial')}",
                f"- session.final_suspects={json.dumps(session.final_suspects, ensure_ascii=False)}",
                f"- session.pending_group={json.dumps(session.pending_group, ensure_ascii=False)}",
                f"- session.continuation_targets={json.dumps(session.continuation_targets, ensure_ascii=False)}",
                f"- session.next_allowed_requests={json.dumps(session.next_allowed_requests, ensure_ascii=False)}",
                f"- session.fallback_targets={json.dumps(session.fallback_targets, ensure_ascii=False)}",
                f"- session.suspects_invalidated={session.suspects_invalidated}",
                f"- session.stagnant_rounds={getattr(session, 'stagnant_rounds', 0)}",
                f"- session.last_preflight_block_reason={getattr(session, 'last_preflight_block_reason', '') or 'none'}",
                f"- session.success_ready={getattr(session, 'success_ready', False)}",
                f"- session.success_guard_reason={getattr(session, 'success_guard_reason', '') or 'none'}",
                f"- session.consecutive_same_issue_on_success={getattr(session, 'consecutive_same_issue_on_success', 0)}",
            ]
        )
        return lines

    def _has_pending_bisect_followup(self) -> bool:
        session = self._coerce_bisect_session()
        return bool(
            getattr(session, "active", False)
            and (
                getattr(session, "pending_group", [])
                or getattr(session, "continuation_targets", [])
                or getattr(session, "next_allowed_requests", [])
                or getattr(session, "fallback_targets", [])
            )
        )

    def _mark_bisect_success_ready(self, reason: str) -> None:
        session = self._coerce_bisect_session()
        history = [*list(getattr(session, "success_guard_history", []) or []), str(reason or "ready")][-8:]
        self.bisect_session = BisectSession(
            **{
                **asdict(session),
                "active": False,
                "success_ready": True,
                "success_guard_reason": str(reason or "ready"),
                "success_guard_history": history,
                "pending_group": [],
                "continuation_targets": [],
                "next_allowed_requests": [],
                "fallback_targets": [],
                "suspects_invalidated": False,
            }
        )

    def _record_success_guard_observation(self, issue: str, confidence: object) -> int:
        session = self._coerce_bisect_session()
        issue_text = str(issue or "other").strip() or "other"
        confidence_text = str(confidence if confidence is not None else "unknown")
        marker = f"issue={issue_text},confidence={confidence_text}"
        history = [*list(getattr(session, "success_guard_history", []) or []), marker][-8:]
        count = int(getattr(session, "consecutive_same_issue_on_success", 0) or 0)
        if issue_text == "client_mod":
            count += 1
        else:
            count = 0
        self.bisect_session = BisectSession(
            **{
                **asdict(session),
                "success_guard_history": history,
                "consecutive_same_issue_on_success": count,
                "success_guard_reason": marker,
            }
        )
        return count

    def _should_accept_success_after_start(self, start_res: dict[str, object]) -> tuple[bool, str]:
        session = self._coerce_bisect_session()
        source = str(start_res.get("success_source") or "unknown")
        if self._has_pending_bisect_followup():
            return False, "bisect_followup_pending"
        if getattr(session, "success_ready", False):
            return True, f"success_guard_cleared:{source}"
        return True, f"server_ready:{source}"

    def _should_auto_resume_full_bisect(self) -> bool:
        session = self._coerce_bisect_session()
        return bool(
            getattr(session, "active", False)
            and getattr(session, "suspects_invalidated", False)
            and "initial" in list(getattr(session, "next_allowed_requests", []) or [])
            and list(getattr(session, "fallback_targets", []) or [])
        )

    def _build_auto_resume_bisect_action(self) -> dict[str, object]:
        session = self._coerce_bisect_session()
        fallback_targets = list(getattr(session, "fallback_targets", []) or [])
        return {
            "type": "bisect_mods",
            "bisect_mode": "initial",
            "targets": fallback_targets,
            "bisect_reason": "首轮 AI 猜测集合已被验证失效，自动切换为按文件名稳定排序的全量 fallback 二分。",
            "request_source": "system_auto_resume",
        }

    def _build_ai_context(self, start_res: dict[str, object], log_info: dict[str, object]) -> dict[str, object]:
        session = self._coerce_bisect_session()
        manifest = self.manifest
        recognition_summary = self._build_recognition_summary() if manifest else {}
        return {
            "mc_version": manifest.mc_version if manifest else "unknown",
            "loader": manifest.loader if manifest else "unknown",
            "loader_version": getattr(manifest, "loader_version", None) if manifest else None,
            "build": getattr(manifest, "build", None) if manifest else None,
            "start_mode": getattr(manifest, "start_mode", "unknown") if manifest else "unknown",
            "recognition_summary": recognition_summary,
            "jvm_args": f"Xmx={self.jvm_xmx} Xms={self.jvm_xms}",
            "available_ram": self.get_system_memory(),
            "mod_count": len(self.list_mods()),
            "current_installed_mods": self.list_mods(),
            "current_installed_client_mods": self.list_current_installed_client_mods(),
            "known_deleted_client_mods": sorted(self.known_deleted_client_mods),
            "deleted_mod_evidence": self.deleted_mod_evidence,
            "dependency_cleanup_rule_enabled": True,
            "recent_actions": self.operations[-20:],
            "bisect_active": bool(getattr(session, "active", False)),
            "bisect_next_allowed_requests": list(getattr(session, "next_allowed_requests", []) or []),
            "bisect_feedback": dict(getattr(self, "last_bisect_feedback", {}) or {}),
            "bisect_fallback_targets": list(getattr(session, "fallback_targets", []) or []),
            "bisect_suspects_invalidated": bool(getattr(session, "suspects_invalidated", False)),
            "bisect_phase": str(getattr(session, "phase", "initial") or "initial"),
            "bisect_stagnant_rounds": int(getattr(session, "stagnant_rounds", 0) or 0),
            "bisect_last_preflight_block_reason": str(getattr(session, "last_preflight_block_reason", "") or ""),
            "bisect_last_preflight_block_details": list(getattr(session, "last_preflight_block_details", []) or []),
            "bisect_success_ready": bool(getattr(session, "success_ready", False)),
            "bisect_success_guard_reason": str(getattr(session, "success_guard_reason", "") or ""),
            "bisect_success_guard_history": list(getattr(session, "success_guard_history", []) or []),
            "bisect_consecutive_same_issue_on_success": int(getattr(session, "consecutive_same_issue_on_success", 0) or 0),
            "done_detected": bool(start_res.get("done_detected", False)),
            "command_probe_detected": bool(start_res.get("command_probe_detected", False)),
            "port_open_detected": bool(start_res.get("port_open_detected", False)),
            "stdout_tail": str(start_res.get("stdout_tail") or ""),
            "stderr_tail": str(start_res.get("stderr_tail") or ""),
            **log_info,
        }

    def _consume_bisect_targets(self, action: dict) -> tuple[str, list[str]]:
        bisect_mode = str(action.get("bisect_mode") or "initial").strip() or "initial"
        session = self._coerce_bisect_session()
        if bisect_mode == "switch_group":
            return bisect_mode, list(getattr(session, "pending_group", []) or [])
        if bisect_mode == "continue_failed_group":
            return bisect_mode, list(getattr(session, "continuation_targets", []) or [])
        suspects = self._resolve_mod_names_to_installed([str(x) for x in (action.get("targets") or self.list_mods()) if str(x).strip()])
        if bisect_mode == "initial":
            fallback_targets = list(getattr(session, "fallback_targets", []) or [])
            fallback_allowed = bool(getattr(session, "suspects_invalidated", False)) and "initial" in list(
                getattr(session, "next_allowed_requests", []) or []
            )
            if fallback_allowed and fallback_targets:
                resolved_fallback = self._resolve_mod_names_to_installed(fallback_targets)
                if resolved_fallback:
                    return bisect_mode, resolved_fallback
        return bisect_mode, suspects

    def _derive_bisect_followups(
        self,
        *,
        bisect_mode: str,
        tested_side: str,
        round_result: str,
        failure_kind: str,
        keep_group: list[str],
        test_group: list[str],
        active_after_setup: list[str],
        suspects: list[str],
        source_mods: list[str],
    ) -> tuple[list[str], list[str], list[str], list[str], list[str], bool]:
        pending_group: list[str] = []
        continuation_targets: list[str] = []
        next_allowed_requests: list[str] = []
        final_suspects: list[str] = []
        fallback_targets: list[str] = []
        suspects_invalidated = False
        other_group = list(test_group if tested_side == "keep" else keep_group)
        tested_group_actual = list(active_after_setup)

        if round_result == "pass":
            final_suspects = list(other_group)
            if bisect_mode == "initial" and tested_side == "keep" and set(suspects) != set(source_mods):
                fallback_targets = list(source_mods)
                next_allowed_requests.append("initial")
                suspects_invalidated = True
                final_suspects = list(source_mods)
            elif other_group and bisect_mode in {"initial", "continue_failed_group"}:
                pending_group = list(other_group)
                next_allowed_requests.append("switch_group")
        else:
            final_suspects = list(tested_group_actual)
            if len(tested_group_actual) > 1:
                continuation_targets = list(tested_group_actual)
                next_allowed_requests.append("continue_failed_group")
            if failure_kind == "dependency_failure":
                next_allowed_requests.append("dependency_move_exception")

        return final_suspects, pending_group, continuation_targets, next_allowed_requests, fallback_targets, suspects_invalidated

    def _set_active_mods(self, active_mods: list[str], snapshot_tag: str, reason: str) -> list[str]:
        self.rollback_mods(snapshot_tag)
        installed = self.list_mods()
        resolved_active = self._resolve_mod_names_to_installed(active_mods, candidates=installed)
        inactive = [m for m in installed if m not in resolved_active]
        if inactive:
            self.remove_mods_by_name(inactive, source="bisect", reason=reason)
        self.operations.append(f"bisect_set_active:snapshot={snapshot_tag}:active={json.dumps(resolved_active, ensure_ascii=False)}")
        return resolved_active

    def _build_bisect_move_records(self, moved_mods: list[str], from_group: str, to_group: str, reason: str) -> list[BisectMoveRecord]:
        return [BisectMoveRecord(mod_name=mod_name, from_group=from_group, to_group=to_group, reason=reason) for mod_name in moved_mods]

    def _prepare_bisect_round_plan(self, idx: int, action: dict, snapshot_tag: str) -> tuple[dict[str, object], dict[str, object]]:
        bisect_mode, suspects = self._consume_bisect_targets(action)
        session = self._coerce_bisect_session()
        source_mods = list(getattr(session, "source_mods", []) or self.list_mods())
        if bisect_mode == "initial":
            fallback_seed = list(getattr(session, "fallback_targets", []) or [])
            if fallback_seed:
                source_mods = self._resolve_mod_names_to_installed(fallback_seed)
        keep_group, test_group = self._split_mods_for_bisect(suspects)
        tested_side = "test" if bisect_mode == "switch_group" else "keep"
        active_group = list(test_group if tested_side == "test" else keep_group)
        plan = {
            "index": idx,
            "snapshot_tag": snapshot_tag,
            "bisect_mode": bisect_mode,
            "suspects": list(suspects),
            "source_mods": list(source_mods),
            "keep_group": list(keep_group),
            "test_group": list(test_group),
            "tested_side": tested_side,
            "active_group": list(active_group),
            "moved_mods": [],
            "notes": [],
            "bisect_reason": str(action.get("bisect_reason") or action.get("reason") or "").strip(),
            "round_index": max(1, len(session.rounds) + 1),
        }
        execution = {
            "index": idx,
            "action_type": "bisect_mods",
            "status": "prepared",
            "snapshot_tag": snapshot_tag,
            "bisect_mode": bisect_mode,
            "tested_side": tested_side,
            "keep_group": keep_group,
            "test_group": test_group,
            "suspects": suspects,
        }
        self._log_bisect_event(
            "install.bisect.start",
            {"round_index": plan["round_index"], "bisect_mode": bisect_mode, "suspects": suspects, "snapshot_tag": snapshot_tag},
        )
        self._log_bisect_event("install.bisect.groups", {"bisect_mode": bisect_mode, "keep_group": keep_group, "test_group": test_group})
        return plan, execution

    def _store_pending_bisect_round_plan(self, plan: dict[str, object]) -> None:
        session = self._coerce_bisect_session()
        self.bisect_session = BisectSession(**{**asdict(session), "pending_round_plan": dict(plan)})

    def _execute_pending_bisect_round(self, plan: dict[str, object]) -> tuple[bool, dict[str, object], dict[str, object] | None]:
        idx = int(plan.get("index") or 0)
        snapshot_tag = str(plan.get("snapshot_tag") or "")
        bisect_mode = str(plan.get("bisect_mode") or "initial")
        tested_side = str(plan.get("tested_side") or "keep")
        keep_group = list(plan.get("keep_group") or [])
        test_group = list(plan.get("test_group") or [])
        suspects = list(plan.get("suspects") or [])
        source_mods = list(plan.get("source_mods") or self.list_mods())
        active_group = list(plan.get("active_group") or [])
        moved_mods = list(plan.get("moved_mods") or [])
        notes = list(plan.get("notes") or [])
        bisect_reason = str(plan.get("bisect_reason") or "")
        session = self._coerce_bisect_session()

        self.backup_mods(snapshot_tag)
        active_after_setup = self._set_active_mods(active_group, snapshot_tag, reason=f"bisect_round:{idx}:active_group")
        start_res = self.start_server(timeout=self.config.runtime.start_timeout)
        round_result = "pass" if bool(start_res.get("success")) else "fail"
        failure_kind, failure_detail = self._classify_bisect_failure(start_res)
        final_suspects, pending_group, continuation_targets, next_allowed_requests, fallback_targets, suspects_invalidated = (
            self._derive_bisect_followups(
                bisect_mode=bisect_mode,
                tested_side=tested_side,
                round_result=round_result,
                failure_kind=failure_kind,
                keep_group=keep_group,
                test_group=test_group,
                active_after_setup=active_after_setup,
                suspects=suspects,
                source_mods=source_mods,
            )
        )
        move_records = self._build_bisect_move_records(
            moved_mods, from_group="test" if tested_side == "keep" else "keep", to_group=tested_side, reason="startup_dependency_probe"
        )
        round_record = BisectRoundRecord(
            round_index=int(plan.get("round_index") or max(1, len(session.rounds) + 1)),
            requested_targets=list(suspects),
            bisect_mode=bisect_mode,
            tested_side=tested_side,
            kept_group=list(keep_group),
            tested_group=list(test_group),
            moved_mods=move_records,
            result=round_result,
            trigger_reason=bisect_reason,
            startup_success=bool(start_res.get("success")),
            failure_kind="" if round_result == "pass" else failure_kind,
            failure_detail="" if round_result == "pass" else failure_detail,
            continuation_targets=list(continuation_targets),
            pending_other_group=list(pending_group),
            next_allowed_requests=list(next_allowed_requests),
            fallback_targets=list(fallback_targets),
            suspects_invalidated=suspects_invalidated,
            notes=notes + [f"start_success={bool(start_res.get('success'))}"],
        )
        feedback = self._build_bisect_feedback_payload(
            suspects=suspects,
            bisect_mode=bisect_mode,
            tested_side=tested_side,
            keep_group=keep_group,
            test_group=test_group,
            moved_mods=moved_mods,
            round_result=round_result,
            startup_success=bool(start_res.get("success")),
            failure_kind="" if round_result == "pass" else failure_kind,
            failure_detail="" if round_result == "pass" else failure_detail,
            reason=bisect_reason,
            pending_group=pending_group,
            continuation_targets=continuation_targets,
            next_allowed_requests=next_allowed_requests,
            fallback_targets=fallback_targets,
            suspects_invalidated=suspects_invalidated,
        )
        completed_requests = list(dict.fromkeys([*(getattr(session, "completed_requests", []) or []), bisect_mode]))
        progress_token = self._make_bisect_progress_token(
            suspects=suspects,
            bisect_mode=bisect_mode,
            tested_side=tested_side,
            round_result=round_result,
            final_suspects=final_suspects,
            next_allowed_requests=next_allowed_requests,
        )
        previous_token = str(getattr(session, "progress_token", "") or "")
        stagnant_rounds = int(getattr(session, "stagnant_rounds", 0) or 0)
        if progress_token == previous_token:
            stagnant_rounds += 1
            round_record.notes.append(f"stagnant_round_detected={stagnant_rounds}")
        else:
            stagnant_rounds = 0
        self.bisect_session = BisectSession(
            **{
                **asdict(session),
                "active": bool(
                    next_allowed_requests
                    or pending_group
                    or continuation_targets
                    or fallback_targets
                    or (round_result != "pass" and len(final_suspects) > 1)
                ),
                "source_mods": list(source_mods),
                "suspect_mods": list(final_suspects),
                "safe_mods": [m for m in source_mods if m not in final_suspects],
                "rounds": [*session.rounds, round_record],
                "final_suspects": list(final_suspects if len(final_suspects) <= 3 else final_suspects[:3]),
                "stopped_reason": "bisect_round_completed",
                "last_round_feedback": feedback,
                "pending_group": list(pending_group),
                "continuation_targets": list(continuation_targets),
                "next_allowed_requests": list(next_allowed_requests),
                "completed_requests": completed_requests,
                "fallback_targets": list(fallback_targets),
                "suspects_invalidated": suspects_invalidated,
                "progress_token": progress_token,
                "stagnant_rounds": stagnant_rounds,
                "pending_round_plan": {},
            }
        )
        self.last_bisect_feedback = feedback
        self.rollback_mods(snapshot_tag)
        self._log_bisect_event(
            "install.bisect.result",
            {
                "bisect_mode": bisect_mode,
                "tested_side": tested_side,
                "result": round_result,
                "startup_success": bool(start_res.get("success")),
                "failure_kind": "" if round_result == "pass" else failure_kind,
                "moved_mods": moved_mods,
                "active_after_setup": active_after_setup,
                "stagnant_rounds": stagnant_rounds,
            },
        )
        self._log_bisect_event(
            "install.bisect.next",
            {
                "next_suspects": final_suspects,
                "pending_group": pending_group,
                "continuation_targets": continuation_targets,
                "next_allowed_requests": next_allowed_requests,
                "fallback_targets": fallback_targets,
                "suspects_invalidated": suspects_invalidated,
            },
        )
        self.operations.append(
            "bisect_round:"
            f"result={round_result}:keep={json.dumps(keep_group, ensure_ascii=False)}:"
            f"test={json.dumps(test_group, ensure_ascii=False)}:moves={json.dumps(moved_mods, ensure_ascii=False)}"
        )
        execution = {
            "index": idx,
            "action_type": "bisect_mods",
            "status": "applied",
            "snapshot_tag": snapshot_tag,
            "result": round_result,
            "tested_side": tested_side,
            "keep_group": keep_group,
            "test_group": test_group,
            "moved_mods": moved_mods,
            "next_suspects": final_suspects,
            "startup_success": bool(start_res.get("success")),
            "failure_kind": "" if round_result == "pass" else failure_kind,
            "already_bisected": True,
            "next_allowed_requests": next_allowed_requests,
            "fallback_targets": fallback_targets,
            "suspects_invalidated": suspects_invalidated,
            "feedback": feedback,
        }
        return False, execution, None

    def _run_move_bisect_mods_action(
        self, idx: int, action: dict, snapshot_tag: str
    ) -> tuple[bool, dict[str, object], dict[str, object] | None]:
        session = self._coerce_bisect_session()
        plan = dict(getattr(session, "pending_round_plan", {}) or {})
        execution: dict[str, object] = {"index": idx, "action_type": "move_bisect_mods", "status": "skipped", "snapshot_tag": snapshot_tag}
        if not plan:
            execution["reason"] = "missing_pending_bisect_round_plan"
            return False, execution, None
        tested_side = str(plan.get("tested_side") or "keep")
        opposite_group = list(plan.get("test_group") or []) if tested_side == "keep" else list(plan.get("keep_group") or [])
        move_targets = self._resolve_mod_names_to_installed(
            [str(x) for x in (action.get("targets") or []) if str(x).strip()], candidates=opposite_group
        )
        active_group = list(plan.get("active_group") or [])
        moved_mods = list(plan.get("moved_mods") or [])
        for mod_name in move_targets:
            if mod_name in opposite_group and mod_name not in active_group:
                active_group.append(mod_name)
                moved_mods.append(mod_name)
        plan["active_group"] = active_group
        plan["moved_mods"] = moved_mods
        plan["notes"] = [*list(plan.get("notes") or []), "moved_dependency_candidates"]
        self._store_pending_bisect_round_plan(plan)
        return self._execute_pending_bisect_round(plan)

    def _run_bisect_mods_action(
        self, idx: int, action: dict, snapshot_tag: str
    ) -> tuple[bool, dict[str, object], dict[str, object] | None]:
        bisect_mode, suspects = self._consume_bisect_targets(action)
        session = self._coerce_bisect_session()
        source_mods = list(getattr(session, "source_mods", []) or self.list_mods())
        request_source = str(action.get("request_source") or "ai").strip() or "ai"
        if bisect_mode == "initial":
            fallback_seed = list(getattr(session, "fallback_targets", []) or [])
            if fallback_seed:
                source_mods = self._resolve_mod_names_to_installed(fallback_seed)
        execution: dict[str, object] = {
            "index": idx,
            "action_type": "bisect_mods",
            "status": "skipped",
            "snapshot_tag": snapshot_tag,
            "bisect_mode": bisect_mode,
        }
        if len(suspects) < 2:
            execution.update({"status": "blocked", "reason": "insufficient_mods_for_bisect", "suspects": suspects})
            return False, execution, None

        keep_group, test_group = self._split_mods_for_bisect(suspects)
        self._log_bisect_event(
            "install.bisect.start",
            {
                "round_index": max(1, len(self.bisect_session.rounds) + 1),
                "bisect_mode": bisect_mode,
                "suspects": suspects,
                "snapshot_tag": snapshot_tag,
            },
        )
        self._log_bisect_event(
            "install.bisect.groups",
            {
                "bisect_mode": bisect_mode,
                "keep_group": keep_group,
                "test_group": test_group,
            },
        )

        allow_moves = bool(action.get("allow_dependency_moves", False))
        move_candidates = self._resolve_mod_names_to_installed(
            [str(x) for x in (action.get("move_candidates") or []) if str(x).strip()],
            candidates=suspects,
        )
        moved_mods: list[str] = []
        notes: list[str] = []
        bisect_reason = str(action.get("bisect_reason") or action.get("reason") or "").strip()
        tested_side = "keep"
        active_group = list(keep_group)
        if bisect_mode == "switch_group":
            tested_side = "test"
            active_group = list(test_group)
        if allow_moves and move_candidates:
            for mod_name in move_candidates:
                opposite_group = test_group if tested_side == "keep" else keep_group
                if mod_name in opposite_group and mod_name not in active_group:
                    active_group.append(mod_name)
                    moved_mods.append(mod_name)
            if moved_mods:
                notes.append("moved_dependency_candidates")

        self.backup_mods(snapshot_tag)
        active_after_setup = self._set_active_mods(
            active_group,
            snapshot_tag,
            reason=f"bisect_round:{idx}:keep_group_with_moves",
        )
        start_res = self.start_server(timeout=self.config.runtime.start_timeout)
        round_result = "pass" if bool(start_res.get("success")) else "fail"
        failure_kind, failure_detail = self._classify_bisect_failure(start_res)
        final_suspects, pending_group, continuation_targets, next_allowed_requests, fallback_targets, suspects_invalidated = (
            self._derive_bisect_followups(
                bisect_mode=bisect_mode,
                tested_side=tested_side,
                round_result=round_result,
                failure_kind=failure_kind,
                keep_group=keep_group,
                test_group=test_group,
                active_after_setup=active_after_setup,
                suspects=suspects,
                source_mods=source_mods,
            )
        )
        move_records = self._build_bisect_move_records(
            moved_mods,
            from_group="test" if tested_side == "keep" else "keep",
            to_group=tested_side,
            reason="startup_dependency_probe",
        )
        round_record = BisectRoundRecord(
            round_index=max(1, len(session.rounds) + 1),
            requested_targets=list(suspects),
            bisect_mode=bisect_mode,
            tested_side=tested_side,
            kept_group=list(keep_group),
            tested_group=list(test_group),
            moved_mods=move_records,
            result=round_result,
            trigger_reason=bisect_reason,
            startup_success=bool(start_res.get("success")),
            failure_kind="" if round_result == "pass" else failure_kind,
            failure_detail="" if round_result == "pass" else failure_detail,
            continuation_targets=list(continuation_targets),
            pending_other_group=list(pending_group),
            next_allowed_requests=list(next_allowed_requests),
            fallback_targets=list(fallback_targets),
            suspects_invalidated=suspects_invalidated,
            notes=notes + [f"start_success={bool(start_res.get('success'))}"],
        )
        feedback = self._build_bisect_feedback_payload(
            suspects=suspects,
            bisect_mode=bisect_mode,
            tested_side=tested_side,
            keep_group=keep_group,
            test_group=test_group,
            moved_mods=moved_mods,
            round_result=round_result,
            startup_success=bool(start_res.get("success")),
            failure_kind="" if round_result == "pass" else failure_kind,
            failure_detail="" if round_result == "pass" else failure_detail,
            reason=bisect_reason,
            pending_group=pending_group,
            continuation_targets=continuation_targets,
            next_allowed_requests=next_allowed_requests,
            fallback_targets=fallback_targets,
            suspects_invalidated=suspects_invalidated,
        )
        request_token = bisect_mode
        phase = str(getattr(session, "phase", "initial") or "initial")
        if bisect_mode == "initial" and request_source == "system_auto_resume":
            phase = "fallback"
            request_token = f"initial:fallback:{','.join(sorted(suspects, key=str.lower))}"
        completed_requests = list(dict.fromkeys([*(getattr(session, "completed_requests", []) or []), bisect_mode]))
        completed_request_tokens = list(dict.fromkeys([*(getattr(session, "completed_request_tokens", []) or []), request_token]))
        progress_token = self._make_bisect_progress_token(
            suspects=suspects,
            bisect_mode=bisect_mode,
            tested_side=tested_side,
            round_result=round_result,
            final_suspects=final_suspects,
            next_allowed_requests=next_allowed_requests,
        )
        previous_token = str(getattr(session, "progress_token", "") or "")
        stagnant_rounds = int(getattr(session, "stagnant_rounds", 0) or 0)
        if progress_token == previous_token:
            stagnant_rounds += 1
            round_record.notes.append(f"stagnant_round_detected={stagnant_rounds}")
        else:
            stagnant_rounds = 0
        self.bisect_session = BisectSession(
            active=bool(
                next_allowed_requests
                or pending_group
                or continuation_targets
                or fallback_targets
                or (round_result != "pass" and len(final_suspects) > 1)
            ),
            source_mods=list(source_mods),
            suspect_mods=list(final_suspects),
            safe_mods=[m for m in source_mods if m not in final_suspects],
            phase=phase,
            rounds=[*session.rounds, round_record],
            final_suspects=list(final_suspects if len(final_suspects) <= 3 else final_suspects[:3]),
            stopped_reason="bisect_round_completed",
            last_round_feedback=feedback,
            pending_group=list(pending_group),
            continuation_targets=list(continuation_targets),
            next_allowed_requests=list(next_allowed_requests),
            completed_requests=completed_requests,
            completed_request_tokens=completed_request_tokens,
            fallback_targets=list(fallback_targets),
            suspects_invalidated=suspects_invalidated,
            progress_token=progress_token,
            stagnant_rounds=stagnant_rounds,
            success_ready=bool(
                round_result == "pass"
                and not next_allowed_requests
                and not pending_group
                and not continuation_targets
                and not fallback_targets
            ),
            success_guard_reason=(
                "bisect_converged"
                if round_result == "pass"
                and not next_allowed_requests
                and not pending_group
                and not continuation_targets
                and not fallback_targets
                else ""
            ),
            success_guard_history=list(getattr(session, "success_guard_history", []) or []),
            consecutive_same_issue_on_success=0,
        )
        self.last_bisect_feedback = feedback
        self.rollback_mods(snapshot_tag)
        self._log_bisect_event(
            "install.bisect.result",
            {
                "bisect_mode": bisect_mode,
                "tested_side": tested_side,
                "result": round_result,
                "startup_success": bool(start_res.get("success")),
                "failure_kind": "" if round_result == "pass" else failure_kind,
                "moved_mods": moved_mods,
                "active_after_setup": active_after_setup,
                "stagnant_rounds": stagnant_rounds,
            },
        )
        self._log_bisect_event(
            "install.bisect.next",
            {
                "next_suspects": final_suspects,
                "pending_group": pending_group,
                "continuation_targets": continuation_targets,
                "next_allowed_requests": next_allowed_requests,
                "fallback_targets": fallback_targets,
                "suspects_invalidated": suspects_invalidated,
            },
        )
        self.operations.append(
            "bisect_round:"
            f"result={round_result}:keep={json.dumps(keep_group, ensure_ascii=False)}:"
            f"test={json.dumps(test_group, ensure_ascii=False)}:moves={json.dumps(moved_mods, ensure_ascii=False)}"
        )
        execution.update(
            {
                "status": "applied",
                "result": round_result,
                "tested_side": tested_side,
                "keep_group": keep_group,
                "test_group": test_group,
                "moved_mods": moved_mods,
                "next_suspects": final_suspects,
                "startup_success": bool(start_res.get("success")),
                "failure_kind": "" if round_result == "pass" else failure_kind,
                "already_bisected": True,
                "next_allowed_requests": next_allowed_requests,
                "fallback_targets": fallback_targets,
                "suspects_invalidated": suspects_invalidated,
                "feedback": feedback,
            }
        )
        return False, execution, None

    def _attempt_trace_path(self, attempt: int, stage: str) -> Path:
        safe_stage = re.sub(r"[^a-zA-Z0-9_\-.]+", "_", str(stage or "unknown")).strip("_") or "unknown"
        return self.workdirs.logs / f"attempt_{attempt:02d}_{safe_stage}.json"

    def _append_attempt_trace(
        self,
        attempt: int,
        stage: str,
        status: str,
        *,
        context_summary: dict | None = None,
        recognition_plan: dict | None = None,
        ai_result: dict | None = None,
        action_plan: list[dict] | None = None,
        preflight: list[dict] | None = None,
        execution: list[dict] | None = None,
        rollback: list[dict] | None = None,
    ) -> None:
        trace = AttemptTrace(
            attempt=attempt,
            stage=stage,
            status=status,
            context_summary=dict(context_summary or {}),
            recognition_plan=dict(recognition_plan or {}),
            ai_result=dict(ai_result or {}),
            action_plan=[dict(item) for item in (action_plan or [])],
            preflight=[dict(item) for item in (preflight or [])],
            execution=[dict(item) for item in (execution or [])],
            rollback=[dict(item) for item in (rollback or [])],
        )
        self.attempt_traces.append(trace)
        path = self._attempt_trace_path(attempt, stage)
        path.write_text(json.dumps(asdict(trace), ensure_ascii=False, indent=2), encoding="utf-8")

    def _summarize_ai_context(self, context: dict) -> dict[str, object]:
        log_excerpt = self._normalize_text_list(context.get("log_signal_summary", []), limit=10)
        if not log_excerpt:
            log_excerpt = self._extract_log_signal_lines(context.get("refined_log", ""), limit=8)
        recognition_summary = context.get("recognition_summary", {})
        return {
            "mc_version": context.get("mc_version", "unknown"),
            "loader": context.get("loader", "unknown"),
            "loader_version": context.get("loader_version"),
            "build": context.get("build"),
            "start_mode": context.get("start_mode", "unknown"),
            "recognition_summary": dict(recognition_summary) if isinstance(recognition_summary, dict) else {},
            "mod_count": int(context.get("mod_count", 0) or 0),
            "current_installed_mods_preview": self._normalize_text_list(context.get("current_installed_mods", []), limit=12),
            "known_deleted_client_mods": self._normalize_text_list(context.get("known_deleted_client_mods", []), limit=20),
            "recent_actions": self._normalize_text_list(context.get("recent_actions", []), limit=12),
            "key_exception": str(context.get("key_exception") or "none"),
            "log_signal_summary": log_excerpt,
        }

    def _serialize_detection_candidates(self, candidates: object, *, limit: int = 3) -> list[dict[str, object]]:
        items = list(candidates or [])
        serialized: list[dict[str, object]] = []
        for candidate in items[:limit]:
            value = getattr(candidate, "value", None)
            if not value:
                continue
            serialized.append(
                {
                    "value": str(value),
                    "confidence": float(getattr(candidate, "confidence", 0.0) or 0.0),
                    "reason": str(getattr(candidate, "reason", "") or ""),
                }
            )
        return serialized

    def _build_recognition_summary(self) -> dict[str, object]:
        manifest = getattr(self, "manifest", None)
        if not manifest:
            return {}
        evidence = []
        for item in list(getattr(manifest, "evidence", []) or [])[:5]:
            evidence.append(
                {
                    "source_type": str(getattr(item, "source_type", "") or ""),
                    "evidence_type": str(getattr(item, "evidence_type", "") or ""),
                    "file": str(getattr(item, "file", "") or ""),
                    "matched_text": str(getattr(item, "matched_text", "") or ""),
                    "weight": float(getattr(item, "weight", 0.0) or 0.0),
                    "reason": str(getattr(item, "reason", "") or ""),
                }
            )
        return {
            "pack_name": manifest.pack_name,
            "confidence": float(getattr(manifest, "confidence", 0.0) or 0.0),
            "active_loader": getattr(manifest, "loader", "unknown"),
            "active_mc_version": getattr(manifest, "mc_version", "unknown"),
            "active_loader_version": getattr(manifest, "loader_version", None),
            "active_build": getattr(manifest, "build", None),
            "active_start_mode": getattr(manifest, "start_mode", "unknown"),
            "warnings": list(getattr(manifest, "warnings", []) or []),
            "loader_candidates": self._serialize_detection_candidates(getattr(manifest, "loader_candidates", [])),
            "mc_version_candidates": self._serialize_detection_candidates(getattr(manifest, "mc_version_candidates", [])),
            "loader_version_candidates": self._serialize_detection_candidates(getattr(manifest, "loader_version_candidates", [])),
            "build_candidates": self._serialize_detection_candidates(getattr(manifest, "build_candidates", [])),
            "start_mode_candidates": self._serialize_detection_candidates(getattr(manifest, "start_mode_candidates", [])),
            "evidence_preview": evidence,
            "fallback_history": list(getattr(self, "recognition_attempts", [])[-5:]),
            "recognition_strategy_used": str(getattr(manifest, "raw", {}).get("pack_type", "unknown")),
            "recognition_pipeline": list(getattr(manifest, "raw", {}).get("recognition_pipeline", []) or []),
            "recognition_phase_hits": list(getattr(manifest, "raw", {}).get("recognition_phase_hits", []) or []),
            "recognition_phase_details": dict(getattr(manifest, "raw", {}).get("recognition_phase_details", {}) or {}),
            "recognition_fallback_count": len(list(getattr(self, "recognition_attempts", []) or [])),
            "recognition_switched": len(list(getattr(self, "recognition_attempts", []) or [])) > 0,
            "recognition_finalized_after_runtime_feedback": any(
                str(item.get("reason") or "") == "runtime_feedback_fallback"
                for item in list(getattr(self, "recognition_attempts", []) or [])
                if isinstance(item, dict)
            ),
        }

    def _recognition_confidence_level(self, confidence: float) -> str:
        if confidence >= 0.85:
            return "high"
        if confidence >= 0.55:
            return "medium"
        return "low"

    def _build_recognition_candidates(self) -> list[RecognitionFallbackPlan]:
        manifest = self.manifest
        if not manifest:
            return []
        loaders = top_candidate_values(getattr(manifest, "loader_candidates", [])) or [
            str(getattr(manifest, "loader", "unknown") or "unknown")
        ]
        mc_versions = top_candidate_values(getattr(manifest, "mc_version_candidates", [])) or [
            str(getattr(manifest, "mc_version", "unknown") or "unknown")
        ]
        loader_versions = top_candidate_values(
            getattr(manifest, "loader_version_candidates", []),
            limit=4,
        ) or [str(getattr(manifest, "loader_version", "") or "")]
        start_modes = top_candidate_values(getattr(manifest, "start_mode_candidates", [])) or [
            str(getattr(manifest, "start_mode", "jar") or "jar")
        ]
        builds = top_candidate_values(getattr(manifest, "build_candidates", []), limit=4) or [str(getattr(manifest, "build", "") or "")]
        plans: list[RecognitionFallbackPlan] = []
        for loader in loaders[:3]:
            for mc_version in mc_versions[:2]:
                for start_mode in start_modes[:2]:
                    loader_version = next(
                        (
                            item
                            for item in loader_versions
                            if item and (mc_version in item or loader in item.lower())
                        ),
                        loader_versions[0] or None,
                    )
                    build = next((item for item in builds if item), None)
                    confidence = 0.4
                    if loader == getattr(manifest, "loader", "unknown"):
                        confidence += 0.2
                    if mc_version == getattr(manifest, "mc_version", "unknown"):
                        confidence += 0.2
                    if start_mode == getattr(manifest, "start_mode", "unknown"):
                        confidence += 0.1
                    plans.append(
                        RecognitionFallbackPlan(
                            loader=loader,
                            loader_version=loader_version,
                            mc_version=mc_version,
                            build=build,
                            start_mode=start_mode,
                            java_version=choose_java_version(manifest, loader=loader, mc_version=mc_version),
                            confidence=min(1.0, round(confidence, 3)),
                            reason="候选识别计划",
                            source_candidates=[loader, mc_version, start_mode],
                        )
                    )
        dedup: dict[tuple[str, str | None, str | None, str], RecognitionFallbackPlan] = {}
        for plan in plans:
            key = (plan.loader, plan.loader_version, plan.mc_version, plan.start_mode)
            if key not in dedup or dedup[key].confidence < plan.confidence:
                dedup[key] = plan
        return sorted(dedup.values(), key=lambda item: (-item.confidence, item.loader, item.start_mode))

    def _preflight_recognition_plan(self, plan: RecognitionFallbackPlan) -> dict[str, object]:
        server = self.workdirs.server
        checks: list[str] = []
        score = 0
        if plan.start_mode in {"argsfile", "args_file"} and any(server.glob("libraries/**/unix_args.txt")):
            score += 1
            checks.append("argsfile_path_present")
        if plan.loader == "forge" and (server / "libraries" / "net" / "minecraftforge").exists():
            score += 1
            checks.append("forge_libraries_present")
        if plan.loader == "neoforge" and (server / "libraries" / "net" / "neoforged").exists():
            score += 1
            checks.append("neoforge_libraries_present")
        if plan.loader in {"fabric", "quilt"} and any(server.glob("**/*fabric*loader*.jar")):
            score += 1
            checks.append("fabric_like_loader_present")
        if (server / self.server_jar_name).exists():
            score += 1
            checks.append("server_jar_present")
        if plan.java_version == choose_java_version(self.manifest, loader=plan.loader, mc_version=plan.mc_version):
            score += 1
            checks.append("java_version_matches_loader_strategy")
        return {
            "allowed": score > 0,
            "score": score,
            "checks": checks,
            "confidence_level": self._recognition_confidence_level(plan.confidence),
        }

    def _apply_recognition_plan(self, plan: RecognitionFallbackPlan, *, reason: str) -> None:
        if not self.manifest:
            return
        self.manifest.loader = plan.loader  # type: ignore[assignment]
        self.manifest.mc_version = plan.mc_version or self.manifest.mc_version
        self.manifest.loader_version = plan.loader_version
        self.manifest.build = plan.build
        self.manifest.start_mode = "args_file" if plan.start_mode in {"argsfile", "args_file"} else plan.start_mode  # type: ignore[assignment]
        if plan.start_mode in {"argsfile", "args_file"}:
            self._apply_modern_loader_start_mode()
        self.recognition_attempts.append(
            {
                "loader": plan.loader,
                "loader_version": plan.loader_version,
                "mc_version": plan.mc_version,
                "start_mode": plan.start_mode,
                "java_version": plan.java_version,
                "reason": reason,
                "confidence": plan.confidence,
                "confidence_level": self._recognition_confidence_level(plan.confidence),
            }
        )
        if plan.java_version != self.current_java_version:
            self.switch_java_version(plan.java_version)

    def _recognition_runtime_feedback(self, start_res: dict[str, object], log_info: dict[str, object]) -> dict[str, object]:
        text = "\n".join(
            [
                str(start_res.get("stdout_tail") or ""),
                str(start_res.get("stderr_tail") or ""),
                str(log_info.get("refined_log") or ""),
                str(log_info.get("key_exception") or ""),
            ]
        ).lower()
        inferred_loader = None
        if any(token in text for token in ("fml", "minecraftforge", "forge mod loader")):
            inferred_loader = "forge"
        elif "neoforge" in text:
            inferred_loader = "neoforge"
        elif "fabric-loader" in text or "fabricloader" in text:
            inferred_loader = "fabric"
        elif "quilt-loader" in text or "quilt" in text:
            inferred_loader = "quilt"
        inferred_mc_version = None
        version_match = re.search(r"\b1\.\d+(?:\.\d+)?\b", text)
        if version_match:
            inferred_mc_version = version_match.group(0)
        java_hint = infer_java_from_runtime_feedback(text, self.current_java_version)
        return {
            "inferred_loader": inferred_loader,
            "inferred_mc_version": inferred_mc_version,
            "java_hint": java_hint,
            "raw": text[:800],
        }

    def _select_next_recognition_plan(self, start_res: dict[str, object], log_info: dict[str, object]) -> RecognitionFallbackPlan | None:
        runtime = self._recognition_runtime_feedback(start_res, log_info)
        plans = self._build_recognition_candidates()
        tried = {
            (
                str(item.get("loader")),
                str(item.get("loader_version")),
                str(item.get("mc_version")),
                str(item.get("start_mode")),
            )
            for item in self.recognition_attempts
        }
        inferred_loader = runtime.get("inferred_loader")
        inferred_mc_version = runtime.get("inferred_mc_version")
        runtime_java_hint = runtime.get("java_hint")
        boosted: list[RecognitionFallbackPlan] = []
        for plan in plans:
            if (plan.loader, str(plan.loader_version), str(plan.mc_version), plan.start_mode) in tried:
                continue
            preflight = self._preflight_recognition_plan(plan)
            if not preflight.get("allowed"):
                continue
            confidence = plan.confidence + (0.25 if inferred_loader and plan.loader == inferred_loader else 0.0)
            confidence += 0.12 if inferred_mc_version and plan.mc_version == inferred_mc_version else 0.0
            confidence += 0.08 if runtime_java_hint and plan.java_version == runtime_java_hint else 0.0
            confidence += min(float(preflight.get("score") or 0) * 0.03, 0.15)
            boosted.append(
                RecognitionFallbackPlan(
                    loader=plan.loader,
                    loader_version=plan.loader_version,
                    mc_version=plan.mc_version,
                    build=plan.build,
                    start_mode=plan.start_mode,
                    java_version=int(runtime_java_hint or plan.java_version),
                    confidence=min(1.0, round(confidence, 3)),
                    reason=(
                        f"{plan.reason}; runtime_loader={inferred_loader or 'unknown'}; "
                        f"runtime_mc={inferred_mc_version or 'unknown'}; "
                        f"preflight={','.join(preflight.get('checks', [])) or 'none'}"
                    ),
                    source_candidates=list(plan.source_candidates),
                )
            )
        if not boosted:
            return None
        return sorted(boosted, key=lambda item: (-item.confidence, item.java_version))[0]

    def _assess_action_preflight(self, action: dict) -> ActionPreflight:
        action_type = str(action.get("type") or "unknown")
        details: list[str] = []
        if action_type == "bisect_mods":
            bisect_mode = str(action.get("bisect_mode") or "initial").strip() or "initial"
            if bisect_mode not in {"initial", "switch_group", "continue_failed_group"}:
                return ActionPreflight(
                    action_type=action_type,
                    risk="high",
                    allowed=False,
                    reason="invalid_bisect_mode",
                    details=[f"bisect_mode={bisect_mode}"],
                )
            session = self._coerce_bisect_session()
            next_allowed = list(getattr(session, "next_allowed_requests", []) or [])
            completed = set(getattr(session, "completed_requests", []) or [])
            completed_tokens = set(getattr(session, "completed_request_tokens", []) or [])
            request_source = str(action.get("request_source") or "ai").strip() or "ai"
            details.append(f"bisect_mode={bisect_mode}")
            details.append(f"request_source={request_source}")
            if bisect_mode != "initial" and bisect_mode not in next_allowed:
                details.append(f"next_allowed_requests={json.dumps(next_allowed, ensure_ascii=False)}")
                return ActionPreflight(
                    action_type=action_type,
                    risk="medium",
                    allowed=False,
                    reason="bisect_request_not_allowed_in_current_state",
                    details=details,
                )
            if bisect_mode == "switch_group":
                resolved = self._resolve_mod_names_to_installed(list(getattr(session, "pending_group", []) or []))
            elif bisect_mode == "continue_failed_group":
                resolved = self._resolve_mod_names_to_installed(list(getattr(session, "continuation_targets", []) or []))
            else:
                targets = [str(x).strip() for x in (action.get("targets") or []) if str(x).strip()]
                resolved = self._resolve_mod_names_to_installed(targets or self.list_mods())
            move_candidates = self._resolve_mod_names_to_installed(
                [str(x).strip() for x in (action.get("move_candidates") or []) if str(x).strip()],
                candidates=resolved,
            )
            details.append(f"resolved_targets={json.dumps(resolved, ensure_ascii=False)}")
            if action.get("keep_group") or action.get("test_group"):
                details.append("manual_grouping_ignored_by_system=true")
            if move_candidates:
                details.append(f"move_candidates={json.dumps(move_candidates, ensure_ascii=False)}")
            fallback_targets = self._resolve_mod_names_to_installed(list(getattr(session, "fallback_targets", []) or []))
            fallback_phase_allowed = (
                bisect_mode == "initial"
                and request_source == "system_auto_resume"
                and bool(getattr(session, "suspects_invalidated", False))
                and "initial" in next_allowed
                and bool(fallback_targets)
                and set(resolved) == set(fallback_targets)
            )
            request_token = bisect_mode
            if fallback_phase_allowed:
                request_token = f"initial:fallback:{','.join(sorted(resolved, key=str.lower))}"
                details.append("fallback_phase=auto_resume")
            if len(resolved) < 2:
                return ActionPreflight(
                    action_type=action_type, risk="medium", allowed=False, reason="insufficient_mods_for_bisect", details=details
                )
            if len(resolved) > 24:
                return ActionPreflight(
                    action_type=action_type, risk="high", allowed=False, reason="too_many_mod_targets_for_bisect", details=details
                )
            if len(move_candidates) > 3:
                return ActionPreflight(
                    action_type=action_type, risk="high", allowed=False, reason="too_many_dependency_moves", details=details
                )
            if request_token in completed_tokens and bisect_mode != "continue_failed_group":
                details.append(f"completed_request_tokens={json.dumps(sorted(completed_tokens), ensure_ascii=False)}")
                return ActionPreflight(
                    action_type=action_type,
                    risk="medium",
                    allowed=False,
                    reason="duplicate_bisect_stage_request",
                    details=details,
                )
            if request_token == bisect_mode and bisect_mode in completed and bisect_mode != "continue_failed_group":
                details.append(f"completed_requests={json.dumps(sorted(completed), ensure_ascii=False)}")
                return ActionPreflight(
                    action_type=action_type, risk="medium", allowed=False, reason="duplicate_bisect_stage_request", details=details
                )
            last_bisect_feedback = dict(getattr(self, "last_bisect_feedback", {}) or {})
            if bisect_mode == "initial" and last_bisect_feedback and not fallback_phase_allowed:
                last_targets = self._resolve_mod_names_to_installed(
                    [str(x) for x in (last_bisect_feedback.get("requested_targets") or []) if str(x).strip()],
                    candidates=resolved,
                )
                if set(last_targets) == set(resolved) and not move_candidates:
                    details.append(f"last_bisect_feedback={json.dumps(last_bisect_feedback, ensure_ascii=False)}")
                    return ActionPreflight(
                        action_type=action_type,
                        risk="medium",
                        allowed=False,
                        reason="duplicate_bisect_request_after_previous_round",
                        details=details,
                    )
            return ActionPreflight(
                action_type=action_type,
                risk="medium",
                allowed=True,
                reason="controlled_bisect_allowed",
                details=details,
            )
        if action_type == "remove_mods":
            targets = [str(x).strip() for x in (action.get("targets") or []) if str(x).strip()]
            rollback_on_failure = bool(action.get("rollback_on_failure", False))
            regex_targets = [x for x in targets if x.startswith("regex:")]
            direct_targets = [x for x in targets if not x.startswith("regex:")]
            resolved = self._resolve_mod_names_to_installed(direct_targets)
            unresolved = [x for x in direct_targets if x not in resolved]
            details.append(f"rollback_on_failure={rollback_on_failure}")
            if regex_targets:
                details.append(f"regex_targets={json.dumps(regex_targets, ensure_ascii=False)}")
            if resolved:
                details.append(f"resolved_targets={json.dumps(resolved, ensure_ascii=False)}")
            if unresolved:
                details.append(f"unresolved_targets={json.dumps(unresolved, ensure_ascii=False)}")
            if regex_targets:
                return ActionPreflight(
                    action_type=action_type,
                    risk="high",
                    allowed=False,
                    reason="regex_remove_requires_manual_review",
                    details=details,
                )
            if not resolved:
                return ActionPreflight(
                    action_type=action_type,
                    risk="medium",
                    allowed=False,
                    reason="no_installed_targets_resolved",
                    details=details,
                )
            if len(resolved) > 3:
                return ActionPreflight(
                    action_type=action_type,
                    risk="high",
                    allowed=False,
                    reason="too_many_mod_targets",
                    details=details,
                )
            return ActionPreflight(
                action_type=action_type,
                risk="medium",
                allowed=True,
                reason="resolved_low_volume_mod_removal",
                details=details,
            )

        if action_type == "adjust_memory":
            xmx = str(action.get("xmx", self.jvm_xmx) or self.jvm_xmx)
            xms = str(action.get("xms", self.jvm_xms) or self.jvm_xms)
            xmx_norm, xms_norm = self._normalize_memory_plan(xmx, xms)
            details.append(f"normalized_plan=Xmx={xmx_norm},Xms={xms_norm}")
            current_xmx_gb = parse_mem_to_gb(self.jvm_xmx)
            next_xmx_gb = parse_mem_to_gb(xmx_norm)
            if next_xmx_gb > self.get_system_memory() * float(self.config.memory.max_ram_ratio):
                return ActionPreflight(
                    action_type=action_type,
                    risk="high",
                    allowed=False,
                    reason="memory_plan_exceeds_cap",
                    details=details,
                )
            delta = abs(next_xmx_gb - current_xmx_gb)
            if delta > 4:
                return ActionPreflight(
                    action_type=action_type,
                    risk="high",
                    allowed=False,
                    reason="memory_change_too_large",
                    details=details,
                )
            return ActionPreflight(
                action_type=action_type,
                risk="low",
                allowed=True,
                reason="bounded_memory_adjustment",
                details=details,
            )

        if action_type == "change_java":
            version = int(action.get("version", self.current_java_version) or self.current_java_version)
            details.append(f"target_version={version}")
            if version not in SUPPORTED_JAVA_VERSIONS:
                return ActionPreflight(
                    action_type=action_type,
                    risk="high",
                    allowed=False,
                    reason="unsupported_java_version",
                    details=details,
                )
            if abs(version - self.current_java_version) > 4:
                return ActionPreflight(
                    action_type=action_type,
                    risk="high",
                    allowed=False,
                    reason="java_version_jump_too_large",
                    details=details,
                )
            return ActionPreflight(
                action_type=action_type,
                risk="medium",
                allowed=True,
                reason="whitelisted_java_switch",
                details=details,
            )

        if action_type in {"stop_and_report", "report_manual_fix"}:
            return ActionPreflight(action_type=action_type, risk="low", allowed=True, reason="non_mutating_action", details=details)

        return ActionPreflight(action_type=action_type, risk="high", allowed=False, reason="unknown_action_type", details=details)

    def _rollback_action(self, action_type: str, snapshot_tag: str, previous_state: dict[str, object]) -> dict[str, object]:
        result: dict[str, object] = {"action_type": action_type, "snapshot_tag": snapshot_tag, "performed": False}
        try:
            if action_type == "remove_mods":
                self.rollback_mods(snapshot_tag)
                result["performed"] = True
            elif action_type == "bisect_mods":
                self.rollback_mods(snapshot_tag)
                result["performed"] = True
            elif action_type == "adjust_memory":
                self.set_jvm_args(
                    str(previous_state.get("jvm_xmx") or self.jvm_xmx),
                    str(previous_state.get("jvm_xms") or self.jvm_xms),
                    list(previous_state.get("extra_jvm_flags") or self.extra_jvm_flags),
                )
                result["performed"] = True
            elif action_type == "change_java":
                previous_version = int(previous_state.get("current_java_version") or self.current_java_version)
                previous_bin = previous_state.get("current_java_bin")
                self.current_java_version = previous_version
                self.current_java_bin = Path(str(previous_bin)) if previous_bin else None
                self.extra_jvm_flags = list(previous_state.get("extra_jvm_flags") or self.extra_jvm_flags)
                self._write_start_script()
                self.operations.append(f"rollback_java_version:{previous_version}")
                result["performed"] = True
        except Exception as exc:
            result["error"] = f"{type(exc).__name__}:{exc}"
        return result

    def _execute_action_with_safeguards(
        self, idx: int, action: dict, preflight: ActionPreflight, snapshot_tag: str
    ) -> tuple[bool, dict[str, object], dict[str, object] | None]:
        action_type = str(action.get("type") or "unknown")
        current_jvm_xmx = str(getattr(self, "jvm_xmx", "4G") or "4G")
        current_jvm_xms = str(getattr(self, "jvm_xms", current_jvm_xmx) or current_jvm_xmx)
        current_extra_jvm_flags = list(getattr(self, "extra_jvm_flags", []) or [])
        current_java_version = int(getattr(self, "current_java_version", 21) or 21)
        current_java_bin = getattr(self, "current_java_bin", None)
        previous_state: dict[str, object] = {
            "jvm_xmx": current_jvm_xmx,
            "jvm_xms": current_jvm_xms,
            "extra_jvm_flags": current_extra_jvm_flags,
            "current_java_version": current_java_version,
            "current_java_bin": str(current_java_bin) if current_java_bin else "",
        }
        execution: dict[str, object] = {
            "index": idx,
            "action_type": action_type,
            "status": "skipped",
            "snapshot_tag": snapshot_tag,
            "risk": preflight.risk,
        }
        rollback: dict[str, object] | None = None

        if action_type in {"remove_mods", "bisect_mods"}:
            self.backup_mods(snapshot_tag)

        try:
            if action_type == "bisect_mods":
                return self._run_bisect_mods_action(idx, action, snapshot_tag)
            if action_type == "remove_mods":
                targets = action.get("targets") or []
                rollback_on_failure = bool(action.get("rollback_on_failure", False))
                names = [x for x in targets if not str(x).startswith("regex:")]
                resolved_names = self._resolve_mod_names_to_installed([str(x) for x in names])
                if resolved_names:
                    self.remove_mods_by_name(
                        resolved_names,
                        source="ai_action",
                        reason=f"attempt_action_index={idx}:explicit_targets",
                    )
                installed_after_ai = self.list_mods()
                forced_targets, forced_rationale, matched_chains = self._resolve_dependency_cleanup_targets(
                    self.last_ai_result.dependency_chains if self.last_ai_result else [],
                    installed_after_ai,
                )
                execution.update(
                    {
                        "status": "applied",
                        "resolved_targets": resolved_names,
                        "rollback_on_failure": rollback_on_failure,
                        "forced_targets": forced_targets,
                        "forced_rationale": forced_rationale[:20],
                        "matched_dependency_chains": matched_chains[:10],
                    }
                )
                if forced_targets:
                    self.remove_mods_by_name(
                        forced_targets,
                        source="dependency_cleanup",
                        reason="depend_on_known_deleted_client_mod",
                    )
                    self.operations.append(f"dependency_cleanup_forced_remove:targets={json.dumps(forced_targets, ensure_ascii=False)}")
                if rollback_on_failure:
                    validation_res = self.start_server(timeout=self.config.runtime.start_timeout)
                    validation_success = bool(validation_res.get("success"))
                    execution.update(
                        {
                            "validation_start_performed": True,
                            "validation_success": validation_success,
                            "validation_success_source": validation_res.get("success_source"),
                        }
                    )
                    if not validation_success:
                        rollback = self._rollback_action(action_type, snapshot_tag, previous_state)
                        execution.update(
                            {
                                "status": "rolled_back",
                                "rollback_reason": "startup_validation_failed",
                                "validation_failure_excerpt": self._extract_log_signal_lines(
                                    "\n".join(
                                        [
                                            str(validation_res.get("stdout") or ""),
                                            str(validation_res.get("stderr") or ""),
                                            str(validation_res.get("reason") or ""),
                                        ]
                                    ),
                                    limit=8,
                                ),
                            }
                        )
                        return False, execution, rollback
            elif action_type == "adjust_memory":
                xmx = action.get("xmx", self.jvm_xmx)
                xms = action.get("xms", self.jvm_xms)
                xmx_norm, xms_norm = self._normalize_memory_plan(str(xmx), str(xms))
                self.set_jvm_args(xmx_norm, xms_norm)
                execution.update({"status": "applied", "xmx": xmx_norm, "xms": xms_norm})
            elif action_type == "change_java":
                version = int(action.get("version", 21))
                self.switch_java_version(version)
                execution.update({"status": "applied", "version": version})
            elif action_type == "stop_and_report":
                self.stop_reason = str(action.get("final_reason", "stop_and_report"))
                self.operations.append(f"stop_and_report:{self.stop_reason}")
                execution.update({"status": "applied", "stop_reason": self.stop_reason})
                return True, execution, None
            elif action_type == "report_manual_fix":
                final_reason = str(action.get("final_reason") or action.get("reason") or "manual_fix_required")
                manual_steps = self._normalize_text_list(action.get("manual_steps", []), limit=20)
                evidence = self._normalize_text_list(action.get("evidence", []), limit=20)
                self.last_ai_manual_report = {
                    "user_summary": str(self.last_ai_result.user_summary if self.last_ai_result else final_reason) or final_reason,
                    "suggested_manual_steps": manual_steps,
                    "evidence": evidence,
                }
                self.stop_reason = final_reason
                self.operations.append(f"report_manual_fix:{final_reason}")
                execution.update({"status": "applied", "stop_reason": final_reason, "manual_steps": manual_steps, "evidence": evidence})
                return True, execution, None
            else:
                execution.update({"status": "ignored", "reason": "unknown_action_type"})
        except Exception as exc:
            execution.update({"status": "failed", "error": f"{type(exc).__name__}:{exc}"})
            rollback = self._rollback_action(action_type, snapshot_tag, previous_state)
            return False, execution, rollback

        return False, execution, rollback

    # 系统与JVM
    def get_system_memory(self) -> float:
        mem = psutil.virtual_memory().total
        return round(mem / 1024 / 1024 / 1024, 2)

    def set_jvm_args(self, xmx: str, xms: str | None = None, extra_flags: list[str] | None = None):
        self.jvm_xmx = xmx
        if xms:
            self.jvm_xms = xms
        if extra_flags is not None:
            self.extra_jvm_flags = extra_flags
        self._write_start_script()
        self.operations.append(f"set_jvm_args:Xmx={self.jvm_xmx},Xms={self.jvm_xms}")

    def switch_java_version(self, version: int):
        if version not in SUPPORTED_JAVA_VERSIONS:
            raise ValueError(f"不支持的 Java 版本: {version}, 支持: {SUPPORTED_JAVA_VERSIONS}")
        if not self._ensure_java_installed(version):
            raise FileNotFoundError(f"Java {version} 安装失败或不存在: {self._java_bin_path(version)}")
        java_bin = self._java_bin_path(version)
        self.current_java_bin = java_bin
        self.current_java_version = version
        self.extra_jvm_flags = list(
            dict.fromkeys(
                [
                    *self._resolve_java_params_for_version(version),
                    *self.config.extra_jvm_flags,
                ]
            )
        )
        self._write_start_script()
        self.operations.append(f"switch_java_version:{version}")

    def _select_java_version_for_current_manifest(self) -> int:
        manifest = self.manifest
        if not manifest:
            return choose_latest_lts_java_version()
        plans = self._build_recognition_candidates()
        if plans:
            preferred = plans[0]
            return choose_java_version(manifest, loader=preferred.loader, mc_version=preferred.mc_version)
        return choose_java_version(manifest)

    def _collect_process_resource_snapshot(self, proc: subprocess.Popen) -> dict[str, float | int | str | None]:
        try:
            ps_proc = psutil.Process(proc.pid)
            children = ps_proc.children(recursive=True)
            rss_bytes = ps_proc.memory_info().rss
            cpu_percent = ps_proc.cpu_percent(interval=None)
            for child in children:
                try:
                    rss_bytes += child.memory_info().rss
                    cpu_percent += child.cpu_percent(interval=None)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            return {
                "timestamp": datetime.now().isoformat(),
                "rss_mb": round(rss_bytes / 1024 / 1024, 2),
                "cpu_percent": round(cpu_percent, 2),
                "process_count": len(children) + 1,
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return {
                "timestamp": datetime.now().isoformat(),
                "rss_mb": 0.0,
                "cpu_percent": 0.0,
                "process_count": 0,
                "error": "process_unavailable",
            }

    def _detect_failure_signals(self, text: str) -> list[str]:
        lowered = (text or "").lower()
        patterns = (
            (r"outofmemoryerror|java heap space|gc overhead limit exceeded", "memory_oom"),
            (r"could not reserve enough space|insufficient memory|os::commit_memory", "memory_allocation"),
            (r"address already in use|failed to bind to port|port .* in use", "port_in_use"),
            (r"unsupportedclassversionerror|has been compiled by a more recent version", "java_version_mismatch"),
            (r"could not find or load main class|unable to access jarfile|no such file", "start_command_error"),
            (r"missing dependency|depends on|requires .* but it is missing", "missing_dependency"),
            (r"client-only|dedicated server|invalid dist|wrong side", "client_mod_detected"),
            (r"main class .* not found|@.*args\.txt|argument file .* not found", "loader_misclassification"),
            (r"watchdog|server watchdog|deadlock", "watchdog_or_deadlock"),
            (r"neoforge", "loader_signal_neoforge"),
            (r"quilt", "loader_signal_quilt"),
            (r"fabricloader|fabric", "loader_signal_fabric"),
            (r"fml|forge", "loader_signal_forge"),
        )
        matched: list[str] = []
        for pattern, label in patterns:
            if re.search(pattern, lowered):
                matched.append(label)
        return matched

    def detect_current_java_version(self) -> int:
        cmd = [str(self.current_java_bin or "java"), "-version"]
        cp = subprocess.run(cmd, capture_output=True, text=True, check=False)
        text = cp.stderr + cp.stdout
        m = re.search(r'"(\d+)(?:\.(\d+))?.*"', text)
        if not m:
            return 0
        major = int(m.group(1))
        if major == 1 and m.group(2):
            return int(m.group(2))
        return major

    def _detect_log_ready_signal(self, text: str) -> tuple[bool, str]:
        lower = (text or "").lower()
        markers = [
            ("done", "log_done"),
            ("preparing spawn area", "log_preparing_spawn_area"),
        ]
        for marker, source in markers:
            if marker in lower:
                return True, source
        return False, ""

    def _detect_command_probe_ready(self, text: str) -> tuple[bool, str]:
        if re.search(r"there\s+are.*players\s+online", text or "", flags=re.IGNORECASE | re.DOTALL):
            return True, "cmd_probe_list_response"
        return False, ""

    # 运行与日志
    def start_server(self, timeout: int = 300) -> dict:
        script = self._start_script_path()
        if not script.exists():
            self._write_start_script()

        latest_log = self.workdirs.server / "logs" / "latest.log"
        latest_log.parent.mkdir(parents=True, exist_ok=True)

        cmd = [str(script)] if os.name != "nt" else ["cmd", "/c", str(script)]
        proc = subprocess.Popen(
            cmd,
            cwd=self.workdirs.server,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        stdout_lines: list[str] = []
        stderr_lines: list[str] = []
        threads = [
            threading.Thread(target=threaded_pipe_reader, args=(proc.stdout, stdout_lines), daemon=True),
            threading.Thread(target=threaded_pipe_reader, args=(proc.stderr, stderr_lines), daemon=True),
        ]
        for t in threads:
            t.start()

        probe_enabled = bool(self.config.runtime.startup_command_probe_enabled)
        loop_interval = max(0.2, float(self.config.runtime.startup_probe_interval_sec))
        soft_timeout = max(8.0, float(self.config.runtime.startup_soft_timeout))
        hard_timeout = max(float(timeout), float(self.config.runtime.startup_hard_timeout))
        start_at = time.monotonic()
        soft_deadline = start_at + soft_timeout
        hard_deadline = start_at + hard_timeout
        next_probe_at = start_at + max(1.0, float(self.config.runtime.startup_command_probe_initial_delay_sec))
        probe_retry = max(1.0, float(self.config.runtime.startup_command_probe_retry_sec))
        probe_command = "list"

        done = False
        cmd_probe_ok = False
        port_open = False
        success_source = ""
        readiness_evidence: list[str] = []
        resource_samples: list[dict[str, float | int | str | None]] = []
        failure_signals: list[str] = []

        while True:
            now = time.monotonic()
            if now >= hard_deadline:
                readiness_evidence.append("hard_timeout_reached")
                break

            log_tail = read_tail_text(latest_log, lines=300)
            out_tail = "\n".join(stdout_lines[-120:])
            err_tail = "\n".join(stderr_lines[-120:])
            merged_tail = "\n".join([log_tail, out_tail, err_tail])

            if proc.poll() is None:
                resource_samples.append(self._collect_process_resource_snapshot(proc))

            for signal in self._detect_failure_signals(merged_tail):
                if signal not in failure_signals:
                    failure_signals.append(signal)

            if not port_open:
                try:
                    port_open = is_local_tcp_port_open(port=int(self.config.server_port), host="127.0.0.1", timeout=0.6)
                except Exception:
                    port_open = False
                if port_open:
                    readiness_evidence.append("port_open")
                    if not success_source and proc.poll() is None:
                        success_source = "port_open_alive"

            if not done:
                done_detected, done_source = self._detect_log_ready_signal(merged_tail)
                if done_detected:
                    done = True
                    success_source = done_source
                    readiness_evidence.append(done_source)

            if probe_enabled and not cmd_probe_ok and now >= soft_deadline and now >= next_probe_at and proc.poll() is None:
                try:
                    if proc.stdin:
                        proc.stdin.write(f"{probe_command}\n")
                        proc.stdin.flush()
                        readiness_evidence.append(f"probe_sent:{probe_command}")
                except Exception as e:
                    readiness_evidence.append(f"probe_send_failed:{type(e).__name__}")
                next_probe_at = now + probe_retry

            if not cmd_probe_ok:
                probe_detected, probe_source = self._detect_command_probe_ready(merged_tail)
                if probe_detected:
                    cmd_probe_ok = True
                    success_source = probe_source
                    readiness_evidence.append(probe_source)

            if cmd_probe_ok or done or (port_open and proc.poll() is None):
                break

            if proc.poll() is not None:
                readiness_evidence.append(f"process_exit:{proc.returncode}")
                break

            time.sleep(loop_interval)

        process_alive = proc.poll() is None
        if process_alive and not self.config.runtime.keep_running:
            graceful_stop_process(proc, timeout_sec=20.0, stop_command="stop")
            process_alive = proc.poll() is None
        elif (not success_source) and process_alive:
            terminate_process(proc, timeout_sec=8.0)
            process_alive = proc.poll() is None

        if proc.stdout:
            proc.stdout.close()
        if proc.stderr:
            proc.stderr.close()

        exit_code = proc.poll()
        stdout_tail = "\n".join(stdout_lines[-80:])
        stderr_tail = "\n".join(stderr_lines[-80:])
        success = bool(success_source)
        peak_rss_mb = max((float(item.get("rss_mb") or 0.0) for item in resource_samples), default=0.0)
        peak_cpu_percent = max((float(item.get("cpu_percent") or 0.0) for item in resource_samples), default=0.0)
        max_process_count = max((int(item.get("process_count") or 0) for item in resource_samples), default=0)

        result = StartResult(
            success=success,
            done_detected=done,
            command_probe_detected=cmd_probe_ok,
            port_open_detected=port_open,
            process_alive=process_alive,
            success_source=success_source or "none",
            readiness_evidence=readiness_evidence[-12:],
            failure_signals=failure_signals[-12:],
            resource_samples=resource_samples[-20:],
            resource_summary={
                "peak_rss_mb": round(peak_rss_mb, 2),
                "peak_cpu_percent": round(peak_cpu_percent, 2),
                "max_process_count": max_process_count,
            },
            exit_code=exit_code,
            log_path=latest_log,
            crash_dir=self.workdirs.server / "crash-reports",
            stdout_tail=stdout_tail,
            stderr_tail=stderr_tail,
        )
        self.operations.append(
            "start_server:"
            f"success={success},source={result.success_source},"
            f"done={done},cmd_probe={cmd_probe_ok},port={port_open},exit={exit_code},alive={process_alive},"
            f"failure_signals={json.dumps(result.failure_signals, ensure_ascii=False)},"
            f"resource={json.dumps(result.resource_summary, ensure_ascii=False)}"
        )
        return asdict(result)

    def extract_relevant_log(self, log_path: str, crash_dir: str) -> dict:
        crash_path = Path(crash_dir)
        key_exception = ""
        suspected_mods: list[str] = []
        has_crash = False
        crash_content = ""
        crash_mod_issue = ""
        oom_detected = False
        jvm_exit_code: int | None = None

        if crash_path.exists():
            crashes = sorted(crash_path.glob("crash-*.txt"), key=lambda p: p.stat().st_mtime)
            if crashes:
                has_crash = True
                crash_content = crashes[-1].read_text(encoding="utf-8", errors="ignore")
                crash_mod_issue = self._extract_latest_crash_mod_issue(crash_content)
                m = re.search(r"(?m)^\s*Caused by:\s*([^\n]+)", crash_content)
                key_exception = m.group(1).strip() if m else ""
                suspected_mods = re.findall(r"(?i)(?:mod|mods?)\s*[:=]\s*([A-Za-z0-9_\-\.]+)", crash_content)
                oom_detected = bool(re.search(r"(?i)(outofmemoryerror|java heap space|gc overhead limit exceeded)", crash_content))
                exit_code_match = re.search(r"(?i)(?:process\s+)?(?:exit\s*code|exitcode|returned\s+code)\s*[:=]\s*(-?\d+)", crash_content)
                if exit_code_match:
                    try:
                        jvm_exit_code = int(exit_code_match.group(1))
                    except ValueError:
                        jvm_exit_code = None

        log = Path(log_path)
        refined = ""
        if log.exists():
            lines = log.read_text(encoding="utf-8", errors="ignore").splitlines()
            trigger = [
                "Exception",
                "Error",
                "Crash",
                "at net.minecraft",
                "java.lang.",
                "Caused by",
                "Mod Loading has failed",
                "The game crashed",
            ]
            slices: list[list[str]] = []

            idx = -1
            for i in range(len(lines) - 1, -1, -1):
                if any(t in lines[i] for t in trigger):
                    idx = i
                    break
            if idx != -1:
                start = max(0, idx - 100)
                slices.append(lines[start:])

            if lines:
                slices.append(lines[-500:])

            merged: list[str] = []
            for part in slices:
                for line in part:
                    if not merged or merged[-1] != line:
                        merged.append(line)

            if len(merged) > 2000:
                merged = merged[-2000:]
            elif len(merged) > 1500:
                merged = merged[-1800:]

            refined = "\n".join(merged)

            if not oom_detected:
                oom_detected = bool(re.search(r"(?i)(outofmemoryerror|java heap space|gc overhead limit exceeded)", refined))

            if jvm_exit_code is None:
                code_patterns = [
                    r"(?i)(?:process\s+)?(?:exit\s*code|exitcode|returned\s+code)\s*[:=]\s*(-?\d+)",
                    r"(?i)(?:\bexit\b)\s*(-?\d+)",
                ]
                for pat in code_patterns:
                    match_list = re.findall(pat, refined)
                    if not match_list:
                        continue
                    try:
                        jvm_exit_code = int(match_list[-1])
                        break
                    except ValueError:
                        continue

        if not key_exception:
            m = re.search(r"(?m)([A-Za-z0-9_.]+(?:Exception|Error))", refined)
            key_exception = m.group(1) if m else "unknown"

        return {
            "has_crash": has_crash,
            "crash_content": crash_content,
            "crash_mod_issue": crash_mod_issue,
            "refined_log": refined,
            "key_exception": key_exception,
            "suspected_mods": sorted(set(suspected_mods))[:20],
            "oom_detected": oom_detected,
            "jvm_exit_code": jvm_exit_code,
        }

    def _extract_latest_crash_mod_issue(self, crash_content: str) -> str:
        text = str(crash_content or "")
        if not text.strip():
            return ""

        issue_pattern = re.compile(
            r"(?ms)^\s*(--\s+Mod loading issue for:\s+.+?\s+--)\s*(.*?)\s*(?=^\s*--\s+System Details\s+--|\Z)",
        )
        matches = list(issue_pattern.finditer(text))
        if not matches:
            return ""

        header = re.sub(r"\s+", " ", matches[-1].group(1)).strip()
        body = matches[-1].group(2)
        cleaned_lines: list[str] = []
        seen: set[str] = set()
        for raw_line in body.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            normalized = re.sub(r"\s+", " ", line)
            if normalized in seen:
                continue
            seen.add(normalized)
            cleaned_lines.append(normalized)

        if not cleaned_lines:
            return header
        return "\n".join([header, *cleaned_lines[:20]])

    def _extract_json_object(self, text: str) -> dict | None:
        return self.ai_service._extract_json_object(text)

    def _safe_ai_result(self, reason: str, confidence: float = 0.1) -> AIResult:
        return self.ai_service._safe_ai_result(reason, confidence)

    def _normalize_text_list(self, value: object, limit: int = 50) -> list[str]:
        return self.ai_service._normalize_text_list(value, limit)

    def _normalize_ai_result(self, data: dict) -> AIResult:
        return self.ai_service._normalize_ai_result(data)

    def _resolve_dependency_cleanup_targets(
        self,
        dependency_chains: list[list[str]],
        installed_mods: list[str],
    ) -> tuple[list[str], list[str], list[list[str]]]:
        if not dependency_chains or not installed_mods or not self.known_deleted_client_mods:
            return [], [], []

        known_deleted_tokens = {self._normalize_mod_token(x) for x in self.known_deleted_client_mods if str(x).strip()}
        forced_names: list[str] = []
        rationale: list[str] = []
        matched_chains: list[list[str]] = []

        for chain in dependency_chains:
            clean_chain = [str(x).strip() for x in chain if str(x).strip()]
            if len(clean_chain) < 2:
                continue

            hit_indexes = [idx for idx, node in enumerate(clean_chain) if self._normalize_mod_token(node) in known_deleted_tokens]
            if not hit_indexes:
                continue

            matched_chains.append(clean_chain)
            for hit_idx in hit_indexes:
                deleted_node = clean_chain[hit_idx]
                dependents = clean_chain[:hit_idx]
                resolved = self._resolve_mod_names_to_installed(dependents, candidates=installed_mods)
                for dep in resolved:
                    if dep not in forced_names:
                        forced_names.append(dep)
                    rationale.append(f"{dep} 依赖已删除客户端mod {deleted_node}，触发强制删除")

        return forced_names, rationale, matched_chains

    def _build_openai_messages(self, prompt: str) -> list[dict[str, str]]:
        return self.ai_service._build_openai_messages(prompt)

    def _build_openai_headers(self) -> dict[str, str]:
        return self.ai_service._build_openai_headers()

    def _resolve_openai_chat_endpoint(self) -> str:
        return self.ai_service._resolve_openai_chat_endpoint()

    def _extract_openai_text_from_non_stream(self, body: dict) -> str:
        return self.ai_service._extract_openai_text_from_non_stream(body)

    def _extract_openai_text_from_stream(self, resp) -> str:
        return self.ai_service._extract_openai_text_from_stream(resp)

    def _map_ai_http_error(self, status_code: int, body_preview: str = "") -> str:
        return self.ai_service._map_ai_http_error(status_code, body_preview)

    def _call_ollama_generate(self, prompt: str) -> str:
        return self.ai_service._call_ollama_generate(prompt)

    def _call_openai_compatible_chat(self, prompt: str) -> str:
        return self.ai_service._call_openai_compatible_chat(prompt)

    def _call_ai_provider(self, prompt: str) -> str:
        return self.ai_service._call_ai_provider(prompt)

    def analyze_with_ai(self, context: dict) -> dict:
        return self.ai_service.analyze(context)

    # 输出
    def generate_report(self) -> str:
        report_path = self.workdirs.root / "report.txt"
        recognition_summary = self._build_recognition_summary()
        ai_summary = "none"
        ai_detail_lines: list[str] = []
        if self.last_ai_result:
            ai_summary = (
                f"issue={self.last_ai_result.primary_issue}, "
                f"confidence={self.last_ai_result.confidence:.2f}, "
                f"reason={self.last_ai_result.reason}"
            )
            ai_detail_lines = [
                f"- 输入摘要: {self.last_ai_result.input_summary or 'none'}",
                f"- 用户可读摘要: {self.last_ai_result.user_summary or 'none'}",
                f"- 命中的已删除mod: {json.dumps(self.last_ai_result.hit_deleted_mods, ensure_ascii=False)}",
                f"- 依赖链: {json.dumps(self.last_ai_result.dependency_chains, ensure_ascii=False)}",
                f"- 删除判定依据: {json.dumps(self.last_ai_result.deletion_rationale, ensure_ascii=False)}",
                f"- 冲突/异常说明: {json.dumps(self.last_ai_result.conflicts_or_exceptions, ensure_ascii=False)}",
                f"- 证据: {json.dumps(self.last_ai_result.evidence, ensure_ascii=False)}",
                f"- 建议手动修复步骤: {json.dumps(self.last_ai_result.suggested_manual_steps, ensure_ascii=False)}",
                f"- 思考链: {json.dumps(self.last_ai_result.thought_chain, ensure_ascii=False)}",
            ]

        deleted_history_lines: list[str] = []
        for mod_name in sorted(self.known_deleted_client_mods):
            evidence = self.deleted_mod_evidence.get(mod_name, [])
            deleted_history_lines.append(f"- {mod_name}: {json.dumps(evidence, ensure_ascii=False)}")
        deleted_mod_sources = getattr(self, "deleted_mod_sources", {}) if isinstance(getattr(self, "deleted_mod_sources", {}), dict) else {}
        deleted_source_lines: list[str] = []
        for mod_name in sorted(deleted_mod_sources):
            deleted_source_lines.append(f"- {mod_name}: {json.dumps(deleted_mod_sources.get(mod_name, {}), ensure_ascii=False)}")
        attempt_trace_lines = [
            (
                f"- attempt={trace.attempt}, stage={trace.stage}, status={trace.status}, "
                f"file={self._attempt_trace_path(trace.attempt, trace.stage).name}"
            )
            for trace in self.attempt_traces
        ]
        bisect_tree_lines = self._format_bisect_tree_lines()
        loader_candidate_values = [item.get("value") for item in recognition_summary.get("loader_candidates", [])]
        mc_candidate_values = [item.get("value") for item in recognition_summary.get("mc_version_candidates", [])]
        build_candidate_values = [item.get("value") for item in recognition_summary.get("build_candidates", [])]
        start_mode_candidate_values = [item.get("value") for item in recognition_summary.get("start_mode_candidates", [])]
        recognition_lines = [
            f"- 输入包名: {recognition_summary.get('pack_name', 'unknown')}",
            f"- 当前 loader: {recognition_summary.get('active_loader', 'unknown')}",
            f"- 当前 MC 版本: {recognition_summary.get('active_mc_version', 'unknown')}",
            f"- 当前 loader_version: {recognition_summary.get('active_loader_version', None)}",
            f"- 当前 build: {recognition_summary.get('active_build', None)}",
            f"- 当前启动模式: {recognition_summary.get('active_start_mode', 'unknown')}",
            f"- 识别置信度: {recognition_summary.get('confidence', 0.0):.2f}",
            f"- 候选 loader: {json.dumps(loader_candidate_values, ensure_ascii=False)}",
            f"- 候选 MC 版本: {json.dumps(mc_candidate_values, ensure_ascii=False)}",
            f"- 候选 build: {json.dumps(build_candidate_values, ensure_ascii=False)}",
            f"- 候选启动模式: {json.dumps(start_mode_candidate_values, ensure_ascii=False)}",
            f"- 识别流水线: {json.dumps(recognition_summary.get('recognition_pipeline', []), ensure_ascii=False)}",
            f"- 命中的识别阶段: {json.dumps(recognition_summary.get('recognition_phase_hits', []), ensure_ascii=False)}",
            f"- 阶段明细: {json.dumps(recognition_summary.get('recognition_phase_details', {}), ensure_ascii=False)}",
            f"- 回退历史: {json.dumps(recognition_summary.get('fallback_history', []), ensure_ascii=False)}",
            f"- 证据摘要: {json.dumps(recognition_summary.get('evidence_preview', []), ensure_ascii=False)}",
        ]
        lines = [
            "MC Auto Server Builder 报告",
            f"生成时间: {datetime.now().isoformat()}",
            f"工作目录: {self.workdirs.root}",
            f"是否成功启动: {self.run_success}",
            f"实际尝试次数: {self.attempts_used}",
            f"最终状态: {'成功' if self.run_success else '失败'} / {self.stop_reason or 'success_or_attempt_limit'}",
            f"清理/删除Mods数量: {len(self.removed_mods)}",
            f"二分测试临时移除数量: {len(getattr(self, 'bisect_removed_mods', []))}",
            "删除列表:",
            *[f"- {m}" for m in self.removed_mods],
            f"最终JVM: Xmx={self.jvm_xmx}, Xms={self.jvm_xms}",
            f"Java版本: {self.detect_current_java_version()}",
            "识别过程摘要:",
            *recognition_lines,
            f"最后一次AI结论: {ai_summary}",
            "AI 手动兜底摘要:",
            f"- 用户摘要: {self.last_ai_manual_report.get('user_summary', 'none') if self.last_ai_manual_report else 'none'}",
            (
                f"- 手动步骤: {json.dumps(self.last_ai_manual_report.get('suggested_manual_steps', []), ensure_ascii=False)}"
                if self.last_ai_manual_report
                else "- 手动步骤: []"
            ),
            (
                f"- 证据: {json.dumps(self.last_ai_manual_report.get('evidence', []), ensure_ascii=False)}"
                if self.last_ai_manual_report
                else "- 证据: []"
            ),
            "AI高价值分析明细:",
            *(ai_detail_lines or ["- none"]),
            "Attempt Trace 索引:",
            *(attempt_trace_lines or ["- none"]),
            "完整 Bisect Tree:",
            *bisect_tree_lines,
            "已知且已删除客户端mod（本次运行历史）:",
            *(deleted_history_lines or ["- none"]),
            "删除 mod 来源分层统计:",
            *(deleted_source_lines or ["- none"]),
            f"终止原因: {self.stop_reason or 'success_or_attempt_limit'}",
            f"总操作数: {len(self.operations)}",
            "操作记录:",
            *[f"- {x}" for x in self.operations],
        ]
        report_path.write_text("\n".join(lines), encoding="utf-8")
        return str(report_path)

    def _build_meta_payload(self) -> dict[str, object]:
        manifest = self.manifest
        recognition_summary = self._build_recognition_summary()
        return {
            "pack_source": {
                "input_type": getattr(self.pack_input, "input_type", "unknown"),
                "source": getattr(self.pack_input, "source", "unknown"),
                "file_id": getattr(self.pack_input, "file_id", None),
            },
            "manifest_summary": {
                "pack_name": getattr(manifest, "pack_name", "unknown") if manifest else "unknown",
                "mc_version": getattr(manifest, "mc_version", "unknown") if manifest else "unknown",
                "loader": getattr(manifest, "loader", "unknown") if manifest else "unknown",
                "loader_version": getattr(manifest, "loader_version", None) if manifest else None,
                "build": getattr(manifest, "build", None) if manifest else None,
                "start_mode": getattr(manifest, "start_mode", "unknown") if manifest else "unknown",
                "warnings": list(getattr(manifest, "warnings", []) or []) if manifest else [],
            },
            "recognition_result": recognition_summary,
            "java": {
                "selected_version": self.current_java_version,
                "detected_version": self.detect_current_java_version(),
                "xmx": self.jvm_xmx,
                "xms": self.jvm_xms,
                "extra_jvm_flags": list(self.extra_jvm_flags),
            },
            "start_command": {
                "mode": self.start_command_mode,
                "value": self.start_command_value,
            },
            "deleted_mods": {
                "removed_mods": list(self.removed_mods),
                "bisect_removed_mods": list(self.bisect_removed_mods),
                "evidence": dict(self.deleted_mod_evidence),
                "source_breakdown": dict(getattr(self, "deleted_mod_sources", {})),
            },
            "ai": {
                "last_result": asdict(self.last_ai_result) if self.last_ai_result else None,
                "manual_report": dict(self.last_ai_manual_report),
            },
            "attempts": {
                "attempts_used": self.attempts_used,
                "run_success": self.run_success,
                "stop_reason": self.stop_reason,
                "recognition_attempts": list(self.recognition_attempts),
            },
            "operations": list(self.operations),
        }

    def package_server(self) -> str:
        out = self.workdirs.root / "server_pack.zip"
        with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("build_meta.json", json.dumps(self._build_meta_payload(), ensure_ascii=False, indent=2))
            for p in self.workdirs.server.rglob("*"):
                if p.is_file():
                    zf.write(p, p.relative_to(self.workdirs.server))
            for p in self.workdirs.java_bins.rglob("*"):
                if p.is_file():
                    zf.write(p, Path("java_bins") / p.relative_to(self.workdirs.java_bins))
        return str(out)

    # 主流程
    def run(self) -> dict:
        self._log("install.start", f"开始安装，source={self.pack_input.source}")
        try:
            self._log("install.resolve", "解析输入与 manifest")
            self._resolve_pack_and_manifest()

            self._log("install.prepare", "准备服务端文件")
            self._prepare_server_files()

            self._log("install.blacklist", "应用客户端黑名单规则")
            self.apply_known_client_blacklist()
            self.backup_mods("initial_copy")

            self._log("install.meta", "首次启动前生成 eula.txt 与 server.properties")
            self._ensure_server_meta_files()
            desired_java = self._select_java_version_for_current_manifest()
            if desired_java != self.current_java_version:
                self.switch_java_version(desired_java)

            success = False
            for i in range(1, self.config.runtime.max_attempts + 1):
                self.attempts_used = i
                self._log("install.attempt", f"启动尝试 {i}/{self.config.runtime.max_attempts}")
                self.backup_mods(f"attempt_{i}")
                start_res = self.start_server(timeout=self.config.runtime.start_timeout)
                if start_res["success"]:
                    source = str(start_res.get("success_source") or "unknown")
                    self._log("install.attempt", f"尝试 {i} 成功，判定来源={source}")
                    if self._has_pending_bisect_followup():
                        auto_resumed_bisect = False
                        if self._should_auto_resume_full_bisect():
                            auto_actions = [self._build_auto_resume_bisect_action()]
                            self._append_attempt_trace(
                                i,
                                "success_auto_bisect_resume",
                                "ok",
                                action_plan=[dict(x) for x in auto_actions if isinstance(x, dict)],
                            )
                            self._log("install.bisect.auto_resume", json.dumps(auto_actions[0], ensure_ascii=False, sort_keys=True))
                            should_stop = self._apply_actions(auto_actions, attempt=i)
                            if should_stop:
                                self._log("install.stop", f"AI 决策停止，reason={self.stop_reason}", level="WARN")
                                break
                            auto_resumed_bisect = True
                            if self._has_pending_bisect_followup():
                                continue
                        if auto_resumed_bisect:
                            success = True
                            self.stop_reason = f"server_ready:{source}"
                            break
                        ai_context = self._build_ai_context(
                            start_res,
                            log_info={
                                "log_tail": str(start_res.get("stdout_tail") or ""),
                                "crash_excerpt": str(start_res.get("stderr_tail") or ""),
                                "crash_mod_issue": "",
                                "conflicts_or_exceptions": [],
                            },
                        )
                        self._append_attempt_trace(
                            i,
                            "success_context_prepared",
                            "ok",
                            context_summary=self._summarize_ai_context(ai_context),
                        )
                        ai = self.analyze_with_ai(ai_context)
                        self._append_attempt_trace(
                            i,
                            "success_ai_analysis",
                            "ok",
                            context_summary=self._summarize_ai_context(ai_context),
                            ai_result=dict(ai),
                            action_plan=[dict(x) for x in ai.get("actions", []) if isinstance(x, dict)],
                        )
                        self._log("install.ai", f"AI 成功态续轮分析完成，issue={ai.get('primary_issue')} confidence={ai.get('confidence')}")
                        should_stop = self._apply_actions(ai.get("actions", []), attempt=i)
                        if should_stop:
                            self._log("install.stop", f"AI 决策停止，reason={self.stop_reason}", level="WARN")
                            break
                        same_issue_count = self._record_success_guard_observation(ai.get("primary_issue"), ai.get("confidence"))
                        if same_issue_count >= 2:
                            self.stop_reason = "success_guard_same_issue_requires_manual_review"
                            self.last_ai_manual_report = {
                                "user_summary": (
                                    "服务器虽然出现启动成功信号，但 AI 连续两轮在成功态识别出同类 "
                                    "client_mod 风险，已停止自动回归以避免无意义重试。"
                                ),
                                "suggested_manual_steps": [
                                    "检查最后两轮 success_ai_analysis 与 bisect feedback，确认剩余嫌疑 mod。",
                                    "优先人工验证 success_guard_history 中涉及的客户端模组或渲染相关模组。",
                                ],
                                "evidence": list(getattr(self._coerce_bisect_session(), "success_guard_history", []) or []),
                            }
                            self._log("install.stop", f"AI 决策停止，reason={self.stop_reason}", level="WARN")
                            break
                        if self._has_pending_bisect_followup():
                            continue
                    accept_success, final_reason = self._should_accept_success_after_start(start_res)
                    if not accept_success:
                        continue
                    success = True
                    self.stop_reason = final_reason
                    break
                log_info = self.extract_relevant_log(str(start_res["log_path"]), str(start_res["crash_dir"]))
                ai_context = self._build_ai_context(start_res, log_info)
                next_plan = self._select_next_recognition_plan(start_res, log_info)
                self._append_attempt_trace(
                    i,
                    "context_prepared",
                    "ok",
                    context_summary=self._summarize_ai_context(ai_context),
                    recognition_plan=(
                        {
                            "loader": next_plan.loader,
                            "loader_version": next_plan.loader_version,
                            "mc_version": next_plan.mc_version,
                            "build": next_plan.build,
                            "start_mode": next_plan.start_mode,
                            "java_version": next_plan.java_version,
                            "confidence": next_plan.confidence,
                            "confidence_level": self._recognition_confidence_level(next_plan.confidence),
                            "reason": next_plan.reason,
                            "source_candidates": list(next_plan.source_candidates),
                            "preflight": self._preflight_recognition_plan(next_plan),
                        }
                        if next_plan
                        else {}
                    ),
                )
                if next_plan:
                    self._apply_recognition_plan(next_plan, reason="runtime_feedback_fallback")
                    self._append_attempt_trace(
                        i,
                        "recognition_fallback_applied",
                        "ok",
                        context_summary=self._summarize_ai_context(ai_context),
                        recognition_plan={
                            "loader": next_plan.loader,
                            "loader_version": next_plan.loader_version,
                            "mc_version": next_plan.mc_version,
                            "build": next_plan.build,
                            "start_mode": next_plan.start_mode,
                            "java_version": next_plan.java_version,
                            "confidence": next_plan.confidence,
                            "confidence_level": self._recognition_confidence_level(next_plan.confidence),
                            "reason": next_plan.reason,
                            "source_candidates": list(next_plan.source_candidates),
                            "switch_reason": "runtime_feedback_fallback",
                            "preflight": self._preflight_recognition_plan(next_plan),
                        },
                    )
                    continue
                ai = self.analyze_with_ai(ai_context)
                self._append_attempt_trace(
                    i,
                    "ai_analysis",
                    "ok",
                    context_summary=self._summarize_ai_context(ai_context),
                    ai_result=dict(ai),
                    action_plan=[dict(x) for x in ai.get("actions", []) if isinstance(x, dict)],
                )
                self._log("install.ai", f"AI 分析完成，issue={ai.get('primary_issue')} confidence={ai.get('confidence')}")
                should_stop = self._apply_actions(ai.get("actions", []), attempt=i)
                self._ai_debug(
                    "loop.decision "
                    f"attempt={i}, should_stop={should_stop}, stop_reason={self.stop_reason or 'none'}, "
                    f"actions={json.dumps(ai.get('actions', []), ensure_ascii=False)}"
                )
                if should_stop:
                    self._log("install.stop", f"AI 决策停止，reason={self.stop_reason}", level="WARN")
                    break

            self.run_success = success
            if not success and not self.stop_reason:
                self.stop_reason = "attempt_limit_reached"

            # 兜底：确保最终产物中元文件仍然存在（幂等）
            self._ensure_server_meta_files()
            report = self.generate_report()
            package = self.package_server()

            self._log(
                "install.finish",
                f"完成: success={success}, attempts={self.attempts_used}, "
                f"removed_mods={len(self.removed_mods)}, operations={len(self.operations)}",
            )
            return {
                "success": success,
                "workdir": str(self.workdirs.root),
                "report": report,
                "package": package,
                "log_file": str(self.log_file_path),
            }
        except Exception as e:
            self._log("install.error", f"安装失败: {type(e).__name__}: {e}", level="ERROR")
            self._log("install.error", traceback.format_exc(), level="ERROR")
            raise

    def _resolve_pack_and_manifest(self) -> None:
        if self.pack_input.input_type == "local_zip":
            zip_path = Path(self.pack_input.source)
        elif self.pack_input.input_type == "curseforge":
            zip_path = self._download_curseforge_pack(
                project_id=self.pack_input.source,
                file_id=self.pack_input.file_id,
            )
        elif self.pack_input.input_type == "modrinth":
            zip_path = self._download_modrinth_pack(
                project_or_slug=self.pack_input.source,
                version_id=self.pack_input.file_id,
            )
        elif self.pack_input.input_type == "url":
            zip_path = self._download_file(self.pack_input.source, self.workdirs.root / "pack.zip")
        else:
            raise NotImplementedError("不支持的输入类型")

        self.manifest = parse_manifest_from_zip(zip_path)
        self.operations.append(f"parse_manifest:{self.manifest.pack_name}")

    def _prepare_server_files(self) -> None:
        assert self.pack_input
        source_zip = Path(self.pack_input.source) if self.pack_input.input_type == "local_zip" else (self.workdirs.root / "pack.zip")
        self._log("install.unpack", f"开始解压整合包: {source_zip}")
        with zipfile.ZipFile(source_zip, "r") as zf:
            zf.extractall(self.workdirs.client_temp)
        self._log("install.unpack", f"解压完成 -> {self.workdirs.client_temp}")

        self._extract_full_pack_version_payload_if_needed()

        merged_files, merged_dirs, removed_dirs = merge_overrides_into_base(self.workdirs.client_temp)
        self._log(
            "install.overrides",
            f"overrides 合并完成: merged_files={merged_files}, merged_dirs={merged_dirs}, removed_override_dirs={removed_dirs}",
        )

        self._log("install.download", "补全 CurseForge/Modrinth 清单中的缺失文件")
        self._ensure_curseforge_manifest_mods()
        self._ensure_modrinth_manifest_mods()

        # 黑名单复制策略：默认复制绝大多数文件，仅排除明显客户端专用内容
        # 这样即使会多带一些无关文件，也能尽量避免漏掉服务端关键文件。
        blacklist = {
            "assets",
            "screenshots",
            "shaderpacks",
            "resourcepacks",
            "saves",
            "logs",
            "crash-reports",
            "PCL",
            ".minecraft",
            "launcher_profiles.json",
            "options.txt",
            "optionsof.txt",
            "servers.dat",
            "usercache.json",
            "usernamecache.json",
            "manifest.json",
            "modrinth.index.json",
            "modlist.html",
        }
        copied, skipped = self._copy_client_files_with_blacklist(blacklist)
        self.operations.append(f"prepare_server_files:blacklist_copy:copied={copied},skipped={skipped}")
        self._log("install.copy_server", f"客户端文件复制到服务端完成: copied={copied}, skipped={skipped}")

        self._log("install.download", "下载推荐 Java 与安装服务端核心")
        self._download_recommended_java()
        self._install_server_core()
        self._write_start_script()
        self._log("install.finalize", "启动脚本生成完成")

    def _extract_full_pack_version_payload_if_needed(self) -> None:
        if not self.manifest:
            return
        full_pack = self.manifest.raw.get("full_pack") if isinstance(self.manifest.raw, dict) else None
        if not isinstance(full_pack, dict):
            return

        version_name = str(full_pack.get("version_name") or "").strip()
        version_dir = self.workdirs.client_temp / ".minecraft" / "versions" / version_name
        if not version_name or not version_dir.exists() or not version_dir.is_dir():
            return

        copied = 0
        for child in sorted(version_dir.iterdir(), key=lambda p: p.name.lower()):
            if child.name in {f"{version_name}.jar", f"{version_name}.json"}:
                continue
            destination = self.workdirs.client_temp / child.name
            replace_path(child, destination)
            copied += 1

        self.operations.append(f"full_pack_extract:{version_name}:copied={copied}")
        self._log("install.unpack", f"全量包版本目录提取完成: version={version_name}, copied={copied}")

    def _download_curseforge_pack(self, project_id: str, file_id: str | None = None) -> Path:
        out = self.workdirs.root / "pack.zip"
        resolved_project_id = self._resolve_curseforge_project_id(project_id)

        if file_id:
            file_data = self._cf_get_json(f"/v1/mods/{resolved_project_id}/files/{file_id}").get("data") or {}
            if not file_data:
                raise ValueError(f"CurseForge 文件不存在: project={resolved_project_id}, file={file_id}")
            file_name = str(file_data.get("fileName", ""))
            self.operations.append(f"curseforge_selected_file:project={resolved_project_id},file={file_id},name={file_name}")
        else:
            files = self._cf_get_json(f"/v1/mods/{resolved_project_id}/files", params={"pageSize": 50, "index": 0}).get("data") or []
            if not files:
                raise ValueError(f"CurseForge 项目没有可用文件: {resolved_project_id}")

            selected = self._pick_curseforge_pack_file(files)
            if not selected:
                raise ValueError(f"CurseForge 项目无法选择可下载文件: {resolved_project_id}")

            file_data = selected
            file_id_val = file_data.get("id")
            file_name = str(file_data.get("fileName", ""))
            self.operations.append(
                f"curseforge_selected_file_auto:project={resolved_project_id},file={file_id_val},name={file_name},strategy=generic"
            )

        url = file_data.get("downloadUrl") or self._build_curseforge_edge_download_url(file_data)
        if not url:
            raise ValueError(f"CurseForge 文件缺少下载地址: project={resolved_project_id}, file={file_data.get('id')}")

        self._download_file(str(url), out)
        self.operations.append(f"curseforge_download_pack:{resolved_project_id}:{file_data.get('id')}")
        return out

    def _extract_curseforge_type_hints(self, file_data: dict) -> list[str]:
        hints: list[str] = []
        for key in ("gameVersions", "displayName", "fileName"):
            val = file_data.get(key)
            if isinstance(val, list):
                hints.extend(str(x) for x in val if str(x).strip())
            elif val is not None and str(val).strip():
                hints.append(str(val))
        return hints

    def _extract_modrinth_type_hints(self, item: dict) -> list[str]:
        hints: list[str] = []
        for key in ("project_type", "projectType", "file_type", "fileType", "tags"):
            val = item.get(key)
            if isinstance(val, list):
                hints.extend(str(x) for x in val if str(x).strip())
            elif val is not None and str(val).strip():
                hints.append(str(val))
        return hints

    def _classify_manifest_file_type(
        self,
        *,
        platform: str,
        file_name: str,
        rel_path: str | None,
        platform_hints: list[str],
    ) -> tuple[str, bool, str]:
        def _contains_any(text: str, patterns: set[str]) -> bool:
            return any(p in text for p in patterns)

        shader_patterns = {"shader", "shaders", "shaderpack", "shaderpacks"}
        resource_patterns = {
            "resourcepack",
            "resourcepacks",
            "resource-pack",
            "resource_pack",
            "texturepack",
            "texturepacks",
            "texture-pack",
            "texture_pack",
        }
        plugin_patterns = {"plugin", "plugins", "bukkit", "spigot", "paper", "purpur", "bungeecord", "velocity"}
        datapack_patterns = {"datapack", "datapacks", "data-pack", "data_pack", "pack.mcmeta"}
        mod_patterns = {"mod", "mods"}

        normalized_hints = " ".join(str(x).strip().lower() for x in platform_hints if str(x).strip())
        if normalized_hints:
            if _contains_any(normalized_hints, shader_patterns):
                return "shader", False, "platform_hint:shader"
            if _contains_any(normalized_hints, resource_patterns):
                return "resourcepack", False, "platform_hint:resourcepack"
            if _contains_any(normalized_hints, plugin_patterns):
                return "plugin", True, "platform_hint:plugin"
            if _contains_any(normalized_hints, datapack_patterns):
                return "datapack", True, "platform_hint:datapack"
            if _contains_any(normalized_hints, mod_patterns):
                return "mod", True, "platform_hint:mod"

        merged = " ".join(filter(None, [file_name, rel_path or ""])).strip().lower()
        if merged:
            if _contains_any(merged, shader_patterns):
                return "shader", False, "name_or_path:shader"
            if _contains_any(merged, resource_patterns):
                return "resourcepack", False, "name_or_path:resourcepack"
            if _contains_any(merged, plugin_patterns):
                return "plugin", True, "name_or_path:plugin"
            if _contains_any(merged, datapack_patterns):
                return "datapack", True, "name_or_path:datapack"
            if _contains_any(merged, mod_patterns):
                return "mod", True, "name_or_path:mod"

        suffix = Path(file_name).suffix.lower()
        if suffix in {".jar", ".litemod"}:
            return "mod", True, "file_ext:jar_like_default_mod"

        return "unknown", False, f"unrecognized:{platform}"

    def _manifest_target_path(self, file_type: str, file_name: str, rel_path: str | None = None) -> Path:
        clean_name = (file_name or "").strip() or "unnamed.bin"
        if file_type == "plugin":
            return self.workdirs.client_temp / "plugins" / clean_name
        if file_type == "datapack":
            return self.workdirs.client_temp / "datapacks" / clean_name
        if file_type == "mod":
            return self.workdirs.client_temp / "mods" / clean_name

        normalized_rel = normalize_client_relative_path(rel_path or "")
        if normalized_rel:
            return self.workdirs.client_temp / normalized_rel
        return self.workdirs.client_temp / clean_name

    def _record_manifest_type_decision(
        self,
        *,
        platform: str,
        project_id: str,
        file_id: str,
        file_type: str,
        action: str,
        reason: str,
    ) -> None:
        detail = f"platform={platform},project_id={project_id},file_id={file_id},file_type={file_type},action={action},reason={reason}"
        self.operations.append(f"manifest_type_decision:{detail}")
        self._log("install.download.filter", detail, level="DEBUG")

    def _ensure_curseforge_manifest_mods(self) -> None:
        if not self.manifest:
            return
        if "files" not in self.manifest.raw:
            return

        files = self.manifest.raw.get("files") or []
        if not files:
            return

        if not (self.config.curseforge_api_key or "").strip():
            self.operations.append("curseforge_manifest_fill_skipped:no_api_key")
            return

        started_at = time.perf_counter()
        missing = 0
        skipped_existing = 0
        skipped_filtered = 0
        resolve_failed = 0
        batched_hit = 0
        fallback_hit = 0
        tasks: list[DownloadTask] = []
        seen_pairs: set[tuple[int, int]] = set()
        pairs: list[tuple[int, int]] = []

        for mod in files:
            project_id = mod.get("projectID")
            file_id = mod.get("fileID")
            if project_id is None or file_id is None:
                continue
            try:
                pair = (int(project_id), int(file_id))
            except (TypeError, ValueError):
                continue
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            pairs.append(pair)

        if not pairs:
            return

        batch_size = max(1, int(self.config.download.curseforge_manifest_batch_size or 50))
        batch_retry = max(0, int(self.config.download.curseforge_manifest_batch_retry or 0))
        enable_parallel = bool(self.config.download.manifest_resolve_parallel_enabled)
        resolve_workers = max(1, int(self.config.download.manifest_resolve_max_workers or 1))

        pair_to_data: dict[tuple[int, int], dict] = {}
        unresolved_pairs: list[tuple[int, int]] = []

        batched: list[list[tuple[int, int]]] = [pairs[i : i + batch_size] for i in range(0, len(pairs), batch_size)]

        def _run_cf_batch(batch_pairs: list[tuple[int, int]]) -> tuple[dict[tuple[int, int], dict], list[tuple[int, int]]]:
            result, unresolved = self._cf_fetch_files_batch(batch_pairs, retry=batch_retry)
            return result, unresolved

        if enable_parallel and len(batched) > 1:
            workers = min(resolve_workers, len(batched))
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="mcasb-cf-batch") as pool:
                fut_map = {pool.submit(_run_cf_batch, batch): batch for batch in batched}
                for fut in as_completed(fut_map):
                    resolved, unresolved = fut.result()
                    pair_to_data.update(resolved)
                    unresolved_pairs.extend(unresolved)
        else:
            for batch in batched:
                resolved, unresolved = _run_cf_batch(batch)
                pair_to_data.update(resolved)
                unresolved_pairs.extend(unresolved)

        batched_hit = len(pair_to_data)

        if unresolved_pairs:

            def _fetch_single(pair: tuple[int, int]) -> tuple[tuple[int, int], dict | None]:
                project_id_val, file_id_val = pair
                try:
                    data = self._cf_get_json(f"/v1/mods/{project_id_val}/files/{file_id_val}").get("data") or {}
                    return pair, data if isinstance(data, dict) and data else None
                except Exception:
                    return pair, None

            if enable_parallel and len(unresolved_pairs) > 1:
                workers = min(resolve_workers, len(unresolved_pairs))
                with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="mcasb-cf-fallback") as pool:
                    fut_map = {pool.submit(_fetch_single, pair): pair for pair in unresolved_pairs}
                    for fut in as_completed(fut_map):
                        pair, data = fut.result()
                        if data:
                            pair_to_data[pair] = data
                            fallback_hit += 1
                        else:
                            resolve_failed += 1
            else:
                for pair in unresolved_pairs:
                    _, data = _fetch_single(pair)
                    if data:
                        pair_to_data[pair] = data
                        fallback_hit += 1
                    else:
                        resolve_failed += 1

        for project_id, file_id in pairs:
            data = pair_to_data.get((project_id, file_id)) or {}
            if not data:
                self.operations.append(f"curseforge_mod_meta_missing:{project_id}:{file_id}")
                continue

            file_name = str(data.get("fileName") or f"cf-{project_id}-{file_id}.jar")
            file_type, can_download, classify_reason = self._classify_manifest_file_type(
                platform="curseforge",
                file_name=file_name,
                rel_path=None,
                platform_hints=self._extract_curseforge_type_hints(data),
            )
            if not can_download:
                skipped_filtered += 1
                self._record_manifest_type_decision(
                    platform="curseforge",
                    project_id=str(project_id),
                    file_id=str(file_id),
                    file_type=file_type,
                    action="skip",
                    reason=classify_reason,
                )
                continue

            self._record_manifest_type_decision(
                platform="curseforge",
                project_id=str(project_id),
                file_id=str(file_id),
                file_type=file_type,
                action="download",
                reason=classify_reason,
            )
            dst = self._manifest_target_path(file_type=file_type, file_name=file_name)
            dst.parent.mkdir(parents=True, exist_ok=True)
            if dst.exists() and dst.stat().st_size > 0:
                skipped_existing += 1
                continue

            missing += 1
            url = data.get("downloadUrl") or self._build_curseforge_edge_download_url(data)
            if not url:
                self.operations.append(f"curseforge_mod_no_url:{project_id}:{file_id}")
                continue

            tasks.append(DownloadTask(out=dst, urls=[str(url)], stage="install.download.curseforge"))

        downloaded = 0
        failed = 0
        if tasks:
            done, failed_items = self.downloader.download_files(tasks)
            downloaded = len(done)
            failed = len(failed_items)
            for item in failed_items:
                failed_task = item.task
                self.operations.append(f"curseforge_manifest_fill_failed:{failed_task.out.name}:{item.error}")

        resolve_elapsed = time.perf_counter() - started_at
        self.operations.append(
            "curseforge_manifest_fill:"
            f"entries={len(pairs)},resolved={len(pair_to_data)},resolve_failed={resolve_failed},"
            f"batch_hit={batched_hit},fallback_hit={fallback_hit},"
            f"missing={missing},downloaded={downloaded},existing={skipped_existing},filtered={skipped_filtered},failed={failed},"
            f"resolve_elapsed_sec={resolve_elapsed:.3f}"
        )

    def _resolve_curseforge_project_id(self, source: str) -> str:
        if source.isdigit():
            return source

        resp = self._cf_get_json("/v1/mods/search", params={"gameId": 432, "classId": 4471, "slug": source})
        data = resp.get("data") or []
        if not data:
            raise ValueError(f"CurseForge 未找到整合包项目: {source}")
        project_id = data[0].get("id")
        if project_id is None:
            raise ValueError(f"CurseForge 返回结果缺少项目ID: {source}")
        self.operations.append(f"curseforge_resolve_project_slug:{source}->{project_id}")
        return str(project_id)

    def _download_modrinth_pack(self, project_or_slug: str, version_id: str | None = None) -> Path:
        out = self.workdirs.root / "pack.zip"

        project = self._mr_get_json(f"/v2/project/{project_or_slug}")
        resolved_project_id = str(project.get("id") or project_or_slug)
        project_slug = str(project.get("slug") or project_or_slug)

        if version_id:
            version = self._mr_get_json(f"/v2/version/{version_id}")
            self.operations.append(f"modrinth_selected_version:project={resolved_project_id},version={version.get('id')},manual=true")
        else:
            versions = self._mr_get_json(f"/v2/project/{project_or_slug}/version")
            if not isinstance(versions, list) or not versions:
                raise ValueError(f"Modrinth 项目没有可用版本: {project_or_slug}")

            selected = self._pick_modrinth_pack_version(versions)
            if not selected:
                raise ValueError(f"Modrinth 项目无法选择可下载版本: {project_or_slug}")
            self.operations.append(
                f"modrinth_selected_version_auto:project={resolved_project_id},version={selected.get('id')},strategy=generic"
            )

            version = selected

        file_data = self._pick_modrinth_primary_pack_file(version.get("files") or [])
        if not file_data:
            raise ValueError(f"Modrinth 版本缺少可下载整合包文件: project={resolved_project_id}, version={version.get('id')}")

        url = str(file_data.get("url") or "")
        if not url:
            raise ValueError(f"Modrinth 文件缺少下载地址: project={resolved_project_id}, version={version.get('id')}")

        self._download_file(url, out)
        self.operations.append(
            "modrinth_download_pack:"
            f"project={resolved_project_id},slug={project_slug},version={version.get('id')},file={file_data.get('filename')}"
        )
        return out

    def _ensure_modrinth_manifest_mods(self) -> None:
        if not self.manifest:
            return
        files = self.manifest.raw.get("files") or []
        if not isinstance(files, list) or not files:
            return

        started_at = time.perf_counter()
        skipped_existing = 0
        skipped_filtered = 0
        failed = 0
        tasks: list[DownloadTask] = []
        fallback_urls: dict[Path, list[str]] = {}
        seen_rel: set[str] = set()
        parent_dirs: set[Path] = set()

        for item in files:
            rel_path = str(item.get("path") or "").strip()
            if not rel_path:
                continue

            normalized_rel = normalize_client_relative_path(rel_path)
            if not normalized_rel:
                continue
            if normalized_rel in seen_rel:
                continue
            seen_rel.add(normalized_rel)

            file_name = PurePosixPath(normalized_rel).name
            project_id = str(item.get("project_id") or item.get("projectId") or "")
            file_id = str(item.get("file_id") or item.get("fileId") or item.get("version_id") or item.get("versionId") or "")
            file_type, can_download, classify_reason = self._classify_manifest_file_type(
                platform="modrinth",
                file_name=file_name,
                rel_path=normalized_rel,
                platform_hints=self._extract_modrinth_type_hints(item),
            )
            if not can_download:
                skipped_filtered += 1
                self._record_manifest_type_decision(
                    platform="modrinth",
                    project_id=project_id,
                    file_id=file_id,
                    file_type=file_type,
                    action="skip",
                    reason=classify_reason,
                )
                continue

            self._record_manifest_type_decision(
                platform="modrinth",
                project_id=project_id,
                file_id=file_id,
                file_type=file_type,
                action="download",
                reason=classify_reason,
            )

            dst = self._manifest_target_path(file_type=file_type, file_name=file_name, rel_path=normalized_rel)

            if dst.exists() and dst.stat().st_size > 0:
                skipped_existing += 1
                continue

            downloads = [str(x) for x in (item.get("downloads") or []) if str(x).startswith("http")]
            if not downloads:
                failed += 1
                self.operations.append(f"modrinth_manifest_fill_no_url:{normalized_rel}")
                continue

            hashes = item.get("hashes") or {}
            tasks.append(
                DownloadTask(
                    out=dst,
                    urls=downloads[:1],
                    stage="install.download.modrinth",
                    expected_hashes=hashes,
                )
            )
            parent_dirs.add(dst.parent)
            if len(downloads) > 1:
                fallback_urls[dst] = downloads[1:]

        for parent in parent_dirs:
            parent.mkdir(parents=True, exist_ok=True)

        downloaded = 0
        if tasks:
            done, failed_items = self.downloader.download_files(tasks)
            downloaded += len(done)

            remain: list[DownloadFailure] = []
            for item in failed_items:
                extra_urls = fallback_urls.get(item.task.out, [])
                if not extra_urls:
                    remain.append(item)
                    continue

                retried = DownloadTask(
                    out=item.task.out,
                    urls=extra_urls,
                    stage=item.task.stage,
                    expected_hashes=item.task.expected_hashes,
                )
                try:
                    self.downloader.download_task(retried)
                    downloaded += 1
                except Exception as e:
                    remain.append(DownloadFailure(task=retried, error=f"{type(e).__name__}:{e}"))

            for item in remain:
                failed += 1
                safe_unlink(item.task.out)
                self.operations.append(f"modrinth_manifest_fill_failed:{item.task.out}:{item.error}")

        self.operations.append(
            "modrinth_manifest_fill:"
            f"entries={len(seen_rel)},downloaded={downloaded},existing={skipped_existing},filtered={skipped_filtered},failed={failed},"
            f"resolve_elapsed_sec={time.perf_counter() - started_at:.3f}"
        )

    def _verify_modrinth_file_hash(self, file_path: Path, hashes: dict) -> bool:
        return verify_hashes(file_path, hashes)

    def _mr_get_json(self, path: str, params: dict | None = None):
        base = "https://api.modrinth.com"
        headers = {
            "Accept": "application/json",
            "User-Agent": (self.config.modrinth_user_agent or "brokestar233/mc-auto-server-builder").strip(),
        }
        token = (self.config.modrinth_api_token or "").strip()
        if token:
            headers["Authorization"] = token

        return http_get_json(
            f"{base}{path}",
            headers=headers,
            params=params,
            timeout=60,
        )

    def _pick_modrinth_pack_version(self, versions: list[dict]) -> dict | None:
        candidates: list[tuple[int, str, dict]] = []
        for v in versions:
            files = v.get("files") or []
            if not files:
                continue

            pack_like = 0
            for f in files:
                fname = str(f.get("filename", "")).lower()
                if fname.endswith((".mrpack", ".zip")):
                    pack_like += 1
                if bool(f.get("primary")):
                    pack_like += 1

            if pack_like <= 0:
                continue

            published = str(v.get("date_published", ""))
            release_bonus = 1 if v.get("version_type") == "release" else 0
            candidates.append((pack_like + release_bonus, published, v))

        if not candidates:
            return None
        return sorted(candidates, key=lambda x: (x[0], x[1]), reverse=True)[0][2]

    def _pick_modrinth_primary_pack_file(self, files: list[dict]) -> dict | None:
        if not files:
            return None

        candidates: list[tuple[int, dict]] = []

        for f in files:
            name = str(f.get("filename", "")).lower()
            if not name.endswith((".mrpack", ".zip")):
                continue

            score = 0
            if bool(f.get("primary")):
                score += 4
            if name.endswith(".mrpack"):
                score += 2
            candidates.append((score, f))

        if not candidates:
            return None
        return sorted(candidates, key=lambda x: x[0], reverse=True)[0][1]

    def _cf_get_json(self, path: str, params: dict | None = None) -> dict:
        api_key = (self.config.curseforge_api_key or "").strip()
        if not api_key:
            raise ValueError("CurseForge 需要配置 curseforge_api_key 才能下载整合包或补全模组")

        headers = {
            "Accept": "application/json",
            "x-api-key": api_key,
        }
        return http_get_json(
            f"https://api.curseforge.com{path}",
            headers=headers,
            params=params,
            timeout=60,
        )

    def _cf_post_json(self, path: str, payload: dict) -> dict:
        api_key = (self.config.curseforge_api_key or "").strip()
        if not api_key:
            raise ValueError("CurseForge 需要配置 curseforge_api_key 才能下载整合包或补全模组")

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "x-api-key": api_key,
        }
        resp = requests.post(
            f"https://api.curseforge.com{path}",
            headers=headers,
            json=payload,
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()

    def _cf_fetch_files_batch(
        self,
        pairs: list[tuple[int, int]],
        *,
        retry: int = 0,
    ) -> tuple[dict[tuple[int, int], dict], list[tuple[int, int]]]:
        if not pairs:
            return {}, []

        file_ids = sorted({fid for _, fid in pairs})
        attempts = max(1, retry + 1)
        last_error: Exception | None = None

        for attempt in range(1, attempts + 1):
            try:
                data_arr = self._cf_post_json("/v1/mods/files", payload={"fileIds": file_ids}).get("data") or []
                data_map: dict[tuple[int, int], dict] = {}
                for item in data_arr:
                    if not isinstance(item, dict):
                        continue
                    mod_id = item.get("modId")
                    fid = item.get("id")
                    try:
                        key = (int(mod_id), int(fid))
                    except (TypeError, ValueError):
                        continue
                    data_map[key] = item

                resolved: dict[tuple[int, int], dict] = {}
                unresolved: list[tuple[int, int]] = []
                for pair in pairs:
                    found = data_map.get(pair)
                    if found:
                        resolved[pair] = found
                    else:
                        unresolved.append(pair)
                return resolved, unresolved
            except Exception as e:
                last_error = e

        self.operations.append(
            f"curseforge_manifest_batch_failed:file_ids={len(file_ids)},error={type(last_error).__name__ if last_error else 'unknown'}"
        )
        return {}, list(pairs)

    def _pick_curseforge_pack_file(self, files: list[dict]) -> dict | None:
        zip_files = [f for f in files if str(f.get("fileName", "")).lower().endswith(".zip")]
        if not zip_files:
            return None
        return sorted(zip_files, key=lambda x: str(x.get("fileDate", "")), reverse=True)[0]

    def _build_curseforge_edge_download_url(self, file_data: dict) -> str | None:
        file_id = file_data.get("id")
        file_name = file_data.get("fileName")
        if file_id is None or not file_name:
            return None
        num = int(file_id)
        return f"https://edge.forgecdn.net/files/{num // 1000}/{num % 1000:03d}/{file_name}"

    def _copy_client_files_with_blacklist(self, blacklist: set[str]) -> tuple[int, int]:
        copied = 0
        skipped = 0

        base = self.workdirs.client_temp
        roots: list[Path] = [base]

        base_files = [p for p in base.iterdir() if p.is_file()]

        # 一些压缩包会再包一层根目录，兜底纳入扫描
        top_dirs = [p for p in base.iterdir() if p.is_dir()]
        if len(top_dirs) == 1:
            nested_root = top_dirs[0]
            if nested_root.name.lower() not in {
                "overrides",
                "override",
                "server-overrides",
                "server_overrides",
                "serveroverrides",
                "server",
                "serverfiles",
                "server-files",
                "serverpack",
                "server_pack",
                "resourcepacks",
            }:
                # 若 client_temp 仅有一层根目录且没有根层文件，则仅展开该目录内容，避免多一层路径
                if not base_files:
                    roots = [nested_root]
                else:
                    roots.append(nested_root)

        # 去重保持顺序
        dedup_roots: list[Path] = []
        seen: set[Path] = set()
        for r in roots:
            if r not in seen and r.exists() and r.is_dir():
                dedup_roots.append(r)
                seen.add(r)

        for root in dedup_roots:
            for src in root.iterdir():
                name_lc = src.name.lower()

                # overrides 必须在 prepare 阶段被扁平合并，不允许作为目录层级进入 server
                if name_lc in {"overrides", "override", "server-overrides", "server_overrides", "serveroverrides"}:
                    skipped += 1
                    continue
                if name_lc == "resourcepacks" and src.is_dir():
                    kept = self._extract_server_resourcepacks(src)
                    if kept:
                        copied += kept
                    else:
                        skipped += 1
                    continue
                if name_lc in blacklist:
                    skipped += 1
                    continue

                dst = self.workdirs.server / src.name
                replace_path(src, dst)
                copied += 1

        return copied, skipped

    def _extract_server_resourcepacks(self, resourcepacks_dir: Path) -> int:
        if not resourcepacks_dir.exists() or not resourcepacks_dir.is_dir():
            return 0

        copied = 0
        target_root = self.workdirs.server / "resourcepacks"
        keep_markers = {"pack.mcmeta", "server-resource-packs.json", "server-resource-pack.txt"}

        for item in sorted(resourcepacks_dir.iterdir(), key=lambda p: p.name.lower()):
            should_keep = False
            if item.is_file() and item.name.lower().endswith(".zip"):
                should_keep = True
            elif item.is_dir() and any((item / marker).exists() for marker in keep_markers):
                should_keep = True
            if not should_keep:
                continue
            replace_path(item, target_root / item.name)
            copied += 1

        if copied:
            self.operations.append(f"resourcepacks_subset:copied={copied}")
        return copied

    def _install_server_core(self) -> None:
        if not self.manifest:
            server_jar = self.workdirs.server / "server.jar"
            if not server_jar.exists():
                server_jar.write_bytes(b"")
            self.server_jar_name = "server.jar"
            self._set_start_command("jar", self.server_jar_name, "install_server_core:no_manifest")
            self.operations.append("install_server_core:fallback_placeholder_no_manifest")
            return

        loader = (self.manifest.loader or "unknown").lower()
        mc_version = self.manifest.mc_version
        loader_version = self.manifest.loader_version

        try:
            if loader in ("forge", "neoforge"):
                self._install_forge_like_server(loader=loader, mc_version=mc_version, loader_version=loader_version)
                self.operations.append(f"install_server_core:{loader}:ok")
                return
            if loader in ("fabric", "quilt"):
                self._install_fabric_like_server(loader=loader, mc_version=mc_version, loader_version=loader_version)
                self.operations.append(f"install_server_core:{loader}:ok")
                return
        except Exception as e:
            self.operations.append(f"install_server_core:{loader}:failed:{type(e).__name__}")

        # 无法识别或安装失败：保底占位，确保流程不中断
        server_jar = self.workdirs.server / "server.jar"
        if not server_jar.exists():
            server_jar.write_bytes(b"")
        self.server_jar_name = "server.jar"
        self._set_start_command("jar", self.server_jar_name, f"install_server_core:fallback:{loader}")
        self.operations.append(f"install_server_core:fallback_placeholder_loader_{loader}")

    def _install_forge_like_server(self, loader: str, mc_version: str, loader_version: str | None) -> None:
        if loader == "forge":
            self._install_forge_server(mc_version=mc_version, loader_version=loader_version)
            return
        self._install_neoforge_server(mc_version=mc_version, loader_version=loader_version)

    def _install_forge_server(self, mc_version: str, loader_version: str | None) -> None:
        self._install_forge_family_server(loader="forge", mc_version=mc_version, loader_version=loader_version)

    def _install_neoforge_server(self, mc_version: str, loader_version: str | None) -> None:
        self._install_forge_family_server(loader="neoforge", mc_version=mc_version, loader_version=loader_version)

    def _install_fabric_like_server(self, loader: str, mc_version: str, loader_version: str | None) -> None:
        if loader == "fabric":
            self._install_fabric_server(mc_version=mc_version, loader_version=loader_version)
            return
        self._install_quilt_server(mc_version=mc_version, loader_version=loader_version)

    def _install_fabric_server(self, mc_version: str, loader_version: str | None) -> None:
        self._install_fabric_family_server(loader="fabric", mc_version=mc_version, loader_version=loader_version)

    def _install_quilt_server(self, mc_version: str, loader_version: str | None) -> None:
        self._install_fabric_family_server(loader="quilt", mc_version=mc_version, loader_version=loader_version)

    def _download_recommended_java(self) -> None:
        if not self.manifest:
            return
        version = choose_latest_lts_java_version()
        try:
            version = choose_java_version(self.manifest)
        except Exception:
            version = choose_latest_lts_java_version()

        if self._ensure_java_installed(version):
            self.current_java_bin = self._java_bin_path(version)
            self.current_java_version = version
            self._import_graalvm_external_packages(version)
            self.operations.append(f"download_java:installed_target_{version}")
        else:
            # 回退系统 Java，避免中断主流程
            self.current_java_bin = Path("java")
            self.current_java_version = version
            self.operations.append(f"download_java:fallback_system_java_target_{version}")

        self.extra_jvm_flags = list(
            dict.fromkeys(
                [
                    *self._resolve_java_params_for_version(version),
                    *self.config.extra_jvm_flags,
                ]
            )
        )

    def _resolve_java_params_for_version(self, version: int) -> list[str]:
        mode = self.java_params_mode_by_version.get(version)
        if mode == "common_only":
            return get_common_jvm_params()
        return get_jvm_params_for_java_version(version)

    def _java_bin_path(self, version: int) -> Path:
        bin_name = "java.exe" if os.name == "nt" else "java"
        return self.workdirs.java_bins / f"jdk-{version}" / "bin" / bin_name

    def _oracle_graalvm_manual_page_url(self) -> str:
        return "https://www.oracle.com/downloads/graalvm-downloads.html"

    def _oracle_download_headers(self) -> dict[str, str]:
        # Oracle 站点对某些自定义请求头较敏感，默认采用最小头策略。
        headers: dict[str, str] = {}
        cookies = (self.config.oracle_download_cookies or "").strip()
        if cookies:
            headers["Cookie"] = cookies
        return headers

    def _oracle_download_headers_compat(self) -> dict[str, str]:
        # 兼容重试头：用于最小头策略失败后的二次尝试。
        headers = dict(self._oracle_download_headers())
        headers["Accept"] = "application/json, text/plain, */*"
        headers["User-Agent"] = "curl/8"
        return headers

    def _oracle_fetch_json_with_diag(
        self,
        url: str,
        stage: str,
        op_prefix: str,
        version: int,
        profiles: list[tuple[str, dict[str, str]]],
    ) -> tuple[dict | None, str]:
        for profile_name, headers in profiles:
            try:
                resp = requests.get(
                    url,
                    headers=headers,
                    timeout=(self.config.download.connect_timeout, self.config.download.read_timeout),
                )
                status = int(resp.status_code)
                content_type = str(resp.headers.get("Content-Type", "")).strip()
                body_preview = (resp.text or "")[:220].replace("\n", " ").replace("\r", " ").strip()
                body_preview = re.sub(r"\s+", " ", body_preview)

                self.operations.append(f"{op_prefix}:http:{version}:profile={profile_name}:status={status}:ctype={content_type[:80]}")
                self._log(
                    stage,
                    f"{op_prefix} 请求 profile={profile_name} status={status} ctype={content_type or 'unknown'}",
                    level="INFO",
                )

                if status >= 400:
                    self._log(
                        stage,
                        f"{op_prefix} 请求失败 profile={profile_name} status={status} preview={body_preview[:160]}",
                        level="WARN",
                    )
                    continue

                try:
                    data = resp.json()
                except ValueError:
                    self.operations.append(f"{op_prefix}:non_json:{version}:profile={profile_name}")
                    self._log(
                        stage,
                        f"{op_prefix} 返回非 JSON profile={profile_name} ctype={content_type or 'unknown'} preview={body_preview[:160]}",
                        level="WARN",
                    )
                    continue

                if isinstance(data, dict):
                    self.operations.append(f"{op_prefix}:ok:{version}:profile={profile_name}")
                    return data, profile_name

                self.operations.append(f"{op_prefix}:unexpected_json_type:{version}:profile={profile_name}:{type(data).__name__}")
                self._log(
                    stage,
                    f"{op_prefix} JSON 类型异常 profile={profile_name}: {type(data).__name__}",
                    level="WARN",
                )
            except Exception as e:
                error_message = str(e).strip()
                self.operations.append(f"{op_prefix}:request_error:{version}:profile={profile_name}:{type(e).__name__}")
                self._log(
                    stage,
                    f"{op_prefix} 请求异常 profile={profile_name}: {type(e).__name__}{f' - {error_message}' if error_message else ''}",
                    level="WARN",
                )

        return None, ""

    def _download_graalvm_from_oracle(self, version: int) -> bool:
        if version not in (17, 21, 25):
            return False

        stage = "install.download.oracle_graalvm"
        manual_url = self._oracle_graalvm_manual_page_url()
        cookies = (self.config.oracle_download_cookies or "").strip()
        if not cookies:
            self._log(stage, f"未配置 oracle_download_cookies，若下载受限请手动访问: {manual_url}", level="WARN")

        try:
            os_name, arch_name, ext = oracle_platform_triplet()
        except ValueError as e:
            self.operations.append(f"oracle_graalvm_platform_unsupported:{version}:{type(e).__name__}")
            return False

        group_title = "GraalVM Enterprise 21" if version == 17 else "Oracle GraalVM"
        group_subtitle = "" if version == 17 else ("Oracle GraalVM for JDK 21" if version == 21 else "Oracle GraalVM 25")

        base_url = "https://www.oracle.com"
        headers = self._oracle_download_headers()
        compat_headers = self._oracle_download_headers_compat()

        index_data, index_profile = self._oracle_fetch_json_with_diag(
            url=f"{base_url}/a/tech/docs/graalvm-downloads.json",
            stage=stage,
            op_prefix="oracle_graalvm_index",
            version=version,
            profiles=[("minimal", headers), ("compat", compat_headers)],
        )
        if not index_data:
            self.operations.append(f"oracle_graalvm_index_fetch_failed:{version}:all_profiles_failed")
            self.operations.append(f"oracle_graalvm_blocked_or_unavailable:{version}:index")
            self._log(stage, f"Oracle GraalVM 索引解析失败，手动页面: {manual_url}", level="WARN")
            return False

        self.operations.append(f"oracle_graalvm_index_profile_selected:{version}:{index_profile}")

        release_json_path = ""
        for _, group in (index_data or {}).items():
            if not isinstance(group, dict):
                continue
            title = str(group.get("Title", "")).strip()
            subtitle = str(group.get("SubTitle", "")).strip()
            if title != group_title:
                continue
            if group_subtitle and subtitle != group_subtitle:
                continue
            releases = group.get("Releases") or {}
            if not isinstance(releases, dict) or not releases:
                continue
            rel_keys = sorted(releases.keys(), reverse=True)
            latest_rel = releases.get(rel_keys[0], {}) if rel_keys else {}
            if isinstance(latest_rel, dict):
                release_json_path = str(latest_rel.get("JSON File", "")).strip()
                if release_json_path:
                    break

        if not release_json_path:
            self.operations.append(f"oracle_graalvm_release_not_found:{version}")
            self._log(stage, f"未在 Oracle 页面找到 Java {version} 对应发布，手动页面: {manual_url}", level="WARN")
            return False

        release_url = f"{base_url}{release_json_path}" if release_json_path.startswith("/") else release_json_path
        release_data, release_profile = self._oracle_fetch_json_with_diag(
            url=release_url,
            stage=stage,
            op_prefix="oracle_graalvm_release",
            version=version,
            profiles=[("minimal", headers), ("compat", compat_headers)],
        )
        if not release_data:
            self.operations.append(f"oracle_graalvm_release_fetch_failed:{version}:all_profiles_failed")
            self.operations.append(f"oracle_graalvm_blocked_or_unavailable:{version}:release")
            self._log(stage, f"Oracle GraalVM 发布详情解析失败，手动页面: {manual_url}", level="WARN")
            return False

        self.operations.append(f"oracle_graalvm_release_profile_selected:{version}:{release_profile}")

        files = (((release_data or {}).get("Packages") or {}).get("Core") or {}).get("Files") or {}
        picked: dict | None = None
        if isinstance(files, dict):
            token = f"-{os_name}-{arch_name}-{version}".lower()
            for key, value in files.items():
                if token in str(key).lower() and isinstance(value, dict):
                    picked = value
                    break

        if not picked:
            self.operations.append(f"oracle_graalvm_asset_not_found:{version}:{os_name}:{arch_name}")
            self._log(stage, f"未匹配到 Oracle GraalVM 资产，手动页面: {manual_url}", level="WARN")
            return False

        file_url = str(picked.get("File") or "").strip()
        if not file_url:
            self.operations.append(f"oracle_graalvm_asset_url_missing:{version}")
            return False

        hash_arr = picked.get("Hash") or []
        expected_hashes: dict[str, str] | None = None
        if isinstance(hash_arr, list) and len(hash_arr) >= 2:
            algo = str(hash_arr[0]).strip().lower()
            value = str(hash_arr[1]).strip()
            if algo and value:
                expected_hashes = {algo: value}

        suffix = ".zip" if ext == "zip" else ".tar.gz"
        archive_path = self.workdirs.java_bins / f"oracle-graalvm-{version}{suffix}"
        java_home = self.workdirs.java_bins / f"jdk-{version}"
        bin_name = "java.exe" if os.name == "nt" else "java"

        try:
            self._download_file(file_url, archive_path, stage=stage, headers=headers)
            if expected_hashes and not verify_hashes(archive_path, expected_hashes):
                safe_unlink(archive_path)
                self.operations.append(f"oracle_graalvm_hash_mismatch:{version}")
                return False

            if java_home.exists():
                shutil.rmtree(java_home)
            java_home.mkdir(parents=True, exist_ok=True)

            extract_archive(archive_path, java_home)
            normalized, changed = normalize_java_home_layout(java_home)
            if changed:
                self.operations.append(f"oracle_graalvm_java_home_normalized:{version}")

            java_bin = normalized / "bin" / bin_name
            if not java_bin.exists():
                self.operations.append(f"oracle_graalvm_java_bin_missing:{version}")
                self._log(stage, f"Oracle GraalVM 安装后未找到 java 可执行文件，手动页面: {manual_url}", level="WARN")
                return False

            if os.name != "nt":
                java_bin.chmod(0o755)

            self.java_params_mode_by_version[version] = "graalvm"
            self.operations.append(f"oracle_graalvm_download_success:{version}:{os_name}:{arch_name}")
            return True
        except Exception as e:
            self.operations.append(f"oracle_graalvm_download_failed:{version}:{type(e).__name__}")
            self._log(stage, f"Oracle GraalVM 下载失败，手动页面: {manual_url}", level="WARN")
            return False

    def _ensure_java_installed(self, version: int) -> bool:
        java_bin = self._java_bin_path(version)
        if java_bin.exists():
            if version in (17, 21, 25) and version not in self.java_params_mode_by_version:
                self.java_params_mode_by_version[version] = "graalvm"
            return True

        # Java 8/11：仅 Dragonwell（不回退 Adoptium）
        if version in (8, 11):
            if self._download_dragonwell_from_github(version):
                self.java_params_mode_by_version[version] = "graalvm"
                return self._java_bin_path(version).exists()
            return False

        # Java 17/21/25：优先 Oracle GraalVM，失败回退 Adoptium（并降级参数为 common_only）
        if version in (17, 21, 25):
            if self._download_graalvm_from_oracle(version):
                return self._java_bin_path(version).exists()
            if self._download_temurin_from_adoptium(version):
                self.java_params_mode_by_version[version] = "common_only"
                self.operations.append(f"java_params_mode_fallback_common:{version}")
                return self._java_bin_path(version).exists()
            return False

        return False

    def _download_temurin_from_adoptium(self, version: int) -> bool:
        try:
            os_name, arch_name, ext = adoptium_platform_triplet()
        except ValueError as e:
            self.operations.append(f"temurin_platform_unsupported:{type(e).__name__}")
            return False

        url = f"https://api.adoptium.net/v3/binary/latest/{version}/ga/{os_name}/{arch_name}/jdk/hotspot/normal/eclipse"

        suffix = ".zip" if ext == "zip" else ".tar.gz"
        archive_path = self.workdirs.java_bins / f"temurin-{version}{suffix}"
        java_home = self.workdirs.java_bins / f"jdk-{version}"

        try:
            self._download_file(url, archive_path)
            if java_home.exists():
                shutil.rmtree(java_home)
            java_home.mkdir(parents=True, exist_ok=True)

            extract_archive(archive_path, java_home)
            normalized, changed = normalize_java_home_layout(java_home)
            if changed:
                self.operations.append(f"temurin_java_home_normalized:{version}")

            bin_name = "java.exe" if os.name == "nt" else "java"
            java_bin = normalized / "bin" / bin_name

            if not java_bin.exists():
                self.operations.append(f"temurin_java_bin_missing:{version}")
                return False

            if os.name != "nt":
                java_bin.chmod(0o755)

            self.java_params_mode_by_version[version] = "common_only"
            self.operations.append(f"temurin_download_success:{version}:{os_name}:{arch_name}")
            return True
        except Exception as e:
            self.operations.append(f"temurin_download_failed:{version}:{type(e).__name__}")
            return False

    def _download_dragonwell_from_github(self, version: int) -> bool:
        repo = "dragonwell8" if version == 8 else "dragonwell11"
        api_url = f"https://api.github.com/repos/dragonwell-project/{repo}/releases"
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.config.github_api_key:
            headers["Authorization"] = f"Bearer {self.config.github_api_key}"

        try:
            releases = http_get_json(api_url, headers=headers, timeout=60)
        except Exception as e:
            self.operations.append(f"dragonwell_release_fetch_failed:{repo}:{type(e).__name__}")
            return False

        asset = self._pick_dragonwell_asset(releases)
        if not asset:
            self.operations.append(f"dragonwell_asset_not_found:{repo}")
            return False

        url = asset.get("browser_download_url")
        name = asset.get("name", "")
        if not url:
            self.operations.append(f"dragonwell_asset_no_url:{repo}:{name}")
            return False

        archive_path = self.workdirs.java_bins / name
        try:
            self._download_file(url, archive_path)
            java_home = self.workdirs.java_bins / f"jdk-{version}"
            if java_home.exists():
                shutil.rmtree(java_home)
            java_home.mkdir(parents=True, exist_ok=True)

            bin_name = "java.exe" if os.name == "nt" else "java"
            extract_archive(archive_path, java_home)
            normalized, changed = normalize_java_home_layout(java_home)
            if changed:
                self.operations.append(f"dragonwell_java_home_normalized:{repo}:{name}")

            java_bin = normalized / "bin" / bin_name

            if not java_bin.exists():
                self.operations.append(f"dragonwell_java_bin_missing:{repo}:{name}")
                return False

            self.current_java_bin = java_bin
            self.current_java_version = version
            if os.name != "nt":
                java_bin.chmod(0o755)
            self.java_params_mode_by_version[version] = "graalvm"
            self.operations.append(f"dragonwell_selected_asset:{repo}:{name}")
            return True
        except Exception as e:
            self.operations.append(f"dragonwell_download_or_extract_failed:{repo}:{type(e).__name__}")
            return False

    def _pick_dragonwell_asset(self, releases: list[dict]) -> dict | None:
        arch_aliases = self._current_arch_aliases()
        is_windows = os.name == "nt"

        for rel in releases:
            tag_name = str(rel.get("tag_name", ""))
            rel_name = str(rel.get("name", ""))
            if "extended" not in (tag_name + " " + rel_name).lower():
                continue
            assets = rel.get("assets") or []
            chosen = self._pick_asset_by_arch(assets, arch_aliases, is_windows=is_windows)
            if chosen:
                return chosen
        return None

    def _pick_asset_by_arch(self, assets: list[dict], arch_aliases: set[str], is_windows: bool) -> dict | None:
        preferred_ext = (".zip", ".tar.gz", ".tgz") if is_windows else (".tar.gz", ".tgz", ".zip")
        candidates: list[dict] = []

        for a in assets:
            name = str(a.get("name", "")).lower()
            if not any(name.endswith(ext) for ext in preferred_ext):
                continue
            if not any(alias in name for alias in arch_aliases):
                continue
            candidates.append(a)

        if not candidates:
            return None

        def score(item: dict) -> tuple[int, int]:
            n = str(item.get("name", "")).lower()
            ext_score = 0
            for i, ext in enumerate(preferred_ext):
                if n.endswith(ext):
                    ext_score = len(preferred_ext) - i
                    break
            # 尽量优先 jdk 资产（排除 jre / test）
            role_score = 2 if "jdk" in n else 1
            if "jre" in n:
                role_score = 0
            return role_score, ext_score

        return sorted(candidates, key=score, reverse=True)[0]

    def _current_arch_aliases(self) -> set[str]:
        machine = platform.machine().lower()
        if machine in {"x86_64", "amd64"}:
            return {"x64", "x86_64", "amd64"}
        if machine in {"aarch64", "arm64"}:
            return {"aarch64", "arm64"}
        if machine in {"x86", "i386", "i686"}:
            return {"x86", "i386", "i686"}
        return {machine}

    def _import_graalvm_external_packages(self, version: int) -> None:
        if version not in (17, 21, 25):
            return
        items = [str(x).strip() for x in self.config.graalvm_external_packages if str(x).strip()]
        if not items:
            return

        java_home = self.workdirs.java_bins / f"jdk-{version}"
        if not java_home.exists():
            return

        imported = 0
        failed = 0
        ext_dir = java_home / "external_packages"
        ext_dir.mkdir(parents=True, exist_ok=True)

        for idx, item in enumerate(items, start=1):
            try:
                if is_http_url(item):
                    parsed = urlparse(item)
                    filename = Path(parsed.path).name or f"external-{idx}.bin"
                    local_artifact = self.workdirs.java_bins / "external_packages" / filename
                    self._download_file(item, local_artifact)
                    src = local_artifact
                else:
                    src = Path(item)
                    if not src.is_absolute():
                        src = (self.base_dir / src).resolve()
                    if not src.exists() or not src.is_file():
                        raise FileNotFoundError(str(src))

                lower_name = src.name.lower()
                if lower_name.endswith(".zip") or lower_name.endswith(".tar.gz") or lower_name.endswith(".tgz"):
                    extract_archive_payload_into(src, ext_dir, tag=f"pkg_{idx}")
                else:
                    shutil.copy2(src, ext_dir / src.name)

                imported += 1
                self.operations.append(f"graalvm_external_package_imported:{version}:{item}")
            except Exception as e:
                failed += 1
                self.operations.append(f"graalvm_external_package_import_failed:{version}:{item}:{type(e).__name__}")

        self.operations.append(f"graalvm_external_package_import_summary:{version}:ok={imported},failed={failed}")

    def _set_start_command(self, mode: str, value: str, reason: str) -> None:
        normalized_mode = mode if mode in {"jar", "argsfile"} else "jar"
        normalized_value = value.strip().strip('"').strip("'")
        if not normalized_value:
            normalized_mode = "jar"
            normalized_value = self.server_jar_name
        self.start_command_mode = normalized_mode
        self.start_command_value = normalized_value
        self.operations.append(f"start_command_set:{normalized_mode}:{normalized_value}:{reason}")

    def _parse_start_command_from_run_scripts(self) -> bool:
        run_sh = self.workdirs.server / "run.sh"
        run_bat = self.workdirs.server / "run.bat"
        candidates = [run_bat, run_sh] if os.name == "nt" else [run_sh, run_bat]

        for script in candidates:
            if not script.exists() or not script.is_file():
                continue
            try:
                lines = script.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue

            for line in lines:
                parsed = extract_start_command_from_line(line)
                if not parsed:
                    continue
                mode, value = parsed
                self._set_start_command(mode, value, f"run_script:{script.name}")
                self.operations.append(f"start_command_parse_run_scripts:hit:{script.name}:{mode}:{value}")
                return True

        self.operations.append("start_command_parse_run_scripts:miss")
        return False

    def _apply_modern_loader_start_mode(self) -> bool:
        candidates = [
            *self.workdirs.server.glob("libraries/**/unix_args.txt"),
            *self.workdirs.server.glob("libraries/**/win_args.txt"),
        ]
        if not candidates:
            return False

        manifest = getattr(self, "manifest", None)
        loader = str(getattr(manifest, "loader", "") or "").lower()
        loader_version = str(getattr(manifest, "loader_version", "") or "")
        mc_version = str(getattr(manifest, "mc_version", "") or "")

        def score(item: Path) -> tuple[int, int, int, int, str]:
            posix = item.as_posix().lower()
            value = 0

            if loader == "neoforge":
                if "/net/neoforged/neoforge/" in posix:
                    value += 12
                if "/net/minecraftforge/forge/" in posix:
                    value -= 4
            elif loader == "forge":
                if "/net/minecraftforge/forge/" in posix:
                    value += 12
                if "/net/neoforged/neoforge/" in posix:
                    value -= 4
            else:
                if "/net/neoforged/neoforge/" in posix:
                    value += 6
                if "/net/minecraftforge/forge/" in posix:
                    value += 6

            if loader_version and loader_version.lower() in posix:
                value += 8
            elif mc_version and mc_version.lower() in posix:
                value += 4

            if item.name == "unix_args.txt":
                value += 2 if os.name != "nt" else 0
            elif item.name == "win_args.txt":
                value += 2 if os.name == "nt" else 0

            return (value, -len(item.parts), -len(item.as_posix()), 0, item.as_posix())

        preferred = sorted(
            candidates,
            key=score,
            reverse=True,
        )[0]
        rel = preferred.relative_to(self.workdirs.server).as_posix()
        self._set_start_command("argsfile", rel, "modern_loader_args")
        return True

    def _write_start_script(self) -> None:
        script = self._start_script_path()
        flags = " ".join(self.extra_jvm_flags).strip()

        self._parse_start_command_from_run_scripts()

        mode = self.start_command_mode if self.start_command_mode in {"jar", "argsfile"} else "jar"
        value = (self.start_command_value or "").strip()
        if not value:
            mode = "jar"
            value = self.server_jar_name

        jvm_parts = [f"-Xms{self.jvm_xms}", f"-Xmx{self.jvm_xmx}"]
        if flags:
            jvm_parts.append(flags)
        jvm_part = " ".join(jvm_parts)

        bat_value = value.replace('"', '""')
        sh_value = value.replace('"', r"\"")

        if os.name == "nt":
            if mode == "argsfile":
                exec_line = f'"%JAVA_BIN%" {jvm_part} @"{bat_value}" %* nogui\n'
            else:
                exec_line = f'"%JAVA_BIN%" {jvm_part} -jar "{bat_value}" %* nogui\n'
            content = (
                "@echo off\n"
                "setlocal\n"
                "\n"
                'set "SCRIPT_DIR=%~dp0"\n'
                'cd /d "%SCRIPT_DIR%"\n'
                "\n"
                'set "JAVA_BIN="\n'
                "\n"
                'if exist "%SCRIPT_DIR%java_bins\\bin\\java.exe" set "JAVA_BIN=%SCRIPT_DIR%java_bins\\bin\\java.exe"\n'
                'if not defined JAVA_BIN if exist "%SCRIPT_DIR%..\\java_bins\\bin\\java.exe" '
                'set "JAVA_BIN=%SCRIPT_DIR%..\\java_bins\\bin\\java.exe"\n'
                "\n"
                "if not defined JAVA_BIN (\n"
                '  for /d %%D in ("%SCRIPT_DIR%java_bins\\jdk-*") do (\n'
                '    if exist "%%~fD\\bin\\java.exe" (\n'
                '      set "JAVA_BIN=%%~fD\\bin\\java.exe"\n'
                "      goto :java_found\n"
                "    )\n"
                "  )\n"
                ")\n"
                "\n"
                "if not defined JAVA_BIN (\n"
                '  for /d %%D in ("%SCRIPT_DIR%..\\java_bins\\jdk-*") do (\n'
                '    if exist "%%~fD\\bin\\java.exe" (\n'
                '      set "JAVA_BIN=%%~fD\\bin\\java.exe"\n'
                "      goto :java_found\n"
                "    )\n"
                "  )\n"
                ")\n"
                "\n"
                ":java_found\n"
                'if not defined JAVA_BIN set "JAVA_BIN=java"\n'
                "\n"
                f"{exec_line}"
            )
        else:
            if mode == "argsfile":
                exec_line = f'exec "$JAVA_BIN" {jvm_part} @"{sh_value}" "$@" nogui\n'
            else:
                exec_line = f'exec "$JAVA_BIN" {jvm_part} -jar "{sh_value}" "$@" nogui\n'
            content = (
                "#!/usr/bin/env sh\n"
                "set -e\n"
                "\n"
                'SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\n'
                'cd "$SCRIPT_DIR"\n'
                "\n"
                'JAVA_BIN=""\n'
                "\n"
                'if [ -x "$SCRIPT_DIR/java_bins/bin/java" ]; then\n'
                '  JAVA_BIN="$SCRIPT_DIR/java_bins/bin/java"\n'
                'elif [ -x "$SCRIPT_DIR/../java_bins/bin/java" ]; then\n'
                '  JAVA_BIN="$SCRIPT_DIR/../java_bins/bin/java"\n'
                "else\n"
                '  for candidate in "$SCRIPT_DIR"/java_bins/jdk-*/bin/java "$SCRIPT_DIR"/../java_bins/jdk-*/bin/java; do\n'
                '    if [ -x "$candidate" ]; then\n'
                '      JAVA_BIN="$candidate"\n'
                "      break\n"
                "    fi\n"
                "  done\n"
                "fi\n"
                "\n"
                'if [ -z "$JAVA_BIN" ]; then\n'
                "  JAVA_BIN=java\n"
                "fi\n"
                "\n"
                f"{exec_line}"
            )
        script.write_text(content, encoding="utf-8")
        if os.name != "nt":
            script.chmod(0o755)

    def _start_script_path(self) -> Path:
        return self.workdirs.server / ("start.bat" if os.name == "nt" else "start.sh")

    def _extract_log_signal_lines(self, text: object, limit: int = 12) -> list[str]:
        return self.ai_service._extract_log_signal_lines(text, limit)

    def _build_ai_context_payload(self, context: dict) -> dict[str, object]:
        return self.ai_service.build_context_payload(context)

    def _build_prompt(self, context: dict) -> str:
        return self.ai_service.build_prompt(context)

    def _apply_actions(self, actions: list[dict], attempt: int = 0) -> bool:
        for idx, a in enumerate(actions[:2], start=1):
            if str(a.get("type") or "") == "bisect_mods":
                next_action = actions[idx] if idx < len(actions[:2]) else None
                if isinstance(next_action, dict) and str(next_action.get("type") or "") == "move_bisect_mods":
                    a = {**a, "defer_execution": True}
            t = a.get("type")
            self._ai_debug(f"apply.actions[{idx}] type={t!r} payload={json.dumps(a, ensure_ascii=False)}")
            preflight = self._assess_action_preflight(a)
            preflight_payload = asdict(preflight)
            if t == "bisect_mods":
                self._log_bisect_event(
                    "install.bisect.preflight",
                    {
                        "attempt": attempt or int(getattr(self, "attempts_used", 0) or 0),
                        "index": idx,
                        "allowed": preflight.allowed,
                        "reason": preflight.reason,
                        "risk": preflight.risk,
                        "details": preflight.details,
                        "action": dict(a),
                    },
                )
            self.operations.append(f"action_preflight:{t}:allowed={preflight.allowed}:risk={preflight.risk}:reason={preflight.reason}")
            if attempt > 0:
                self._append_attempt_trace(
                    attempt,
                    f"action_{idx}_preflight",
                    "ok" if preflight.allowed else "blocked",
                    preflight=[preflight_payload],
                    action_plan=[dict(a)],
                )
            if not preflight.allowed:
                if t == "bisect_mods":
                    current_session = self._coerce_bisect_session()
                    self.bisect_session = BisectSession(
                        **{
                            **asdict(current_session),
                            "last_preflight_block_reason": preflight.reason,
                            "last_preflight_block_details": list(preflight.details),
                            "stagnant_rounds": int(getattr(current_session, "stagnant_rounds", 0) or 0) + 1,
                        }
                    )
                self._ai_debug(
                    (
                        f"apply.actions[{idx}] blocked risk={preflight.risk} "
                        f"reason={preflight.reason} "
                        f"details={json.dumps(preflight.details, ensure_ascii=False)}"
                    )
                )
                continue
            current_attempt = attempt or int(getattr(self, "attempts_used", 0) or 0)
            stop, execution, rollback = self._execute_action_with_safeguards(
                idx,
                a,
                preflight,
                snapshot_tag=f"attempt_{current_attempt}_action_{idx}",
            )
            if attempt > 0:
                self._append_attempt_trace(
                    attempt,
                    f"action_{idx}_execution",
                    str(execution.get("status") or "unknown"),
                    action_plan=[dict(a)],
                    preflight=[preflight_payload],
                    execution=[execution],
                    rollback=[rollback] if rollback else [],
                )
            if t == "bisect_mods":
                self._log_bisect_event(
                    "install.bisect.execution",
                    {
                        "attempt": attempt or int(getattr(self, "attempts_used", 0) or 0),
                        "index": idx,
                        "status": execution.get("status"),
                        "tested_side": execution.get("tested_side"),
                        "result": execution.get("result"),
                        "next_suspects": execution.get("next_suspects"),
                        "next_allowed_requests": execution.get("next_allowed_requests"),
                        "failure_kind": execution.get("failure_kind"),
                    },
                )
            if rollback and rollback.get("performed"):
                self.operations.append(f"action_rollback:{t}:{rollback.get('snapshot_tag')}")
            if stop:
                return True
        if int(getattr(self.bisect_session, "stagnant_rounds", 0) or 0) >= 2 and self._has_pending_bisect_followup():
            final_reason = "bisect_stagnated_requires_manual_review"
            self.last_ai_manual_report = {
                "user_summary": "AI 二分连续无进展，已停止自动试探并建议人工排查当前嫌疑集合。",
                "suggested_manual_steps": [
                    "查看报告中的完整 Bisect Tree，确认最后一次通过/失败的分组",
                    "优先人工验证 final_suspects、pending_group、continuation_targets 中的 mod",
                    "结合 latest.log 与 crash-report 检查依赖缺失或前置库问题",
                ],
                "evidence": [
                    f"stagnant_rounds={int(getattr(self.bisect_session, 'stagnant_rounds', 0) or 0)}",
                    f"last_preflight_block_reason={getattr(self.bisect_session, 'last_preflight_block_reason', '') or 'none'}",
                ],
            }
            self.stop_reason = final_reason
            self.operations.append(f"report_manual_fix:{final_reason}")
            self._log("install.stop", f"AI 二分连续无进展，转人工处理，reason={final_reason}", level="WARN")
            return True
        return False

    def _ensure_server_meta_files(self) -> None:
        eula = self.workdirs.server / "eula.txt"
        eula.write_text("eula=true\n", encoding="utf-8")

        props = self.workdirs.server / "server.properties"
        if not props.exists():
            props.write_text(f"server-port={self.config.server_port}\nmotd=MC Auto Server Builder\n", encoding="utf-8")

    def _download_file(
        self,
        url: str,
        out: Path,
        stage: str = "install.download",
        headers: dict[str, str] | None = None,
    ) -> Path:
        task = DownloadTask(out=out, urls=[url], stage=stage, headers=headers)
        done, failed = self.downloader.download_files([task])
        if failed:
            raise RuntimeError(f"下载失败: {url} ({failed[0].error})")
        return done[0]

    def _normalize_memory_plan(self, xmx: str, xms: str) -> tuple[str, str]:
        xmx_norm, xms_norm, cap_gb = normalize_memory_plan(
            xmx=xmx,
            xms=xms,
            total_gb=self.get_system_memory(),
            max_ram_ratio=self.config.memory.max_ram_ratio,
        )
        self.operations.append(f"normalize_memory_plan:Xmx={xmx_norm},Xms={xms_norm},cap={cap_gb:.2f}G")
        return xmx_norm, xms_norm

    def _parse_mem_to_gb(self, value: str) -> float:
        return parse_mem_to_gb(value, default_gb=4.0, min_gb=0.25)

    def _gb_to_mem_str(self, gb: float) -> str:
        return gb_to_mem_str(gb, min_gb=0.25)

    def _install_forge_family_server(self, loader: str, mc_version: str, loader_version: str | None) -> None:
        installer = self.workdirs.server / f"{loader}-installer.jar"
        installer_paths: list[Path] = []
        try:
            if loader == "forge":
                forge_ver = self._resolve_forge_version(mc_version, loader_version)
                forge_coord = self._normalize_forge_installer_coord(mc_version, forge_ver)
                url = f"https://maven.minecraftforge.net/net/minecraftforge/forge/{forge_coord}/forge-{forge_coord}-installer.jar"
                self.operations.append(f"forge_installer_url:{url}")
            else:
                neo_mc_ver, neo_ver = self._resolve_neoforge_version(mc_version, loader_version)
                if neo_mc_ver == "1.20.1":
                    url = (
                        "https://maven.neoforged.net/releases/net/neoforged/forge/"
                        f"{neo_mc_ver}-{neo_ver}/forge-{neo_mc_ver}-{neo_ver}-installer.jar"
                    )
                else:
                    url = f"https://maven.neoforged.net/releases/net/neoforged/neoforge/{neo_ver}/neoforge-{neo_ver}-installer.jar"

            self._download_file(url, installer)
            installer_paths.append(installer)
            self._run_java_jar(installer, ["--installServer"], timeout=600)

            if self._parse_start_command_from_run_scripts():
                return

            # 部分版本会生成 run.sh/run.bat；否则尝试识别 server jar
            if not (self.workdirs.server / "run.sh").exists() and not (self.workdirs.server / "run.bat").exists():
                candidates = sorted(self.workdirs.server.glob("*server*.jar"))
                if candidates:
                    self.server_jar_name = candidates[-1].name
                else:
                    self.server_jar_name = "server.jar"
                self._set_start_command("jar", self.server_jar_name, f"forge_family_fallback:{loader}")
                return

            # 存在 run 脚本但未能解析，回退 jar 推断
            candidates = sorted(self.workdirs.server.glob("*server*.jar"))
            if candidates:
                self.server_jar_name = candidates[-1].name
            else:
                self.server_jar_name = "server.jar"
            self._set_start_command("jar", self.server_jar_name, f"forge_family_parse_failed_fallback:{loader}")
        finally:
            self._cleanup_server_install_artifacts(installer_paths)

    def _install_fabric_family_server(self, loader: str, mc_version: str, loader_version: str | None) -> None:
        installer_paths: list[Path] = []
        try:
            if loader == "fabric":
                installer_ver = self._resolve_fabric_installer_version()
                loader_ver = (loader_version or self._resolve_fabric_loader_version()).strip()
                installer = self.workdirs.server / f"fabric-installer-{installer_ver}.jar"
                installer_url = (
                    f"https://maven.fabricmc.net/net/fabricmc/fabric-installer/{installer_ver}/fabric-installer-{installer_ver}.jar"
                )
                args_candidates = [
                    ["server", "-mcversion", mc_version, "-loader", loader_ver, "-downloadMinecraft"],
                    ["server", "-mcversion", mc_version, "-loader", loader_ver],
                ]
            else:
                installer_ver = self._resolve_quilt_installer_version()
                loader_ver = (loader_version or self._resolve_quilt_loader_version()).strip()
                installer = self.workdirs.server / f"quilt-installer-{installer_ver}.jar"
                installer_url = (
                    "https://maven.quiltmc.org/repository/release/org/quiltmc/"
                    f"quilt-installer/{installer_ver}/quilt-installer-{installer_ver}.jar"
                )
                args_candidates = [
                    ["install", "server", mc_version, loader_ver, "--install-dir=."],
                    ["install", "server", mc_version, loader_ver],
                ]

            self._download_file(installer_url, installer)
            installer_paths.append(installer)
            self._run_installer_with_fallback_args(installer, args_candidates, installer_tag=loader)

            if self._parse_start_command_from_run_scripts():
                return

            # 优先从已安装产物中推断 server jar，最终回退到 server.jar
            candidates = sorted(self.workdirs.server.glob("*server*.jar"))
            if candidates:
                self.server_jar_name = candidates[-1].name
            else:
                self.server_jar_name = "server.jar"
            self._set_start_command("jar", self.server_jar_name, f"fabric_family_parse_failed_fallback:{loader}")
        finally:
            self._cleanup_server_install_artifacts(installer_paths)

    def _run_installer_with_fallback_args(
        self,
        installer: Path,
        args_candidates: list[list[str]],
        installer_tag: str,
    ) -> None:
        last_error: Exception | None = None
        for args in args_candidates:
            try:
                self._run_java_jar(installer, args, timeout=900)
                self.operations.append(f"{installer_tag}_installer_args_ok:{' '.join(args)}")
                return
            except Exception as e:
                last_error = e
                self.operations.append(f"{installer_tag}_installer_args_failed:{' '.join(args)}:{type(e).__name__}")

        if last_error:
            raise last_error

    def _cleanup_server_install_artifacts(self, installer_paths: list[Path]) -> None:
        server_root = self.workdirs.server
        removed_installer = 0
        removed_logs = 0
        removed_args = 0
        removed_run_scripts = 0

        for installer in installer_paths:
            if installer.exists():
                safe_unlink(installer)
                removed_installer += 1

        for path in server_root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() == ".log":
                safe_unlink(path)
                removed_logs += 1

        for name in ("user_args.txt", "user_jvm_args.txt"):
            for path in server_root.rglob(name):
                if not path.is_file():
                    continue
                safe_unlink(path)
                removed_args += 1

        for name in ("run.sh", "run.bat"):
            for path in server_root.rglob(name):
                if not path.is_file():
                    continue
                safe_unlink(path)
                removed_run_scripts += 1

        self.operations.append(
            "cleanup_server_install_artifacts:"
            f"installer={removed_installer},logs={removed_logs},args={removed_args},run_scripts={removed_run_scripts}"
        )

    def _resolve_forge_version(self, mc_version: str, loader_version: str | None) -> str:
        if loader_version:
            ver = loader_version.strip()
            ver = ver.removeprefix("forge-")
            if ver.startswith(f"{mc_version}-"):
                ver = ver[len(mc_version) + 1 :]
            if ver:
                return ver

        # 回退：promotions_slim 推荐/最新
        data = http_get_json(
            "https://files.minecraftforge.net/net/minecraftforge/forge/promotions_slim.json",
            timeout=30,
        )
        promos = data.get("promos", {}) if isinstance(data, dict) else {}
        for key in (f"{mc_version}-recommended", f"{mc_version}-latest"):
            if key in promos:
                return str(promos[key])
        raise ValueError(f"无法解析 Forge 版本: mc={mc_version}, loader={loader_version}")

    def _normalize_forge_installer_coord(self, mc_version: str, forge_ver: str) -> str:
        ver = forge_ver.strip().removeprefix("forge-")
        coord = ver if ver.startswith(f"{mc_version}-") else f"{mc_version}-{ver}"

        # Forge 1.7.10 安装器在 Maven 坐标需要完整尾缀：1.7.10-<forge>-1.7.10
        if mc_version == "1.7.10" and not coord.endswith(f"-{mc_version}"):
            coord = f"{coord}-{mc_version}"
            self.operations.append(f"forge_legacy_1710_coord_suffix_applied:{coord}")

        return coord

    def _resolve_neoforge_version(self, mc_version: str, loader_version: str | None) -> tuple[str, str]:
        if not (loader_version and loader_version.strip()):
            raise ValueError("NeoForge 需要 manifest 中提供 loader_version")

        ver = loader_version.strip().removeprefix("neoforge-").removeprefix("forge-")
        m = re.match(r"^(\d+\.\d+\.\d+)-(\d+\.\d+\.\d+)$", ver)
        if m:
            return m.group(1), m.group(2)

        if re.match(r"^\d+\.\d+\.\d+$", ver):
            return mc_version, ver

        raise ValueError(f"无法解析 NeoForge 版本: mc={mc_version}, loader={loader_version}")

    def _resolve_fabric_installer_version(self) -> str:
        data = http_get_json("https://meta.fabricmc.net/v2/versions/installer", timeout=30)
        if isinstance(data, list) and data:
            stable = [x for x in data if isinstance(x, dict) and x.get("stable") is True]
            target = stable[0] if stable else data[0]
            return str(target.get("version"))
        raise ValueError("无法获取 Fabric installer 版本")

    def _resolve_fabric_loader_version(self) -> str:
        data = http_get_json("https://meta.fabricmc.net/v2/versions/loader", timeout=30)
        if isinstance(data, list) and data:
            stable = [x for x in data if isinstance(x, dict) and x.get("stable") is True]
            target = stable[0] if stable else data[0]
            return str(target.get("version"))
        raise ValueError("无法获取 Fabric loader 版本")

    def _resolve_quilt_installer_version(self) -> str:
        data = http_get_json("https://meta.quiltmc.org/v3/versions/installer", timeout=30)
        if isinstance(data, list) and data:
            return str(data[0].get("version"))
        raise ValueError("无法获取 Quilt installer 版本")

    def _resolve_quilt_loader_version(self) -> str:
        data = http_get_json("https://meta.quiltmc.org/v3/versions/loader", timeout=30)
        if isinstance(data, list) and data:
            return str(data[0].get("version"))
        raise ValueError("无法获取 Quilt loader 版本")

    def _run_java_jar(self, jar_path: Path, extra_args: list[str], timeout: int = 600) -> None:
        java_bin = str(self.current_java_bin or "java")
        cmd = [java_bin, "-jar", str(jar_path), *extra_args]
        cp = subprocess.run(
            cmd,
            cwd=self.workdirs.server,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if cp.returncode != 0:
            stderr_tail = "\n".join((cp.stderr or "").splitlines()[-40:])
            stdout_tail = "\n".join((cp.stdout or "").splitlines()[-40:])
            raise RuntimeError(f"installer_failed exit={cp.returncode} stdout_tail={stdout_tail!r} stderr_tail={stderr_tail!r}")
