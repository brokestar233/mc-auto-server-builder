from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import tarfile
import threading
import time
import zipfile
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, fields
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Literal, Mapping, TypedDict, cast
from urllib.parse import urlparse

import psutil
import requests

from .action_executor import (
    build_initial_execution_result,
    build_previous_action_state,
    execute_adjust_memory_action,
    execute_change_java_action,
    execute_continue_after_restore_mods_action,
    execute_remove_mods_action,
)
from .action_preflight import (
    BisectPreflightInput,
    ContinueAfterRestoreModsState,
    assess_adjust_memory,
    assess_bisect_mods,
    assess_change_java,
    assess_continue_after_restore_mods,
    assess_non_mutating_action,
    assess_remove_mods,
    assess_unknown_action,
)
from .ai import BuilderAIService
from .bisect_runtime import (
    build_bisect_feedback_payload,
    build_bisect_move_records,
    build_bisect_round_record,
    derive_bisect_followups,
    make_bisect_progress_token,
    prepare_bisect_round_plan,
    prepare_bisect_session_round_update,
    store_pending_bisect_round_plan,
    summarize_bisect_round_outcome,
    update_bisect_session_after_round,
    update_bisect_session_fields,
)
from .config import AppConfig
from .defaults import (
    SUPPORTED_JAVA_VERSIONS,
    get_common_jvm_params,
    get_jvm_params_for_java_version,
)
from .diagnostics import (
    build_dependency_graph,
    inspect_crash_report,
    inspect_mod_metadata,
    verify_start_command_artifacts,
)
from .input_parser import parse_pack_input
from .install_runtime import (
    download_curseforge_pack,
    download_modrinth_pack,
    prepare_runtime_environment,
    prepare_server_files,
    resolve_pack_and_manifest,
)
from .mod_runtime import (
    add_remove_regex,
    apply_known_client_blacklist,
    apply_recognition_based_client_cleanup,
    backup_mods,
    list_current_installed_client_mods,
    list_mods,
    normalize_mod_token,
    record_deleted_client_mod,
    record_deleted_mod_detail,
    remove_mods_by_name,
    remove_mods_by_regex,
    resolve_dependency_cleanup_targets,
    resolve_mod_names_to_installed,
    rollback_mods,
)
from .models import (
    ActionPreflight,
    AIResult,
    AttemptTrace,
    BisectMoveRecord,
    BisectRoundRecord,
    BisectSession,
    CacheDirs,
    PackInput,
    PackManifest,
    WorkDirs,
)
from .pack_runtime import (
    classify_manifest_file_type,
    copy_client_files_with_blacklist,
    extract_curseforge_type_hints,
    extract_full_pack_version_payload_if_needed,
    extract_modrinth_type_hints,
    manifest_target_path,
)
from .recognition import RecognitionFallbackPlan, choose_java_version, choose_latest_lts_java_version
from .recognition_runtime import (
    build_ai_context,
    build_recognition_candidates,
    preflight_recognition_plan,
    recognition_confidence_level,
    recognition_runtime_feedback,
    select_next_recognition_plan,
)
from .reporting import (
    append_attempt_trace,
    attempt_trace_path,
    build_meta_payload,
    build_recognition_summary,
    generate_report,
    package_server,
    serialize_detection_candidates,
    summarize_ai_context,
    summarize_remote_failure_events,
)
from .resume_runtime import (
    build_pack_cache_key,
    build_resume_state,
    download_pack_to_cache,
    load_manifest_from_cache,
    load_resume_source_from_path,
    manifest_cache_path,
    pack_cache_zip_path,
    persist_manifest_cache,
    persist_resume_state,
    read_resume_state,
    restore_resume_state,
    resume_prepared_server_available,
)
from .rule_db import RuleDB
from .runtime_startup import (
    collect_process_resource_snapshot,
    detect_command_probe_ready,
    detect_current_java_version,
    detect_failure_signals,
    detect_log_ready_signal,
    extract_latest_crash_mod_issue,
    extract_relevant_log,
    read_startup_log_tail,
    snapshot_crash_reports,
    start_server,
)
from .util import (
    ColorPolicy,
    DownloadConfig,
    Downloader,
    DownloadError,
    DownloadFailure,
    DownloadTask,
    ExternalDataError,
    ExternalRequestError,
    ExternalResponseError,
    ExternalServiceError,
    StructuredLogger,
    adoptium_platform_triplet,
    configure_requests_session,
    extract_archive,
    extract_archive_payload_into,
    extract_start_command_from_line,
    gb_to_mem_str,
    graceful_stop_process,
    http_get_json,
    is_http_url,
    is_local_tcp_port_open,
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
from .workspace import create_cache_dirs, create_workdirs

AI_REMOVE_MODS_SAFE_LIMIT = 3

# Keep these module-level names available for monkeypatch-based tests and runtime indirection.
_STARTUP_COMPAT_EXPORTS = (
    threading,
    read_tail_text,
    threaded_pipe_reader,
    terminate_process,
    graceful_stop_process,
    is_local_tcp_port_open,
)


class PreviousActionState(TypedDict):
    jvm_xmx: str
    jvm_xms: str
    extra_jvm_flags: list[str]
    current_java_version: int
    current_java_bin: str


class RollbackResult(TypedDict, total=False):
    action_type: str
    snapshot_tag: str
    performed: bool
    error: str


AttemptLoopDecision = Literal["continue", "stop", "success"]


class ActionExecutionResult(TypedDict, total=False):
    index: int
    action_type: str
    status: str
    snapshot_tag: str
    risk: str
    resolved_targets: list[str]
    rollback_on_failure: bool
    forced_targets: list[str]
    forced_rationale: list[str]
    matched_dependency_chains: list[object]
    validation_start_performed: bool
    validation_success: bool
    validation_success_source: object
    validation_problem_changed: bool
    rollback_reason: str
    validation_failure_excerpt: list[str]
    restored_snapshot_tag: str
    restored_active_mods: list[str]
    restored_targets: list[str]
    xmx: str
    xms: str
    version: int
    stop_reason: str
    manual_steps: list[str]
    evidence: list[str]
    reason: str
    error: str


class CurseForgeFilePayload(TypedDict, total=False):
    id: int
    modId: int
    fileName: str
    downloadUrl: str | None


class PreparedBisectSessionRoundUpdate(TypedDict):
    session: BisectSession
    source_mods: list[str]
    final_suspects: list[str]
    round_record: BisectRoundRecord
    feedback: dict[str, object]
    pending_group: list[str]
    continuation_targets: list[str]
    next_allowed_requests: list[str]
    completed_requests: list[str]
    fallback_targets: list[str]
    suspects_invalidated: bool
    progress_token: str
    stagnant_rounds: int


class CurseForgeManifestEntry(TypedDict):
    projectID: object
    fileID: object


@dataclass(frozen=True, slots=True)
class RemoteFailureDetail:
    stage: str
    category: str
    exc_type: str = ""
    message: str = ""

    def operation_token(self) -> str:
        parts = [self.stage, self.category]
        if self.exc_type:
            parts.append(self.exc_type)
        return ":".join(parts)

    def log_message(self, label: str) -> str:
        detail = f"{label} 失败，阶段={self.stage}，分类={self.category}"
        if self.exc_type:
            detail += f"，异常={self.exc_type}"
        if self.message:
            detail += f"，原因={self.message}"
        return detail

    def to_event_payload(self) -> dict[str, str]:
        return {
            "stage": self.stage,
            "category": self.category,
            "exc_type": self.exc_type,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class CurseForgeManifestPairResolution:
    pair: tuple[int, int]
    data: CurseForgeFilePayload | None


@dataclass(frozen=True, slots=True)
class CurseForgeBatchResolution:
    resolved: dict[tuple[int, int], CurseForgeFilePayload]
    unresolved: list[tuple[int, int]]


@dataclass(slots=True)
class RemoveValidationStatePayload:
    triggered: bool = False
    continue_allowed: bool = False
    continued: bool = False
    rollback_snapshot_tag: str = ""
    action_index: int = 0
    removed_targets: list[str] | None = None
    forced_targets: list[str] | None = None
    post_remove_active_mods: list[str] | None = None
    previous_crash_reports: list[str] | None = None
    validation_crash_reports: list[str] | None = None
    crash_report_delta: list[str] | None = None
    previous_excerpt: str = ""
    validation_excerpt: str = ""
    failure_signals: list[str] | None = None
    readiness_evidence: list[str] | None = None
    problem_changed: bool = False

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        for key in (
            "removed_targets",
            "forced_targets",
            "post_remove_active_mods",
            "previous_crash_reports",
            "validation_crash_reports",
            "crash_report_delta",
            "failure_signals",
            "readiness_evidence",
        ):
            payload[key] = list(payload.get(key) or [])
        return payload

    @classmethod
    def from_mapping(cls, state: object) -> "RemoveValidationStatePayload":
        raw = cast(dict[str, object], state if isinstance(state, dict) else {})
        action_index_raw = raw.get("action_index")
        return cls(
            triggered=bool(raw.get("triggered", False)),
            continue_allowed=bool(raw.get("continue_allowed", False)),
            continued=bool(raw.get("continued", False)),
            rollback_snapshot_tag=str(raw.get("rollback_snapshot_tag") or "").strip(),
            action_index=int(action_index_raw) if isinstance(action_index_raw, (int, str)) else 0,
            removed_targets=_normalize_object_list(raw.get("removed_targets")),
            forced_targets=_normalize_object_list(raw.get("forced_targets")),
            post_remove_active_mods=_normalize_object_list(raw.get("post_remove_active_mods")),
            previous_crash_reports=_normalize_object_list(raw.get("previous_crash_reports")),
            validation_crash_reports=_normalize_object_list(raw.get("validation_crash_reports")),
            crash_report_delta=_normalize_object_list(raw.get("crash_report_delta")),
            previous_excerpt=str(raw.get("previous_excerpt") or ""),
            validation_excerpt=str(raw.get("validation_excerpt") or ""),
            failure_signals=_normalize_object_list(raw.get("failure_signals")),
            readiness_evidence=_normalize_object_list(raw.get("readiness_evidence")),
            problem_changed=bool(raw.get("problem_changed", False)),
        )


def _normalize_start_server_result(payload: object) -> dict[str, object]:
    raw = cast(dict[str, object], payload if isinstance(payload, dict) else {})
    return {
        "success": bool(raw.get("success", False)),
        "success_source": raw.get("success_source"),
        "reason": str(raw.get("reason") or ""),
        "stdout": str(raw.get("stdout") or ""),
        "stderr": str(raw.get("stderr") or ""),
        "stderr_tail": str(raw.get("stderr_tail") or ""),
        "crash_reports_snapshot": _normalize_object_list(raw.get("crash_reports_snapshot")),
        "crash_reports_new": _normalize_object_list(raw.get("crash_reports_new")),
        "failure_signals": _normalize_object_list(raw.get("failure_signals")),
        "readiness_evidence": _normalize_object_list(raw.get("readiness_evidence")),
    }


def _normalize_curseforge_file_payload(payload: object) -> CurseForgeFilePayload | None:
    if not isinstance(payload, dict) or not payload:
        return None

    normalized: dict[str, object] = {}
    file_id = payload.get("id")
    mod_id = payload.get("modId")
    file_name = payload.get("fileName")
    download_url = payload.get("downloadUrl")

    if isinstance(file_id, int):
        normalized["id"] = file_id
    if isinstance(mod_id, int):
        normalized["modId"] = mod_id
    if isinstance(file_name, str) and file_name:
        normalized["fileName"] = file_name
    if download_url is None or isinstance(download_url, str):
        normalized["downloadUrl"] = download_url

    for key, value in payload.items():
        if key not in normalized:
            normalized[key] = value

    return cast(CurseForgeFilePayload, normalized)


def _normalize_curseforge_manifest_entry(payload: object) -> CurseForgeManifestEntry | None:
    if not isinstance(payload, dict):
        return None
    if "projectID" not in payload or "fileID" not in payload:
        return None
    return {
        "projectID": payload.get("projectID"),
        "fileID": payload.get("fileID"),
    }


def _normalize_object_list(values: object) -> list[str]:
    normalized: list[str] = []
    for value in cast(list[object], values or []):
        if value is None:
            continue
        text = str(value).strip()
        if text:
            normalized.append(text)
    return normalized


def _object_to_int(value: object, default: int = 0) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text:
            try:
                return int(text)
            except ValueError:
                return default
    return default


def _object_to_str_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [text for item in value if (text := str(item).strip())]


def _object_to_dict(value: object) -> dict[str, object]:
    return dict(value) if isinstance(value, dict) else {}


def _build_remote_failure_detail(
    stage: str,
    exc: BaseException | None = None,
    *,
    category: str | None = None,
    message: str = "",
) -> RemoteFailureDetail:
    if category is None:
        if isinstance(exc, ExternalRequestError):
            category = "request"
        elif isinstance(exc, ExternalResponseError):
            category = "response"
        elif isinstance(exc, ExternalDataError):
            category = "data"
        elif isinstance(exc, DownloadError):
            category = "download"
        elif isinstance(exc, (zipfile.BadZipFile, tarfile.TarError, ValueError)):
            category = "extract"
        elif isinstance(exc, (FileNotFoundError, OSError)):
            category = "filesystem"
        else:
            category = "unknown"
    exc_type = type(exc).__name__ if exc is not None else ""
    text = message.strip() if message.strip() else (str(exc).strip() if exc is not None else "")
    return RemoteFailureDetail(stage=stage, category=category, exc_type=exc_type, message=text)


def _build_download_failure_detail(item: DownloadFailure) -> RemoteFailureDetail:
    category = str(getattr(item, "category", "") or "download").strip() or "download"
    stage = str(getattr(item, "stage", "") or item.task.stage or "download_task").strip()
    exc_type = str(getattr(item, "exc_type", "") or "").strip()
    message = str(getattr(item, "message", "") or getattr(item, "error", "") or "").strip()
    if not exc_type and ":" in message:
        exc_type, _, remainder = message.partition(":")
        exc_type = exc_type.strip()
        if remainder.strip():
            message = remainder.strip()
    return RemoteFailureDetail(stage=stage, category=category, exc_type=exc_type, message=message)


class ServerBuilder:
    _ALLOWED_MANIFEST_DOWNLOAD_TYPES = {"mod", "plugin", "datapack"}

    def __init__(
        self,
        source: str | None,
        config: AppConfig | None = None,
        base_dir: str | Path = ".",
        resume_dir: str | Path | None = None,
    ):
        self.config = config or AppConfig()
        self.resume_requested = resume_dir is not None
        resume_path = Path(resume_dir).resolve() if resume_dir is not None else None
        derived_base_dir = Path(base_dir).resolve()
        if resume_path is not None and resume_path.parent.name == "runs":
            derived_base_dir = resume_path.parent.parent
        self.base_dir = derived_base_dir
        self.cache_dirs: CacheDirs = create_cache_dirs(self.base_dir)
        self.workdirs: WorkDirs = create_workdirs(self.base_dir, resume_dir=resume_path, cache_dirs=self.cache_dirs)
        self.resume_state_path: Path = self.workdirs.root / "run_state.json"
        self.source_input = str(source or "").strip()
        if not self.source_input and resume_path is not None:
            resume_source = self._load_resume_source_from_path(resume_path)
            self.source_input = resume_source
        if not self.source_input:
            raise ValueError("缺少 source 参数")
        self.pack_input: PackInput = parse_pack_input(self.source_input)
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
        self.remote_failure_events: list[dict[str, object]] = []
        self.removed_mods: list[str] = []
        self.bisect_removed_mods: list[str] = []
        self.known_deleted_client_mods: set[str] = set()
        self.deleted_mod_evidence: dict[str, list[str]] = {}
        self.deleted_mod_sources: dict[str, dict[str, list[str]]] = {}
        self.last_ai_payload: dict[str, object] = {}
        self.last_ai_result: AIResult | None = None
        self.last_ai_manual_report: dict[str, object] = {}
        self.last_rollback_remove_mods: dict[str, object] = {}
        self.remove_validation_state: dict[str, object] = {}
        self.attempt_traces: list[AttemptTrace] = []
        self.bisect_session = BisectSession()
        self.last_bisect_feedback: dict[str, object] = {}
        self.ai_service = BuilderAIService(self)
        self.attempts_used: int = 0
        self.run_success: bool = False
        self.stop_reason: str = ""
        self._mods_backup_signatures: dict[str, tuple[str, ...]] = {}
        self.server_jar_name: str = "server.jar"
        self.start_command_mode: str = "jar"
        self.start_command_value: str = self.server_jar_name
        self.recognition_attempts: list[dict[str, object]] = []
        self.log_file_path: Path = self.workdirs.logs / "install.log"
        self.resolved_pack_zip_path: Path | None = None
        self.pack_cache_key: str = ""
        self.resume_state: dict[str, object] = {}
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
                proxies=self.config.proxy.to_requests_proxies(),
                trust_env=self.config.proxy.trust_env,
            ),
            logger=self.logger,
        )
        if self.resume_requested:
            self._restore_resume_state()

    def _request_proxies(self) -> dict[str, str] | None:
        return self.config.proxy.to_requests_proxies()

    def _request_trust_env(self) -> bool:
        return self.config.proxy.trust_env

    def _create_request_session(self) -> requests.Session:
        return configure_requests_session(
            requests.Session(),
            proxies=self._request_proxies(),
            trust_env=self._request_trust_env(),
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

    def _load_resume_source_from_path(self, resume_path: Path) -> str:
        return load_resume_source_from_path(self, resume_path)

    def _read_resume_state(self) -> dict[str, object]:
        return read_resume_state(self)

    def _build_resume_state(self, *, prepared_server: bool) -> dict[str, object]:
        return build_resume_state(self, prepared_server=prepared_server)

    def _persist_resume_state(self, *, prepared_server: bool) -> None:
        persist_resume_state(self, prepared_server=prepared_server)

    def _restore_resume_state(self) -> None:
        restore_resume_state(self)

    def _resume_prepared_server_available(self) -> bool:
        return resume_prepared_server_available(self)

    def _build_pack_cache_key(self, *, source_hint: str | None = None) -> str:
        return build_pack_cache_key(self, source_hint=source_hint)

    def _pack_cache_zip_path(self, cache_key: str) -> Path:
        return pack_cache_zip_path(self, cache_key)

    def _manifest_cache_path(self, cache_key: str) -> Path:
        return manifest_cache_path(self, cache_key)

    def _load_manifest_from_cache(self, cache_key: str) -> PackManifest | None:
        return load_manifest_from_cache(self, cache_key)

    def _persist_manifest_cache(self, cache_key: str, manifest: PackManifest) -> None:
        persist_manifest_cache(self, cache_key, manifest)

    def _download_pack_to_cache(self, url: str, cache_key: str, *, stage: str = "install.download") -> Path:
        return download_pack_to_cache(self, url, cache_key, stage=stage)

    # 文件与mods操作
    def list_mods(self) -> list[str]:
        return list_mods(self)

    def _record_deleted_client_mod(self, mod_name: str, source: str, reason: str) -> None:
        record_deleted_client_mod(self, mod_name, source, reason)

    def _record_deleted_mod_detail(self, mod_name: str, category: str, source: str, reason: str) -> None:
        record_deleted_mod_detail(self, mod_name, category, source, reason)

    def _normalize_mod_token(self, value: str) -> str:
        return normalize_mod_token(self, value)

    def _resolve_mod_names_to_installed(self, names: list[str], candidates: list[str] | None = None) -> list[str]:
        return resolve_mod_names_to_installed(self, names, candidates=candidates)

    def list_current_installed_client_mods(self) -> list[str]:
        return list_current_installed_client_mods(self)

    def remove_mods_by_name(self, names: list[str], source: str = "manual", reason: str = ""):
        remove_mods_by_name(self, names, source=source, reason=reason)

    def remove_mods_by_regex(self, patterns: list[str], source: str = "regex_rule"):
        remove_mods_by_regex(self, patterns, source=source)

    def add_remove_regex(self, pattern: str, desc: str = ""):
        add_remove_regex(self, pattern, desc=desc)

    def apply_known_client_blacklist(self):
        apply_known_client_blacklist(self)

    def apply_recognition_based_client_cleanup(self) -> list[str]:
        return apply_recognition_based_client_cleanup(self)

    def backup_mods(self, tag: str):
        backup_mods(self, tag)

    def rollback_mods(self, tag: str):
        rollback_mods(self, tag)

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
        return build_bisect_feedback_payload(
            suspects=suspects,
            bisect_mode=bisect_mode,
            tested_side=tested_side,
            keep_group=keep_group,
            test_group=test_group,
            moved_mods=moved_mods,
            round_result=round_result,
            startup_success=startup_success,
            failure_kind=failure_kind,
            failure_detail=failure_detail,
            reason=reason,
            pending_group=pending_group,
            continuation_targets=continuation_targets,
            next_allowed_requests=next_allowed_requests,
            fallback_targets=fallback_targets,
            suspects_invalidated=suspects_invalidated,
        )

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
        return make_bisect_progress_token(
            suspects=suspects,
            bisect_mode=bisect_mode,
            tested_side=tested_side,
            round_result=round_result,
            final_suspects=final_suspects,
            next_allowed_requests=next_allowed_requests,
        )

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
        return BisectRoundRecord(
            **cast(dict[str, Any], {key: value for key, value in normalized_payload.items() if key in allowed_fields})
        )

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
        return BisectSession(**cast(dict[str, Any], {key: value for key, value in normalized_payload.items() if key in allowed_fields}))

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
        self.bisect_session = update_bisect_session_fields(
            session,
            active=False,
            success_ready=True,
            success_guard_reason=str(reason or "ready"),
            success_guard_history=history,
            pending_group=[],
            continuation_targets=[],
            next_allowed_requests=[],
            fallback_targets=[],
            suspects_invalidated=False,
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
        self.bisect_session = update_bisect_session_fields(
            session,
            success_guard_history=history,
            consecutive_same_issue_on_success=count,
            success_guard_reason=marker,
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
        return build_ai_context(self, start_res, log_info)

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
        return derive_bisect_followups(
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
        return build_bisect_move_records(moved_mods, from_group=from_group, to_group=to_group, reason=reason)

    def _prepare_bisect_round_plan(self, idx: int, action: dict, snapshot_tag: str) -> tuple[dict[str, object], dict[str, object]]:
        bisect_mode, suspects = self._consume_bisect_targets(action)
        session = self._coerce_bisect_session()
        source_mods = list(getattr(session, "source_mods", []) or self.list_mods())
        if bisect_mode == "initial":
            fallback_seed = list(getattr(session, "fallback_targets", []) or [])
            if fallback_seed:
                source_mods = self._resolve_mod_names_to_installed(fallback_seed)
        keep_group, test_group = self._split_mods_for_bisect(suspects)
        plan, execution = prepare_bisect_round_plan(
            idx=idx,
            snapshot_tag=snapshot_tag,
            action=action,
            bisect_mode=bisect_mode,
            suspects=suspects,
            session=session,
            source_mods=source_mods,
            keep_group=keep_group,
            test_group=test_group,
        )
        self._log_bisect_event(
            "install.bisect.start",
            {"round_index": plan["round_index"], "bisect_mode": bisect_mode, "suspects": suspects, "snapshot_tag": snapshot_tag},
        )
        self._log_bisect_event("install.bisect.groups", {"bisect_mode": bisect_mode, "keep_group": keep_group, "test_group": test_group})
        return plan, execution

    def _store_pending_bisect_round_plan(self, plan: dict[str, object]) -> None:
        session = self._coerce_bisect_session()
        self.bisect_session = store_pending_bisect_round_plan(session, plan)

    def _execute_pending_bisect_round(self, plan: dict[str, object]) -> tuple[bool, dict[str, object], dict[str, object] | None]:
        idx = _object_to_int(plan.get("index"), 0)
        snapshot_tag = str(plan.get("snapshot_tag") or "")
        bisect_mode = str(plan.get("bisect_mode") or "initial")
        tested_side = str(plan.get("tested_side") or "keep")
        keep_group = _object_to_str_list(plan.get("keep_group"))
        test_group = _object_to_str_list(plan.get("test_group"))
        suspects = _object_to_str_list(plan.get("suspects"))
        source_mods = _object_to_str_list(plan.get("source_mods")) or self.list_mods()
        active_group = _object_to_str_list(plan.get("active_group"))
        moved_mods = _object_to_str_list(plan.get("moved_mods"))
        notes = _object_to_str_list(plan.get("notes"))
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
        round_record = build_bisect_round_record(
            session=session,
            plan={**plan, "bisect_reason": bisect_reason},
            suspects=suspects,
            bisect_mode=bisect_mode,
            tested_side=tested_side,
            keep_group=keep_group,
            test_group=test_group,
            moved_mods=moved_mods,
            round_result=round_result,
            start_res=start_res,
            failure_kind=failure_kind,
            failure_detail=failure_detail,
            continuation_targets=continuation_targets,
            pending_group=pending_group,
            next_allowed_requests=next_allowed_requests,
            fallback_targets=fallback_targets,
            suspects_invalidated=suspects_invalidated,
            notes=notes,
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
        session_update: PreparedBisectSessionRoundUpdate = cast(PreparedBisectSessionRoundUpdate, prepare_bisect_session_round_update(
            session=session,
            bisect_mode=bisect_mode,
            suspects=suspects,
            source_mods=source_mods,
            final_suspects=final_suspects,
            round_result=round_result,
            round_record=round_record,
            feedback=feedback,
            pending_group=pending_group,
            continuation_targets=continuation_targets,
            next_allowed_requests=next_allowed_requests,
            fallback_targets=fallback_targets,
            suspects_invalidated=suspects_invalidated,
        ))
        stagnant_rounds = session_update["stagnant_rounds"]
        self.bisect_session = update_bisect_session_after_round(**session_update)
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
        execution = summarize_bisect_round_outcome(
            idx=idx,
            snapshot_tag=snapshot_tag,
            tested_side=tested_side,
            keep_group=keep_group,
            test_group=test_group,
            moved_mods=moved_mods,
            final_suspects=final_suspects,
            round_result=round_result,
            startup_success=bool(start_res.get("success")),
            failure_kind="" if round_result == "pass" else failure_kind,
            next_allowed_requests=next_allowed_requests,
            fallback_targets=fallback_targets,
            suspects_invalidated=suspects_invalidated,
            feedback=feedback,
        )
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
        return attempt_trace_path(self, attempt, stage)

    def _sanitize_trace_stage(self, stage: str) -> str:
        return re.sub(r"[^a-zA-Z0-9_\-.]+", "_", str(stage or "unknown")).strip("_") or "unknown"

    def _append_attempt_trace(
        self,
        attempt: int,
        stage: str,
        status: str,
        *,
        context_summary: dict[str, object] | None = None,
        recognition_plan: dict[str, object] | None = None,
        ai_result: dict[str, object] | None = None,
        action_plan: list[dict[str, object]] | None = None,
        preflight: list[dict[str, object]] | None = None,
        execution: list[dict[str, object]] | None = None,
        rollback: list[dict[str, object]] | None = None,
    ) -> None:
        append_attempt_trace(
            self,
            attempt,
            stage,
            status,
            context_summary=context_summary,
            recognition_plan=recognition_plan,
            ai_result=ai_result,
            action_plan=action_plan,
            preflight=preflight,
            execution=execution,
            rollback=rollback,
        )

    def _summarize_ai_context(self, context: dict) -> dict[str, object]:
        return summarize_ai_context(self, context)

    def _serialize_detection_candidates(self, candidates: object, *, limit: int = 3) -> list[dict[str, object]]:
        return serialize_detection_candidates(candidates, limit=limit)

    def _build_recognition_summary(self) -> dict[str, object]:
        return build_recognition_summary(self)

    def _summarize_remote_failure_events(self, *, detail_limit: int = 5) -> dict[str, object]:
        return summarize_remote_failure_events(self, detail_limit=detail_limit)

    def _recognition_confidence_level(self, confidence: float) -> str:
        return recognition_confidence_level(confidence)

    def _build_recognition_candidates(self) -> list[RecognitionFallbackPlan]:
        manifest = self.manifest
        if not manifest:
            return []
        return build_recognition_candidates(manifest, choose_java_version)

    def _preflight_recognition_plan(self, plan: RecognitionFallbackPlan) -> dict[str, object]:
        return preflight_recognition_plan(
            plan,
            server_dir=self.workdirs.server,
            server_jar_name=self.server_jar_name,
            manifest=self.manifest,
            choose_java=choose_java_version,
        )

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
        return recognition_runtime_feedback(start_res, log_info, self.current_java_version)

    def _select_next_recognition_plan(self, start_res: dict[str, object], log_info: dict[str, object]) -> RecognitionFallbackPlan | None:
        return select_next_recognition_plan(
            start_res=start_res,
            log_info=log_info,
            plans=self._build_recognition_candidates(),
            recognition_attempts=list(self.recognition_attempts),
            current_java_version=self.current_java_version,
            preflight=self._preflight_recognition_plan,
        )

    def _assess_action_preflight(self, action: dict) -> ActionPreflight:
        action_type = str(action.get("type") or "unknown")
        if action_type == "continue_after_restore_mods":
            state = dict(getattr(self, "remove_validation_state", {}) or {})
            return assess_continue_after_restore_mods(
                ContinueAfterRestoreModsState(
                    continue_allowed=bool(state.get("continue_allowed", False)),
                    post_remove_active_mods=[str(x).strip() for x in (state.get("post_remove_active_mods") or []) if str(x).strip()],
                    rollback_snapshot_tag=str(state.get("rollback_snapshot_tag") or "").strip(),
                    continued=bool(state.get("continued", False)),
                    problem_changed=bool(state.get("problem_changed", False)),
                ),
                action_type=action_type,
            )
        if action_type == "bisect_mods":
            bisect_mode = str(action.get("bisect_mode") or "initial").strip() or "initial"
            session = self._coerce_bisect_session()
            next_allowed = list(getattr(session, "next_allowed_requests", []) or [])
            completed = set(getattr(session, "completed_requests", []) or [])
            completed_tokens = set(getattr(session, "completed_request_tokens", []) or [])
            request_source = str(action.get("request_source") or "ai").strip() or "ai"
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
            fallback_targets = self._resolve_mod_names_to_installed(list(getattr(session, "fallback_targets", []) or []))
            last_bisect_feedback = dict(getattr(self, "last_bisect_feedback", {}) or {})
            last_targets = self._resolve_mod_names_to_installed(
                [str(x) for x in (last_bisect_feedback.get("requested_targets") or []) if str(x).strip()],
                candidates=resolved,
            )
            return assess_bisect_mods(
                BisectPreflightInput(
                    action_type=action_type,
                    bisect_mode=bisect_mode,
                    request_source=request_source,
                    resolved_targets=resolved,
                    move_candidates=move_candidates,
                    next_allowed_requests=next_allowed,
                    completed_requests=sorted(completed),
                    completed_request_tokens=sorted(completed_tokens),
                    last_requested_targets=last_targets,
                    fallback_targets=fallback_targets,
                    suspects_invalidated=bool(getattr(session, "suspects_invalidated", False)),
                    manual_grouping_requested=bool(action.get("keep_group") or action.get("test_group")),
                )
            )
        if action_type == "remove_mods":
            targets = [str(x).strip() for x in (action.get("targets") or []) if str(x).strip()]
            rollback_on_failure = bool(action.get("rollback_on_failure", False))
            regex_targets = [x for x in targets if x.startswith("regex:")]
            direct_targets = [x for x in targets if not x.startswith("regex:")]
            resolved = self._resolve_mod_names_to_installed(direct_targets)
            unresolved = [x for x in direct_targets if x not in resolved]
            return assess_remove_mods(
                action_type=action_type,
                resolved_targets=resolved,
                regex_targets=regex_targets,
                unresolved_targets=unresolved,
                rollback_on_failure=rollback_on_failure,
                safe_limit=AI_REMOVE_MODS_SAFE_LIMIT,
            )

        if action_type == "adjust_memory":
            xmx = str(action.get("xmx", self.jvm_xmx) or self.jvm_xmx)
            xms = str(action.get("xms", self.jvm_xms) or self.jvm_xms)
            xmx_norm, xms_norm = self._normalize_memory_plan(xmx, xms)
            current_xmx_gb = parse_mem_to_gb(self.jvm_xmx)
            next_xmx_gb = parse_mem_to_gb(xmx_norm)
            return assess_adjust_memory(
                action_type=action_type,
                xmx_norm=xmx_norm,
                xms_norm=xms_norm,
                current_xmx_gb=current_xmx_gb,
                next_xmx_gb=next_xmx_gb,
                system_memory_gb=self.get_system_memory(),
                max_ram_ratio=float(self.config.memory.max_ram_ratio),
            )

        if action_type == "change_java":
            version = int(action.get("version", self.current_java_version) or self.current_java_version)
            return assess_change_java(action_type=action_type, target_version=version, current_java_version=self.current_java_version)

        if action_type in {"stop_and_report", "report_manual_fix"}:
            return assess_non_mutating_action(action_type)

        return assess_unknown_action(action_type)

    def _rollback_action(self, action_type: str, snapshot_tag: str, previous_state: PreviousActionState) -> RollbackResult:
        result: RollbackResult = {"action_type": action_type, "snapshot_tag": snapshot_tag, "performed": False}
        try:
            if action_type == "remove_mods":
                self.rollback_mods(snapshot_tag)
                result["performed"] = True
            elif action_type == "bisect_mods":
                self.rollback_mods(snapshot_tag)
                result["performed"] = True
            elif action_type == "adjust_memory":
                self.set_jvm_args(
                    previous_state["jvm_xmx"] or self.jvm_xmx,
                    previous_state["jvm_xms"] or self.jvm_xms,
                    list(previous_state["extra_jvm_flags"] or self.extra_jvm_flags),
                )
                result["performed"] = True
            elif action_type == "change_java":
                previous_version = int(previous_state["current_java_version"] or self.current_java_version)
                previous_bin = previous_state["current_java_bin"]
                self.current_java_version = previous_version
                self.current_java_bin = Path(str(previous_bin)) if previous_bin else None
                self.extra_jvm_flags = list(previous_state["extra_jvm_flags"] or self.extra_jvm_flags)
                self._write_start_script()
                self.operations.append(f"rollback_java_version:{previous_version}")
                result["performed"] = True
        except (FileNotFoundError, OSError, ValueError) as exc:
            result["error"] = f"{type(exc).__name__}:{exc}"
        return result

    def _execute_action_with_safeguards(
        self, idx: int, action: dict, preflight: ActionPreflight, snapshot_tag: str
    ) -> tuple[bool, ActionExecutionResult, RollbackResult | None]:
        action_type = str(action.get("type") or "unknown")
        previous_state = build_previous_action_state(self)
        execution = build_initial_execution_result(idx=idx, action_type=action_type, snapshot_tag=snapshot_tag, preflight=preflight)
        rollback: RollbackResult | None = None

        if action_type in {"remove_mods", "bisect_mods"}:
            self.backup_mods(snapshot_tag)

        try:
            if action_type == "bisect_mods":
                ok, bisect_execution, bisect_rollback = self._run_bisect_mods_action(idx, action, snapshot_tag)
                return ok, cast(ActionExecutionResult, bisect_execution), cast(RollbackResult | None, bisect_rollback)
            if action_type == "remove_mods":
                return execute_remove_mods_action(
                    self,
                    idx=idx,
                    action=action,
                    snapshot_tag=snapshot_tag,
                    previous_state=previous_state,
                    execution=execution,
                )
            elif action_type == "continue_after_restore_mods":
                return execute_continue_after_restore_mods_action(self, snapshot_tag=snapshot_tag, execution=execution)
            elif action_type == "adjust_memory":
                return execute_adjust_memory_action(self, action=action, execution=execution)
            elif action_type == "change_java":
                return execute_change_java_action(self, action=action, execution=execution)
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
        except (FileNotFoundError, OSError, ValueError, DownloadError, ExternalServiceError) as exc:
            execution.update({"status": "failed", "error": f"{type(exc).__name__}:{exc}"})
            rollback = self._rollback_action(action_type, snapshot_tag, previous_state)
            rollback_state = "none"
            if rollback is not None:
                rollback_state = "performed" if rollback.get("performed") else f"failed:{rollback.get('error', 'unknown')}"
            self.operations.append(f"action_failed:{action_type}:{type(exc).__name__}:rollback={rollback_state}")
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
        return collect_process_resource_snapshot(self, proc)

    def _detect_failure_signals(self, text: str) -> list[str]:
        return detect_failure_signals(self, text)

    def detect_current_java_version(self) -> int:
        return detect_current_java_version(self)

    def _detect_log_ready_signal(self, text: str) -> tuple[bool, str]:
        return detect_log_ready_signal(self, text)

    def _detect_command_probe_ready(self, text: str) -> tuple[bool, str]:
        return detect_command_probe_ready(self, text)

    def _snapshot_crash_reports(self, crash_dir: Path) -> tuple[bool, set[str]]:
        return snapshot_crash_reports(self, crash_dir)

    def _read_startup_log_tail(self, log_path: Path, state: dict[str, object], *, lines: int = 300) -> str:
        return read_startup_log_tail(self, log_path, state, lines=lines)

    # 运行与日志
    def start_server(self, timeout: int = 300) -> dict:
        return start_server(self, timeout=timeout)

    def extract_relevant_log(self, log_path: str, crash_dir: str) -> dict:
        return extract_relevant_log(self, log_path, crash_dir)

    def _extract_latest_crash_mod_issue(self, crash_content: str) -> str:
        return extract_latest_crash_mod_issue(self, crash_content)

    def _extract_json_object(self, text: str) -> dict | None:
        return self.ai_service._extract_json_object(text)

    def _safe_ai_result(self, reason: str, confidence: float = 0.1) -> AIResult:
        return self.ai_service._safe_ai_result(reason, confidence)

    def _normalize_text_list(self, value: object, limit: int = 50) -> list[str]:
        return self.ai_service._normalize_text_list(value, limit)

    def _normalize_ai_result(self, data: dict) -> AIResult:
        return self.ai_service._normalize_ai_result(data)

    def _inspect_mod_metadata(self) -> dict[str, object]:
        server_dir = getattr(getattr(self, "workdirs", None), "server", None)
        if not isinstance(server_dir, Path):
            return {"files": [], "mod_id_to_files": {}, "client_only_mods": []}
        return inspect_mod_metadata(server_dir / "mods")

    def _build_dependency_graph(self, mod_metadata: dict[str, object]) -> dict[str, object]:
        return build_dependency_graph(mod_metadata, sorted(getattr(self, "known_deleted_client_mods", set()) or set()))

    def _inspect_crash_report(self, log_info: dict[str, object]) -> dict[str, object]:
        return inspect_crash_report(
            str(log_info.get("crash_content") or ""),
            str(log_info.get("refined_log") or ""),
            str(log_info.get("crash_mod_issue") or ""),
        )

    def _verify_start_command_artifacts(self) -> dict[str, object]:
        server_dir = getattr(getattr(self, "workdirs", None), "server", None)
        if not isinstance(server_dir, Path):
            return {"mode": "unknown", "value": "", "target_exists": False, "issues": ["missing_server_dir"]}
        return verify_start_command_artifacts(
            server_dir,
            str(getattr(self, "start_command_mode", "jar") or "jar"),
            str(getattr(self, "start_command_value", "") or ""),
            server_jar_name=str(getattr(self, "server_jar_name", "server.jar") or "server.jar"),
        )

    def _build_deterministic_diagnostics(self, log_info: dict[str, object]) -> dict[str, object]:
        mod_metadata = self._inspect_mod_metadata()
        return {
            "mod_metadata_summary": mod_metadata,
            "dependency_graph": self._build_dependency_graph(mod_metadata),
            "crash_report_analysis": self._inspect_crash_report(log_info),
            "start_command_check": self._verify_start_command_artifacts(),
        }

    def _resolve_dependency_cleanup_targets(
        self,
        dependency_chains: list[list[str]],
        installed_mods: list[str],
    ) -> tuple[list[str], list[str], list[list[str]]]:
        return resolve_dependency_cleanup_targets(self, dependency_chains, installed_mods)

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

    def _call_openai_compatible_chat(self, prompt: str, response_format: dict[str, object] | None = None) -> str:
        return self.ai_service._call_openai_compatible_chat(prompt, response_format=response_format)

    def _call_ai_provider(self, prompt: str, response_format: dict[str, object] | None = None) -> str:
        return self.ai_service._call_ai_provider(prompt, response_format=response_format)

    def analyze_with_ai(self, context: dict) -> dict:
        return self.ai_service.analyze(context)

    def analyze_success_guard_with_ai(self, context: dict) -> dict:
        return self.ai_service.analyze_success_guard(context)

    def analyze_remove_validation_with_ai(self, context: dict) -> dict:
        return self.ai_service.analyze_remove_validation(context)

    def _consume_remove_validation_followup(self, attempt: int, start_res: dict, log_info: dict) -> bool | None:
        state = dict(getattr(self, "remove_validation_state", {}) or {})
        if not state or not bool(state.get("continue_allowed", False)) or bool(state.get("continued", False)):
            return None

        validation_context = self._build_ai_context(start_res, log_info)
        validation_context["remove_validation_state"] = state
        self._append_attempt_trace(
            attempt,
            "remove_validation_context_prepared",
            "ok",
            context_summary=self._summarize_ai_context(validation_context),
        )
        ai = self.analyze_remove_validation_with_ai(validation_context)
        self._append_attempt_trace(
            attempt,
            "remove_validation_ai_analysis",
            "ok",
            context_summary=self._summarize_ai_context(validation_context),
            ai_result=dict(ai),
            action_plan=[dict(x) for x in ai.get("actions", []) if isinstance(x, dict)],
        )
        self._log(
            "install.ai",
            f"AI 删除验证阶段完成，issue={ai.get('primary_issue')} confidence={ai.get('confidence')}",
        )
        should_stop = self._apply_actions(ai.get("actions", []), attempt=attempt)
        self._ai_debug(
            "remove_validation.loop.decision "
            f"attempt={attempt}, should_stop={should_stop}, stop_reason={self.stop_reason or 'none'}, "
            f"actions={json.dumps(ai.get('actions', []), ensure_ascii=False)}"
        )
        if should_stop:
            self._log("install.stop", f"AI 决策停止，reason={self.stop_reason}", level="WARN")
            return True

        post_state = dict(getattr(self, "remove_validation_state", {}) or {})
        if bool(post_state.get("continued", False)):
            phase2_context = self._build_ai_context(start_res, log_info)
            phase2_context["remove_validation_state"] = post_state
            self._append_attempt_trace(
                attempt,
                "remove_validation_phase2_context_prepared",
                "ok",
                context_summary=self._summarize_ai_context(phase2_context),
            )
            ai = self.analyze_with_ai(phase2_context)
            self._append_attempt_trace(
                attempt,
                "remove_validation_phase2_ai_analysis",
                "ok",
                context_summary=self._summarize_ai_context(phase2_context),
                ai_result=dict(ai),
                action_plan=[dict(x) for x in ai.get("actions", []) if isinstance(x, dict)],
            )
            self._log(
                "install.ai",
                f"AI 删除验证接力后阶段二完成，issue={ai.get('primary_issue')} confidence={ai.get('confidence')}",
            )
            should_stop = self._apply_actions(ai.get("actions", []), attempt=attempt)
            self._ai_debug(
                "remove_validation.phase2.loop.decision "
                f"attempt={attempt}, should_stop={should_stop}, stop_reason={self.stop_reason or 'none'}, "
                f"actions={json.dumps(ai.get('actions', []), ensure_ascii=False)}"
            )
            if should_stop:
                self._log("install.stop", f"AI 决策停止，reason={self.stop_reason}", level="WARN")
                return True
        return False

    # 输出
    def generate_report(self) -> str:
        return generate_report(self)

    def _build_meta_payload(self) -> dict[str, object]:
        return build_meta_payload(self)

    def package_server(self) -> str:
        return package_server(self)

    def _prepare_runtime_environment(self) -> None:
        prepare_runtime_environment(self)

    def _run_attempt_loop(self) -> bool:
        from .attempt_runner import run_attempt_loop

        return run_attempt_loop(self)

    def _run_single_attempt(self, attempt: int) -> AttemptLoopDecision:
        from .attempt_runner import run_single_attempt

        return run_single_attempt(self, attempt)

    def _handle_successful_attempt(self, attempt: int, start_res: dict[str, object]) -> AttemptLoopDecision:
        from .attempt_runner import handle_successful_attempt

        return handle_successful_attempt(self, attempt, start_res)

    def _handle_failed_attempt(self, attempt: int, start_res: dict[str, object]) -> AttemptLoopDecision:
        from .attempt_runner import handle_failed_attempt

        return handle_failed_attempt(self, attempt, start_res)

    def _finalize_run_result(self, success: bool) -> dict[str, object]:
        from .attempt_runner import finalize_run_result

        return finalize_run_result(self, success)

    # 主流程
    def run(self) -> dict:
        from .attempt_runner import run

        return run(self)

    def _resolve_pack_and_manifest(self) -> None:
        resolve_pack_and_manifest(self)

    def _prepare_server_files(self) -> None:
        prepare_server_files(self)

    def _extract_full_pack_version_payload_if_needed(self) -> None:
        extract_full_pack_version_payload_if_needed(self)

    def _download_curseforge_pack(self, project_id: str, file_id: str | None = None) -> Path:
        return download_curseforge_pack(self, project_id, file_id=file_id)

    def _extract_curseforge_type_hints(self, file_data: dict) -> list[str]:
        return extract_curseforge_type_hints(self, file_data)

    def _extract_modrinth_type_hints(self, item: dict) -> list[str]:
        return extract_modrinth_type_hints(self, item)

    def _classify_manifest_file_type(
        self,
        *,
        platform: str,
        file_name: str,
        rel_path: str | None,
        platform_hints: list[str],
    ) -> tuple[str, bool, str]:
        return classify_manifest_file_type(
            self,
            platform=platform,
            file_name=file_name,
            rel_path=rel_path,
            platform_hints=platform_hints,
        )

    def _manifest_target_path(self, file_type: str, file_name: str, rel_path: str | None = None) -> Path:
        return manifest_target_path(self, file_type, file_name, rel_path=rel_path)

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

        for raw_mod in files:
            mod = _normalize_curseforge_manifest_entry(raw_mod)
            if not mod:
                continue
            project_id = mod["projectID"]
            file_id = mod["fileID"]
            if project_id is None or file_id is None:
                continue
            try:
                pair = (int(cast(Any, project_id)), int(cast(Any, file_id)))
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

        pair_to_data: dict[tuple[int, int], CurseForgeFilePayload] = {}
        unresolved_pairs: list[tuple[int, int]] = []

        batched: list[list[tuple[int, int]]] = [pairs[i : i + batch_size] for i in range(0, len(pairs), batch_size)]

        def _run_cf_batch(batch_pairs: list[tuple[int, int]]) -> CurseForgeBatchResolution:
            return self._cf_fetch_files_batch(batch_pairs, retry=batch_retry)

        if enable_parallel and len(batched) > 1:
            workers = min(resolve_workers, len(batched))
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="mcasb-cf-batch") as pool:
                fut_map: dict[Future[CurseForgeBatchResolution], list[tuple[int, int]]] = {
                    pool.submit(_run_cf_batch, batch): batch for batch in batched
                }
                for batch_fut in as_completed(fut_map):
                    resolution = batch_fut.result()
                    pair_to_data.update(resolution.resolved)
                    unresolved_pairs.extend(resolution.unresolved)
        else:
            for batch in batched:
                resolution = _run_cf_batch(batch)
                pair_to_data.update(resolution.resolved)
                unresolved_pairs.extend(resolution.unresolved)

        batched_hit = len(pair_to_data)

        if unresolved_pairs:

            def _fetch_single(pair: tuple[int, int]) -> CurseForgeManifestPairResolution:
                project_id_val, file_id_val = pair
                try:
                    response = self._cf_get_json(f"/v1/mods/{project_id_val}/files/{file_id_val}")
                    data = _normalize_curseforge_file_payload(response.get("data"))
                    return CurseForgeManifestPairResolution(pair=pair, data=data)
                except Exception as exc:
                    self._record_manifest_failure_event(
                        platform="curseforge",
                        subject="manifest_file_fallback",
                        operation="curseforge_manifest_fallback_failed",
                        failure=_build_remote_failure_detail("fallback_fetch", exc),
                        context={"project_id": project_id_val, "file_id": file_id_val},
                    )
                    return CurseForgeManifestPairResolution(pair=pair, data=None)

            if enable_parallel and len(unresolved_pairs) > 1:
                workers = min(resolve_workers, len(unresolved_pairs))
                with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="mcasb-cf-fallback") as pool:
                    fallback_fut_map: dict[Future[CurseForgeManifestPairResolution], tuple[int, int]] = {
                        pool.submit(_fetch_single, pair): pair for pair in unresolved_pairs
                    }
                    for fallback_fut in as_completed(fallback_fut_map):
                        resolved_pair = fallback_fut.result()
                        if resolved_pair.data is not None:
                            pair_to_data[resolved_pair.pair] = resolved_pair.data
                            fallback_hit += 1
                        else:
                            resolve_failed += 1
            else:
                for pair in unresolved_pairs:
                    resolved_pair = _fetch_single(pair)
                    if resolved_pair.data is not None:
                        pair_to_data[pair] = resolved_pair.data
                        fallback_hit += 1
                    else:
                        resolve_failed += 1

        for project_id, file_id in pairs:
            data = pair_to_data.get((project_id, file_id))
            if data is None:
                self.operations.append(f"curseforge_mod_meta_missing:{project_id}:{file_id}")
                self._record_manifest_failure_event(
                    platform="curseforge",
                    subject="manifest_mod",
                    operation="curseforge_mod_meta_missing",
                    failure=RemoteFailureDetail(stage="resolve", category="fallback_miss", message="manifest metadata unresolved"),
                    context={"project_id": project_id, "file_id": file_id},
                )
                continue

            file_name = str(data.get("fileName") or f"cf-{project_id}-{file_id}.jar")
            file_type, can_download, classify_reason = self._classify_manifest_file_type(
                platform="curseforge",
                file_name=file_name,
                rel_path=None,
                platform_hints=self._extract_curseforge_type_hints(cast(dict[str, Any], data)),
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
            url = data.get("downloadUrl") or self._build_curseforge_edge_download_url(cast(dict[str, Any], data))
            if not url:
                self.operations.append(f"curseforge_mod_no_url:{project_id}:{file_id}")
                self._record_manifest_failure_event(
                    platform="curseforge",
                    subject="manifest_mod",
                    operation="curseforge_mod_no_url",
                    failure=RemoteFailureDetail(stage="resolve_url", category="no_url", message="download URL missing"),
                    context={"project_id": project_id, "file_id": file_id, "file_name": file_name},
                )
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
                self._record_manifest_failure_event(
                    platform="curseforge",
                    subject="manifest_download",
                    operation="curseforge_manifest_fill_failed",
                    failure=_build_download_failure_detail(item),
                    context={"target": failed_task.out.name},
                )

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
        return download_modrinth_pack(self, project_or_slug, version_id=version_id)

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
                self._record_manifest_failure_event(
                    platform="modrinth",
                    subject="manifest_file",
                    operation="modrinth_manifest_fill_no_url",
                    failure=RemoteFailureDetail(stage="resolve_url", category="no_url", message="downloads missing"),
                    context={"path": normalized_rel, "project_id": project_id, "file_id": file_id},
                )
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
                    remain.append(
                        DownloadFailure(
                            task=retried,
                            error=f"{type(e).__name__}:{e}",
                            category="fallback_miss",
                            stage=retried.stage,
                            exc_type=type(e).__name__,
                            message=str(e),
                        )
                    )

            for item in remain:
                failed += 1
                safe_unlink(item.task.out)
                self.operations.append(f"modrinth_manifest_fill_failed:{item.task.out}:{item.error}")
                self._record_manifest_failure_event(
                    platform="modrinth",
                    subject="manifest_download",
                    operation="modrinth_manifest_fill_failed",
                    failure=_build_download_failure_detail(item),
                    context={"target": str(item.task.out)},
                )

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

        try:
            return http_get_json(
                f"{base}{path}",
                headers=headers,
                params=params,
                timeout=60,
                proxies=self._request_proxies(),
                trust_env=self._request_trust_env(),
            )
        except (ExternalRequestError, ExternalResponseError, ExternalDataError) as exc:
            raise ExternalServiceError(f"Modrinth API 请求失败: {path}") from exc

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
        try:
            return http_get_json(
                f"https://api.curseforge.com{path}",
                headers=headers,
                params=params,
                timeout=60,
                proxies=self._request_proxies(),
                trust_env=self._request_trust_env(),
            )
        except (ExternalRequestError, ExternalResponseError, ExternalDataError) as exc:
            raise ExternalServiceError(f"CurseForge API 请求失败: {path}") from exc

    def _cf_post_json(self, path: str, payload: dict) -> dict:
        api_key = (self.config.curseforge_api_key or "").strip()
        if not api_key:
            raise ValueError("CurseForge 需要配置 curseforge_api_key 才能下载整合包或补全模组")

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "x-api-key": api_key,
        }
        try:
            with self._create_request_session() as session:
                resp = session.post(
                    f"https://api.curseforge.com{path}",
                    headers=headers,
                    json=payload,
                    timeout=60,
                )
        except requests.RequestException as exc:
            raise ExternalRequestError(f"CurseForge POST 请求失败: {path}") from exc
        try:
            resp.raise_for_status()
        except requests.HTTPError as exc:
            raise ExternalResponseError(f"CurseForge POST 返回非成功状态: {path} (HTTP {resp.status_code})") from exc
        try:
            return resp.json()
        except ValueError as exc:
            raise ExternalDataError(f"CurseForge POST 响应不是合法 JSON: {path}") from exc

    def _cf_fetch_files_batch(
        self,
        pairs: list[tuple[int, int]],
        *,
        retry: int = 0,
    ) -> CurseForgeBatchResolution:
        if not pairs:
            return CurseForgeBatchResolution(resolved={}, unresolved=[])

        file_ids = sorted({fid for _, fid in pairs})
        attempts = max(1, retry + 1)
        last_error: Exception | None = None

        for attempt in range(1, attempts + 1):
            try:
                data_arr = self._cf_post_json("/v1/mods/files", payload={"fileIds": file_ids}).get("data") or []
                data_map: dict[tuple[int, int], CurseForgeFilePayload] = {}
                for item in data_arr:
                    normalized_item = _normalize_curseforge_file_payload(item)
                    if normalized_item is None:
                        continue
                    mod_id = normalized_item.get("modId")
                    fid = normalized_item.get("id")
                    try:
                        key = (int(cast(Any, mod_id)), int(cast(Any, fid)))
                    except (TypeError, ValueError):
                        continue
                    data_map[key] = normalized_item

                resolved: dict[tuple[int, int], CurseForgeFilePayload] = {}
                unresolved: list[tuple[int, int]] = []
                for pair in pairs:
                    found = data_map.get(pair)
                    if found is not None:
                        resolved[pair] = found
                    else:
                        unresolved.append(pair)
                return CurseForgeBatchResolution(resolved=resolved, unresolved=unresolved)
            except Exception as e:
                last_error = e

        self.operations.append(
            f"curseforge_manifest_batch_failed:file_ids={len(file_ids)},error={type(last_error).__name__ if last_error else 'unknown'}"
        )
        if last_error is not None:
            self._record_manifest_failure_event(
                platform="curseforge",
                subject="manifest_file_batch",
                operation="curseforge_manifest_batch_failed",
                failure=_build_remote_failure_detail("batch_fetch", last_error),
                context={"file_ids": len(file_ids), "attempts": attempts},
            )
        return CurseForgeBatchResolution(resolved={}, unresolved=list(pairs))

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
        return copy_client_files_with_blacklist(self, blacklist)

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

        if self._recover_start_command_from_existing_server_artifacts(
            loader=loader,
            mc_version=mc_version,
            loader_version=loader_version,
            reason=f"install_server_core:recover_existing:{loader}",
        ):
            return

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
        return {}

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
                self._log(
                    stage,
                    f"{op_prefix} 请求 URL={url} profile={profile_name}",
                    level="DEBUG",
                )
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
            except (ExternalRequestError, ExternalResponseError, ExternalDataError) as e:
                failure = _build_remote_failure_detail("fetch_json", e)
                error_suffix = f" - {failure.message}" if failure.message else ""
                self.operations.append(
                    f"{op_prefix}:{failure.category}_error:{version}:profile={profile_name}:{failure.exc_type or 'unknown'}"
                )
                self._log(
                    stage,
                    f"{op_prefix} 请求异常 URL={url} profile={profile_name}: {failure.exc_type or 'unknown'}{error_suffix}",
                    level="DEBUG",
                )
                self._log(
                    stage,
                    f"{op_prefix} 请求异常 profile={profile_name}: {failure.exc_type or 'unknown'}{error_suffix}",
                    level="WARN",
                )

        return None, ""

    def _record_remote_failure(
        self,
        op_prefix: str,
        version: int | str,
        failure: RemoteFailureDetail,
        *,
        stage: str,
        profile: str = "",
    ) -> None:
        suffix = f":profile={profile}" if profile else ""
        self.operations.append(f"{op_prefix}_{failure.operation_token()}:{version}{suffix}")
        self._log(stage, failure.log_message(op_prefix), level="WARN")

    def _append_remote_failure_event(
        self,
        *,
        platform: str,
        subject: str,
        failure: RemoteFailureDetail,
        operation: str,
        context: Mapping[str, object] | None = None,
    ) -> None:
        events = getattr(self, "remote_failure_events", None)
        if not isinstance(events, list):
            events = []
            self.remote_failure_events = events
        payload: dict[str, object] = {
            "platform": platform,
            "subject": subject,
            "operation": operation,
            **failure.to_event_payload(),
        }
        if context:
            payload["context"] = {str(key): value for key, value in context.items()}
        events.append(payload)

    def _record_manifest_failure_event(
        self,
        *,
        platform: str,
        subject: str,
        operation: str,
        failure: RemoteFailureDetail,
        context: Mapping[str, object] | None = None,
    ) -> None:
        self._append_remote_failure_event(
            platform=platform,
            subject=subject,
            operation=operation,
            failure=failure,
            context=context,
        )

    def _download_graalvm_from_oracle(self, version: int) -> bool:
        if version not in (21, 25):
            return False

        stage = "install.download.oracle_graalvm"
        manual_url = self._oracle_graalvm_manual_page_url()

        try:
            os_name, arch_name, ext = oracle_platform_triplet()
        except ValueError as e:
            self.operations.append(f"oracle_graalvm_platform_unsupported:{version}:{type(e).__name__}")
            return False

        group_title = "Oracle GraalVM"
        group_subtitle = "Oracle GraalVM for JDK 21" if version == 21 else "Oracle GraalVM 25"

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

        core_package = (((release_data or {}).get("Packages") or {}).get("Core") or {})
        files = (core_package.get("Files") or {}) if isinstance(core_package, dict) else {}
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
            self._log(stage, f"oracle_graalvm_download 请求 URL={file_url}", level="DEBUG")
            self._download_file(
                file_url,
                archive_path,
                stage=stage,
                headers=headers,
                session_factory=None,
            )
            if expected_hashes and not verify_hashes(archive_path, expected_hashes):
                safe_unlink(archive_path)
                self.operations.append(f"oracle_graalvm_hash_mismatch:{version}")
                return False

            if java_home.exists():
                shutil.rmtree(java_home)
            java_home.mkdir(parents=True, exist_ok=True)

            extract_archive(archive_path, java_home)
            safe_unlink(archive_path)
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
        except (DownloadError, OSError, zipfile.BadZipFile, tarfile.TarError, ValueError) as e:
            failure = _build_remote_failure_detail("download_or_extract", e)
            self._record_remote_failure("oracle_graalvm", version, failure, stage=stage)
            self._log(stage, f"Oracle GraalVM 下载失败，手动页面: {manual_url}", level="WARN")
            return False

    def _download_graalvm17_from_github(self) -> bool:
        api_url = "https://api.github.com/repos/brokestar233/grallvm17-bin/releases"
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.config.github_api_key:
            headers["Authorization"] = f"Bearer {self.config.github_api_key}"

        try:
            releases = http_get_json(api_url, headers=headers, timeout=60)
        except (ExternalRequestError, ExternalResponseError, ExternalDataError) as e:
            failure = _build_remote_failure_detail("release_fetch", e)
            self._record_remote_failure("graalvm17", 17, failure, stage="install.download.github_graalvm")
            return False

        arch_aliases = self._current_arch_aliases()
        is_windows = os.name == "nt"
        asset = None
        if releases:
            asset = self._pick_asset_by_arch(
                releases[0].get("assets") or [],
                arch_aliases,
                is_windows=is_windows,
            )
        if not asset:
            for rel in releases if isinstance(releases, list) else []:
                asset = self._pick_asset_by_arch(
                    rel.get("assets") or [],
                    arch_aliases,
                    is_windows=is_windows,
                )
                if asset:
                    break
        if not asset:
            self.operations.append("graalvm17_asset_not_found")
            return False

        url = str(asset.get("browser_download_url") or "").strip()
        name = str(asset.get("name") or "").strip()
        if not url:
            self.operations.append(f"graalvm17_asset_no_url:{name}")
            return False

        archive_path = self.workdirs.java_bins / (name or "graalvm17")
        try:
            self._download_file(url, archive_path)
            java_home = self.workdirs.java_bins / "jdk-17"
            if java_home.exists():
                shutil.rmtree(java_home)
            java_home.mkdir(parents=True, exist_ok=True)

            bin_name = "java.exe" if os.name == "nt" else "java"
            extract_archive(archive_path, java_home)
            safe_unlink(archive_path)
            normalized, changed = normalize_java_home_layout(java_home)
            if changed:
                self.operations.append("graalvm17_java_home_normalized")

            java_bin = normalized / "bin" / bin_name
            if not java_bin.exists():
                self.operations.append(f"graalvm17_java_bin_missing:{name}")
                return False

            self.current_java_bin = java_bin
            self.current_java_version = 17
            if os.name != "nt":
                java_bin.chmod(0o755)
            self.java_params_mode_by_version[17] = "graalvm"
            self.operations.append(f"graalvm17_selected_asset:{name}")
            return True
        except (DownloadError, OSError, zipfile.BadZipFile, tarfile.TarError, ValueError) as e:
            failure = _build_remote_failure_detail("download_or_extract", e)
            self._record_remote_failure("graalvm17", 17, failure, stage="install.download.github_graalvm")
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

        # Java 17：优先 GitHub Releases 的 graalvm17，失败回退 Adoptium（并降级参数为 common_only）
        if version == 17:
            if self._download_graalvm17_from_github():
                return self._java_bin_path(version).exists()
            if self._download_temurin_from_adoptium(version):
                self.java_params_mode_by_version[version] = "common_only"
                self.operations.append(f"java_params_mode_fallback_common:{version}")
                return self._java_bin_path(version).exists()
            return False

        # Java 21/25：优先 Oracle GraalVM，失败回退 Adoptium（并降级参数为 common_only）
        if version in (21, 25):
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
            safe_unlink(archive_path)
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
        except (DownloadError, OSError, zipfile.BadZipFile, tarfile.TarError, ValueError) as e:
            failure = _build_remote_failure_detail("download_or_extract", e)
            self._record_remote_failure("temurin", version, failure, stage="install.download.temurin")
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
        except (ExternalRequestError, ExternalResponseError, ExternalDataError) as e:
            failure = _build_remote_failure_detail("release_fetch", e)
            self._record_remote_failure("dragonwell", repo, failure, stage="install.download.dragonwell")
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
            safe_unlink(archive_path)
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
        except (DownloadError, OSError, zipfile.BadZipFile, tarfile.TarError, ValueError) as e:
            failure = _build_remote_failure_detail("download_or_extract", e)
            self._record_remote_failure("dragonwell", repo, failure, stage="install.download.dragonwell")
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
            except (DownloadError, OSError, zipfile.BadZipFile, tarfile.TarError, ValueError) as e:
                failed += 1
                failure = _build_remote_failure_detail("external_package_import", e)
                self.operations.append(
                    f"graalvm_external_package_import_failed:{version}:{item}:{failure.category}:{failure.exc_type or 'unknown'}"
                )

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

    def _pick_installed_server_jar(
        self,
        loader: str | None = None,
        mc_version: str | None = None,
        loader_version: str | None = None,
    ) -> str | None:
        candidates = [path for path in self.workdirs.server.glob("*.jar") if path.is_file()]
        if not candidates:
            return None

        normalized_loader = str(loader or getattr(getattr(self, "manifest", None), "loader", "") or "").strip().lower()
        normalized_mc_version = str(mc_version or getattr(getattr(self, "manifest", None), "mc_version", "") or "").strip().lower()
        normalized_loader_version = str(
            loader_version or getattr(getattr(self, "manifest", None), "loader_version", "") or ""
        ).strip().lower()

        def score(path: Path) -> tuple[int, int, int, str]:
            name = path.name
            lower = name.lower()
            value = 0

            if lower.endswith("-installer.jar") or lower == "forge-installer.jar" or lower == "neoforge-installer.jar":
                value -= 100

            if normalized_loader == "forge":
                if lower.startswith("forge-"):
                    value += 40
                if lower.startswith("minecraft_server"):
                    value -= 24
                if lower.startswith("neoforge-"):
                    value -= 12
                if "fabric" in lower or "quilt" in lower:
                    value -= 12
            elif normalized_loader == "neoforge":
                if lower.startswith("neoforge-"):
                    value += 40
                if lower.startswith("forge-"):
                    value += 8
                if lower.startswith("minecraft_server"):
                    value -= 24
                if "fabric" in lower or "quilt" in lower:
                    value -= 12
            elif normalized_loader == "fabric":
                if "fabric" in lower:
                    value += 40
                if lower.startswith("minecraft_server"):
                    value -= 16
            elif normalized_loader == "quilt":
                if "quilt" in lower:
                    value += 40
                if lower.startswith("minecraft_server"):
                    value -= 16
            else:
                if lower.startswith(("forge-", "neoforge-")) or "fabric" in lower or "quilt" in lower:
                    value += 16

            if normalized_loader_version:
                if normalized_loader_version in lower:
                    value += 20
                else:
                    compact_loader_version = normalized_loader_version.split("-", 1)[-1]
                    if compact_loader_version and compact_loader_version in lower:
                        value += 12

            if normalized_mc_version and normalized_mc_version in lower:
                value += 8

            if lower == "server.jar":
                value -= 10
            elif "server" in lower:
                value += 2

            return (value, len(name), -len(lower), lower)

        preferred = sorted(candidates, key=score, reverse=True)[0]
        self.operations.append(f"start_command_pick_server_jar:{preferred.name}:{normalized_loader or 'unknown'}")
        return preferred.name

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

    def _recover_start_command_from_existing_server_artifacts(
        self,
        loader: str | None = None,
        mc_version: str | None = None,
        loader_version: str | None = None,
        reason: str = "existing_server_artifacts",
    ) -> bool:
        if self._parse_start_command_from_run_scripts():
            self.operations.append(f"start_command_recovered:run_script:{reason}")
            return True
        if self._apply_modern_loader_start_mode():
            self.operations.append(f"start_command_recovered:argsfile:{reason}")
            return True

        picked = self._pick_installed_server_jar(loader=loader, mc_version=mc_version, loader_version=loader_version)
        if picked:
            self.server_jar_name = picked
            self._set_start_command("jar", self.server_jar_name, reason)
            self.operations.append(f"start_command_recovered:jar:{picked}:{reason}")
            return True
        return False

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
                'if not defined JAVA_BIN if exist "%SCRIPT_DIR%..\\..\\.mcasb_cache\\java_bins\\bin\\java.exe" '
                'set "JAVA_BIN=%SCRIPT_DIR%..\\..\\.mcasb_cache\\java_bins\\bin\\java.exe"\n'
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
                "if not defined JAVA_BIN (\n"
                '  for /d %%D in ("%SCRIPT_DIR%..\\..\\.mcasb_cache\\java_bins\\jdk-*") do (\n'
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
                'elif [ -x "$SCRIPT_DIR/../../.mcasb_cache/java_bins/bin/java" ]; then\n'
                '  JAVA_BIN="$SCRIPT_DIR/../../.mcasb_cache/java_bins/bin/java"\n'
                "else\n"
                '  for candidate in "$SCRIPT_DIR"/java_bins/jdk-*/bin/java '
                '"$SCRIPT_DIR"/../java_bins/jdk-*/bin/java '
                '"$SCRIPT_DIR"/../../.mcasb_cache/java_bins/jdk-*/bin/java; do\n'
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
                    execution=[dict(execution)],
                    rollback=[dict(rollback)] if rollback else [],
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
        session_factory: Callable[[], requests.Session] | None = None,
    ) -> Path:
        task = DownloadTask(out=out, urls=[url], stage=stage, headers=headers, session_factory=session_factory)
        done, failed = self.downloader.download_files([task])
        if failed:
            raise DownloadError(f"下载失败: {url} ({failed[0].error})")
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
                self.server_jar_name = (
                    self._pick_installed_server_jar(loader=loader, mc_version=mc_version, loader_version=loader_version)
                    or "server.jar"
                )
                self._set_start_command("jar", self.server_jar_name, f"forge_family_fallback:{loader}")
                return

            # 存在 run 脚本但未能解析，回退 jar 推断
            self.server_jar_name = (
                self._pick_installed_server_jar(loader=loader, mc_version=mc_version, loader_version=loader_version)
                or "server.jar"
            )
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
            self.server_jar_name = (
                self._pick_installed_server_jar(loader=loader, mc_version=mc_version, loader_version=loader_version)
                or "server.jar"
            )
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
