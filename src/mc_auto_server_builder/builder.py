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
from dataclasses import asdict, fields, is_dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

import psutil
import requests

from .config import AppConfig
from .defaults import (
    SUPPORTED_JAVA_VERSIONS,
    get_common_jvm_params,
    get_jvm_params_for_java_version,
)
from .input_parser import parse_manifest_from_zip, parse_pack_input
from .models import AIAction, AIResult, PackInput, PackManifest, StartResult, WorkDirs
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
            dict.fromkeys([
                *self._resolve_java_params_for_version(self.current_java_version),
                *self.config.extra_jvm_flags,
            ])
        )
        self.operations: list[str] = []
        self.removed_mods: list[str] = []
        self.known_deleted_client_mods: set[str] = set()
        self.deleted_mod_evidence: dict[str, list[str]] = {}
        self.last_ai_payload: dict[str, object] = {}
        self.last_ai_result: AIResult | None = None
        self.attempts_used: int = 0
        self.run_success: bool = False
        self.stop_reason: str = ""
        self.server_jar_name: str = "server.jar"
        self.start_command_mode: str = "jar"
        self.start_command_value: str = self.server_jar_name
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
        return bool(self.config.ai.enabled and self.config.ai.debug)

    def _ai_debug(self, message: str) -> None:
        if self._ai_debug_enabled():
            noisy_prefixes = (
                "response.parse.stage=",
                "response.raw",
                "response.parse failed",
                "openai.retry",
                "ollama.retry",
                "openai.request",
                "openai.response",
                "normalize.actions[",
                "normalize.confidence.invalid",
            )
            if message.startswith(noisy_prefixes):
                return
            self._log("install.ai.debug", message, level="DEBUG")

    def _truncate_debug_text(self, value: object, limit: int = 1000) -> str:
        text = str(value)
        if len(text) <= limit:
            return text
        return f"{text[:limit]}...<truncated:{len(text)-limit}>"

    def _serialize_ai_action(self, action: object) -> dict:
        if isinstance(action, dict):
            return dict(action)

        if is_dataclass(action):
            return asdict(action)

        if hasattr(action, "model_dump") and callable(getattr(action, "model_dump")):
            dumped = action.model_dump()  # type: ignore[attr-defined]
            return dumped if isinstance(dumped, dict) else {"type": str(action)}

        if hasattr(action, "dict") and callable(getattr(action, "dict")):
            dumped = action.dict()  # type: ignore[attr-defined]
            return dumped if isinstance(dumped, dict) else {"type": str(action)}

        # 兼容 slots 对象：按显式字段映射，避免依赖 __dict__
        if isinstance(action, AIAction):
            return {f.name: getattr(action, f.name) for f in fields(AIAction)}

        mapped: dict[str, object] = {}
        for key in ("type", "targets", "xmx", "xms", "version", "reason", "final_reason"):
            if hasattr(action, key):
                mapped[key] = getattr(action, key)
        if mapped:
            return mapped

        return {"type": str(action)}

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
                self.removed_mods.append(n)
                self.operations.append(f"remove_mod_by_name:{n}")
                self._log("install.remove_mod", f"删除mod:{n} 原因:{reason}")
                self._record_deleted_client_mod(n, source=source, reason=reason or "explicit_name")

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
            dict.fromkeys([
                *self._resolve_java_params_for_version(version),
                *self.config.extra_jvm_flags,
            ])
        )
        self._write_start_script()
        self.operations.append(f"switch_java_version:{version}")

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
        lower = (text or "").lower()
        if "unknown command" in lower or "unknown or incomplete command" in lower:
            return True, "cmd_probe_unknown_command"
        if "available commands" in lower:
            return True, "cmd_probe_available_commands"
        if "for help, type" in lower and "help" in lower:
            return True, "cmd_probe_help_hint"
        if "there are" in lower and "players online" in lower:
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
        probe_commands = ["help", "list"]
        probe_index = 0

        done = False
        cmd_probe_ok = False
        port_open = False
        success_source = ""
        readiness_evidence: list[str] = []

        while True:
            now = time.monotonic()
            if now >= hard_deadline:
                readiness_evidence.append("hard_timeout_reached")
                break

            log_tail = read_tail_text(latest_log, lines=300)
            out_tail = "\n".join(stdout_lines[-120:])
            err_tail = "\n".join(stderr_lines[-120:])
            merged_tail = "\n".join([log_tail, out_tail, err_tail])

            if not done:
                done_detected, done_source = self._detect_log_ready_signal(merged_tail)
                if done_detected:
                    done = True
                    success_source = done_source
                    readiness_evidence.append(done_source)

            if probe_enabled and not cmd_probe_ok and now >= soft_deadline and now >= next_probe_at and proc.poll() is None:
                command = probe_commands[probe_index % len(probe_commands)]
                probe_index += 1
                try:
                    if proc.stdin:
                        proc.stdin.write(f"{command}\n")
                        proc.stdin.flush()
                        readiness_evidence.append(f"probe_sent:{command}")
                except Exception as e:
                    readiness_evidence.append(f"probe_send_failed:{type(e).__name__}")
                next_probe_at = now + probe_retry

            if not cmd_probe_ok:
                probe_detected, probe_source = self._detect_command_probe_ready(merged_tail)
                if probe_detected:
                    cmd_probe_ok = True
                    success_source = probe_source
                    readiness_evidence.append(probe_source)

            if not port_open:
                try:
                    port_open = is_local_tcp_port_open(port=int(self.config.server_port), host="127.0.0.1", timeout=0.6)
                except Exception:
                    port_open = False
                if port_open:
                    readiness_evidence.append("port_open")
                    if not success_source and proc.poll() is None:
                        success_source = "port_open_alive"

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

        result = StartResult(
            success=success,
            done_detected=done,
            command_probe_detected=cmd_probe_ok,
            port_open_detected=port_open,
            process_alive=process_alive,
            success_source=success_source or "none",
            readiness_evidence=readiness_evidence[-12:],
            exit_code=exit_code,
            log_path=latest_log,
            crash_dir=self.workdirs.server / "crash-reports",
            stdout_tail=stdout_tail,
            stderr_tail=stderr_tail,
        )
        self.operations.append(
            "start_server:"
            f"success={success},source={result.success_source},"
            f"done={done},cmd_probe={cmd_probe_ok},port={port_open},exit={exit_code},alive={process_alive}"
        )
        return asdict(result)

    def extract_relevant_log(self, log_path: str, crash_dir: str) -> dict:
        crash_path = Path(crash_dir)
        key_exception = ""
        suspected_mods: list[str] = []
        has_crash = False
        crash_content = ""
        oom_detected = False
        jvm_exit_code: int | None = None

        if crash_path.exists():
            crashes = sorted(crash_path.glob("crash-*.txt"), key=lambda p: p.stat().st_mtime)
            if crashes:
                has_crash = True
                crash_content = crashes[-1].read_text(encoding="utf-8", errors="ignore")
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
            "refined_log": refined,
            "key_exception": key_exception,
            "suspected_mods": sorted(set(suspected_mods))[:20],
            "oom_detected": oom_detected,
            "jvm_exit_code": jvm_exit_code,
        }

    def _extract_json_object(self, text: str) -> dict | None:
        payload = (text or "").strip()
        if not payload:
            return None

        try:
            data = json.loads(payload)
            if isinstance(data, dict):
                self._ai_debug("response.parse.stage=full_json status=ok")
                return data
        except json.JSONDecodeError:
            self._ai_debug("response.parse.stage=full_json status=miss")

        fence = re.search(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", payload, flags=re.IGNORECASE)
        if fence:
            block = fence.group(1)
            try:
                data = json.loads(block)
                if isinstance(data, dict):
                    self._ai_debug("response.parse.stage=fenced_json status=ok")
                    return data
            except json.JSONDecodeError:
                self._ai_debug("response.parse.stage=fenced_json status=miss")

        # 回退：扫描文本中的第一个合法 JSON 对象（兼容 thinking + JSON 混杂场景）
        decoder = json.JSONDecoder()
        search_pos = 0
        while True:
            start = payload.find("{", search_pos)
            if start == -1:
                break
            try:
                obj, end = decoder.raw_decode(payload, start)
                if isinstance(obj, dict):
                    self._ai_debug(f"response.parse.stage=raw_decode status=ok start={start} end={end}")
                    return obj
                self._ai_debug(
                    f"response.parse.stage=raw_decode status=skip_non_dict start={start} type={type(obj).__name__}"
                )
                search_pos = max(start + 1, end)
            except json.JSONDecodeError:
                search_pos = start + 1

        start = payload.find("{")
        end = payload.rfind("}")
        if start != -1 and end != -1 and end > start:
            snippet = payload[start : end + 1]
            try:
                data = json.loads(snippet)
                if isinstance(data, dict):
                    self._ai_debug("response.parse.stage=span_snippet status=ok")
                    return data
            except json.JSONDecodeError:
                self._ai_debug("response.parse.stage=span_snippet status=miss")
                return None
        return None

    def _safe_ai_result(self, reason: str, confidence: float = 0.1) -> AIResult:
        return AIResult(
            primary_issue="other",
            confidence=max(0.0, min(1.0, confidence)),
            reason=reason,
            actions=[],
            thought_chain=[],
            input_summary="",
            hit_deleted_mods=[],
            dependency_chains=[],
            deletion_rationale=[],
            conflicts_or_exceptions=[],
        )

    def _normalize_ai_result(self, data: dict) -> AIResult:
        allowed_issue = {
            "client_mod",
            "memory_allocation",
            "memory_oom",
            "java_version_mismatch",
            "mod_conflict",
            "missing_dependency",
            "config_error",
            "other",
        }
        allowed_action = {"remove_mods", "adjust_memory", "change_java", "stop_and_report"}

        final_output = data.get("final_output")
        final_output = final_output if isinstance(final_output, dict) else {}

        def _pick(key: str, default: object) -> object:
            if key in data:
                return data.get(key, default)
            return final_output.get(key, default)

        issue = str(_pick("primary_issue", "other") or "other").strip()
        if issue not in allowed_issue:
            self._ai_debug(f"normalize.primary_issue.invalid value={issue!r}, fallback='other'")
            issue = "other"

        confidence_raw = _pick("confidence", 0.0)
        try:
            confidence = float(confidence_raw)
        except (TypeError, ValueError):
            self._ai_debug(f"normalize.confidence.invalid value={confidence_raw!r}, fallback=0.0")
            confidence = 0.0
        confidence = max(0.0, min(1.0, confidence))

        reason = str(_pick("reason", "") or "").strip() or "AI 返回了空原因"

        raw_thought_chain = _pick("thought_chain", [])
        thought_chain = [
            str(x).strip()
            for x in (raw_thought_chain if isinstance(raw_thought_chain, list) else [])
            if str(x).strip()
        ][:8]

        input_summary = str(_pick("input_summary", "") or "").strip()

        raw_hit_deleted_mods = _pick("hit_deleted_mods", [])
        hit_deleted_mods = [
            str(x).strip()
            for x in (raw_hit_deleted_mods if isinstance(raw_hit_deleted_mods, list) else [])
            if str(x).strip()
        ][:50]

        raw_dependency_chains = _pick("dependency_chains", [])
        dependency_chains: list[list[str]] = []
        if isinstance(raw_dependency_chains, list):
            for item in raw_dependency_chains[:50]:
                if isinstance(item, list):
                    chain = [str(x).strip() for x in item if str(x).strip()]
                elif isinstance(item, str):
                    chain = [x.strip() for x in re.split(r"\s*(?:->|=>|＞|→)\s*", item) if x.strip()]
                else:
                    chain = []
                if len(chain) >= 2:
                    dependency_chains.append(chain)

        raw_deletion_rationale = _pick("deletion_rationale", [])
        deletion_rationale = [
            str(x).strip()
            for x in (raw_deletion_rationale if isinstance(raw_deletion_rationale, list) else [])
            if str(x).strip()
        ][:50]

        raw_conflicts = _pick("conflicts_or_exceptions", [])
        conflicts_or_exceptions = [
            str(x).strip()
            for x in (raw_conflicts if isinstance(raw_conflicts, list) else [])
            if str(x).strip()
        ][:50]

        action_models: list[AIAction] = []
        raw_actions = _pick("actions", []) or []
        if not isinstance(raw_actions, list):
            self._ai_debug(f"normalize.actions.invalid_type type={type(raw_actions).__name__}, fallback=[]")
            raw_actions = []
        for idx, item in enumerate(raw_actions[:2], start=1):
            if not isinstance(item, dict):
                self._ai_debug(f"normalize.actions[{idx}].drop reason=not_dict type={type(item).__name__}")
                continue
            action_type = str(item.get("type", "") or "").strip()
            if action_type not in allowed_action:
                self._ai_debug(f"normalize.actions[{idx}].drop reason=unknown_type type={action_type!r}")
                continue
            try:
                action_models.append(AIAction(**item))
                self._ai_debug(f"normalize.actions[{idx}].accept type={action_type!r}")
            except TypeError:
                self._ai_debug(f"normalize.actions[{idx}].fallback reason=payload_mismatch type={action_type!r}")
                action_models.append(AIAction(type=action_type))

        if not action_models:
            self._ai_debug("normalize.actions.empty -> inject stop_and_report('AI 未返回可执行 actions')")
            action_models = [AIAction(type="stop_and_report", final_reason="AI 未返回可执行 actions")]

        self._ai_debug(
            "normalize.result "
            f"issue={issue}, confidence={confidence:.2f}, actions="
            f"{json.dumps([self._serialize_ai_action(a) for a in action_models], ensure_ascii=False)}"
        )

        return AIResult(
            primary_issue=issue,
            confidence=confidence,
            reason=reason,
            actions=action_models,
            thought_chain=thought_chain,
            input_summary=input_summary,
            hit_deleted_mods=hit_deleted_mods,
            dependency_chains=dependency_chains,
            deletion_rationale=deletion_rationale,
            conflicts_or_exceptions=conflicts_or_exceptions,
        )

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

            hit_indexes = [
                idx
                for idx, node in enumerate(clean_chain)
                if self._normalize_mod_token(node) in known_deleted_tokens
            ]
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
        return [
            {
                "role": "system",
                "content": "你是一个专业的Minecraft服务器部署与优化助手，请严格输出JSON。",
            },
            {
                "role": "user",
                "content": prompt,
            },
        ]

    def _build_openai_headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        api_key = (self.config.ai.api_key or "").strip()
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        return headers

    def _resolve_openai_chat_endpoint(self) -> str:
        ai_cfg = self.config.ai
        base_url = (ai_cfg.base_url or "").strip()
        if base_url:
            chat_path = (ai_cfg.chat_path or "/v1/chat/completions").strip() or "/v1/chat/completions"
            return f"{base_url.rstrip('/')}/{chat_path.lstrip('/')}"

        endpoint = (ai_cfg.endpoint or "").strip()
        if endpoint:
            return endpoint

        raise ValueError("openai_compatible 缺少可用 endpoint/base_url")

    def _extract_openai_text_from_non_stream(self, body: dict) -> str:
        choices = body.get("choices") or []
        if not isinstance(choices, list) or not choices:
            return ""

        first = choices[0] if isinstance(choices[0], dict) else {}
        message = first.get("message") if isinstance(first.get("message"), dict) else {}
        content = message.get("content")

        if isinstance(content, str):
            return content

        if isinstance(content, list):
            parts: list[str] = []
            for item in content:
                if isinstance(item, str):
                    parts.append(item)
                    continue
                if not isinstance(item, dict):
                    continue
                text_val = item.get("text")
                if isinstance(text_val, str):
                    parts.append(text_val)
            return "".join(parts)

        text = first.get("text")
        if isinstance(text, str):
            return text
        return ""

    def _extract_openai_text_from_stream(self, resp: requests.Response) -> str:
        chunks: list[str] = []
        for raw_line in resp.iter_lines(decode_unicode=True):
            if not raw_line:
                continue
            line = raw_line.strip()
            if not line.startswith("data:"):
                continue

            data = line[5:].strip()
            if not data:
                continue
            if data == "[DONE]":
                break

            try:
                obj = json.loads(data)
            except json.JSONDecodeError:
                self._ai_debug(f"openai.stream.skip_invalid_json line={self._truncate_debug_text(data, 300)}")
                continue

            choices = obj.get("choices") or []
            if not isinstance(choices, list) or not choices:
                continue
            first = choices[0] if isinstance(choices[0], dict) else {}
            delta = first.get("delta") if isinstance(first.get("delta"), dict) else {}

            piece = delta.get("content")
            if isinstance(piece, str):
                chunks.append(piece)
                continue

            if isinstance(piece, list):
                for item in piece:
                    if isinstance(item, str):
                        chunks.append(item)
                        continue
                    if not isinstance(item, dict):
                        continue
                    text_val = item.get("text")
                    if isinstance(text_val, str):
                        chunks.append(text_val)
                continue

            text = first.get("text")
            if isinstance(text, str):
                chunks.append(text)

        return "".join(chunks)

    def _map_ai_http_error(self, status_code: int, body_preview: str = "") -> str:
        if status_code == 401:
            return "AI 鉴权失败(401)，请检查 api_key"
        if status_code == 429:
            return "AI 请求限流(429)，请稍后重试或降低频率"
        if 500 <= status_code <= 599:
            return f"AI 服务端异常({status_code})，请稍后重试"
        if status_code == 400:
            return "AI 请求参数错误(400)，请检查 model/messages/采样参数"
        if status_code == 403:
            return "AI 请求被拒绝(403)，请检查账号权限或网关策略"
        return f"AI HTTP错误({status_code}) body={self._truncate_debug_text(body_preview, 180)}"

    def _call_ollama_generate(self, prompt: str) -> str:
        payload = {
            "model": self.config.ai.model,
            "prompt": prompt,
            "stream": False,
        }
        timeout_sec = max(5, int(self.config.ai.timeout_sec or 300))
        max_retries = max(0, int(self.config.ai.max_retries or 0))
        backoff = max(0.1, float(self.config.ai.retry_backoff_sec or 1.0))

        last_error: Exception | None = None
        for attempt in range(1, max_retries + 2):
            try:
                resp = requests.post(self.config.ai.endpoint, json=payload, timeout=timeout_sec)
                if resp.status_code >= 400:
                    msg = self._map_ai_http_error(resp.status_code, body_preview=resp.text)
                    raise RuntimeError(msg)

                body = resp.json()
                if not isinstance(body, dict):
                    raise ValueError("ollama_response_not_dict")

                text = body.get("response", "")
                if not isinstance(text, str):
                    text = str(text)

                # 某些模型/参数组合可能把正文放在 thinking，而 response 为空
                if not text.strip():
                    thinking = body.get("thinking", "")
                    if isinstance(thinking, str):
                        text = thinking
                    elif isinstance(thinking, list):
                        text = "\n".join(str(x) for x in thinking if x is not None)
                    elif isinstance(thinking, dict):
                        text = json.dumps(thinking, ensure_ascii=False)
                    elif thinking is not None:
                        text = str(thinking)
                    self._ai_debug(
                        "ollama.response.fallback "
                        f"source=thinking used={bool((text or '').strip())}, thinking_type={type(thinking).__name__}"
                    )

                self._ai_debug(
                    "ollama.response "
                    f"status={resp.status_code}, keys={sorted(body.keys())}, response_preview="
                    f"{json.dumps(self._truncate_debug_text(text, 1200), ensure_ascii=False)}"
                )
                return text
            except Exception as e:
                last_error = e
                retryable = isinstance(e, (requests.Timeout, requests.ConnectionError))
                if not retryable and isinstance(e, RuntimeError):
                    retryable = "(429)" in str(e) or "AI 服务端异常(" in str(e)
                self._ai_debug(
                    f"ollama.retry attempt={attempt}/{max_retries + 1} retryable={retryable} err={type(e).__name__}:{e}"
                )
                if (not retryable) or attempt >= max_retries + 1:
                    break
                time.sleep(backoff * attempt)

        assert last_error is not None
        raise last_error

    def _call_openai_compatible_chat(self, prompt: str) -> str:
        ai_cfg = self.config.ai
        endpoint = self._resolve_openai_chat_endpoint()
        timeout_sec = max(5, int(ai_cfg.timeout_sec or 300))
        max_retries = max(0, int(ai_cfg.max_retries or 0))
        backoff = max(0.1, float(ai_cfg.retry_backoff_sec or 1.0))
        stream = bool(ai_cfg.stream)

        payload: dict[str, object] = {
            "model": ai_cfg.model,
            "messages": self._build_openai_messages(prompt),
            "temperature": float(ai_cfg.temperature),
            "top_p": float(ai_cfg.top_p),
            "max_tokens": int(ai_cfg.max_tokens),
            "stream": stream,
        }
        if ai_cfg.stop:
            payload["stop"] = list(ai_cfg.stop)

        headers = self._build_openai_headers()
        self._ai_debug(
            "openai.request "
            f"endpoint={endpoint}, model={ai_cfg.model}, stream={stream}, payload="
            f"{json.dumps({k: v for k, v in payload.items() if k != 'messages'}, ensure_ascii=False)}"
        )

        last_error: Exception | None = None
        for attempt in range(1, max_retries + 2):
            try:
                if stream:
                    with requests.post(
                        endpoint,
                        headers=headers,
                        json=payload,
                        timeout=timeout_sec,
                        stream=True,
                    ) as resp:
                        if resp.status_code >= 400:
                            raise RuntimeError(self._map_ai_http_error(resp.status_code, body_preview=resp.text))
                        text = self._extract_openai_text_from_stream(resp)
                        self._ai_debug(
                            "openai.response.stream "
                            f"status={resp.status_code}, response_preview="
                            f"{json.dumps(self._truncate_debug_text(text, 1200), ensure_ascii=False)}"
                        )
                        return text

                resp = requests.post(
                    endpoint,
                    headers=headers,
                    json=payload,
                    timeout=timeout_sec,
                )
                if resp.status_code >= 400:
                    raise RuntimeError(self._map_ai_http_error(resp.status_code, body_preview=resp.text))

                body = resp.json()
                if not isinstance(body, dict):
                    raise ValueError("openai_response_not_dict")
                text = self._extract_openai_text_from_non_stream(body)
                self._ai_debug(
                    "openai.response "
                    f"status={resp.status_code}, keys={sorted(body.keys())}, response_preview="
                    f"{json.dumps(self._truncate_debug_text(text, 1200), ensure_ascii=False)}"
                )
                return text
            except Exception as e:
                last_error = e
                retryable = isinstance(e, (requests.Timeout, requests.ConnectionError))
                if not retryable and isinstance(e, RuntimeError):
                    retryable = "(429)" in str(e) or "AI 服务端异常(" in str(e)
                self._ai_debug(
                    f"openai.retry attempt={attempt}/{max_retries + 1} retryable={retryable} err={type(e).__name__}:{e}"
                )
                if (not retryable) or attempt >= max_retries + 1:
                    break
                time.sleep(backoff * attempt)

        assert last_error is not None
        raise last_error

    def _call_ai_provider(self, prompt: str) -> str:
        provider = (self.config.ai.provider or "ollama").strip().lower()
        if provider in {"openai_compatible", "openai-compatible", "openai"}:
            return self._call_openai_compatible_chat(prompt)
        return self._call_ollama_generate(prompt)

    def analyze_with_ai(self, context: dict) -> dict:
        if not self.config.ai.enabled:
            result = AIResult(
                primary_issue="other",
                confidence=0.2,
                reason="AI未启用，返回保守策略",
                actions=[AIAction(type="stop_and_report", final_reason="AI disabled")],
            )
            self.last_ai_result = result
            self.last_ai_payload = {}
            return {
                "primary_issue": result.primary_issue,
                "confidence": result.confidence,
                "reason": result.reason,
                "thought_chain": [],
                "input_summary": "",
                "hit_deleted_mods": [],
                "dependency_chains": [],
                "deletion_rationale": [],
                "conflicts_or_exceptions": [],
                "actions": [self._serialize_ai_action(a) for a in result.actions],
            }

        prompt = self._build_prompt(context)
        provider = (self.config.ai.provider or "ollama").strip().lower()
        self._ai_debug(
            "request.prepare "
            f"provider={provider}, endpoint={self.config.ai.endpoint}, model={self.config.ai.model}, "
            f"context_keys={sorted(context.keys())}, prompt_len={len(prompt)}, "
            f"prompt_preview={json.dumps(self._truncate_debug_text(prompt, 800), ensure_ascii=False)}"
        )
        try:
            text = self._call_ai_provider(prompt)
            self._ai_debug(f"response.raw len={len(str(text))}")
            parsed = self._extract_json_object(str(text))
            if not isinstance(parsed, dict):
                self._ai_debug("response.parse failed reason=no_json_object attempt=1 -> retry_once")
                retry_text = self._call_ai_provider(prompt)
                self._ai_debug(f"response.raw.retry len={len(str(retry_text))}")
                parsed = self._extract_json_object(str(retry_text))
                if not isinstance(parsed, dict):
                    self._ai_debug("response.parse failed reason=no_json_object attempt=2")
                    raise ValueError("ai_response_invalid_json")

            self._ai_debug(
                "response.parse success parsed="
                f"{json.dumps(parsed, ensure_ascii=False)[:2000]}"
            )

            self.last_ai_payload = parsed

            result = self._normalize_ai_result(parsed)
        except Exception as e:
            err = f"AI 分析失败: {type(e).__name__}:{e}"
            self.operations.append(f"analyze_with_ai_failed:{type(e).__name__}")
            self._log("install.ai", err, level="WARN")
            self._ai_debug(f"request.exception detail={self._truncate_debug_text(traceback.format_exc(), 2000)}")
            self.last_ai_payload = {}
            result = self._safe_ai_result(reason=err, confidence=0.05)

        self.last_ai_result = result
        self._ai_debug(
            "analysis.value "
            f"input_summary={self._truncate_debug_text(result.input_summary or 'none', 400)}; "
            f"hit_deleted_mods={json.dumps(result.hit_deleted_mods, ensure_ascii=False)}; "
            f"dependency_chains={json.dumps(result.dependency_chains, ensure_ascii=False)[:800]}"
        )
        self._ai_debug(
            "analysis.judgement "
            f"deletion_rationale={json.dumps(result.deletion_rationale, ensure_ascii=False)[:800]}; "
            f"conflicts_or_exceptions={json.dumps(result.conflicts_or_exceptions, ensure_ascii=False)[:600]}"
        )
        self._ai_debug(
            "result.final "
            f"issue={result.primary_issue}, confidence={result.confidence:.2f}, reason={result.reason}, "
            f"actions={json.dumps([self._serialize_ai_action(a) for a in result.actions], ensure_ascii=False)}"
        )
        return {
            "primary_issue": result.primary_issue,
            "confidence": result.confidence,
            "reason": result.reason,
            "thought_chain": list(result.thought_chain),
            "input_summary": result.input_summary,
            "hit_deleted_mods": list(result.hit_deleted_mods),
            "dependency_chains": [list(x) for x in result.dependency_chains],
            "deletion_rationale": list(result.deletion_rationale),
            "conflicts_or_exceptions": list(result.conflicts_or_exceptions),
            "actions": [self._serialize_ai_action(a) for a in result.actions],
        }

    # 输出
    def generate_report(self) -> str:
        report_path = self.workdirs.root / "report.txt"
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
                f"- 命中的已删除mod: {json.dumps(self.last_ai_result.hit_deleted_mods, ensure_ascii=False)}",
                f"- 依赖链: {json.dumps(self.last_ai_result.dependency_chains, ensure_ascii=False)}",
                f"- 删除判定依据: {json.dumps(self.last_ai_result.deletion_rationale, ensure_ascii=False)}",
                f"- 冲突/异常说明: {json.dumps(self.last_ai_result.conflicts_or_exceptions, ensure_ascii=False)}",
                f"- 思考链: {json.dumps(self.last_ai_result.thought_chain, ensure_ascii=False)}",
            ]

        deleted_history_lines: list[str] = []
        for mod_name in sorted(self.known_deleted_client_mods):
            evidence = self.deleted_mod_evidence.get(mod_name, [])
            deleted_history_lines.append(f"- {mod_name}: {json.dumps(evidence, ensure_ascii=False)}")
        lines = [
            "MC Auto Server Builder 报告",
            f"生成时间: {datetime.now().isoformat()}",
            f"工作目录: {self.workdirs.root}",
            f"是否成功启动: {self.run_success}",
            f"实际尝试次数: {self.attempts_used}",
            f"清理/删除Mods数量: {len(self.removed_mods)}",
            "删除列表:",
            *[f"- {m}" for m in self.removed_mods],
            f"最终JVM: Xmx={self.jvm_xmx}, Xms={self.jvm_xms}",
            f"Java版本: {self.detect_current_java_version()}",
            f"最后一次AI结论: {ai_summary}",
            "AI高价值分析明细:",
            *(ai_detail_lines or ["- none"]),
            "已知且已删除客户端mod（本次运行历史）:",
            *(deleted_history_lines or ["- none"]),
            f"终止原因: {self.stop_reason or 'success_or_attempt_limit'}",
            f"总操作数: {len(self.operations)}",
            "操作记录:",
            *[f"- {x}" for x in self.operations],
        ]
        report_path.write_text("\n".join(lines), encoding="utf-8")
        return str(report_path)

    def package_server(self) -> str:
        out = self.workdirs.root / "server_pack.zip"
        with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
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

            success = False
            for i in range(1, self.config.runtime.max_attempts + 1):
                self.attempts_used = i
                self._log("install.attempt", f"启动尝试 {i}/{self.config.runtime.max_attempts}")
                self.backup_mods(f"attempt_{i}")
                start_res = self.start_server(timeout=self.config.runtime.start_timeout)
                if start_res["success"]:
                    success = True
                    source = str(start_res.get("success_source") or "unknown")
                    self.stop_reason = f"server_ready:{source}"
                    self._log("install.attempt", f"尝试 {i} 成功，判定来源={source}")
                    break
                log_info = self.extract_relevant_log(str(start_res["log_path"]), str(start_res["crash_dir"]))
                ai_context = {
                    "mc_version": self.manifest.mc_version if self.manifest else "unknown",
                    "loader": self.manifest.loader if self.manifest else "unknown",
                    "jvm_args": f"Xmx={self.jvm_xmx} Xms={self.jvm_xms}",
                    "available_ram": self.get_system_memory(),
                    "mod_count": len(self.list_mods()),
                    "current_installed_mods": self.list_mods(),
                    "current_installed_client_mods": self.list_current_installed_client_mods(),
                    "known_deleted_client_mods": sorted(self.known_deleted_client_mods),
                    "deleted_mod_evidence": self.deleted_mod_evidence,
                    "dependency_cleanup_rule_enabled": True,
                    "recent_actions": self.operations[-20:],
                    **log_info,
                }
                ai = self.analyze_with_ai(ai_context)
                self._log("install.ai", f"AI 分析完成，issue={ai.get('primary_issue')} confidence={ai.get('confidence')}")
                should_stop = self._apply_actions(ai.get("actions", []))
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
        detail = (
            f"platform={platform},project_id={project_id},file_id={file_id},"
            f"file_type={file_type},action={action},reason={reason}"
        )
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
            self.operations.append(
                f"modrinth_selected_version:project={resolved_project_id},version={version.get('id')},manual=true"
            )
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
            raise ValueError(
                f"Modrinth 版本缺少可下载整合包文件: project={resolved_project_id}, version={version.get('id')}"
            )

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
            if nested_root.name.lower() not in {"overrides", "server", "serverfiles", "server-files", "serverpack", "server_pack"}:
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
                if name_lc == "overrides":
                    skipped += 1
                    continue
                if name_lc in blacklist:
                    skipped += 1
                    continue

                dst = self.workdirs.server / src.name
                replace_path(src, dst)
                copied += 1

        return copied, skipped

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
                self._install_forge_family_server(loader=loader, mc_version=mc_version, loader_version=loader_version)
                self.operations.append(f"install_server_core:{loader}:ok")
                return
            if loader in ("fabric", "quilt"):
                self._install_fabric_family_server(loader=loader, mc_version=mc_version, loader_version=loader_version)
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

    def _download_recommended_java(self) -> None:
        if not self.manifest:
            return
        version = 21
        try:
            mc = self.manifest.mc_version
            nums = [int(x) for x in mc.split(".") if x.isdigit()]
            minor = nums[1] if len(nums) > 1 else 18
            if minor <= 16:
                version = 8
            elif minor == 17:
                version = 17
            else:
                version = 21
        except Exception:
            version = 21

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
            dict.fromkeys([
                *self._resolve_java_params_for_version(version),
                *self.config.extra_jvm_flags,
            ])
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

                self.operations.append(
                    f"{op_prefix}:http:{version}:profile={profile_name}:status={status}:ctype={content_type[:80]}"
                )
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
                self.operations.append(f"{op_prefix}:request_error:{version}:profile={profile_name}:{type(e).__name__}")
                self._log(
                    stage,
                    f"{op_prefix} 请求异常 profile={profile_name}: {type(e).__name__}",
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

        url = (
            "https://api.adoptium.net/v3/binary/latest/"
            f"{version}/ga/{os_name}/{arch_name}/jdk/hotspot/normal/eclipse"
        )

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
        sh_value = value.replace('"', r'\"')

        if os.name == "nt":
            if mode == "argsfile":
                exec_line = f'"%JAVA_BIN%" {jvm_part} @"{bat_value}" %* nogui\n'
            else:
                exec_line = f'"%JAVA_BIN%" {jvm_part} -jar "{bat_value}" %* nogui\n'
            content = (
                "@echo off\n"
                "setlocal\n"
                "\n"
                "set \"SCRIPT_DIR=%~dp0\"\n"
                "cd /d \"%SCRIPT_DIR%\"\n"
                "\n"
                "set \"JAVA_BIN=\"\n"
                "\n"
                "if exist \"%SCRIPT_DIR%java_bins\\bin\\java.exe\" set \"JAVA_BIN=%SCRIPT_DIR%java_bins\\bin\\java.exe\"\n"
                "if not defined JAVA_BIN if exist \"%SCRIPT_DIR%..\\java_bins\\bin\\java.exe\" "
                "set \"JAVA_BIN=%SCRIPT_DIR%..\\java_bins\\bin\\java.exe\"\n"
                "\n"
                "if not defined JAVA_BIN (\n"
                "  for /d %%D in (\"%SCRIPT_DIR%java_bins\\jdk-*\") do (\n"
                "    if exist \"%%~fD\\bin\\java.exe\" (\n"
                "      set \"JAVA_BIN=%%~fD\\bin\\java.exe\"\n"
                "      goto :java_found\n"
                "    )\n"
                "  )\n"
                ")\n"
                "\n"
                "if not defined JAVA_BIN (\n"
                "  for /d %%D in (\"%SCRIPT_DIR%..\\java_bins\\jdk-*\") do (\n"
                "    if exist \"%%~fD\\bin\\java.exe\" (\n"
                "      set \"JAVA_BIN=%%~fD\\bin\\java.exe\"\n"
                "      goto :java_found\n"
                "    )\n"
                "  )\n"
                ")\n"
                "\n"
                ":java_found\n"
                "if not defined JAVA_BIN set \"JAVA_BIN=java\"\n"
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
                "SCRIPT_DIR=$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\n"
                "cd \"$SCRIPT_DIR\"\n"
                "\n"
                "JAVA_BIN=\"\"\n"
                "\n"
                "if [ -x \"$SCRIPT_DIR/java_bins/bin/java\" ]; then\n"
                "  JAVA_BIN=\"$SCRIPT_DIR/java_bins/bin/java\"\n"
                "elif [ -x \"$SCRIPT_DIR/../java_bins/bin/java\" ]; then\n"
                "  JAVA_BIN=\"$SCRIPT_DIR/../java_bins/bin/java\"\n"
                "else\n"
                "  for candidate in \"$SCRIPT_DIR\"/java_bins/jdk-*/bin/java \"$SCRIPT_DIR\"/../java_bins/jdk-*/bin/java; do\n"
                "    if [ -x \"$candidate\" ]; then\n"
                "      JAVA_BIN=\"$candidate\"\n"
                "      break\n"
                "    fi\n"
                "  done\n"
                "fi\n"
                "\n"
                "if [ -z \"$JAVA_BIN\" ]; then\n"
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

    def _build_prompt(self, context: dict) -> str:
        return (
            "你是一个专业的Minecraft服务器部署与优化助手。"
            "你必须同时识别：1) 当前已安装客户端mod；2) 已知但已被删除的客户端mod（历史删除记录）。"
            "强规则：只要某个mod依赖任意‘已知且已删除的客户端mod’，该mod必须被标记为需要删除，禁止保留。"
            "依赖关系仅允许从日志与上下文推断。"
            "输出必须采用‘思考链 + 最终输出’核心结构，且严格返回JSON。\n"
            f"上下文: {json.dumps(context, ensure_ascii=False)[:12000]}\n"
            "JSON格式要求："
            "{"
            "\"thought_chain\":[\"...\"],"
            "\"final_output\":{"
            "\"primary_issue\":\"client_mod|memory_allocation|memory_oom|java_version_mismatch|mod_conflict|missing_dependency|config_error|other\"," 
            "\"confidence\":0.0,"
            "\"reason\":\"...\","
            "\"input_summary\":\"...\","
            "\"hit_deleted_mods\":[\"...\"],"
            "\"dependency_chains\":[[\"dependent\",\"...\",\"deleted_mod\"]],"
            "\"deletion_rationale\":[\"...\"],"
            "\"conflicts_or_exceptions\":[\"...\"],"
            "\"actions\":[{\"type\":\"remove_mods\",\"targets\":[\"modA.jar\"]}]"
            "}"
            "}。"
        )

    def _apply_actions(self, actions: list[dict]) -> bool:
        for idx, a in enumerate(actions[:2], start=1):
            t = a.get("type")
            self._ai_debug(f"apply.actions[{idx}] type={t!r} payload={json.dumps(a, ensure_ascii=False)}")
            if t == "remove_mods":
                targets = a.get("targets") or []
                names = [x for x in targets if not str(x).startswith("regex:")]
                regex_targets = [str(x).removeprefix("regex:") for x in targets if str(x).startswith("regex:")]
                if names:
                    resolved_names = self._resolve_mod_names_to_installed([str(x) for x in names])
                    self.remove_mods_by_name(
                        resolved_names,
                        source="ai_action",
                        reason=f"attempt_action_index={idx}:explicit_targets",
                    )
                if regex_targets:
                    self.remove_mods_by_regex(regex_targets, source="ai_action_regex")
                    for pat in regex_targets:
                        self.add_remove_regex(pat, "ai suggested")

                installed_after_ai = self.list_mods()
                forced_targets, forced_rationale, matched_chains = self._resolve_dependency_cleanup_targets(
                    self.last_ai_result.dependency_chains if self.last_ai_result else [],
                    installed_after_ai,
                )
                if forced_targets:
                    self.remove_mods_by_name(
                        forced_targets,
                        source="dependency_cleanup",
                        reason="depend_on_known_deleted_client_mod",
                    )
                    self.operations.append(
                        "dependency_cleanup_forced_remove:"
                        f"targets={json.dumps(forced_targets, ensure_ascii=False)}"
                    )
                if forced_rationale:
                    self.operations.append(
                        "dependency_cleanup_rationale:"
                        f"{json.dumps(forced_rationale[:20], ensure_ascii=False)}"
                    )

                self._ai_debug(
                    "apply.remove_mods "
                    f"names={json.dumps(names, ensure_ascii=False)}, "
                    f"regex={json.dumps(regex_targets, ensure_ascii=False)}, "
                    f"forced_by_dependency={json.dumps(forced_targets, ensure_ascii=False)}, "
                    f"matched_dependency_chains={json.dumps(matched_chains, ensure_ascii=False)[:800]}, "
                    f"forced_rationale={json.dumps(forced_rationale[:20], ensure_ascii=False)}"
                )
            elif t == "adjust_memory":
                xmx = a.get("xmx", self.jvm_xmx)
                xms = a.get("xms", self.jvm_xms)
                xmx, xms = self._normalize_memory_plan(str(xmx), str(xms))
                self.set_jvm_args(xmx, xms)
                self._ai_debug(f"apply.adjust_memory xmx={xmx}, xms={xms}")
            elif t == "change_java":
                version = int(a.get("version", 21))
                try:
                    self.switch_java_version(version)
                    self._ai_debug(f"apply.change_java success version={version}")
                except (FileNotFoundError, ValueError):
                    self.operations.append(f"change_java_failed:{version}")
                    self._ai_debug(f"apply.change_java failed version={version}")
            elif t == "stop_and_report":
                self.stop_reason = str(a.get("final_reason", "stop_and_report"))
                self.operations.append(f"stop_and_report:{self.stop_reason}")
                self._ai_debug(f"apply.stop_and_report stop_reason={self.stop_reason}")
                return True
            else:
                self._ai_debug(f"apply.actions[{idx}] ignored reason=unknown_type type={t!r}")
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
                url = (
                    "https://maven.minecraftforge.net/net/minecraftforge/forge/"
                    f"{forge_coord}/forge-{forge_coord}-installer.jar"
                )
                self.operations.append(f"forge_installer_url:{url}")
            else:
                neo_mc_ver, neo_ver = self._resolve_neoforge_version(mc_version, loader_version)
                if neo_mc_ver == "1.20.1":
                    url = (
                        "https://maven.neoforged.net/releases/net/neoforged/forge/"
                        f"{neo_mc_ver}-{neo_ver}/forge-{neo_mc_ver}-{neo_ver}-installer.jar"
                    )
                else:
                    url = (
                        "https://maven.neoforged.net/releases/net/neoforged/neoforge/"
                        f"{neo_ver}/neoforge-{neo_ver}-installer.jar"
                    )

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
                    "https://maven.fabricmc.net/net/fabricmc/fabric-installer/"
                    f"{installer_ver}/fabric-installer-{installer_ver}.jar"
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
            raise RuntimeError(
                "installer_failed "
                f"exit={cp.returncode} stdout_tail={stdout_tail!r} stderr_tail={stderr_tail!r}"
            )
