from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, cast

import psutil

from .models import StartResult

if TYPE_CHECKING:
    from .builder import ServerBuilder


def _builder_runtime_module():
    import mc_auto_server_builder.builder as builder_module

    return builder_module


def collect_process_resource_snapshot(builder: ServerBuilder, proc: subprocess.Popen) -> dict[str, float | int | str | None]:
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


def detect_failure_signals(builder: ServerBuilder, text: str) -> list[str]:
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


def detect_current_java_version(builder: ServerBuilder) -> int:
    cmd = [str(builder.current_java_bin or "java"), "-version"]
    cp = subprocess.run(cmd, capture_output=True, text=True, check=False)
    text = cp.stderr + cp.stdout
    match = re.search(r'"(\d+)(?:\.(\d+))?.*"', text)
    if not match:
        return 0
    major = int(match.group(1))
    if major == 1 and match.group(2):
        return int(match.group(2))
    return major


def detect_log_ready_signal(builder: ServerBuilder, text: str) -> tuple[bool, str]:
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if re.search(r"\bpreparing spawn area\b", line, flags=re.IGNORECASE):
            return True, "log_preparing_spawn_area"
        if re.search(
            r'(?:^|:\s*)done\s*\([^\n\r)]*\)!?(?:\s*for help, type\s+"?help"?)?\s*$',
            line,
            flags=re.IGNORECASE,
        ):
            return True, "log_done"
    return False, ""


def detect_command_probe_ready(builder: ServerBuilder, text: str) -> tuple[bool, str]:
    if re.search(r"there\s+are.*players\s+online", text or "", flags=re.IGNORECASE | re.DOTALL):
        return True, "cmd_probe_list_response"
    return False, ""


def snapshot_crash_reports(builder: ServerBuilder, crash_dir: Path) -> tuple[bool, set[str]]:
    exists = crash_dir.exists() and crash_dir.is_dir()
    if not exists:
        return False, set()
    try:
        return True, {path.name for path in crash_dir.iterdir() if path.is_file()}
    except OSError:
        return exists, set()


def read_startup_log_tail(builder: ServerBuilder, log_path: Path, state: dict[str, object], *, lines: int = 300) -> str:
    builder_module = _builder_runtime_module()
    if not bool(state.get("initialized", False)):
        text = builder_module.read_tail_text(log_path, lines=lines)
        state["initialized"] = True
        state["position"] = log_path.stat().st_size if log_path.exists() and log_path.is_file() else 0
        state["buffer"] = text.splitlines()[-lines:]
        return text

    if not log_path.exists() or not log_path.is_file():
        state["position"] = 0
        state["buffer"] = []
        return ""

    try:
        current_size = log_path.stat().st_size
        raw_position = state.get("position", 0)
        position = int(raw_position) if isinstance(raw_position, (int, float, str)) else 0
        buffer = [str(item) for item in cast(list[object], state.get("buffer", [])) if str(item).strip() or item == ""]
        if current_size < position:
            position = 0
            buffer = []
        appended = ""
        if current_size > position:
            with log_path.open("r", encoding="utf-8", errors="ignore") as handle:
                handle.seek(position)
                appended = handle.read()
                position = handle.tell()
        if appended:
            buffer.extend(appended.splitlines())
            if len(buffer) > lines:
                del buffer[: len(buffer) - lines]
        state["position"] = position
        state["buffer"] = buffer
        return "\n".join(buffer)
    except OSError:
        fallback = builder_module.read_tail_text(log_path, lines=lines)
        state["position"] = log_path.stat().st_size if log_path.exists() and log_path.is_file() else 0
        state["buffer"] = fallback.splitlines()[-lines:]
        return fallback


def start_server(builder: ServerBuilder, timeout: int = 300) -> dict[str, object]:
    builder_module = _builder_runtime_module()
    script = builder._start_script_path()
    if not script.exists():
        builder._write_start_script()

    latest_log = builder.workdirs.server / "logs" / "latest.log"
    latest_log.parent.mkdir(parents=True, exist_ok=True)
    crash_dir = builder.workdirs.server / "crash-reports"
    initial_crash_dir_exists, initial_crash_reports = builder._snapshot_crash_reports(crash_dir)

    cmd = [str(script)] if os.name != "nt" else ["cmd", "/c", str(script)]
    proc = builder_module.subprocess.Popen(
        cmd,
        cwd=builder.workdirs.server,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    stdout_lines: list[str] = []
    stderr_lines: list[str] = []
    threads = [
        builder_module.threading.Thread(target=builder_module.threaded_pipe_reader, args=(proc.stdout, stdout_lines), daemon=True),
        builder_module.threading.Thread(target=builder_module.threaded_pipe_reader, args=(proc.stderr, stderr_lines), daemon=True),
    ]
    for thread in threads:
        thread.start()

    probe_enabled = bool(builder.config.runtime.startup_command_probe_enabled)
    loop_interval = max(0.2, float(builder.config.runtime.startup_probe_interval_sec))
    soft_timeout = max(8.0, float(builder.config.runtime.startup_soft_timeout))
    hard_timeout = max(float(timeout), float(builder.config.runtime.startup_hard_timeout))
    start_at = builder_module.time.monotonic()
    soft_deadline = start_at + soft_timeout
    hard_deadline = start_at + hard_timeout
    next_probe_at = start_at + max(1.0, float(builder.config.runtime.startup_command_probe_initial_delay_sec))
    probe_retry = max(1.0, float(builder.config.runtime.startup_command_probe_retry_sec))
    probe_command = "list"
    log_tail_state: dict[str, object] = {"initialized": False, "position": 0, "buffer": []}

    done = False
    cmd_probe_ok = False
    port_open = False
    success_source = ""
    readiness_evidence: list[str] = []
    resource_samples: list[dict[str, float | int | str | None]] = []
    failure_signals: list[str] = []
    crash_detected = False
    forced_termination = False

    while True:
        now = builder_module.time.monotonic()
        if now >= hard_deadline:
            readiness_evidence.append("hard_timeout_reached")
            break

        log_tail = builder._read_startup_log_tail(latest_log, log_tail_state, lines=300)
        out_tail = "\n".join(stdout_lines[-120:])
        err_tail = "\n".join(stderr_lines[-120:])
        merged_tail = "\n".join([log_tail, out_tail, err_tail])

        if proc.poll() is None:
            resource_samples.append(builder._collect_process_resource_snapshot(proc))

        for signal in builder._detect_failure_signals(merged_tail):
            if signal not in failure_signals:
                failure_signals.append(signal)

        current_crash_dir_exists, current_crash_reports = builder._snapshot_crash_reports(crash_dir)
        new_crash_reports = sorted(current_crash_reports - initial_crash_reports)
        crash_dir_created = current_crash_dir_exists and not initial_crash_dir_exists
        if crash_dir_created and not new_crash_reports:
            builder._log(
                "install.crash",
                "检测到 crash-reports 目录首次创建，等待 2 秒以便 crash 文件落盘后再分析",
                level="INFO",
            )
            builder_module.time.sleep(2.0)
            current_crash_dir_exists, current_crash_reports = builder._snapshot_crash_reports(crash_dir)
            new_crash_reports = sorted(current_crash_reports - initial_crash_reports)
            crash_report_preview = ",".join(new_crash_reports[:3]) if new_crash_reports else "none"
            builder._log(
                "install.crash",
                f"crash-reports 复扫完成，新增 crash 文件 {len(new_crash_reports)} 个：{crash_report_preview}",
                level="INFO",
            )
        if crash_dir_created or new_crash_reports:
            crash_detected = True
            if "crash_report_created" not in failure_signals:
                failure_signals.append("crash_report_created")
            if crash_dir_created and len(initial_crash_reports) == 0 and not new_crash_reports:
                readiness_evidence.append("crash_reports_dir_created")
            elif len(initial_crash_reports) == 0:
                readiness_evidence.append(f"crash_reports_first_seen:{','.join(new_crash_reports[:3])}")
            else:
                readiness_evidence.append(f"crash_reports_increased:{','.join(new_crash_reports[:3])}")
            crash_report_preview = ",".join(new_crash_reports[:3]) if new_crash_reports else "none"
            builder._log(
                "install.crash",
                f"检测到 crash 证据，目录新建={crash_dir_created}，新增文件={crash_report_preview}，准备进入日志提取与 AI 分析",
                level="INFO",
            )
            break

        if not port_open:
            try:
                port_open = builder_module.is_local_tcp_port_open(
                    port=int(builder.config.server_port), host="127.0.0.1", timeout=0.6
                )
            except Exception:
                port_open = False
            if port_open:
                readiness_evidence.append("port_open")

        if not done:
            done_detected, done_source = builder._detect_log_ready_signal(merged_tail)
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
            except Exception as exc:
                readiness_evidence.append(f"probe_send_failed:{type(exc).__name__}")
            next_probe_at = now + probe_retry

        if not cmd_probe_ok:
            probe_detected, probe_source = builder._detect_command_probe_ready(merged_tail)
            if probe_detected:
                cmd_probe_ok = True
                success_source = probe_source
                readiness_evidence.append(probe_source)

        if cmd_probe_ok or done:
            break

        if proc.poll() is not None:
            readiness_evidence.append(f"process_exit:{proc.returncode}")
            break

        builder_module.time.sleep(loop_interval)

    process_alive = proc.poll() is None
    if process_alive and not builder.config.runtime.keep_running:
        if crash_detected or not (cmd_probe_ok or done):
            builder_module.terminate_process(proc, timeout_sec=8.0)
            forced_termination = True
            readiness_evidence.append("forced_termination")
        else:
            builder_module.graceful_stop_process(proc, timeout_sec=20.0, stop_command="stop")
        process_alive = proc.poll() is None
    elif (not success_source or crash_detected) and process_alive:
        builder_module.terminate_process(proc, timeout_sec=8.0)
        forced_termination = True
        readiness_evidence.append("forced_termination")
        process_alive = proc.poll() is None

    for thread in threads:
        thread.join(timeout=1.0)

    exit_code = proc.poll()
    stdout_tail = "\n".join(stdout_lines[-80:])
    stderr_tail = "\n".join(stderr_lines[-80:])
    success = bool((cmd_probe_ok or done) and not crash_detected)
    peak_rss_mb = max((float(item.get("rss_mb") or 0.0) for item in resource_samples), default=0.0)
    peak_cpu_percent = max((float(item.get("cpu_percent") or 0.0) for item in resource_samples), default=0.0)
    max_process_count = max((int(item.get("process_count") or 0) for item in resource_samples), default=0)

    result = StartResult(
        success=success,
        done_detected=done,
        command_probe_detected=cmd_probe_ok,
        port_open_detected=port_open,
        process_alive=process_alive,
        crash_detected=crash_detected,
        forced_termination=forced_termination,
        success_source=success_source if success else "none",
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
        crash_dir=crash_dir,
        stdout_tail=stdout_tail,
        stderr_tail=stderr_tail,
        crash_reports_snapshot=sorted(current_crash_reports if "current_crash_reports" in locals() else initial_crash_reports),
        crash_reports_new=sorted(new_crash_reports if "new_crash_reports" in locals() else []),
    )
    builder.operations.append(
        "start_server:"
        f"success={success},source={result.success_source},"
        f"done={done},cmd_probe={cmd_probe_ok},port={port_open},exit={exit_code},alive={process_alive},"
        f"failure_signals={json.dumps(result.failure_signals, ensure_ascii=False)},"
        f"resource={json.dumps(result.resource_summary, ensure_ascii=False)}"
    )
    return asdict(result)


def extract_relevant_log(builder: ServerBuilder, log_path: str, crash_dir: str) -> dict[str, object]:
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
            crash_mod_issue = builder._extract_latest_crash_mod_issue(crash_content)
            match = re.search(r"(?m)^\s*Caused by:\s*([^\n]+)", crash_content)
            key_exception = match.group(1).strip() if match else ""
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
            if any(item in lines[i] for item in trigger):
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
            for pattern in code_patterns:
                match_list = re.findall(pattern, refined)
                if not match_list:
                    continue
                try:
                    jvm_exit_code = int(match_list[-1])
                    break
                except ValueError:
                    continue

    if not key_exception:
        match = re.search(r"(?m)([A-Za-z0-9_.]+(?:Exception|Error))", refined)
        key_exception = match.group(1) if match else "unknown"

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


def extract_latest_crash_mod_issue(builder: ServerBuilder, crash_content: str) -> str:
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
