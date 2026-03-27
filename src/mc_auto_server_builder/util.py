from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import threading
import time
import unicodedata
import zipfile
from collections import OrderedDict
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable, TextIO

import psutil
import requests

from .config import ProxyConfig

# `requests` 的类型信息在部分环境下依赖额外桩包；当前项目的 [tool.mypy](pyproject.toml) 已通过
# [ignore_missing_imports](pyproject.toml:58) 降噪，因此这里维持运行时导入，后续若要彻底收敛可在开发依赖补充
# `types-requests` 而无需改动主逻辑。


class UtilError(RuntimeError):
    pass


class DownloadError(UtilError):
    pass


class ConfigReadError(UtilError):
    pass


class ExternalServiceError(UtilError):
    pass


class ExternalRequestError(ExternalServiceError):
    pass


class ExternalResponseError(ExternalServiceError):
    pass


class ExternalDataError(ExternalServiceError):
    pass


class DownloadTaskProcessingError(DownloadError):
    pass


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"


class ColorPolicy(str, Enum):
    AUTO = "auto"
    ALWAYS = "always"
    NEVER = "never"


ANSI_RESET = "\033[0m"
ANSI_BY_LEVEL = {
    LogLevel.DEBUG: "\033[36m",
    LogLevel.INFO: "\033[32m",
    LogLevel.WARN: "\033[33m",
    LogLevel.ERROR: "\033[31m",
}

LOG_LEVEL_PRIORITY = {
    LogLevel.DEBUG: 10,
    LogLevel.INFO: 20,
    LogLevel.WARN: 30,
    LogLevel.ERROR: 40,
}


@dataclass(slots=True)
class DownloadConfig:
    enable_parallel_download: bool = True
    max_workers: int = 32
    connect_timeout: int = 15
    read_timeout: int = 120
    max_retries: int = 3
    retry_backoff_sec: float = 1.0
    chunk_size: int = 1024 * 256
    proxies: dict[str, str] | None = None
    trust_env: bool = True


def configure_requests_session(
    session: requests.Session,
    proxy: ProxyConfig | None = None,
    *,
    proxies: Mapping[str, str] | None = None,
    trust_env: bool | None = None,
) -> requests.Session:
    if proxy is not None:
        session.proxies = proxy.to_requests_proxies() or {}
        session.trust_env = proxy.trust_env
        return session
    if proxies is not None:
        session.proxies = {str(key): str(value) for key, value in proxies.items() if str(value).strip()}
    if trust_env is not None:
        session.trust_env = trust_env
    return session


@dataclass(slots=True)
class DownloadTask:
    out: Path
    urls: list[str]
    stage: str = "install.download"
    headers: dict[str, str] | None = None
    session_factory: Callable[[], requests.Session] | None = None
    expected_hashes: dict[str, str] | None = None
    extract_to: Path | None = None
    task_id: str = ""


@dataclass(slots=True)
class DownloadFailure:
    task: DownloadTask
    error: str
    category: str = ""
    stage: str = ""
    exc_type: str = ""
    message: str = ""


def _classify_download_failure(task: DownloadTask, exc: BaseException) -> DownloadFailure:
    message = str(exc).strip()
    category = "download"
    if isinstance(exc, DownloadError):
        if "hash_mismatch:" in message:
            category = "hash_mismatch"
        elif "缺少可用URL" in message:
            category = "no_url"
    elif isinstance(exc, (zipfile.BadZipFile, tarfile.TarError, ValueError)):
        category = "extract"
    elif isinstance(exc, OSError):
        category = "filesystem"
    return DownloadFailure(
        task=task,
        error=f"{type(exc).__name__}:{exc}",
        category=category,
        stage=task.stage,
        exc_type=type(exc).__name__,
        message=message,
    )


@dataclass(slots=True)
class DownloadUiTaskState:
    label: str
    downloaded_bytes: int = 0
    total_bytes: int | None = None
    speed_bps: float = 0.0
    last_sample_at: float = 0.0
    last_sample_bytes: int = 0


# ---------------------------
# 文件与路径工具
# ---------------------------
def ensure_parent_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def ensure_dirs(paths: Iterable[Path]) -> None:
    for path in paths:
        path.mkdir(parents=True, exist_ok=True)


def path_exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False


def file_exists_nonempty(path: Path) -> bool:
    return path_exists(path) and path.is_file() and path.stat().st_size > 0


def safe_unlink(path: Path) -> None:
    try:
        if path.exists():
            path.unlink()
    except OSError:
        return


def backup_directory(src: Path, dst_root: Path, tag: str) -> Path:
    target = dst_root / tag
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(src, target)
    return target


def replace_path(src: Path, dst: Path) -> None:
    if dst.exists():
        if dst.is_dir():
            shutil.rmtree(dst)
        else:
            dst.unlink()
    if src.is_dir():
        shutil.copytree(src, dst)
    else:
        ensure_parent_dir(dst)
        shutil.copy2(src, dst)


def copy_tree_merge(src: Path, dst: Path) -> tuple[int, int]:
    copied_files = 0
    copied_dirs = 0
    if src.is_dir():
        dst.mkdir(parents=True, exist_ok=True)
        copied_dirs += 1
        for child in src.iterdir():
            c_files, c_dirs = copy_tree_merge(child, dst / child.name)
            copied_files += c_files
            copied_dirs += c_dirs
        return copied_files, copied_dirs

    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    copied_files += 1
    return copied_files, copied_dirs


def merge_overrides_into_base(base: Path) -> tuple[int, int, int]:
    override_dirs = sorted(
        [
            p
            for p in base.rglob("*")
            if p.is_dir()
            and p.name.lower() in {"overrides", "override", "server-overrides", "server_overrides", "serveroverrides"}
        ],
        key=lambda p: len(p.parts),
        reverse=True,
    )

    merged_files = 0
    merged_dirs = 0
    removed_override_dirs = 0

    for ov in override_dirs:
        for item in ov.iterdir():
            f_cnt, d_cnt = copy_tree_merge(item, base / item.name)
            merged_files += f_cnt
            merged_dirs += d_cnt
        shutil.rmtree(ov)
        removed_override_dirs += 1

    return merged_files, merged_dirs, removed_override_dirs


def normalize_client_relative_path(rel_path: str) -> str:
    normalized = rel_path.replace("\\", "/").lstrip("./").strip("/")
    if not normalized:
        return ""
    override_prefixes = (
        "overrides",
        "override",
        "server-overrides",
        "server_overrides",
        "serveroverrides",
    )
    if normalized in override_prefixes:
        return ""
    for prefix in override_prefixes:
        token = f"{prefix}/"
        if normalized.startswith(token):
            return normalized[len(token) :]
    return normalized


def normalize_loader_name(raw_loader: str) -> str:
    text = (raw_loader or "").lower()
    if "neoforge" in text:
        return "neoforge"
    if "forge" in text:
        return "forge"
    if "fabric" in text:
        return "fabric"
    if "quilt" in text:
        return "quilt"
    return "unknown"


def is_http_url(value: str) -> bool:
    text = (value or "").strip().lower()
    return text.startswith("http://") or text.startswith("https://")


# ---------------------------
# 网络与请求工具
# ---------------------------
def http_get_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    timeout: float | tuple[float, float] = 60,
    proxies: Mapping[str, str] | None = None,
    trust_env: bool = True,
) -> Any:
    """统一 GET + JSON 解析流程，并补充稳定的异常分类。"""
    session = configure_requests_session(requests.Session(), proxies=proxies, trust_env=trust_env)
    try:
        resp = session.get(url, headers=headers, params=params or None, timeout=timeout)
    except requests.RequestException as exc:
        raise ExternalRequestError(f"请求失败: {url} ({type(exc).__name__})") from exc
    finally:
        session.close()
    try:
        resp.raise_for_status()
    except requests.HTTPError as exc:
        status = getattr(resp, "status_code", "unknown")
        raise ExternalResponseError(f"请求返回非成功状态: {url} (HTTP {status})") from exc
    try:
        return resp.json()
    except ValueError as exc:
        raise ExternalDataError(f"响应不是合法 JSON: {url}") from exc


def read_tail_text(path: Path, lines: int = 300) -> str:
    if not path.exists() or not path.is_file():
        return ""
    try:
        return "\n".join(path.read_text(encoding="utf-8", errors="ignore").splitlines()[-lines:])
    except OSError:
        return ""


def is_local_tcp_port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.6) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((host, int(port))) == 0
    finally:
        sock.close()


def graceful_stop_process(proc: subprocess.Popen[str], timeout_sec: float = 20.0, stop_command: str = "stop") -> None:
    if proc.poll() is not None:
        return
    try:
        if proc.stdin:
            proc.stdin.write(f"{stop_command}\n")
            proc.stdin.flush()
    except Exception:
        pass
    try:
        proc.wait(timeout=timeout_sec)
    except Exception:
        terminate_process(proc, timeout_sec=8)


def _iter_process_tree(proc: subprocess.Popen[str]) -> list[psutil.Process]:
    try:
        root = psutil.Process(proc.pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return []

    try:
        children = root.children(recursive=True)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        children = []
    return [*children, root]


def _wait_process_tree(processes: list[psutil.Process], timeout_sec: float) -> tuple[list[psutil.Process], list[psutil.Process]]:
    alive: list[psutil.Process] = []
    deadline = time.monotonic() + max(0.0, timeout_sec)
    for ps_proc in reversed(processes):
        remaining = max(0.0, deadline - time.monotonic())
        try:
            ps_proc.wait(timeout=remaining)
        except psutil.TimeoutExpired:
            alive.append(ps_proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return processes, alive


def terminate_process_tree(proc: subprocess.Popen[str], timeout_sec: float = 8.0) -> None:
    if proc.poll() is not None:
        return

    processes = _iter_process_tree(proc)
    if not processes:
        try:
            proc.terminate()
            proc.wait(timeout=timeout_sec)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        return

    for ps_proc in processes:
        try:
            ps_proc.terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    _, alive = _wait_process_tree(processes, timeout_sec)
    for ps_proc in alive:
        try:
            ps_proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    _wait_process_tree(alive, min(3.0, timeout_sec))


def terminate_process(proc: subprocess.Popen[str], timeout_sec: float = 8.0) -> None:
    if proc.poll() is not None:
        return
    terminate_process_tree(proc, timeout_sec=timeout_sec)


def threaded_pipe_reader(stream: TextIO, bucket: list[str], cap: int = 800) -> None:
    try:
        for line in iter(stream.readline, ""):
            bucket.append(line.rstrip("\n"))
            if len(bucket) > cap:
                del bucket[: len(bucket) - cap]
    except Exception:
        return


def parse_mem_to_gb(value: str, default_gb: float = 4.0, min_gb: float = 0.25) -> float:
    text = (value or "").strip().upper()
    m = re.match(r"^(\d+(?:\.\d+)?)([MG])$", text)
    if not m:
        return default_gb
    num = float(m.group(1))
    unit = m.group(2)
    if unit == "M":
        return max(min_gb, num / 1024.0)
    return max(min_gb, num)


def gb_to_mem_str(gb: float, min_gb: float = 0.25) -> str:
    value = max(min_gb, gb)
    if value < 1:
        return f"{int(round(value * 1024))}M"
    return f"{int(value)}G"


def normalize_memory_plan(xmx: str, xms: str, total_gb: float, max_ram_ratio: float) -> tuple[str, str, float]:
    cap_gb = max(1.0, float(total_gb) * float(max_ram_ratio))
    xmx_gb = min(parse_mem_to_gb(xmx), cap_gb)
    xms_gb = min(parse_mem_to_gb(xms), xmx_gb)
    return gb_to_mem_str(xmx_gb), gb_to_mem_str(xms_gb), cap_gb


def extract_start_command_from_line(line: str) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped:
        return None
    if stripped.startswith("#"):
        return None
    if stripped.lower().startswith("rem "):
        return None

    # 支持同一行多个 @args.txt（例如 user_jvm_args + libraries/.../unix_args.txt）
    # 采用“最后一个”更接近实际 java 启动入口，并避免优先命中临时 user_* 参数文件。
    args_matches = list(
        re.finditer(r"@(?:\"([^\"]+\.txt)\"|'([^']+\.txt)'|([^\s]+\.txt))", stripped, flags=re.IGNORECASE)
    )
    if args_matches:
        last = args_matches[-1]
        args_file = last.group(1) or last.group(2) or last.group(3) or ""
        args_file = args_file.strip().strip('"').strip("'")
        if args_file:
            return "argsfile", args_file

    jar_match = re.search(r"(?i)-jar\s+(\"([^\"]+)\"|'([^']+)'|(\S+))", stripped)
    if jar_match:
        jar_name = jar_match.group(2) or jar_match.group(3) or jar_match.group(4) or ""
        jar_name = jar_name.strip().strip('"').strip("'")
        if jar_name:
            return "jar", jar_name

    return None


def oracle_platform_triplet(system_name: str | None = None, machine_name: str | None = None) -> tuple[str, str, str]:
    system = (system_name or platform.system()).lower()
    machine = (machine_name or platform.machine()).lower()

    if system == "linux":
        os_name = "linux"
        ext = "tar.gz"
    elif system == "windows":
        os_name = "windows"
        ext = "zip"
    elif system == "darwin":
        os_name = "macos"
        ext = "tar.gz"
    else:
        raise ValueError(f"unsupported system: {system}")

    if machine in {"x86_64", "amd64"}:
        arch_name = "x64"
    elif machine in {"aarch64", "arm64"}:
        arch_name = "aarch64"
    else:
        raise ValueError(f"unsupported arch for oracle graalvm: {machine}")

    return os_name, arch_name, ext


def adoptium_platform_triplet(system_name: str | None = None, machine_name: str | None = None) -> tuple[str, str, str]:
    system = (system_name or platform.system()).lower()
    machine = (machine_name or platform.machine()).lower()

    if system == "linux":
        os_name = "linux"
        ext = "tar.gz"
    elif system == "windows":
        os_name = "windows"
        ext = "zip"
    elif system == "darwin":
        os_name = "mac"
        ext = "tar.gz"
    else:
        raise ValueError(f"unsupported system: {system}")

    if machine in {"x86_64", "amd64"}:
        arch_name = "x64"
    elif machine in {"aarch64", "arm64"}:
        arch_name = "aarch64"
    elif machine in {"x86", "i386", "i686"}:
        arch_name = "x32"
    else:
        raise ValueError(f"unsupported arch: {machine}")

    return os_name, arch_name, ext


def parse_log_level(value: str) -> LogLevel:
    upper = (value or "INFO").upper()
    return {
        "DEBUG": LogLevel.DEBUG,
        "INFO": LogLevel.INFO,
        "WARN": LogLevel.WARN,
        "WARNING": LogLevel.WARN,
        "ERROR": LogLevel.ERROR,
    }.get(upper, LogLevel.INFO)


def _is_stdout_tty() -> bool:
    return bool(getattr(sys.stdout, "isatty", lambda: False)())


def _should_use_color(policy: ColorPolicy) -> bool:
    if policy == ColorPolicy.NEVER:
        return False
    if policy == ColorPolicy.ALWAYS:
        return True
    if os.getenv("NO_COLOR"):
        return False
    return _is_stdout_tty()


class StructuredLogger:
    def __init__(
        self,
        log_file_path: Path,
        color_policy: ColorPolicy = ColorPolicy.AUTO,
        min_level: LogLevel = LogLevel.INFO,
        download_ui_enabled: bool = True,
        download_ui_running_rows: int = 8,
        download_ui_refresh_interval_sec: float = 0.1,
    ):
        self.log_file_path = log_file_path
        self._lock = threading.RLock()
        self._stdout_tty = _is_stdout_tty()
        force_terminal = bool(color_policy == ColorPolicy.ALWAYS)
        self._use_color = _should_use_color(color_policy)
        self._tty = self._stdout_tty or force_terminal
        self._download_ui_enabled = bool(download_ui_enabled and self._tty)
        self._download_ui_running_rows = max(1, int(download_ui_running_rows))
        self._download_ui_refresh_interval = max(0.02, float(download_ui_refresh_interval_sec))
        self._download_ui_name_width = 36
        self._download_ui_bar_width = 22
        self._download_ui_speed_width = 12
        self._download_ui_size_width = 20
        self._download_ui_eta_width = 12

        self._download_ui_active = False
        self._download_ui_initialized = False
        self._download_ui_rendered_lines = 0
        self._download_total_tasks = 0
        self._download_completed_tasks = 0
        self._download_failed_tasks = 0
        self._download_running_tasks: OrderedDict[str, DownloadUiTaskState] = OrderedDict()
        self._download_last_render_at = 0.0
        self._min_level = min_level
        self._diag_enabled = str(os.getenv("MCASB_DIAG_LOGGING", "")).strip().lower() in {"1", "true", "yes", "on"}

        ensure_parent_dir(self.log_file_path)
        self.log_file_path.write_text("", encoding="utf-8")
        self._emit_runtime_diag("logger.init")

    def _emit_runtime_diag(self, stage: str) -> None:
        if not self._diag_enabled:
            return
        diag = (
            f"stdout_tty={self._stdout_tty}, "
            f"use_color={self._use_color}, "
            f"tty_capable={self._tty}, "
            f"download_ui_enabled={self._download_ui_enabled}, "
            f"NO_COLOR={'1' if os.getenv('NO_COLOR') else '0'}, "
            f"CI={'1' if os.getenv('CI') else '0'}, "
            f"TERM={os.getenv('TERM') or 'unknown'}"
        )
        self.log(stage, diag, LogLevel.DEBUG)

    def is_download_ui_active(self) -> bool:
        with self._lock:
            return bool(self._download_ui_active and self._download_ui_enabled)

    def _should_emit(self, level: LogLevel) -> bool:
        return LOG_LEVEL_PRIORITY.get(level, 20) >= LOG_LEVEL_PRIORITY.get(self._min_level, 20)

    def log(self, stage: str, message: str, level: LogLevel = LogLevel.INFO) -> None:
        if not self._should_emit(level):
            return
        ts = datetime.now().isoformat(timespec="seconds")
        header = f"[{ts}] [{level.value}] [{stage}]"
        plain = f"{header} {message}"
        with self._lock:
            if self._download_ui_active:
                self._clear_download_ui_locked()

            line = plain
            if self._use_color:
                color = ANSI_BY_LEVEL.get(level, "")
                if color:
                    line = f"{color}{header}{ANSI_RESET} {message}"
            self._stdout_write_line(line)

            if self._download_ui_active:
                self._render_download_ui_locked(force=True)

            with self.log_file_path.open("a", encoding="utf-8") as f:
                f.write(plain + "\n")

    def download_ui_start(self, total_tasks: int) -> None:
        with self._lock:
            if not self._download_ui_enabled:
                self._emit_runtime_diag("download.ui.disabled")
                return
            self._emit_runtime_diag("download.ui.start")
            self._download_ui_active = True
            self._download_ui_initialized = False
            self._download_total_tasks = max(0, int(total_tasks))
            self._download_completed_tasks = 0
            self._download_failed_tasks = 0
            self._download_running_tasks.clear()
            self._download_ui_rendered_lines = 0
            self._download_last_render_at = 0.0
            self._download_ui_initialized = True
            self._render_download_ui_locked(force=True)

    def download_ui_task_started(self, task_id: str, task_label: str, total_bytes: int | None = None) -> None:
        with self._lock:
            if not self._download_ui_active:
                return
            label = str(task_label).strip() or task_id
            now = time.monotonic()
            self._download_running_tasks[task_id] = DownloadUiTaskState(
                label=label,
                total_bytes=(int(total_bytes) if total_bytes is not None and total_bytes > 0 else None),
                last_sample_at=now,
                last_sample_bytes=0,
            )
            self._render_download_ui_locked(force=False)

    def download_ui_task_total(self, task_id: str, total_bytes: int | None) -> None:
        with self._lock:
            if not self._download_ui_active:
                return
            task = self._download_running_tasks.get(task_id)
            if not task:
                return
            task.total_bytes = int(total_bytes) if total_bytes is not None and total_bytes > 0 else None
            self._render_download_ui_locked(force=False)

    def download_ui_task_progress(self, task_id: str, delta_bytes: int) -> None:
        with self._lock:
            if not self._download_ui_active:
                return
            task = self._download_running_tasks.get(task_id)
            if not task or delta_bytes <= 0:
                return

            task.downloaded_bytes += int(delta_bytes)
            now = time.monotonic()
            elapsed = max(0.0, now - task.last_sample_at)
            if elapsed > 0:
                instant_speed = max(0.0, (task.downloaded_bytes - task.last_sample_bytes) / elapsed)
                if task.speed_bps <= 0:
                    task.speed_bps = instant_speed
                else:
                    task.speed_bps = task.speed_bps * 0.7 + instant_speed * 0.3
                task.last_sample_at = now
                task.last_sample_bytes = task.downloaded_bytes

            self._render_download_ui_locked(force=False)

    def download_ui_task_finished(self, task_id: str, success: bool) -> None:
        with self._lock:
            if not self._download_ui_active:
                return
            self._download_running_tasks.pop(task_id, None)
            if success:
                self._download_completed_tasks += 1
            else:
                self._download_failed_tasks += 1
            self._render_download_ui_locked(force=True)

    def download_ui_stop(self) -> None:
        with self._lock:
            if not self._download_ui_active:
                return
            self._clear_download_ui_locked()
            self._download_ui_active = False
            self._download_ui_initialized = False
            self._download_running_tasks.clear()
            self._download_ui_rendered_lines = 0
            self._emit_runtime_diag("download.ui.stop")

    def _clear_download_ui_locked(self) -> None:
        if not self._download_ui_enabled:
            return
        lines = self._download_ui_rendered_lines
        if lines <= 0:
            return

        seq: list[str] = [f"\033[{lines}A"]
        for idx in range(lines):
            seq.append("\r\033[2K")
            if idx < lines - 1:
                seq.append("\033[1B")
        if lines > 1:
            seq.append(f"\033[{lines - 1}A")
        seq.append("\r")
        sys.stdout.write("".join(seq))
        sys.stdout.flush()
        self._download_ui_rendered_lines = 0

    def _render_download_ui_locked(self, force: bool) -> None:
        if not self._download_ui_enabled or not self._download_ui_active:
            return
        now = time.monotonic()
        if not force and (now - self._download_last_render_at) < self._download_ui_refresh_interval:
            return

        self._clear_download_ui_locked()
        lines = self._build_download_ui_lines_locked()
        if lines:
            buf = "".join(f"\r\033[2K{line}\n" for line in lines)
            sys.stdout.write(buf)
            sys.stdout.flush()
            self._download_ui_rendered_lines = len(lines)
        self._download_last_render_at = now

    def _build_download_ui_lines_locked(self) -> list[str]:
        done = self._download_completed_tasks + self._download_failed_tasks
        ratio = 0.0
        if self._download_total_tasks > 0:
            ratio = min(1.0, done / self._download_total_tasks)

        summary = f"{done}/{self._download_total_tasks} {self._format_pip_progress_bar(ratio, bar_w=28)}"
        if self._use_color:
            summary = f"\033[1;36m{summary}{ANSI_RESET}"

        lines = [summary]
        visible_tasks = list(self._download_running_tasks.values())[: self._download_ui_running_rows]
        for task in visible_tasks:
            task_ratio: float | None = None
            if task.total_bytes is not None and task.total_bytes > 0:
                task_ratio = min(1.0, task.downloaded_bytes / task.total_bytes)

            speed_txt = self._format_speed(task.speed_bps)
            size_txt = self._format_size(task.downloaded_bytes, task.total_bytes)
            eta_txt = "--:--"
            if task.total_bytes is not None and task.total_bytes > 0 and task.speed_bps > 1:
                remaining = max(0, task.total_bytes - task.downloaded_bytes)
                eta_txt = self._format_eta(remaining / task.speed_bps)

            name_col = self._left_cell(task.label, self._download_ui_name_width)
            bar_col = self._format_pip_progress_bar(task_ratio, bar_w=self._download_ui_bar_width)
            speed_col = self._left_cell(speed_txt, self._download_ui_speed_width)
            size_col = self._left_cell(size_txt, self._download_ui_size_width)
            eta_col = self._left_cell(f"eta {eta_txt}", self._download_ui_eta_width)
            lines.append(f"{name_col} {bar_col} {speed_col} {size_col} {eta_col}")

        while len(lines) < (1 + self._download_ui_running_rows):
            lines.append("")
        return lines

    def _left_cell(self, value: str, width: int) -> str:
        return self._fit_text_to_display_width(str(value or ""), width)

    def _stdout_write_line(self, content: str) -> None:
        sys.stdout.write(content + "\n")
        sys.stdout.flush()

    def _format_pip_progress_bar(self, ratio: float | None, bar_w: int = 20) -> str:
        if ratio is None:
            return f" --%|{'-' * bar_w}|"
        safe_ratio = min(1.0, max(0.0, ratio))
        pct = int(round(safe_ratio * 100.0))
        filled = int(round(bar_w * safe_ratio))
        bar = "█" * filled + "-" * max(0, bar_w - filled)
        return f"{pct:>3}%|{bar}|"

    def _format_speed(self, speed_bps: float) -> str:
        speed = max(0.0, speed_bps)
        if speed < 1.0:
            return "0B/s"
        return f"{self._format_bytes(int(speed))}/s"

    def _format_size(self, downloaded_bytes: int, total_bytes: int | None) -> str:
        if total_bytes is None or total_bytes <= 0:
            return f"{self._format_bytes(downloaded_bytes)}/--"
        return f"{self._format_bytes(downloaded_bytes)}/{self._format_bytes(total_bytes)}"

    def _format_eta(self, eta_seconds: float | None) -> str:
        if eta_seconds is None or eta_seconds < 0 or eta_seconds == float("inf"):
            return "--:--"
        total = int(round(eta_seconds))
        m, s = divmod(total, 60)
        h, m = divmod(m, 60)
        if h > 0:
            return f"{h:d}:{m:02d}:{s:02d}"
        return f"{m:02d}:{s:02d}"

    def _truncate_text(self, text: str, max_len: int) -> str:
        if max_len <= 0:
            return ""
        if len(text) <= max_len:
            return text
        if max_len <= 1:
            return text[:max_len]
        return text[: max_len - 1] + "…"

    def _char_display_width(self, ch: str) -> int:
        if not ch:
            return 0
        cat = unicodedata.category(ch)
        if cat in ("Mn", "Me", "Cf"):
            return 0
        if ch == "\t":
            return 4
        if unicodedata.east_asian_width(ch) in ("W", "F"):
            return 2
        return 1

    def _display_width(self, text: str) -> int:
        return sum(self._char_display_width(ch) for ch in str(text or ""))

    def _fit_text_to_display_width(self, text: str, width: int) -> str:
        if width <= 0:
            return ""

        src = str(text or "")
        cur_w = self._display_width(src)
        if cur_w <= width:
            return src + (" " * (width - cur_w))

        if width == 1:
            return " "

        ellipsis = "…"
        ellipsis_w = self._display_width(ellipsis)
        reserve = max(0, width - ellipsis_w)
        out_chars: list[str] = []
        used = 0
        for ch in src:
            ch_w = self._char_display_width(ch)
            if used + ch_w > reserve:
                break
            out_chars.append(ch)
            used += ch_w

        truncated = "".join(out_chars) + ellipsis
        pad = width - self._display_width(truncated)
        if pad > 0:
            truncated += " " * pad
        return truncated

    def _format_bytes(self, value: int) -> str:
        units = ["B", "KiB", "MiB", "GiB", "TiB"]
        size = float(max(0, value))
        idx = 0
        while size >= 1024.0 and idx < len(units) - 1:
            size /= 1024.0
            idx += 1
        if idx == 0:
            return f"{int(size)}{units[idx]}"
        return f"{size:.2f}{units[idx]}"


def verify_hashes(path: Path, hashes: dict[str, str] | None) -> bool:
    if not hashes:
        return True
    for algo in ("sha512", "sha1"):
        expected = str(hashes.get(algo) or "").strip().lower()
        if not expected:
            continue
        h = hashlib.new(algo)
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 256), b""):
                h.update(chunk)
        return h.hexdigest().lower() == expected
    return True


def _java_bin_name_for_platform() -> str:
    return "java.exe" if os.name == "nt" else "java"


def find_java_home_in_tree(root_dir: Path) -> Path | None:
    """在目录树中寻找最可能的 Java Home（包含 bin/java）。"""
    if not root_dir.exists() or not root_dir.is_dir():
        return None

    bin_name = _java_bin_name_for_platform()
    direct_bin = root_dir / "bin" / bin_name
    if direct_bin.exists() and direct_bin.is_file():
        return root_dir

    candidates: list[tuple[tuple[int, int, int], Path]] = []
    for p in root_dir.rglob(bin_name):
        if not p.is_file() or p.parent.name.lower() != "bin":
            continue
        home = p.parent.parent
        try:
            rel_parts = home.relative_to(root_dir).parts
            depth = len(rel_parts)
        except ValueError:
            depth = 999

        # 优先级：更浅层级 > 含 release 元文件 > 含 lib 目录
        score = (
            depth,
            0 if (home / "release").is_file() else 1,
            0 if (home / "lib").is_dir() else 1,
        )
        candidates.append((score, home))

    if not candidates:
        return None
    return sorted(candidates, key=lambda x: x[0])[0][1]


def normalize_java_home_layout(java_home: Path) -> tuple[Path, bool]:
    """
    归一化 Java Home 目录结构。

    返回值：(resolved_home, changed)
    - resolved_home: 识别到的真实 Java Home（包含 bin/java）
    - changed: 是否对 java_home 目录做了扁平化调整
    """
    java_home.mkdir(parents=True, exist_ok=True)
    resolved = find_java_home_in_tree(java_home)
    if resolved is None:
        return java_home, False

    try:
        if resolved.resolve() == java_home.resolve():
            return java_home, False
    except OSError:
        if resolved == java_home:
            return java_home, False

    tmp_dir = java_home.parent / f"{java_home.name}.normalize_tmp"
    if tmp_dir.exists():
        shutil.rmtree(tmp_dir)
    tmp_dir.mkdir(parents=True, exist_ok=True)

    # 先拷贝到临时目录，避免在删除 java_home 子树时丢失源数据
    for item in resolved.iterdir():
        target = tmp_dir / item.name
        if item.is_dir():
            shutil.copytree(item, target)
        else:
            shutil.copy2(item, target)

    for child in list(java_home.iterdir()):
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()

    for item in tmp_dir.iterdir():
        target = java_home / item.name
        shutil.move(str(item), str(target))
    shutil.rmtree(tmp_dir)
    return java_home, True


def extract_archive(archive_path: Path, target_dir: Path) -> Path:
    target_dir.mkdir(parents=True, exist_ok=True)
    name = archive_path.name.lower()
    if name.endswith(".zip"):
        with zipfile.ZipFile(archive_path, "r") as zf:
            zf.extractall(target_dir)
    elif name.endswith(".tar.gz") or name.endswith(".tgz"):
        with tarfile.open(archive_path, "r:gz") as tf:
            tf.extractall(target_dir)
    else:
        raise ValueError(f"不支持的压缩格式: {archive_path.name}")

    children = [p for p in target_dir.iterdir()]
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return target_dir


def extract_archive_payload_into(archive_path: Path, target_dir: Path, tag: str) -> None:
    stage_dir = target_dir / f".extract_{tag}"
    if stage_dir.exists():
        shutil.rmtree(stage_dir)
    stage_dir.mkdir(parents=True, exist_ok=True)

    extract_archive(archive_path, stage_dir)
    payload_root = stage_dir
    children = [p for p in stage_dir.iterdir()]
    if len(children) == 1 and children[0].is_dir():
        payload_root = children[0]

    for item in payload_root.iterdir():
        replace_path(item, target_dir / item.name)

    shutil.rmtree(stage_dir)


class Downloader:
    def __init__(self, cfg: DownloadConfig, logger: StructuredLogger | None = None):
        self.cfg = cfg
        self.logger = logger

    def _log(self, stage: str, message: str, level: LogLevel = LogLevel.INFO) -> None:
        if self.logger:
            self.logger.log(stage, message, level)

    def download_file(
        self,
        url: str,
        out: Path,
        stage: str = "install.download",
        headers: dict[str, str] | None = None,
        session_factory: Callable[[], requests.Session] | None = None,
        progress_cb: Callable[[int], None] | None = None,
        total_bytes_cb: Callable[[int | None], None] | None = None,
    ) -> Path:
        ensure_parent_dir(out)
        last_err: Exception | None = None
        for attempt in range(1, self.cfg.max_retries + 1):
            session = session_factory() if session_factory is not None else requests.Session()
            configure_requests_session(session, proxies=self.cfg.proxies, trust_env=self.cfg.trust_env)
            try:
                if not (self.logger and self.logger.is_download_ui_active()):
                    self._log(stage, f"开始下载: {url} -> {out}")
                with session.get(
                    url,
                    stream=True,
                    headers=headers,
                    timeout=(self.cfg.connect_timeout, self.cfg.read_timeout),
                ) as resp:
                    resp.raise_for_status()
                    header_value = str(resp.headers.get("Content-Length") or "").strip()
                    total_bytes = int(header_value) if header_value.isdigit() and int(header_value) > 0 else None
                    if total_bytes_cb is not None:
                        total_bytes_cb(total_bytes)
                    total = 0
                    with out.open("wb") as f:
                        for chunk in resp.iter_content(chunk_size=self.cfg.chunk_size):
                            if chunk:
                                f.write(chunk)
                                total += len(chunk)
                                if progress_cb is not None:
                                    progress_cb(len(chunk))
                if not (self.logger and self.logger.is_download_ui_active()):
                    self._log(stage, f"下载完成: {out.name} ({total} bytes)")
                return out
            except requests.RequestException as e:
                last_err = e
                self._log(
                    stage,
                    f"下载失败重试({attempt}/{self.cfg.max_retries}): {url} ({type(e).__name__})",
                    level=LogLevel.WARN,
                )
                safe_unlink(out)
                if attempt < self.cfg.max_retries:
                    time.sleep(self.cfg.retry_backoff_sec * attempt)
            except OSError as e:
                last_err = e
                self._log(stage, f"下载写入失败: {url} ({type(e).__name__})", level=LogLevel.ERROR)
                safe_unlink(out)
                break
            finally:
                session.close()

        raise DownloadError(f"下载失败: {url} ({type(last_err).__name__ if last_err else 'unknown'})") from last_err

    def download_task(self, task: DownloadTask) -> Path:
        if not task.urls:
            raise DownloadError(f"下载任务缺少可用URL: {task.out}")
        task_id = str(task.task_id or str(task.out))
        if self.logger:
            self.logger.download_ui_task_started(task_id=task_id, task_label=task.out.name)
        logger = self.logger

        last_err: Exception | None = None
        for url in task.urls:
            try:
                out = self.download_file(
                    url,
                    task.out,
                    stage=task.stage,
                    headers=task.headers,
                    session_factory=task.session_factory,
                    progress_cb=(lambda delta: logger.download_ui_task_progress(task_id=task_id, delta_bytes=delta))
                    if logger
                    else None,
                    total_bytes_cb=(lambda total: logger.download_ui_task_total(task_id=task_id, total_bytes=total))
                    if logger
                    else None,
                )
                if not verify_hashes(out, task.expected_hashes):
                    safe_unlink(out)
                    raise DownloadError(f"hash_mismatch:{out}")
                if task.extract_to is not None:
                    extract_archive(out, task.extract_to)
                if self.logger:
                    self.logger.download_ui_task_finished(task_id=task_id, success=True)
                return out
            except (DownloadError, OSError, zipfile.BadZipFile, tarfile.TarError, ValueError) as e:
                last_err = e
                self._log(task.stage, f"下载任务候选源失败: {url} ({type(e).__name__})", level=LogLevel.WARN)
                safe_unlink(task.out)
                continue
        if self.logger:
            self.logger.download_ui_task_finished(task_id=task_id, success=False)
        raise DownloadError(f"下载任务失败: {task.out} ({type(last_err).__name__ if last_err else 'unknown'})")

    def download_files(self, tasks: list[DownloadTask]) -> tuple[list[Path], list[DownloadFailure]]:
        if not tasks:
            return [], []

        workers = 1
        if self.cfg.enable_parallel_download:
            workers = max(1, min(self.cfg.max_workers, len(tasks)))

        done: list[Path] = []
        failed: list[DownloadFailure] = []

        for idx, task in enumerate(tasks, start=1):
            task.task_id = f"dl-{idx}:{task.out.name}"

        if self.logger:
            self.logger.download_ui_start(total_tasks=len(tasks))

        try:
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="mcasb-dl") as pool:
                future_map = {pool.submit(self.download_task, t): t for t in tasks}
                for fut in as_completed(future_map):
                    task = future_map[fut]
                    try:
                        done.append(fut.result())
                    except DownloadError as e:
                        failed.append(_classify_download_failure(task, e))
                        self._log(task.stage, f"下载失败: {task.out} ({type(e).__name__})", level=LogLevel.ERROR)
        finally:
            if self.logger:
                self.logger.download_ui_stop()

        return done, failed
