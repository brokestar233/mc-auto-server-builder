from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast


class ConfigError(ValueError):
    """配置加载与校验异常。"""


def _format_expected(expected: str) -> str:
    return f"期望 {expected}"


def _raise_config_error(path: str, message: str) -> "None":
    raise ConfigError(f"配置项 {path}: {message}")


def _normalize_object(value: object, path: str) -> dict[str, object]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        _raise_config_error(path, f"{_format_expected('JSON 对象')}，实际为 {type(value).__name__}")
    normalized = cast(Mapping[object, object], value)
    return {str(key): item for key, item in normalized.items()}


def _normalize_bool(value: object, path: str, *, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "y", "on"}:
            return True
        if normalized in {"0", "false", "no", "n", "off"}:
            return False
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    _raise_config_error(path, f"{_format_expected('布尔值')}，实际为 {value!r}")
    return default


def _normalize_int(value: object, path: str, *, default: int, minimum: int | None = None) -> int:
    if value is None or value == "":
        result = default
    elif isinstance(value, bool):
        _raise_config_error(path, f"{_format_expected('整数')}，实际为布尔值 {value!r}")
    elif isinstance(value, int):
        result = value
    elif isinstance(value, float) and value.is_integer():
        result = int(value)
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            result = default
        else:
            try:
                result = int(text)
            except ValueError as exc:
                raise ConfigError(f"配置项 {path}: {_format_expected('整数')}，实际为 {value!r}") from exc
    else:
        _raise_config_error(path, f"{_format_expected('整数')}，实际为 {type(value).__name__}")
    if minimum is not None and result < minimum:
        _raise_config_error(path, f"数值不能小于 {minimum}，实际为 {result}")
    return result


def _normalize_float(value: object, path: str, *, default: float, minimum: float | None = None) -> float:
    if value is None or value == "":
        result = default
    elif isinstance(value, bool):
        _raise_config_error(path, f"{_format_expected('浮点数')}，实际为布尔值 {value!r}")
    elif isinstance(value, (int, float)):
        result = float(value)
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            result = default
        else:
            try:
                result = float(text)
            except ValueError as exc:
                raise ConfigError(f"配置项 {path}: {_format_expected('浮点数')}，实际为 {value!r}") from exc
    else:
        _raise_config_error(path, f"{_format_expected('浮点数')}，实际为 {type(value).__name__}")
    if minimum is not None and result < minimum:
        _raise_config_error(path, f"数值不能小于 {minimum}，实际为 {result}")
    return result


def _normalize_str(value: object, path: str, *, default: str) -> str:
    if value is None:
        return default
    if isinstance(value, (str, int, float)) and not isinstance(value, bool):
        text = str(value).strip()
        return text or default
    _raise_config_error(path, f"{_format_expected('字符串')}，实际为 {type(value).__name__}")
    return default


def _normalize_str_list(value: object, path: str, *, default: list[str] | None = None) -> list[str]:
    if value is None:
        return list(default or [])
    items: Sequence[object]
    if isinstance(value, str):
        items = [value]
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        items = value
    else:
        _raise_config_error(path, f"{_format_expected('字符串列表')}，实际为 {type(value).__name__}")
    result: list[str] = []
    for index, item in enumerate(items):
        if isinstance(item, bool) or not isinstance(item, (str, int, float)):
            _raise_config_error(f"{path}[{index}]", f"{_format_expected('字符串')}，实际为 {type(item).__name__}")
        text = str(item).strip()
        if text:
            result.append(text)
    return result


def _reject_unknown_fields(section: str, payload: dict[str, object], allowed: set[str]) -> None:
    unknown = sorted(set(payload) - allowed)
    if unknown:
        _raise_config_error(section, f"包含未知字段: {', '.join(unknown)}")


@dataclass(slots=True)
class MemoryConfig:
    xmx: str = "6G"
    xms: str = "4G"
    max_ram_ratio: float = 0.7


@dataclass(slots=True)
class RuntimeConfig:
    max_attempts: int = 20
    start_timeout: int = 300
    keep_running: bool = False
    startup_soft_timeout: int = 45
    startup_hard_timeout: int = 300
    startup_probe_interval_sec: float = 1.0
    startup_command_probe_enabled: bool = True
    startup_command_probe_initial_delay_sec: float = 12.0
    startup_command_probe_retry_sec: float = 6.0


@dataclass(slots=True)
class AIConfig:
    enabled: bool = False
    provider: str = "ollama"
    model: str = "qwen3.5:4b"
    endpoint: str = "http://127.0.0.1:11434/api/generate"
    base_url: str = ""
    api_key: str = ""
    chat_path: str = "/v1/chat/completions"
    stream: bool = False
    timeout_sec: int = 300
    max_retries: int = 2
    retry_backoff_sec: float = 1.0
    temperature: float = 0.2
    top_p: float = 0.95
    max_tokens: int = 1024
    stop: list[str] = field(default_factory=list)
    debug: bool = False


@dataclass(slots=True)
class LoggingConfig:
    level: str = "INFO"
    color_policy: str = "auto"


@dataclass(slots=True)
class DownloadRuntimeConfig:
    enable_parallel_download: bool = True
    max_workers: int = 32
    manifest_resolve_parallel_enabled: bool = True
    manifest_resolve_max_workers: int = 16
    curseforge_manifest_batch_size: int = 50
    curseforge_manifest_batch_retry: int = 2
    connect_timeout: int = 15
    read_timeout: int = 120
    max_retries: int = 3
    retry_backoff_sec: float = 1.0
    chunk_size: int = 1024 * 256
    terminal_ui_enabled: bool = True
    terminal_ui_running_rows: int = 8
    terminal_ui_refresh_interval_sec: float = 0.1


@dataclass(slots=True)
class ProxyConfig:
    http: str = ""
    https: str = ""
    all: str = ""
    no_proxy: str = ""
    trust_env: bool = True

    def to_requests_proxies(self) -> dict[str, str] | None:
        proxies = {
            "http": self.http.strip(),
            "https": self.https.strip(),
            "all": self.all.strip(),
            "no_proxy": self.no_proxy.strip(),
        }
        normalized = {key: value for key, value in proxies.items() if value}
        return normalized or None


@dataclass(slots=True)
class AppConfig:
    memory: MemoryConfig = field(default_factory=MemoryConfig)
    runtime: RuntimeConfig = field(default_factory=RuntimeConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    download: DownloadRuntimeConfig = field(default_factory=DownloadRuntimeConfig)
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    server_port: int = 25565
    extra_jvm_flags: list[str] = field(default_factory=list)
    user_blacklist_regex: list[str] = field(default_factory=list)
    github_api_key: str = ""
    curseforge_api_key: str = ""
    modrinth_api_token: str = ""
    modrinth_user_agent: str = "brokestar233/mc-auto-server-builder"
    graalvm_external_packages: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path | None) -> "AppConfig":
        if path is None:
            return cls()
        p = Path(path)
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ConfigError(f"配置文件 {p} 不是合法 JSON: {exc.msg} (line {exc.lineno}, column {exc.colno})") from exc
        if not isinstance(data, dict):
            raise ConfigError(f"配置文件 {p} 顶层必须是 JSON 对象")

        allowed_top_level = {
            "memory",
            "runtime",
            "ai",
            "logging",
            "download",
            "proxy",
            "server_port",
            "extra_jvm_flags",
            "user_blacklist_regex",
            "github_api_key",
            "curseforge_api_key",
            "modrinth_api_token",
            "modrinth_user_agent",
            "graalvm_external_packages",
        }
        _reject_unknown_fields("<root>", data, allowed_top_level)

        memory_data = _normalize_object(data.get("memory"), "memory")
        runtime_data = _normalize_object(data.get("runtime"), "runtime")
        ai_data = _normalize_object(data.get("ai"), "ai")
        logging_data = _normalize_object(data.get("logging"), "logging")
        download_data = _normalize_object(data.get("download"), "download")
        proxy_data = _normalize_object(data.get("proxy"), "proxy")

        _reject_unknown_fields("memory", memory_data, {"xmx", "xms", "max_ram_ratio"})
        _reject_unknown_fields(
            "runtime",
            runtime_data,
            {
                "max_attempts",
                "start_timeout",
                "keep_running",
                "startup_soft_timeout",
                "startup_hard_timeout",
                "startup_probe_interval_sec",
                "startup_command_probe_enabled",
                "startup_command_probe_initial_delay_sec",
                "startup_command_probe_retry_sec",
            },
        )
        _reject_unknown_fields(
            "ai",
            ai_data,
            {
                "enabled",
                "provider",
                "model",
                "endpoint",
                "base_url",
                "api_key",
                "chat_path",
                "stream",
                "timeout_sec",
                "max_retries",
                "retry_backoff_sec",
                "temperature",
                "top_p",
                "max_tokens",
                "stop",
                "debug",
            },
        )
        _reject_unknown_fields("logging", logging_data, {"level", "color_policy"})
        _reject_unknown_fields(
            "download",
            download_data,
            {
                "enable_parallel_download",
                "max_workers",
                "manifest_resolve_parallel_enabled",
                "manifest_resolve_max_workers",
                "curseforge_manifest_batch_size",
                "curseforge_manifest_batch_retry",
                "connect_timeout",
                "read_timeout",
                "max_retries",
                "retry_backoff_sec",
                "chunk_size",
                "terminal_ui_enabled",
                "terminal_ui_running_rows",
                "terminal_ui_refresh_interval_sec",
            },
        )
        _reject_unknown_fields("proxy", proxy_data, {"http", "https", "all", "no_proxy", "trust_env"})
        return cls(
            memory=MemoryConfig(
                xmx=_normalize_str(memory_data.get("xmx"), "memory.xmx", default="6G"),
                xms=_normalize_str(memory_data.get("xms"), "memory.xms", default="4G"),
                max_ram_ratio=_normalize_float(
                    memory_data.get("max_ram_ratio"),
                    "memory.max_ram_ratio",
                    default=0.7,
                    minimum=0.0,
                ),
            ),
            runtime=RuntimeConfig(
                max_attempts=_normalize_int(
                    runtime_data.get("max_attempts"), "runtime.max_attempts", default=20, minimum=1
                ),
                start_timeout=_normalize_int(
                    runtime_data.get("start_timeout"), "runtime.start_timeout", default=300, minimum=1
                ),
                keep_running=_normalize_bool(runtime_data.get("keep_running"), "runtime.keep_running", default=False),
                startup_soft_timeout=_normalize_int(
                    runtime_data.get("startup_soft_timeout"),
                    "runtime.startup_soft_timeout",
                    default=45,
                    minimum=1,
                ),
                startup_hard_timeout=_normalize_int(
                    runtime_data.get("startup_hard_timeout"),
                    "runtime.startup_hard_timeout",
                    default=300,
                    minimum=1,
                ),
                startup_probe_interval_sec=_normalize_float(
                    runtime_data.get("startup_probe_interval_sec"),
                    "runtime.startup_probe_interval_sec",
                    default=1.0,
                    minimum=0.0,
                ),
                startup_command_probe_enabled=_normalize_bool(
                    runtime_data.get("startup_command_probe_enabled"),
                    "runtime.startup_command_probe_enabled",
                    default=True,
                ),
                startup_command_probe_initial_delay_sec=_normalize_float(
                    runtime_data.get("startup_command_probe_initial_delay_sec"),
                    "runtime.startup_command_probe_initial_delay_sec",
                    default=12.0,
                    minimum=0.0,
                ),
                startup_command_probe_retry_sec=_normalize_float(
                    runtime_data.get("startup_command_probe_retry_sec"),
                    "runtime.startup_command_probe_retry_sec",
                    default=6.0,
                    minimum=0.0,
                ),
            ),
            ai=AIConfig(
                enabled=_normalize_bool(ai_data.get("enabled"), "ai.enabled", default=False),
                provider=_normalize_str(ai_data.get("provider"), "ai.provider", default="ollama"),
                model=_normalize_str(ai_data.get("model"), "ai.model", default="qwen3.5:4b"),
                endpoint=_normalize_str(
                    ai_data.get("endpoint"), "ai.endpoint", default="http://127.0.0.1:11434/api/generate"
                ),
                base_url=_normalize_str(ai_data.get("base_url"), "ai.base_url", default=""),
                api_key=_normalize_str(ai_data.get("api_key"), "ai.api_key", default=""),
                chat_path=_normalize_str(ai_data.get("chat_path"), "ai.chat_path", default="/v1/chat/completions"),
                stream=_normalize_bool(ai_data.get("stream"), "ai.stream", default=False),
                timeout_sec=_normalize_int(ai_data.get("timeout_sec"), "ai.timeout_sec", default=300, minimum=1),
                max_retries=_normalize_int(ai_data.get("max_retries"), "ai.max_retries", default=2, minimum=0),
                retry_backoff_sec=_normalize_float(
                    ai_data.get("retry_backoff_sec"), "ai.retry_backoff_sec", default=1.0, minimum=0.0
                ),
                temperature=_normalize_float(ai_data.get("temperature"), "ai.temperature", default=0.2, minimum=0.0),
                top_p=_normalize_float(ai_data.get("top_p"), "ai.top_p", default=0.95, minimum=0.0),
                max_tokens=_normalize_int(ai_data.get("max_tokens"), "ai.max_tokens", default=1024, minimum=1),
                stop=_normalize_str_list(ai_data.get("stop"), "ai.stop"),
                debug=_normalize_bool(ai_data.get("debug"), "ai.debug", default=False),
            ),
            logging=LoggingConfig(
                level=_normalize_str(logging_data.get("level"), "logging.level", default="INFO"),
                color_policy=_normalize_str(
                    logging_data.get("color_policy"), "logging.color_policy", default="auto"
                ),
            ),
            download=DownloadRuntimeConfig(
                enable_parallel_download=_normalize_bool(
                    download_data.get("enable_parallel_download"),
                    "download.enable_parallel_download",
                    default=True,
                ),
                max_workers=_normalize_int(download_data.get("max_workers"), "download.max_workers", default=32, minimum=1),
                manifest_resolve_parallel_enabled=_normalize_bool(
                    download_data.get("manifest_resolve_parallel_enabled"),
                    "download.manifest_resolve_parallel_enabled",
                    default=True,
                ),
                manifest_resolve_max_workers=_normalize_int(
                    download_data.get("manifest_resolve_max_workers"),
                    "download.manifest_resolve_max_workers",
                    default=16,
                    minimum=1,
                ),
                curseforge_manifest_batch_size=_normalize_int(
                    download_data.get("curseforge_manifest_batch_size"),
                    "download.curseforge_manifest_batch_size",
                    default=50,
                    minimum=1,
                ),
                curseforge_manifest_batch_retry=_normalize_int(
                    download_data.get("curseforge_manifest_batch_retry"),
                    "download.curseforge_manifest_batch_retry",
                    default=2,
                    minimum=0,
                ),
                connect_timeout=_normalize_int(
                    download_data.get("connect_timeout"), "download.connect_timeout", default=15, minimum=1
                ),
                read_timeout=_normalize_int(download_data.get("read_timeout"), "download.read_timeout", default=120, minimum=1),
                max_retries=_normalize_int(download_data.get("max_retries"), "download.max_retries", default=3, minimum=1),
                retry_backoff_sec=_normalize_float(
                    download_data.get("retry_backoff_sec"),
                    "download.retry_backoff_sec",
                    default=1.0,
                    minimum=0.0,
                ),
                chunk_size=_normalize_int(download_data.get("chunk_size"), "download.chunk_size", default=1024 * 256, minimum=1),
                terminal_ui_enabled=_normalize_bool(
                    download_data.get("terminal_ui_enabled"), "download.terminal_ui_enabled", default=True
                ),
                terminal_ui_running_rows=_normalize_int(
                    download_data.get("terminal_ui_running_rows"),
                    "download.terminal_ui_running_rows",
                    default=8,
                    minimum=1,
                ),
                terminal_ui_refresh_interval_sec=_normalize_float(
                    download_data.get("terminal_ui_refresh_interval_sec"),
                    "download.terminal_ui_refresh_interval_sec",
                    default=0.1,
                    minimum=0.0,
                ),
            ),
            proxy=ProxyConfig(
                http=_normalize_str(proxy_data.get("http"), "proxy.http", default=""),
                https=_normalize_str(proxy_data.get("https"), "proxy.https", default=""),
                all=_normalize_str(proxy_data.get("all"), "proxy.all", default=""),
                no_proxy=_normalize_str(proxy_data.get("no_proxy"), "proxy.no_proxy", default=""),
                trust_env=_normalize_bool(proxy_data.get("trust_env"), "proxy.trust_env", default=True),
            ),
            server_port=_normalize_int(data.get("server_port"), "server_port", default=25565, minimum=1),
            extra_jvm_flags=_normalize_str_list(data.get("extra_jvm_flags"), "extra_jvm_flags"),
            user_blacklist_regex=_normalize_str_list(data.get("user_blacklist_regex"), "user_blacklist_regex"),
            github_api_key=_normalize_str(data.get("github_api_key"), "github_api_key", default=""),
            curseforge_api_key=_normalize_str(data.get("curseforge_api_key"), "curseforge_api_key", default=""),
            modrinth_api_token=_normalize_str(data.get("modrinth_api_token"), "modrinth_api_token", default=""),
            modrinth_user_agent=_normalize_str(
                data.get("modrinth_user_agent"),
                "modrinth_user_agent",
                default="brokestar233/mc-auto-server-builder",
            ),
            graalvm_external_packages=_normalize_str_list(data.get("graalvm_external_packages"), "graalvm_external_packages"),
        )
