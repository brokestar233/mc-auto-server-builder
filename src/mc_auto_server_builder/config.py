from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class MemoryConfig:
    xmx: str = "6G"
    xms: str = "4G"
    max_ram_ratio: float = 0.7


@dataclass(slots=True)
class RuntimeConfig:
    max_attempts: int = 8
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
class AppConfig:
    memory: MemoryConfig = field(default_factory=MemoryConfig)
    runtime: RuntimeConfig = field(default_factory=RuntimeConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    download: DownloadRuntimeConfig = field(default_factory=DownloadRuntimeConfig)
    server_port: int = 25565
    extra_jvm_flags: list[str] = field(default_factory=list)
    user_blacklist_regex: list[str] = field(default_factory=list)
    github_api_key: str = ""
    oracle_download_cookies: str = ""
    curseforge_api_key: str = ""
    modrinth_api_token: str = ""
    modrinth_user_agent: str = "brokestar233/mc-auto-server-builder"
    graalvm_external_packages: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path | None) -> "AppConfig":
        if path is None:
            return cls()
        p = Path(path)
        data = json.loads(p.read_text(encoding="utf-8"))
        ai_data = data.get("ai", {})
        ai_stop = ai_data.get("stop", [])
        if isinstance(ai_stop, str):
            ai_stop = [ai_stop]
        elif not isinstance(ai_stop, list):
            ai_stop = []
        return cls(
            memory=MemoryConfig(**data.get("memory", {})),
            runtime=RuntimeConfig(**data.get("runtime", {})),
            ai=AIConfig(
                enabled=bool(ai_data.get("enabled", False)),
                provider=str(ai_data.get("provider", "ollama") or "ollama"),
                model=str(ai_data.get("model", "qwen3.5:4b") or "qwen3.5:4b"),
                endpoint=str(ai_data.get("endpoint", "http://127.0.0.1:11434/api/generate") or "http://127.0.0.1:11434/api/generate"),
                base_url=str(ai_data.get("base_url", "") or ""),
                api_key=str(ai_data.get("api_key", "") or ""),
                chat_path=str(ai_data.get("chat_path", "/v1/chat/completions") or "/v1/chat/completions"),
                stream=bool(ai_data.get("stream", False)),
                timeout_sec=int(ai_data.get("timeout_sec", 300) or 300),
                max_retries=int(ai_data.get("max_retries", 2) or 2),
                retry_backoff_sec=float(ai_data.get("retry_backoff_sec", 1.0) or 1.0),
                temperature=float(ai_data.get("temperature", 0.2) or 0.2),
                top_p=float(ai_data.get("top_p", 0.95) or 0.95),
                max_tokens=int(ai_data.get("max_tokens", 1024) or 1024),
                stop=[str(x) for x in ai_stop if str(x).strip()],
                debug=bool(ai_data.get("debug", False)),
            ),
            logging=LoggingConfig(**data.get("logging", {})),
            download=DownloadRuntimeConfig(**data.get("download", {})),
            server_port=data.get("server_port", 25565),
            extra_jvm_flags=data.get("extra_jvm_flags", []),
            user_blacklist_regex=data.get("user_blacklist_regex", []),
            github_api_key=data.get("github_api_key", "") or "",
            oracle_download_cookies=data.get("oracle_download_cookies", "") or "",
            curseforge_api_key=data.get("curseforge_api_key", "") or "",
            modrinth_api_token=data.get("modrinth_api_token", "") or "",
            modrinth_user_agent=(
                data.get("modrinth_user_agent", "brokestar233/mc-auto-server-builder")
                or "brokestar233/mc-auto-server-builder"
            ),
            graalvm_external_packages=[str(x) for x in data.get("graalvm_external_packages", []) if str(x).strip()],
        )
