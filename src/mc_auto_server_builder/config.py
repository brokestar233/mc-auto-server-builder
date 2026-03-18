from __future__ import annotations

from dataclasses import dataclass, field
import json
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


@dataclass(slots=True)
class AIConfig:
    enabled: bool = False
    provider: str = "ollama"
    model: str = "qwen3.5:4b"
    endpoint: str = "http://127.0.0.1:11434/api/generate"


@dataclass(slots=True)
class AppConfig:
    memory: MemoryConfig = field(default_factory=MemoryConfig)
    runtime: RuntimeConfig = field(default_factory=RuntimeConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    server_port: int = 25565
    extra_jvm_flags: list[str] = field(default_factory=list)
    user_blacklist_regex: list[str] = field(default_factory=list)
    github_api_key: str = ""
    curseforge_api_key: str = ""
    modrinth_api_token: str = ""
    modrinth_user_agent: str = "brokestar/mc-auto-server-builder"

    @classmethod
    def load(cls, path: str | Path | None) -> "AppConfig":
        if path is None:
            return cls()
        p = Path(path)
        data = json.loads(p.read_text(encoding="utf-8"))
        return cls(
            memory=MemoryConfig(**data.get("memory", {})),
            runtime=RuntimeConfig(**data.get("runtime", {})),
            ai=AIConfig(**data.get("ai", {})),
            server_port=data.get("server_port", 25565),
            extra_jvm_flags=data.get("extra_jvm_flags", []),
            user_blacklist_regex=data.get("user_blacklist_regex", []),
            github_api_key=data.get("github_api_key", "") or "",
            curseforge_api_key=data.get("curseforge_api_key", "") or "",
            modrinth_api_token=data.get("modrinth_api_token", "") or "",
            modrinth_user_agent=data.get("modrinth_user_agent", "brokestar/mc-auto-server-builder") or "brokestar/mc-auto-server-builder",
        )
