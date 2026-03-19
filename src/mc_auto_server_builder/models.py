from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

LoaderType = Literal["forge", "neoforge", "fabric", "quilt", "unknown"]
InputType = Literal["local_zip", "curseforge", "modrinth", "url"]


@dataclass(slots=True)
class PackInput:
    input_type: InputType
    source: str
    file_id: str | None = None


@dataclass(slots=True)
class ModInfo:
    name: str
    project_id: str | None = None
    file_id: str | None = None


@dataclass(slots=True)
class PackManifest:
    pack_name: str
    mc_version: str
    loader: LoaderType
    loader_version: str | None = None
    mods: list[ModInfo] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class WorkDirs:
    root: Path
    client_temp: Path
    server: Path
    backups: Path
    logs: Path
    java_bins: Path
    db: Path


@dataclass(slots=True)
class StartResult:
    success: bool
    done_detected: bool
    command_probe_detected: bool
    port_open_detected: bool
    process_alive: bool
    success_source: str
    exit_code: int | None
    log_path: Path
    crash_dir: Path
    readiness_evidence: list[str] = field(default_factory=list)
    stdout_tail: str = ""
    stderr_tail: str = ""


@dataclass(slots=True)
class AIAction:
    type: Literal["remove_mods", "adjust_memory", "change_java", "stop_and_report"]
    targets: list[str] | None = None
    xmx: str | None = None
    xms: str | None = None
    version: int | None = None
    reason: str | None = None
    final_reason: str | None = None


@dataclass(slots=True)
class AIResult:
    primary_issue: str
    confidence: float
    reason: str
    actions: list[AIAction] = field(default_factory=list)
    thought_chain: list[str] = field(default_factory=list)
    input_summary: str = ""
    hit_deleted_mods: list[str] = field(default_factory=list)
    dependency_chains: list[list[str]] = field(default_factory=list)
    deletion_rationale: list[str] = field(default_factory=list)
    conflicts_or_exceptions: list[str] = field(default_factory=list)
