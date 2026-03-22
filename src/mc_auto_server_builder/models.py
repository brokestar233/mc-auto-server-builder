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
    type: Literal["remove_mods", "adjust_memory", "change_java", "stop_and_report", "report_manual_fix", "bisect_mods", "move_bisect_mods"]
    targets: list[str] | None = None
    rollback_on_failure: bool | None = None
    xmx: str | None = None
    xms: str | None = None
    version: int | None = None
    reason: str | None = None
    final_reason: str | None = None
    manual_steps: list[str] | None = None
    evidence: list[str] | None = None
    bisect_mode: Literal["initial", "switch_group", "continue_failed_group"] | None = None
    bisect_reason: str | None = None
    move_candidates: list[str] | None = None
    max_rounds: int | None = None
    allow_dependency_moves: bool | None = None


@dataclass(slots=True)
class BisectMoveRecord:
    mod_name: str
    from_group: str
    to_group: str
    reason: str = ""


@dataclass(slots=True)
class BisectRoundRecord:
    round_index: int
    requested_targets: list[str] = field(default_factory=list)
    bisect_mode: str = "initial"
    tested_side: str = "keep"
    kept_group: list[str] = field(default_factory=list)
    tested_group: list[str] = field(default_factory=list)
    moved_mods: list[BisectMoveRecord] = field(default_factory=list)
    result: str = "unknown"
    trigger_reason: str = ""
    split_strategy: str = "stable_sorted_halves"
    startup_success: bool = False
    failure_kind: str = ""
    failure_detail: str = ""
    continuation_targets: list[str] = field(default_factory=list)
    pending_other_group: list[str] = field(default_factory=list)
    next_allowed_requests: list[str] = field(default_factory=list)
    fallback_targets: list[str] = field(default_factory=list)
    suspects_invalidated: bool = False
    notes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class BisectSession:
    active: bool = False
    source_mods: list[str] = field(default_factory=list)
    suspect_mods: list[str] = field(default_factory=list)
    safe_mods: list[str] = field(default_factory=list)
    phase: str = "initial"
    rounds: list[BisectRoundRecord] = field(default_factory=list)
    final_suspects: list[str] = field(default_factory=list)
    stopped_reason: str = ""
    last_round_feedback: dict[str, Any] = field(default_factory=dict)
    pending_group: list[str] = field(default_factory=list)
    continuation_targets: list[str] = field(default_factory=list)
    next_allowed_requests: list[str] = field(default_factory=list)
    completed_requests: list[str] = field(default_factory=list)
    completed_request_tokens: list[str] = field(default_factory=list)
    fallback_targets: list[str] = field(default_factory=list)
    suspects_invalidated: bool = False
    progress_token: str = ""
    stagnant_rounds: int = 0
    last_preflight_block_reason: str = ""
    last_preflight_block_details: list[str] = field(default_factory=list)
    pending_round_plan: dict[str, Any] = field(default_factory=dict)
    success_ready: bool = False
    success_guard_reason: str = ""
    success_guard_history: list[str] = field(default_factory=list)
    consecutive_same_issue_on_success: int = 0


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
    user_summary: str = ""
    suggested_manual_steps: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ActionPreflight:
    action_type: str
    risk: str
    allowed: bool
    reason: str
    details: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AttemptTrace:
    attempt: int
    stage: str
    status: str
    context_summary: dict[str, Any] = field(default_factory=dict)
    ai_result: dict[str, Any] = field(default_factory=dict)
    action_plan: list[dict[str, Any]] = field(default_factory=list)
    preflight: list[dict[str, Any]] = field(default_factory=list)
    execution: list[dict[str, Any]] = field(default_factory=list)
    rollback: list[dict[str, Any]] = field(default_factory=list)
