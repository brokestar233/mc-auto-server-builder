from __future__ import annotations

import json
from dataclasses import dataclass, field

from .defaults import SUPPORTED_JAVA_VERSIONS
from .models import ActionPreflight


@dataclass(slots=True)
class ContinueAfterRestoreModsState:
    continue_allowed: bool = False
    post_remove_active_mods: list[str] = field(default_factory=list)
    rollback_snapshot_tag: str = ""
    continued: bool = False
    problem_changed: bool = False


@dataclass(slots=True)
class BisectSessionSnapshot:
    next_allowed_requests: list[str] = field(default_factory=list)
    completed_requests: list[str] = field(default_factory=list)
    completed_request_tokens: list[str] = field(default_factory=list)
    pending_group: list[str] = field(default_factory=list)
    continuation_targets: list[str] = field(default_factory=list)
    fallback_targets: list[str] = field(default_factory=list)
    suspects_invalidated: bool = False


@dataclass(slots=True)
class BisectPreflightInput:
    action_type: str
    bisect_mode: str
    request_source: str
    resolved_targets: list[str]
    move_candidates: list[str]
    next_allowed_requests: list[str]
    completed_requests: list[str]
    completed_request_tokens: list[str]
    last_requested_targets: list[str] = field(default_factory=list)
    fallback_targets: list[str] = field(default_factory=list)
    suspects_invalidated: bool = False
    manual_grouping_requested: bool = False


def assess_continue_after_restore_mods(
    state: ContinueAfterRestoreModsState, action_type: str = "continue_after_restore_mods"
) -> ActionPreflight:
    details = [
        f"continue_allowed={state.continue_allowed}",
        f"rollback_snapshot_tag={state.rollback_snapshot_tag or 'none'}",
    ]
    if state.post_remove_active_mods:
        details.append(f"post_remove_active_mods={json.dumps(state.post_remove_active_mods, ensure_ascii=False)}")
    details.append(f"problem_changed={state.problem_changed}")
    details.append(f"continued={state.continued}")
    if not state.continue_allowed or not state.rollback_snapshot_tag or not state.post_remove_active_mods:
        return ActionPreflight(
            action_type=action_type,
            risk="medium",
            allowed=False,
            reason="no_remove_validation_context",
            details=details,
        )
    if state.continued:
        return ActionPreflight(
            action_type=action_type,
            risk="medium",
            allowed=False,
            reason="remove_validation_continue_already_consumed",
            details=details,
        )
    if not state.problem_changed:
        return ActionPreflight(
            action_type=action_type,
            risk="medium",
            allowed=False,
            reason="remove_validation_problem_not_changed",
            details=details,
        )
    return ActionPreflight(
        action_type=action_type,
        risk="low",
        allowed=True,
        reason="remove_validation_continue_allowed",
        details=details,
    )


def assess_remove_mods(
    action_type: str,
    resolved_targets: list[str],
    regex_targets: list[str],
    unresolved_targets: list[str],
    rollback_on_failure: bool,
    safe_limit: int,
) -> ActionPreflight:
    details = [f"rollback_on_failure={rollback_on_failure}"]
    if regex_targets:
        details.append(f"regex_targets={json.dumps(regex_targets, ensure_ascii=False)}")
    if resolved_targets:
        details.append(f"resolved_targets={json.dumps(resolved_targets, ensure_ascii=False)}")
    if unresolved_targets:
        details.append(f"unresolved_targets={json.dumps(unresolved_targets, ensure_ascii=False)}")
    if regex_targets:
        return ActionPreflight(
            action_type=action_type,
            risk="high",
            allowed=False,
            reason="regex_remove_requires_manual_review",
            details=details,
        )
    if not resolved_targets:
        return ActionPreflight(
            action_type=action_type,
            risk="medium",
            allowed=False,
            reason="no_installed_targets_resolved",
            details=details,
        )
    if len(resolved_targets) > safe_limit:
        return ActionPreflight(action_type=action_type, risk="high", allowed=False, reason="too_many_mod_targets", details=details)
    return ActionPreflight(
        action_type=action_type,
        risk="medium",
        allowed=True,
        reason="resolved_low_volume_mod_removal",
        details=details,
    )


def assess_adjust_memory(
    action_type: str,
    xmx_norm: str,
    xms_norm: str,
    current_xmx_gb: float,
    next_xmx_gb: float,
    system_memory_gb: float,
    max_ram_ratio: float,
) -> ActionPreflight:
    details = [f"normalized_plan=Xmx={xmx_norm},Xms={xms_norm}"]
    if next_xmx_gb > system_memory_gb * max_ram_ratio:
        return ActionPreflight(action_type=action_type, risk="high", allowed=False, reason="memory_plan_exceeds_cap", details=details)
    if abs(next_xmx_gb - current_xmx_gb) > 4:
        return ActionPreflight(action_type=action_type, risk="high", allowed=False, reason="memory_change_too_large", details=details)
    return ActionPreflight(action_type=action_type, risk="low", allowed=True, reason="bounded_memory_adjustment", details=details)


def assess_change_java(action_type: str, target_version: int, current_java_version: int) -> ActionPreflight:
    details = [f"target_version={target_version}"]
    if target_version not in SUPPORTED_JAVA_VERSIONS:
        return ActionPreflight(action_type=action_type, risk="high", allowed=False, reason="unsupported_java_version", details=details)
    if abs(target_version - current_java_version) > 4:
        return ActionPreflight(action_type=action_type, risk="high", allowed=False, reason="java_version_jump_too_large", details=details)
    return ActionPreflight(action_type=action_type, risk="medium", allowed=True, reason="whitelisted_java_switch", details=details)


def assess_non_mutating_action(action_type: str) -> ActionPreflight:
    return ActionPreflight(action_type=action_type, risk="low", allowed=True, reason="non_mutating_action", details=[])


def assess_unknown_action(action_type: str) -> ActionPreflight:
    return ActionPreflight(action_type=action_type, risk="high", allowed=False, reason="unknown_action_type", details=[])


def assess_bisect_mods(data: BisectPreflightInput) -> ActionPreflight:
    details = [f"bisect_mode={data.bisect_mode}", f"request_source={data.request_source}"]
    if data.bisect_mode not in {"initial", "switch_group", "continue_failed_group"}:
        return ActionPreflight(
            action_type=data.action_type,
            risk="high",
            allowed=False,
            reason="invalid_bisect_mode",
            details=[f"bisect_mode={data.bisect_mode}"],
        )
    if data.bisect_mode != "initial" and data.bisect_mode not in data.next_allowed_requests:
        details.append(f"next_allowed_requests={json.dumps(data.next_allowed_requests, ensure_ascii=False)}")
        return ActionPreflight(
            action_type=data.action_type,
            risk="medium",
            allowed=False,
            reason="bisect_request_not_allowed_in_current_state",
            details=details,
        )
    details.append(f"resolved_targets={json.dumps(data.resolved_targets, ensure_ascii=False)}")
    if data.manual_grouping_requested:
        details.append("manual_grouping_ignored_by_system=true")
    if data.move_candidates:
        details.append(f"move_candidates={json.dumps(data.move_candidates, ensure_ascii=False)}")
    fallback_phase_allowed = (
        data.bisect_mode == "initial"
        and data.request_source == "system_auto_resume"
        and data.suspects_invalidated
        and "initial" in data.next_allowed_requests
        and bool(data.fallback_targets)
        and set(data.resolved_targets) == set(data.fallback_targets)
    )
    request_token = data.bisect_mode
    if fallback_phase_allowed:
        request_token = f"initial:fallback:{','.join(sorted(data.resolved_targets, key=str.lower))}"
        details.append("fallback_phase=auto_resume")
    if len(data.resolved_targets) < 2:
        return ActionPreflight(
            action_type=data.action_type,
            risk="medium",
            allowed=False,
            reason="insufficient_mods_for_bisect",
            details=details,
        )
    if len(data.resolved_targets) > 24:
        return ActionPreflight(
            action_type=data.action_type,
            risk="high",
            allowed=False,
            reason="too_many_mod_targets_for_bisect",
            details=details,
        )
    if len(data.move_candidates) > 3:
        return ActionPreflight(
            action_type=data.action_type,
            risk="high",
            allowed=False,
            reason="too_many_dependency_moves",
            details=details,
        )
    completed_tokens = set(data.completed_request_tokens)
    if request_token in completed_tokens and data.bisect_mode != "continue_failed_group":
        details.append(f"completed_request_tokens={json.dumps(sorted(completed_tokens), ensure_ascii=False)}")
        return ActionPreflight(
            action_type=data.action_type,
            risk="medium",
            allowed=False,
            reason="duplicate_bisect_stage_request",
            details=details,
        )
    completed = set(data.completed_requests)
    if request_token == data.bisect_mode and data.bisect_mode in completed and data.bisect_mode != "continue_failed_group":
        details.append(f"completed_requests={json.dumps(sorted(completed), ensure_ascii=False)}")
        return ActionPreflight(
            action_type=data.action_type,
            risk="medium",
            allowed=False,
            reason="duplicate_bisect_stage_request",
            details=details,
        )
    if data.bisect_mode == "initial" and data.last_requested_targets and not fallback_phase_allowed:
        if set(data.last_requested_targets) == set(data.resolved_targets) and not data.move_candidates:
            details.append(
                f"last_bisect_feedback={json.dumps({'requested_targets': data.last_requested_targets}, ensure_ascii=False)}"
            )
            return ActionPreflight(
                action_type=data.action_type,
                risk="medium",
                allowed=False,
                reason="duplicate_bisect_request_after_previous_round",
                details=details,
            )
    return ActionPreflight(action_type=data.action_type, risk="medium", allowed=True, reason="controlled_bisect_allowed", details=details)
