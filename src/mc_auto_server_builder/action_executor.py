from __future__ import annotations

import json
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from .builder import ActionExecutionResult, PreviousActionState, RollbackResult, ServerBuilder
    from .models import ActionPreflight


def _update_execution_result(execution: ActionExecutionResult, payload: dict[str, object]) -> None:
    execution.update(cast("ActionExecutionResult", payload))


def build_previous_action_state(builder: ServerBuilder) -> PreviousActionState:
    current_jvm_xmx = str(getattr(builder, "jvm_xmx", "4G") or "4G")
    current_jvm_xms = str(getattr(builder, "jvm_xms", current_jvm_xmx) or current_jvm_xmx)
    current_extra_jvm_flags = list(getattr(builder, "extra_jvm_flags", []) or [])
    current_java_version = int(getattr(builder, "current_java_version", 21) or 21)
    current_java_bin = getattr(builder, "current_java_bin", None)
    return {
        "jvm_xmx": current_jvm_xmx,
        "jvm_xms": current_jvm_xms,
        "extra_jvm_flags": current_extra_jvm_flags,
        "current_java_version": current_java_version,
        "current_java_bin": str(current_java_bin) if current_java_bin else "",
    }


def build_initial_execution_result(
    *, idx: int, action_type: str, snapshot_tag: str, preflight: ActionPreflight
) -> ActionExecutionResult:
    return {
        "index": idx,
        "action_type": action_type,
        "status": "skipped",
        "snapshot_tag": snapshot_tag,
        "risk": preflight.risk,
    }


def execute_remove_mods_action(
    builder: ServerBuilder,
    *,
    idx: int,
    action: dict,
    snapshot_tag: str,
    previous_state: PreviousActionState,
    execution: ActionExecutionResult,
) -> tuple[bool, ActionExecutionResult, RollbackResult | None]:
    from .builder import RemoveValidationStatePayload, _normalize_start_server_result

    targets = action.get("targets") or []
    rollback_on_failure = bool(action.get("rollback_on_failure", False))
    names = [x for x in targets if not str(x).startswith("regex:")]
    resolved_names = builder._resolve_mod_names_to_installed([str(x) for x in names])
    previous_crash_reports = list(getattr(builder, "last_rollback_remove_mods", {}).get("crash_reports_after_validation", []) or [])
    previous_excerpt = str(getattr(builder, "last_rollback_remove_mods", {}).get("validation_crash_excerpt", "") or "")
    if resolved_names:
        builder.remove_mods_by_name(
            resolved_names,
            source="ai_action",
            reason=f"attempt_action_index={idx}:explicit_targets",
        )
    installed_after_ai = builder.list_mods()
    forced_targets, forced_rationale, matched_chains = builder._resolve_dependency_cleanup_targets(
        builder.last_ai_result.dependency_chains if builder.last_ai_result else [],
        installed_after_ai,
    )
    _update_execution_result(
        execution,
        {
            "status": "applied",
            "resolved_targets": resolved_names,
            "rollback_on_failure": rollback_on_failure,
            "forced_targets": forced_targets,
            "forced_rationale": forced_rationale[:20],
            "matched_dependency_chains": cast(list[object], matched_chains[:10]),
        },
    )
    if forced_targets:
        builder.remove_mods_by_name(
            forced_targets,
            source="dependency_cleanup",
            reason="depend_on_known_deleted_client_mod",
        )
        builder.operations.append(f"dependency_cleanup_forced_remove:targets={json.dumps(forced_targets, ensure_ascii=False)}")
    post_remove_active_mods = list(builder.list_mods())
    if not rollback_on_failure:
        builder.last_rollback_remove_mods = {}
        builder.remove_validation_state = {}
        return False, execution, None

    validation_res = _normalize_start_server_result(builder.start_server(timeout=builder.config.runtime.start_timeout))
    validation_success = bool(validation_res["success"])
    crash_reports_after_validation = cast(list[str], validation_res["crash_reports_snapshot"])
    validation_excerpt = str(validation_res["stderr_tail"] or validation_res["reason"] or "")
    crash_report_delta = sorted(set(crash_reports_after_validation).symmetric_difference(set(previous_crash_reports)))
    problem_changed = bool(crash_report_delta)
    _update_execution_result(
        execution,
        {
            "validation_start_performed": True,
            "validation_success": validation_success,
            "validation_success_source": validation_res["success_source"],
            "validation_problem_changed": problem_changed,
        },
    )
    if validation_success:
        return False, execution, None

    rollback = builder._rollback_action("remove_mods", snapshot_tag, previous_state)
    builder.last_rollback_remove_mods = {
        "triggered": bool(rollback and rollback.get("performed")),
        "snapshot_tag": snapshot_tag,
        "action_index": idx,
        "removed_targets": list(resolved_names),
        "forced_targets": list(forced_targets),
        "validation_success": validation_success,
        "validation_failure_signals": list(cast(list[str], validation_res["failure_signals"])),
        "validation_readiness_evidence": list(cast(list[str], validation_res["readiness_evidence"])),
        "validation_crash_excerpt": validation_excerpt,
        "crash_reports_after_validation": crash_reports_after_validation,
        "crash_reports_new_after_validation": [str(x) for x in cast(list[str], validation_res["crash_reports_new"]) if str(x).strip()],
        "crash_reports_changed_since_last_context": False,
    }
    builder.remove_validation_state = RemoveValidationStatePayload(
        triggered=bool(rollback and rollback.get("performed")),
        continue_allowed=problem_changed,
        continued=False,
        rollback_snapshot_tag=snapshot_tag,
        action_index=idx,
        removed_targets=list(resolved_names),
        forced_targets=list(forced_targets),
        post_remove_active_mods=post_remove_active_mods,
        previous_crash_reports=previous_crash_reports,
        validation_crash_reports=crash_reports_after_validation,
        crash_report_delta=crash_report_delta,
        previous_excerpt=previous_excerpt,
        validation_excerpt=validation_excerpt,
        failure_signals=cast(list[str], validation_res["failure_signals"]),
        readiness_evidence=cast(list[str], validation_res["readiness_evidence"]),
        problem_changed=problem_changed,
    ).to_dict()
    _update_execution_result(
        execution,
        {
            "status": "rolled_back",
            "rollback_reason": "startup_validation_failed",
            "validation_failure_excerpt": builder._extract_log_signal_lines(
                "\n".join(
                    [
                        str(validation_res.get("stdout") or ""),
                        str(validation_res.get("stderr") or ""),
                        str(validation_res.get("reason") or ""),
                    ]
                ),
                limit=8,
            ),
        },
    )
    return False, execution, rollback


def execute_continue_after_restore_mods_action(
    builder: ServerBuilder,
    *,
    snapshot_tag: str,
    execution: ActionExecutionResult,
) -> tuple[bool, ActionExecutionResult, RollbackResult | None]:
    from .builder import RemoveValidationStatePayload

    state = RemoveValidationStatePayload.from_mapping(getattr(builder, "remove_validation_state", {}))
    rollback_snapshot_tag = state.rollback_snapshot_tag or snapshot_tag
    restored_active = builder._set_active_mods(
        list(state.post_remove_active_mods or []),
        rollback_snapshot_tag,
        reason="continue_after_restore_mods",
    )
    builder.operations.append(f"continue_after_restore_mods:{rollback_snapshot_tag}")
    _update_execution_result(
        execution,
        {
            "status": "applied",
            "restored_snapshot_tag": rollback_snapshot_tag,
            "restored_active_mods": restored_active,
            "restored_targets": list(state.removed_targets or []),
        },
    )
    state.continued = True
    builder.remove_validation_state = state.to_dict()
    return False, execution, None


def execute_adjust_memory_action(
    builder: ServerBuilder,
    *,
    action: dict,
    execution: ActionExecutionResult,
) -> tuple[bool, ActionExecutionResult, RollbackResult | None]:
    xmx = action.get("xmx", builder.jvm_xmx)
    xms = action.get("xms", builder.jvm_xms)
    xmx_norm, xms_norm = builder._normalize_memory_plan(str(xmx), str(xms))
    builder.set_jvm_args(xmx_norm, xms_norm)
    _update_execution_result(execution, {"status": "applied", "xmx": xmx_norm, "xms": xms_norm})
    return False, execution, None


def execute_change_java_action(
    builder: ServerBuilder,
    *,
    action: dict,
    execution: ActionExecutionResult,
) -> tuple[bool, ActionExecutionResult, RollbackResult | None]:
    version = int(action.get("version", 21))
    builder.switch_java_version(version)
    _update_execution_result(execution, {"status": "applied", "version": version})
    return False, execution, None
