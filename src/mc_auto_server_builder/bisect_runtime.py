from __future__ import annotations

from dataclasses import asdict
from typing import Any

from .models import BisectMoveRecord, BisectRoundRecord, BisectSession


def _coerce_int(value: object, default: int) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text:
            try:
                return int(text)
            except ValueError:
                return default
    return default


def build_bisect_move_records(moved_mods: list[str], from_group: str, to_group: str, reason: str) -> list[BisectMoveRecord]:
    return [BisectMoveRecord(mod_name=mod_name, from_group=from_group, to_group=to_group, reason=reason) for mod_name in moved_mods]


def derive_bisect_followups(
    *,
    bisect_mode: str,
    tested_side: str,
    round_result: str,
    failure_kind: str,
    keep_group: list[str],
    test_group: list[str],
    active_after_setup: list[str],
    suspects: list[str],
    source_mods: list[str],
) -> tuple[list[str], list[str], list[str], list[str], list[str], bool]:
    pending_group: list[str] = []
    continuation_targets: list[str] = []
    next_allowed_requests: list[str] = []
    final_suspects: list[str] = []
    fallback_targets: list[str] = []
    suspects_invalidated = False
    other_group = list(test_group if tested_side == "keep" else keep_group)
    tested_group_actual = list(active_after_setup)

    if round_result == "pass":
        final_suspects = list(other_group)
        if bisect_mode == "initial" and tested_side == "keep" and set(suspects) != set(source_mods):
            fallback_targets = list(source_mods)
            next_allowed_requests.append("initial")
            suspects_invalidated = True
            final_suspects = list(source_mods)
        elif other_group and bisect_mode in {"initial", "continue_failed_group"}:
            pending_group = list(other_group)
            next_allowed_requests.append("switch_group")
    else:
        final_suspects = list(tested_group_actual)
        if len(tested_group_actual) > 1:
            continuation_targets = list(tested_group_actual)
            next_allowed_requests.append("continue_failed_group")
        if failure_kind == "dependency_failure":
            next_allowed_requests.append("dependency_move_exception")

    return final_suspects, pending_group, continuation_targets, next_allowed_requests, fallback_targets, suspects_invalidated


def prepare_bisect_round_plan(
    *,
    idx: int,
    snapshot_tag: str,
    action: dict[str, object],
    bisect_mode: str,
    suspects: list[str],
    session: BisectSession,
    source_mods: list[str],
    keep_group: list[str],
    test_group: list[str],
) -> tuple[dict[str, object], dict[str, object]]:
    tested_side = "test" if bisect_mode == "switch_group" else "keep"
    active_group = list(test_group if tested_side == "test" else keep_group)
    plan = {
        "index": idx,
        "snapshot_tag": snapshot_tag,
        "bisect_mode": bisect_mode,
        "suspects": list(suspects),
        "source_mods": list(source_mods),
        "keep_group": list(keep_group),
        "test_group": list(test_group),
        "tested_side": tested_side,
        "active_group": list(active_group),
        "moved_mods": [],
        "notes": [],
        "bisect_reason": str(action.get("bisect_reason") or action.get("reason") or "").strip(),
        "round_index": max(1, len(session.rounds) + 1),
    }
    execution = {
        "index": idx,
        "action_type": "bisect_mods",
        "status": "prepared",
        "snapshot_tag": snapshot_tag,
        "bisect_mode": bisect_mode,
        "tested_side": tested_side,
        "keep_group": keep_group,
        "test_group": test_group,
        "suspects": suspects,
    }
    return plan, execution


def store_pending_bisect_round_plan(session: BisectSession, plan: dict[str, object]) -> BisectSession:
    return BisectSession(**{**asdict(session), "pending_round_plan": dict(plan)})


def build_bisect_round_record(
    *,
    session: BisectSession,
    plan: dict[str, object],
    suspects: list[str],
    bisect_mode: str,
    tested_side: str,
    keep_group: list[str],
    test_group: list[str],
    moved_mods: list[str],
    round_result: str,
    start_res: dict[str, object],
    failure_kind: str,
    failure_detail: str,
    continuation_targets: list[str],
    pending_group: list[str],
    next_allowed_requests: list[str],
    fallback_targets: list[str],
    suspects_invalidated: bool,
    notes: list[str],
) -> BisectRoundRecord:
    move_records = build_bisect_move_records(
        moved_mods,
        from_group="test" if tested_side == "keep" else "keep",
        to_group=tested_side,
        reason="startup_dependency_probe",
    )
    return BisectRoundRecord(
        round_index=_coerce_int(plan.get("round_index"), max(1, len(session.rounds) + 1)),
        requested_targets=list(suspects),
        bisect_mode=bisect_mode,
        tested_side=tested_side,
        kept_group=list(keep_group),
        tested_group=list(test_group),
        moved_mods=move_records,
        result=round_result,
        trigger_reason=str(plan.get("bisect_reason") or ""),
        startup_success=bool(start_res.get("success")),
        failure_kind="" if round_result == "pass" else failure_kind,
        failure_detail="" if round_result == "pass" else failure_detail,
        continuation_targets=list(continuation_targets),
        pending_other_group=list(pending_group),
        next_allowed_requests=list(next_allowed_requests),
        fallback_targets=list(fallback_targets),
        suspects_invalidated=suspects_invalidated,
        notes=notes + [f"start_success={bool(start_res.get('success'))}"],
    )


def build_bisect_feedback_payload(
    *,
    suspects: list[str],
    bisect_mode: str,
    tested_side: str,
    keep_group: list[str],
    test_group: list[str],
    moved_mods: list[str],
    round_result: str,
    startup_success: bool,
    failure_kind: str,
    failure_detail: str,
    reason: str,
    pending_group: list[str],
    continuation_targets: list[str],
    next_allowed_requests: list[str],
    fallback_targets: list[str],
    suspects_invalidated: bool,
) -> dict[str, object]:
    return {
        "already_bisected": True,
        "requested_targets": list(suspects),
        "bisect_mode": bisect_mode,
        "tested_side": tested_side,
        "split_strategy": "stable_sorted_halves",
        "keep_group": list(keep_group),
        "test_group": list(test_group),
        "moved_mods": list(moved_mods),
        "result": round_result,
        "startup_success": startup_success,
        "failure_kind": failure_kind,
        "failure_detail": failure_detail,
        "reason": reason,
        "pending_group": list(pending_group),
        "continuation_targets": list(continuation_targets),
        "next_allowed_requests": list(next_allowed_requests),
        "fallback_targets": list(fallback_targets),
        "suspects_invalidated": bool(suspects_invalidated),
        "grouping_explanation": (
            f"系统先按文件名稳定排序，再平分为 keep_group({len(keep_group)}) 和 test_group({len(test_group)})；"
            f"本轮实际验证侧={tested_side}。"
        ),
    }


def make_bisect_progress_token(
    *,
    suspects: list[str],
    bisect_mode: str,
    tested_side: str,
    round_result: str,
    final_suspects: list[str],
    next_allowed_requests: list[str],
) -> str:
    payload = {
        "suspects": list(suspects),
        "bisect_mode": bisect_mode,
        "tested_side": tested_side,
        "round_result": round_result,
        "final_suspects": list(final_suspects),
        "next_allowed_requests": list(next_allowed_requests),
    }
    return __import__("json").dumps(payload, ensure_ascii=False, sort_keys=True)


def summarize_bisect_round_outcome(
    *,
    idx: int,
    snapshot_tag: str,
    tested_side: str,
    keep_group: list[str],
    test_group: list[str],
    moved_mods: list[str],
    final_suspects: list[str],
    round_result: str,
    startup_success: bool,
    failure_kind: str,
    next_allowed_requests: list[str],
    fallback_targets: list[str],
    suspects_invalidated: bool,
    feedback: dict[str, object],
) -> dict[str, object]:
    return {
        "index": idx,
        "action_type": "bisect_mods",
        "status": "applied",
        "snapshot_tag": snapshot_tag,
        "result": round_result,
        "tested_side": tested_side,
        "keep_group": list(keep_group),
        "test_group": list(test_group),
        "moved_mods": list(moved_mods),
        "next_suspects": list(final_suspects),
        "startup_success": startup_success,
        "failure_kind": failure_kind,
        "already_bisected": True,
        "next_allowed_requests": list(next_allowed_requests),
        "fallback_targets": list(fallback_targets),
        "suspects_invalidated": suspects_invalidated,
        "feedback": feedback,
    }


def prepare_bisect_session_round_update(
    *,
    session: BisectSession,
    bisect_mode: str,
    suspects: list[str],
    source_mods: list[str],
    final_suspects: list[str],
    round_result: str,
    round_record: BisectRoundRecord,
    feedback: dict[str, object],
    pending_group: list[str],
    continuation_targets: list[str],
    next_allowed_requests: list[str],
    fallback_targets: list[str],
    suspects_invalidated: bool,
) -> dict[str, object]:
    completed_requests = list(dict.fromkeys([*(getattr(session, "completed_requests", []) or []), bisect_mode]))
    progress_token = make_bisect_progress_token(
        suspects=suspects,
        bisect_mode=bisect_mode,
        tested_side=round_record.tested_side,
        round_result=round_result,
        final_suspects=final_suspects,
        next_allowed_requests=next_allowed_requests,
    )
    previous_token = str(getattr(session, "progress_token", "") or "")
    stagnant_rounds = int(getattr(session, "stagnant_rounds", 0) or 0)
    if progress_token == previous_token:
        stagnant_rounds += 1
        round_record.notes.append(f"stagnant_round_detected={stagnant_rounds}")
    else:
        stagnant_rounds = 0
    return {
        "session": session,
        "source_mods": list(source_mods),
        "final_suspects": list(final_suspects),
        "round_record": round_record,
        "feedback": feedback,
        "pending_group": list(pending_group),
        "continuation_targets": list(continuation_targets),
        "next_allowed_requests": list(next_allowed_requests),
        "completed_requests": completed_requests,
        "fallback_targets": list(fallback_targets),
        "suspects_invalidated": suspects_invalidated,
        "progress_token": progress_token,
        "stagnant_rounds": stagnant_rounds,
    }


def update_bisect_session_after_round(
    *,
    session: BisectSession,
    source_mods: list[str],
    final_suspects: list[str],
    round_record: BisectRoundRecord,
    feedback: dict[str, object],
    pending_group: list[str],
    continuation_targets: list[str],
    next_allowed_requests: list[str],
    completed_requests: list[str],
    fallback_targets: list[str],
    suspects_invalidated: bool,
    progress_token: str,
    stagnant_rounds: int,
) -> BisectSession:
    return BisectSession(
        **{
            **asdict(session),
            "active": bool(
                next_allowed_requests
                or pending_group
                or continuation_targets
                or fallback_targets
                or (round_record.result != "pass" and len(final_suspects) > 1)
            ),
            "source_mods": list(source_mods),
            "suspect_mods": list(final_suspects),
            "safe_mods": [m for m in source_mods if m not in final_suspects],
            "rounds": [*session.rounds, round_record],
            "final_suspects": list(final_suspects if len(final_suspects) <= 3 else final_suspects[:3]),
            "stopped_reason": "bisect_round_completed",
            "last_round_feedback": feedback,
            "pending_group": list(pending_group),
            "continuation_targets": list(continuation_targets),
            "next_allowed_requests": list(next_allowed_requests),
            "completed_requests": completed_requests,
            "fallback_targets": list(fallback_targets),
            "suspects_invalidated": suspects_invalidated,
            "progress_token": progress_token,
            "stagnant_rounds": stagnant_rounds,
            "pending_round_plan": {},
        }
    )


def update_bisect_session_fields(session: BisectSession, **changes: Any) -> BisectSession:
    return BisectSession(**{**asdict(session), **changes})
