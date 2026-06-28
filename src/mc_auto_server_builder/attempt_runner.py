from __future__ import annotations

import json
import traceback
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .builder import AttemptLoopDecision, ServerBuilder


def run_attempt_loop(builder: ServerBuilder) -> bool:
    for attempt in range(1, builder.config.runtime.max_attempts + 1):
        decision = run_single_attempt(builder, attempt)
        if decision == "success":
            return True
        if decision == "stop":
            return False
    return False


def run_single_attempt(builder: ServerBuilder, attempt: int) -> AttemptLoopDecision:
    builder.attempts_used = attempt
    builder._log("install.attempt", f"启动尝试 {attempt}/{builder.config.runtime.max_attempts}")
    builder.backup_mods(f"attempt_{attempt}")
    start_res = builder.start_server(timeout=builder.config.runtime.start_timeout)
    if bool(start_res.get("success")):
        return handle_successful_attempt(builder, attempt, start_res)
    return handle_failed_attempt(builder, attempt, start_res)


def handle_successful_attempt(builder: ServerBuilder, attempt: int, start_res: dict[str, object]) -> AttemptLoopDecision:
    source = str(start_res.get("success_source") or "unknown")
    builder._log("install.attempt", f"尝试 {attempt} 成功，判定来源={source}")
    if builder._has_pending_bisect_followup():
        auto_resumed_bisect = False
        if builder._should_auto_resume_full_bisect():
            auto_actions = [builder._build_auto_resume_bisect_action()]
            builder._append_attempt_trace(
                attempt,
                "success_auto_bisect_resume",
                "ok",
                action_plan=[dict(x) for x in auto_actions if isinstance(x, dict)],
            )
            builder._log("install.bisect.auto_resume", json.dumps(auto_actions[0], ensure_ascii=False, sort_keys=True))
            should_stop = builder._apply_actions(auto_actions, attempt=attempt)
            if should_stop:
                builder._log("install.stop", f"AI 决策停止，reason={builder.stop_reason}", level="WARN")
                return "stop"
            auto_resumed_bisect = True
            if builder._has_pending_bisect_followup():
                return "continue"
        if auto_resumed_bisect:
            builder.stop_reason = f"server_ready:{source}"
            return "success"

        ai_context = builder._build_ai_context(
            start_res,
            log_info={
                "log_tail": str(start_res.get("stdout_tail") or ""),
                "crash_excerpt": str(start_res.get("stderr_tail") or ""),
                "crash_mod_issue": "",
                "conflicts_or_exceptions": [],
            },
        )
        builder._append_attempt_trace(
            attempt,
            "success_context_prepared",
            "ok",
            context_summary=builder._summarize_ai_context(ai_context),
        )
        ai = builder.analyze_success_guard_with_ai(ai_context)
        builder._append_attempt_trace(
            attempt,
            "success_ai_analysis",
            "ok",
            context_summary=builder._summarize_ai_context(ai_context),
            ai_result=dict(ai),
            action_plan=[dict(x) for x in ai.get("actions", []) if isinstance(x, dict)],
        )
        builder._log("install.ai", f"AI 成功态续轮分析完成，issue={ai.get('primary_issue')} confidence={ai.get('confidence')}")
        should_stop = builder._apply_actions(ai.get("actions", []), attempt=attempt)
        if should_stop:
            builder._log("install.stop", f"AI 决策停止，reason={builder.stop_reason}", level="WARN")
            return "stop"
        same_issue_count = builder._record_success_guard_observation(
            str(ai.get("primary_issue") or "other"),
            ai.get("confidence"),
        )
        if same_issue_count >= 2:
            builder.stop_reason = "success_guard_same_issue_requires_manual_review"
            builder.last_ai_manual_report = {
                "user_summary": (
                    "服务器虽然出现启动成功信号，但 AI 连续两轮在成功态识别出同类 "
                    "client_mod 风险，已停止自动回归以避免无意义重试。"
                ),
                "suggested_manual_steps": [
                    "检查最后两轮 success_ai_analysis 与 bisect feedback，确认剩余嫌疑 mod。",
                    "优先人工验证 success_guard_history 中涉及的客户端模组或渲染相关模组。",
                ],
                "evidence": list(getattr(builder._coerce_bisect_session(), "success_guard_history", []) or []),
            }
            builder._log("install.stop", f"AI 决策停止，reason={builder.stop_reason}", level="WARN")
            return "stop"
        if builder._has_pending_bisect_followup():
            return "continue"

    accept_success, final_reason = builder._should_accept_success_after_start(start_res)
    if not accept_success:
        return "continue"
    builder.stop_reason = final_reason
    return "success"


def handle_failed_attempt(builder: ServerBuilder, attempt: int, start_res: dict[str, object]) -> AttemptLoopDecision:
    log_info = builder.extract_relevant_log(str(start_res["log_path"]), str(start_res["crash_dir"]))
    ai_context = builder._build_ai_context(start_res, log_info)
    next_plan = None
    if start_res.get("crash_detected"):
        builder._log("install.ai", "检测到 crash 证据，跳过 runtime recognition fallback，直接进入 AI 分析")
    else:
        next_plan = builder._select_next_recognition_plan(start_res, log_info)
    builder._append_attempt_trace(
        attempt,
        "context_prepared",
        "ok",
        context_summary=builder._summarize_ai_context(ai_context),
        recognition_plan=(
            {
                "loader": next_plan.loader,
                "loader_version": next_plan.loader_version,
                "mc_version": next_plan.mc_version,
                "build": next_plan.build,
                "start_mode": next_plan.start_mode,
                "java_version": next_plan.java_version,
                "confidence": next_plan.confidence,
                "confidence_level": builder._recognition_confidence_level(next_plan.confidence),
                "reason": next_plan.reason,
                "source_candidates": list(next_plan.source_candidates),
                "preflight": builder._preflight_recognition_plan(next_plan),
            }
            if next_plan
            else {}
        ),
    )
    if next_plan:
        builder._apply_recognition_plan(next_plan, reason="runtime_feedback_fallback")
        builder._append_attempt_trace(
            attempt,
            "recognition_fallback_applied",
            "ok",
            context_summary=builder._summarize_ai_context(ai_context),
            recognition_plan={
                "loader": next_plan.loader,
                "loader_version": next_plan.loader_version,
                "mc_version": next_plan.mc_version,
                "build": next_plan.build,
                "start_mode": next_plan.start_mode,
                "java_version": next_plan.java_version,
                "confidence": next_plan.confidence,
                "confidence_level": builder._recognition_confidence_level(next_plan.confidence),
                "reason": next_plan.reason,
                "source_candidates": list(next_plan.source_candidates),
                "switch_reason": "runtime_feedback_fallback",
                "preflight": builder._preflight_recognition_plan(next_plan),
            },
        )
        return "continue"
    remove_validation_stop = builder._consume_remove_validation_followup(attempt, start_res, log_info)
    if remove_validation_stop is True:
        return "stop"
    if remove_validation_stop is False:
        return "continue"
    ai = builder.analyze_with_ai(ai_context)
    builder._append_attempt_trace(
        attempt,
        "ai_analysis",
        "ok",
        context_summary=builder._summarize_ai_context(ai_context),
        ai_result=dict(ai),
        action_plan=[dict(x) for x in ai.get("actions", []) if isinstance(x, dict)],
    )
    builder._log("install.ai", f"AI 分析完成，issue={ai.get('primary_issue')} confidence={ai.get('confidence')}")
    should_stop = builder._apply_actions(ai.get("actions", []), attempt=attempt)
    builder._ai_debug(
        "loop.decision "
        f"attempt={attempt}, should_stop={should_stop}, stop_reason={builder.stop_reason or 'none'}, "
        f"actions={json.dumps(ai.get('actions', []), ensure_ascii=False)}"
    )
    if should_stop:
        builder._log("install.stop", f"AI 决策停止，reason={builder.stop_reason}", level="WARN")
        return "stop"
    return "continue"


def finalize_run_result(builder: ServerBuilder, success: bool) -> dict[str, object]:
    builder.run_success = success
    if not success and not builder.stop_reason:
        builder.stop_reason = "attempt_limit_reached"

    builder._ensure_server_meta_files()
    report = builder.generate_report()
    builder._persist_resume_state(prepared_server=True)
    package = builder.package_server()

    builder._log(
        "install.finish",
        f"完成: success={success}, attempts={builder.attempts_used}, "
        f"removed_mods={len(builder.removed_mods)}, operations={len(builder.operations)}",
    )
    return {
        "success": success,
        "workdir": str(builder.workdirs.root),
        "report": report,
        "package": package,
        "log_file": str(builder.log_file_path),
    }


def run(builder: ServerBuilder) -> dict[str, object]:
    builder._log("install.start", f"开始安装，source={builder.pack_input.source}")
    try:
        builder._prepare_runtime_environment()
        success = builder._run_attempt_loop()
        return builder._finalize_run_result(success)
    except Exception as exc:
        builder._log("install.error", f"安装失败: {type(exc).__name__}: {exc}", level="ERROR")
        builder._log("install.error", traceback.format_exc(), level="ERROR")
        raise
