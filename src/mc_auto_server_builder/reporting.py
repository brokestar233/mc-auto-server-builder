from __future__ import annotations

import json
import zipfile
from collections.abc import Iterable
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .builder import ServerBuilder


def attempt_trace_path(builder: ServerBuilder, attempt: int, stage: str) -> Path:
    safe_stage = builder._sanitize_trace_stage(stage)
    return builder.workdirs.logs / f"attempt_{attempt:02d}_{safe_stage}.json"


def append_attempt_trace(
    builder: ServerBuilder,
    attempt: int,
    stage: str,
    status: str,
    *,
    context_summary: dict[str, Any] | None = None,
    recognition_plan: dict[str, Any] | None = None,
    ai_result: dict[str, Any] | None = None,
    action_plan: list[dict[str, Any]] | None = None,
    preflight: list[dict[str, Any]] | None = None,
    execution: list[dict[str, Any]] | None = None,
    rollback: list[dict[str, Any]] | None = None,
) -> None:
    from .models import AttemptTrace

    trace = AttemptTrace(
        attempt=attempt,
        stage=stage,
        status=status,
        context_summary=dict(context_summary or {}),
        recognition_plan=dict(recognition_plan or {}),
        ai_result=dict(ai_result or {}),
        action_plan=[dict(item) for item in (action_plan or [])],
        preflight=[dict(item) for item in (preflight or [])],
        execution=[dict(item) for item in (execution or [])],
        rollback=[dict(item) for item in (rollback or [])],
    )
    builder.attempt_traces.append(trace)
    path = attempt_trace_path(builder, attempt, stage)
    path.write_text(json.dumps(asdict(trace), ensure_ascii=False, indent=2), encoding="utf-8")


def summarize_ai_context(builder: ServerBuilder, context: dict[str, Any]) -> dict[str, object]:
    log_excerpt = builder._normalize_text_list(context.get("log_signal_summary", []), limit=10)
    if not log_excerpt:
        log_excerpt = builder._extract_log_signal_lines(context.get("refined_log", ""), limit=8)
    recognition_summary = context.get("recognition_summary", {})
    return {
        "mc_version": context.get("mc_version", "unknown"),
        "loader": context.get("loader", "unknown"),
        "loader_version": context.get("loader_version"),
        "build": context.get("build"),
        "start_mode": context.get("start_mode", "unknown"),
        "recognition_summary": dict(recognition_summary) if isinstance(recognition_summary, dict) else {},
        "mod_count": int(context.get("mod_count", 0) or 0),
        "current_installed_mods_preview": builder._normalize_text_list(context.get("current_installed_mods", []), limit=12),
        "known_deleted_client_mods": builder._normalize_text_list(context.get("known_deleted_client_mods", []), limit=20),
        "recent_actions": builder._normalize_text_list(context.get("recent_actions", []), limit=12),
        "key_exception": str(context.get("key_exception") or "none"),
        "log_signal_summary": log_excerpt,
    }


def serialize_detection_candidates(candidates: object, *, limit: int = 3) -> list[dict[str, object]]:
    items = list(candidates) if isinstance(candidates, Iterable) else []
    serialized: list[dict[str, object]] = []
    for candidate in items[:limit]:
        value = getattr(candidate, "value", None)
        if not value:
            continue
        serialized.append(
            {
                "value": str(value),
                "confidence": float(getattr(candidate, "confidence", 0.0) or 0.0),
                "reason": str(getattr(candidate, "reason", "") or ""),
            }
        )
    return serialized


def _coerce_dict_list(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


def summarize_remote_failure_events(builder: ServerBuilder, *, detail_limit: int = 5) -> dict[str, object]:
    events = _coerce_dict_list(getattr(builder, "remote_failure_events", []))
    category_counts: dict[str, int] = {}
    operation_counts: dict[str, int] = {}
    stage_counts: dict[str, int] = {}
    platform_counts: dict[str, int] = {}
    recent_events: list[dict[str, object]] = []

    for event in events:
        category = str(event.get("category") or "unknown")
        operation = str(event.get("operation") or "unknown")
        stage = str(event.get("stage") or "unknown")
        platform = str(event.get("platform") or "unknown")
        category_counts[category] = category_counts.get(category, 0) + 1
        operation_counts[operation] = operation_counts.get(operation, 0) + 1
        stage_counts[stage] = stage_counts.get(stage, 0) + 1
        platform_counts[platform] = platform_counts.get(platform, 0) + 1

    for event in events[-detail_limit:]:
        context = event.get("context")
        recent_events.append(
            {
                "platform": str(event.get("platform") or "unknown"),
                "subject": str(event.get("subject") or "unknown"),
                "operation": str(event.get("operation") or "unknown"),
                "stage": str(event.get("stage") or "unknown"),
                "category": str(event.get("category") or "unknown"),
                "exc_type": str(event.get("exc_type") or ""),
                "message": str(event.get("message") or ""),
                "context": {str(key): value for key, value in context.items()} if isinstance(context, dict) else {},
            }
        )

    return {
        "total": len(events),
        "category_counts": dict(sorted(category_counts.items())),
        "operation_counts": dict(sorted(operation_counts.items())),
        "stage_counts": dict(sorted(stage_counts.items())),
        "platform_counts": dict(sorted(platform_counts.items())),
        "recent_events": recent_events,
    }


def build_recognition_summary(builder: ServerBuilder) -> dict[str, object]:
    manifest = getattr(builder, "manifest", None)
    if not manifest:
        return {}
    evidence = []
    for item in list(getattr(manifest, "evidence", []) or [])[:5]:
        evidence.append(
            {
                "source_type": str(getattr(item, "source_type", "") or ""),
                "evidence_type": str(getattr(item, "evidence_type", "") or ""),
                "file": str(getattr(item, "file", "") or ""),
                "matched_text": str(getattr(item, "matched_text", "") or ""),
                "weight": float(getattr(item, "weight", 0.0) or 0.0),
                "reason": str(getattr(item, "reason", "") or ""),
            }
        )
    return {
        "pack_name": manifest.pack_name,
        "confidence": float(getattr(manifest, "confidence", 0.0) or 0.0),
        "active_loader": getattr(manifest, "loader", "unknown"),
        "active_mc_version": getattr(manifest, "mc_version", "unknown"),
        "active_loader_version": getattr(manifest, "loader_version", None),
        "active_build": getattr(manifest, "build", None),
        "active_start_mode": getattr(manifest, "start_mode", "unknown"),
        "warnings": list(getattr(manifest, "warnings", []) or []),
        "loader_candidates": serialize_detection_candidates(getattr(manifest, "loader_candidates", [])),
        "mc_version_candidates": serialize_detection_candidates(getattr(manifest, "mc_version_candidates", [])),
        "loader_version_candidates": serialize_detection_candidates(getattr(manifest, "loader_version_candidates", [])),
        "build_candidates": serialize_detection_candidates(getattr(manifest, "build_candidates", [])),
        "start_mode_candidates": serialize_detection_candidates(getattr(manifest, "start_mode_candidates", [])),
        "evidence_preview": evidence,
        "fallback_history": list(getattr(builder, "recognition_attempts", [])[-5:]),
        "recognition_strategy_used": str(getattr(manifest, "raw", {}).get("pack_type", "unknown")),
        "recognition_pipeline": list(getattr(manifest, "raw", {}).get("recognition_pipeline", []) or []),
        "recognition_phase_hits": list(getattr(manifest, "raw", {}).get("recognition_phase_hits", []) or []),
        "recognition_phase_details": dict(getattr(manifest, "raw", {}).get("recognition_phase_details", {}) or {}),
        "recognition_fallback_count": len(list(getattr(builder, "recognition_attempts", []) or [])),
        "recognition_switched": len(list(getattr(builder, "recognition_attempts", []) or [])) > 0,
        "recognition_finalized_after_runtime_feedback": any(
            str(item.get("reason") or "") == "runtime_feedback_fallback"
            for item in list(getattr(builder, "recognition_attempts", []) or [])
            if isinstance(item, dict)
        ),
    }


def build_meta_payload(builder: ServerBuilder) -> dict[str, object]:
    manifest = builder.manifest
    recognition_summary = builder._build_recognition_summary()
    remote_failure_summary = summarize_remote_failure_events(builder)
    return {
        "pack_source": {
            "input_type": getattr(builder.pack_input, "input_type", "unknown"),
            "source": getattr(builder.pack_input, "source", "unknown"),
            "file_id": getattr(builder.pack_input, "file_id", None),
        },
        "manifest_summary": {
            "pack_name": getattr(manifest, "pack_name", "unknown") if manifest else "unknown",
            "mc_version": getattr(manifest, "mc_version", "unknown") if manifest else "unknown",
            "loader": getattr(manifest, "loader", "unknown") if manifest else "unknown",
            "loader_version": getattr(manifest, "loader_version", None) if manifest else None,
            "build": getattr(manifest, "build", None) if manifest else None,
            "start_mode": getattr(manifest, "start_mode", "unknown") if manifest else "unknown",
            "warnings": list(getattr(manifest, "warnings", []) or []) if manifest else [],
        },
        "recognition_result": recognition_summary,
        "java": {
            "selected_version": builder.current_java_version,
            "detected_version": builder.detect_current_java_version(),
            "xmx": builder.jvm_xmx,
            "xms": builder.jvm_xms,
            "extra_jvm_flags": list(builder.extra_jvm_flags),
        },
        "start_command": {
            "mode": builder.start_command_mode,
            "value": builder.start_command_value,
        },
        "deleted_mods": {
            "removed_mods": list(builder.removed_mods),
            "bisect_removed_mods": list(builder.bisect_removed_mods),
            "evidence": dict(builder.deleted_mod_evidence),
            "source_breakdown": dict(getattr(builder, "deleted_mod_sources", {})),
        },
        "ai": {
            "last_result": asdict(builder.last_ai_result) if builder.last_ai_result else None,
            "manual_report": dict(builder.last_ai_manual_report),
        },
        "attempts": {
            "attempts_used": builder.attempts_used,
            "run_success": builder.run_success,
            "stop_reason": builder.stop_reason,
            "recognition_attempts": list(builder.recognition_attempts),
        },
        "remote_failures": {
            "summary": remote_failure_summary,
            "events": _coerce_dict_list(getattr(builder, "remote_failure_events", [])),
        },
        "operations": list(builder.operations),
    }


def package_server(builder: ServerBuilder) -> str:
    out = builder.workdirs.root / "server_pack.zip"
    excluded_runtime_dirs = {
        "crash-reports",
        "logs",
        "world",
        "world_nether",
        "world_the_end",
    }
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("build_meta.json", json.dumps(builder._build_meta_payload(), ensure_ascii=False, indent=2))
        for p in builder.workdirs.server.rglob("*"):
            if p.is_file() and not any(part in excluded_runtime_dirs for part in p.relative_to(builder.workdirs.server).parts):
                zf.write(p, p.relative_to(builder.workdirs.server))
        for p in builder.workdirs.java_bins.rglob("*"):
            if p.is_file():
                zf.write(p, Path("java_bins") / p.relative_to(builder.workdirs.java_bins))
    return str(out)


def generate_report(builder: ServerBuilder) -> str:
    report_path = builder.workdirs.root / "report.txt"
    recognition_summary = builder._build_recognition_summary()
    remote_failure_summary = summarize_remote_failure_events(builder)
    ai_summary = "none"
    ai_detail_lines: list[str] = []
    if builder.last_ai_result:
        ai_summary = (
            f"issue={builder.last_ai_result.primary_issue}, "
            f"confidence={builder.last_ai_result.confidence:.2f}, "
            f"reason={builder.last_ai_result.reason}"
        )
        ai_detail_lines = [
            f"- 输入摘要: {builder.last_ai_result.input_summary or 'none'}",
            f"- 用户可读摘要: {builder.last_ai_result.user_summary or 'none'}",
            f"- 命中的已删除mod: {json.dumps(builder.last_ai_result.hit_deleted_mods, ensure_ascii=False)}",
            f"- 依赖链: {json.dumps(builder.last_ai_result.dependency_chains, ensure_ascii=False)}",
            f"- 删除判定依据: {json.dumps(builder.last_ai_result.deletion_rationale, ensure_ascii=False)}",
            f"- 冲突/异常说明: {json.dumps(builder.last_ai_result.conflicts_or_exceptions, ensure_ascii=False)}",
            f"- 证据: {json.dumps(builder.last_ai_result.evidence, ensure_ascii=False)}",
            f"- 建议手动修复步骤: {json.dumps(builder.last_ai_result.suggested_manual_steps, ensure_ascii=False)}",
            f"- 思考链: {json.dumps(builder.last_ai_result.thought_chain, ensure_ascii=False)}",
        ]

    deleted_history_lines: list[str] = []
    for mod_name in sorted(builder.known_deleted_client_mods):
        evidence = builder.deleted_mod_evidence.get(mod_name, [])
        deleted_history_lines.append(f"- {mod_name}: {json.dumps(evidence, ensure_ascii=False)}")
    deleted_mod_sources = (
        getattr(builder, "deleted_mod_sources", {}) if isinstance(getattr(builder, "deleted_mod_sources", {}), dict) else {}
    )
    deleted_source_lines: list[str] = []
    for mod_name in sorted(deleted_mod_sources):
        deleted_source_lines.append(f"- {mod_name}: {json.dumps(deleted_mod_sources.get(mod_name, {}), ensure_ascii=False)}")
    attempt_trace_lines = [
        (
            f"- attempt={trace.attempt}, stage={trace.stage}, status={trace.status}, "
            f"file={builder._attempt_trace_path(trace.attempt, trace.stage).name}"
        )
        for trace in builder.attempt_traces
    ]
    bisect_tree_lines = builder._format_bisect_tree_lines()
    loader_candidates = _coerce_dict_list(recognition_summary.get("loader_candidates", []))
    mc_version_candidates = _coerce_dict_list(recognition_summary.get("mc_version_candidates", []))
    build_candidates = _coerce_dict_list(recognition_summary.get("build_candidates", []))
    start_mode_candidates = _coerce_dict_list(recognition_summary.get("start_mode_candidates", []))
    loader_candidate_values = [item.get("value") for item in loader_candidates]
    mc_candidate_values = [item.get("value") for item in mc_version_candidates]
    build_candidate_values = [item.get("value") for item in build_candidates]
    start_mode_candidate_values = [item.get("value") for item in start_mode_candidates]
    recognition_lines = [
        f"- 输入包名: {recognition_summary.get('pack_name', 'unknown')}",
        f"- 当前 loader: {recognition_summary.get('active_loader', 'unknown')}",
        f"- 当前 MC 版本: {recognition_summary.get('active_mc_version', 'unknown')}",
        f"- 当前 loader_version: {recognition_summary.get('active_loader_version', None)}",
        f"- 当前 build: {recognition_summary.get('active_build', None)}",
        f"- 当前启动模式: {recognition_summary.get('active_start_mode', 'unknown')}",
        f"- 识别置信度: {recognition_summary.get('confidence', 0.0):.2f}",
        f"- 候选 loader: {json.dumps(loader_candidate_values, ensure_ascii=False)}",
        f"- 候选 MC 版本: {json.dumps(mc_candidate_values, ensure_ascii=False)}",
        f"- 候选 build: {json.dumps(build_candidate_values, ensure_ascii=False)}",
        f"- 候选启动模式: {json.dumps(start_mode_candidate_values, ensure_ascii=False)}",
        f"- 识别流水线: {json.dumps(recognition_summary.get('recognition_pipeline', []), ensure_ascii=False)}",
        f"- 命中的识别阶段: {json.dumps(recognition_summary.get('recognition_phase_hits', []), ensure_ascii=False)}",
        f"- 阶段明细: {json.dumps(recognition_summary.get('recognition_phase_details', {}), ensure_ascii=False)}",
        f"- 回退历史: {json.dumps(recognition_summary.get('fallback_history', []), ensure_ascii=False)}",
        f"- 证据摘要: {json.dumps(recognition_summary.get('evidence_preview', []), ensure_ascii=False)}",
    ]
    remote_failure_lines = [
        f"- 总失败事件数: {remote_failure_summary.get('total', 0)}",
        f"- 按平台统计: {json.dumps(remote_failure_summary.get('platform_counts', {}), ensure_ascii=False)}",
        f"- 按阶段统计: {json.dumps(remote_failure_summary.get('stage_counts', {}), ensure_ascii=False)}",
        f"- 按类别统计: {json.dumps(remote_failure_summary.get('category_counts', {}), ensure_ascii=False)}",
        f"- 按操作统计: {json.dumps(remote_failure_summary.get('operation_counts', {}), ensure_ascii=False)}",
    ]
    remote_failure_recent_lines = [
        (
            "- "
            f"platform={event.get('platform', 'unknown')}, "
            f"subject={event.get('subject', 'unknown')}, "
            f"operation={event.get('operation', 'unknown')}, "
            f"stage={event.get('stage', 'unknown')}, "
            f"category={event.get('category', 'unknown')}, "
            f"exc_type={event.get('exc_type', '') or 'none'}, "
            f"message={event.get('message', '') or 'none'}, "
            f"context={json.dumps(event.get('context', {}), ensure_ascii=False)}"
        )
        for event in _coerce_dict_list(remote_failure_summary.get("recent_events", []))
    ]
    lines = [
        "MC Auto Server Builder 报告",
        f"生成时间: {datetime.now().isoformat()}",
        f"工作目录: {builder.workdirs.root}",
        f"是否成功启动: {builder.run_success}",
        f"实际尝试次数: {builder.attempts_used}",
        f"最终状态: {'成功' if builder.run_success else '失败'} / {builder.stop_reason or 'success_or_attempt_limit'}",
        f"清理/删除Mods数量: {len(builder.removed_mods)}",
        f"二分测试临时移除数量: {len(getattr(builder, 'bisect_removed_mods', []))}",
        "删除列表:",
        *[f"- {m}" for m in builder.removed_mods],
        f"最终JVM: Xmx={builder.jvm_xmx}, Xms={builder.jvm_xms}",
        f"Java版本: {builder.detect_current_java_version()}",
        "识别过程摘要:",
        *recognition_lines,
        f"最后一次AI结论: {ai_summary}",
        "AI 手动兜底摘要:",
        f"- 用户摘要: {builder.last_ai_manual_report.get('user_summary', 'none') if builder.last_ai_manual_report else 'none'}",
        (
            f"- 手动步骤: {json.dumps(builder.last_ai_manual_report.get('suggested_manual_steps', []), ensure_ascii=False)}"
            if builder.last_ai_manual_report
            else "- 手动步骤: []"
        ),
        (
            f"- 证据: {json.dumps(builder.last_ai_manual_report.get('evidence', []), ensure_ascii=False)}"
            if builder.last_ai_manual_report
            else "- 证据: []"
        ),
        "AI高价值分析明细:",
        *(ai_detail_lines or ["- none"]),
        "Attempt Trace 索引:",
        *(attempt_trace_lines or ["- none"]),
        "完整 Bisect Tree:",
        *bisect_tree_lines,
        "已知且已删除客户端mod（本次运行历史）:",
        *(deleted_history_lines or ["- none"]),
        "删除 mod 来源分层统计:",
        *(deleted_source_lines or ["- none"]),
        "远端失败事件摘要:",
        *remote_failure_lines,
        "最近远端失败明细:",
        *(remote_failure_recent_lines or ["- none"]),
        f"终止原因: {builder.stop_reason or 'success_or_attempt_limit'}",
        f"总操作数: {len(builder.operations)}",
        "操作记录:",
        *[f"- {x}" for x in builder.operations],
    ]
    report_path.write_text("\n".join(lines), encoding="utf-8")
    return str(report_path)
