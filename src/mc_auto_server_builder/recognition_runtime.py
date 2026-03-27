from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Iterable, cast

from .recognition import RecognitionFallbackPlan, infer_java_from_runtime_feedback, top_candidate_values

if TYPE_CHECKING:
    from .builder import ServerBuilder
    from .models import PackManifest


def _string_list(value: object) -> list[str]:
    if not isinstance(value, Iterable) or isinstance(value, (str, bytes, dict)):
        return []
    return [str(item) for item in value if str(item).strip()]


def recognition_confidence_level(confidence: float) -> str:
    if confidence >= 0.85:
        return "high"
    if confidence >= 0.55:
        return "medium"
    return "low"


def build_recognition_candidates(manifest: PackManifest, choose_java: Callable[..., int]) -> list[RecognitionFallbackPlan]:
    loaders = top_candidate_values(getattr(manifest, "loader_candidates", [])) or [
        str(getattr(manifest, "loader", "unknown") or "unknown")
    ]
    mc_versions = top_candidate_values(getattr(manifest, "mc_version_candidates", [])) or [
        str(getattr(manifest, "mc_version", "unknown") or "unknown")
    ]
    loader_versions = top_candidate_values(getattr(manifest, "loader_version_candidates", []), limit=4) or [
        str(getattr(manifest, "loader_version", "") or "")
    ]
    start_modes = top_candidate_values(getattr(manifest, "start_mode_candidates", [])) or [
        str(getattr(manifest, "start_mode", "jar") or "jar")
    ]
    builds = top_candidate_values(getattr(manifest, "build_candidates", []), limit=4) or [
        str(getattr(manifest, "build", "") or "")
    ]
    plans: list[RecognitionFallbackPlan] = []
    for loader in loaders[:3]:
        for mc_version in mc_versions[:2]:
            for start_mode in start_modes[:2]:
                loader_version = next(
                    (item for item in loader_versions if item and (mc_version in item or loader in item.lower())),
                    loader_versions[0] or None,
                )
                build = next((item for item in builds if item), None)
                confidence = 0.4
                if loader == getattr(manifest, "loader", "unknown"):
                    confidence += 0.2
                if mc_version == getattr(manifest, "mc_version", "unknown"):
                    confidence += 0.2
                if start_mode == getattr(manifest, "start_mode", "unknown"):
                    confidence += 0.1
                plans.append(
                    RecognitionFallbackPlan(
                        loader=loader,
                        loader_version=loader_version,
                        mc_version=mc_version,
                        build=build,
                        start_mode=start_mode,
                        java_version=choose_java(manifest, loader=loader, mc_version=mc_version),
                        confidence=min(1.0, round(confidence, 3)),
                        reason="候选识别计划",
                        source_candidates=[loader, mc_version, start_mode],
                    )
                )
    dedup: dict[tuple[str, str | None, str | None, str], RecognitionFallbackPlan] = {}
    for plan in plans:
        key = (plan.loader, plan.loader_version, plan.mc_version, plan.start_mode)
        if key not in dedup or dedup[key].confidence < plan.confidence:
            dedup[key] = plan
    return sorted(dedup.values(), key=lambda item: (-item.confidence, item.loader, item.start_mode))


def preflight_recognition_plan(
    plan: RecognitionFallbackPlan,
    *,
    server_dir: Path,
    server_jar_name: str,
    manifest: PackManifest | None,
    choose_java: Callable[..., int],
) -> dict[str, object]:
    checks: list[str] = []
    score = 0
    if plan.start_mode in {"argsfile", "args_file"} and any(server_dir.glob("libraries/**/unix_args.txt")):
        score += 1
        checks.append("argsfile_path_present")
    if plan.loader == "forge" and (server_dir / "libraries" / "net" / "minecraftforge").exists():
        score += 1
        checks.append("forge_libraries_present")
    if plan.loader == "neoforge" and (server_dir / "libraries" / "net" / "neoforged").exists():
        score += 1
        checks.append("neoforge_libraries_present")
    if plan.loader in {"fabric", "quilt"} and any(server_dir.glob("**/*fabric*loader*.jar")):
        score += 1
        checks.append("fabric_like_loader_present")
    if (server_dir / server_jar_name).exists():
        score += 1
        checks.append("server_jar_present")
    if manifest and plan.java_version == choose_java(manifest, loader=plan.loader, mc_version=plan.mc_version):
        score += 1
        checks.append("java_version_matches_loader_strategy")
    return {
        "allowed": score > 0,
        "score": score,
        "checks": checks,
        "confidence_level": recognition_confidence_level(plan.confidence),
    }


def recognition_runtime_feedback(start_res: dict[str, object], log_info: dict[str, object], current_java_version: int) -> dict[str, object]:
    text = "\n".join(
        [
            str(start_res.get("stdout_tail") or ""),
            str(start_res.get("stderr_tail") or ""),
            str(log_info.get("refined_log") or ""),
            str(log_info.get("key_exception") or ""),
        ]
    ).lower()
    inferred_loader = None
    if any(token in text for token in ("fml", "minecraftforge", "forge mod loader")):
        inferred_loader = "forge"
    elif "neoforge" in text:
        inferred_loader = "neoforge"
    elif "fabric-loader" in text or "fabricloader" in text:
        inferred_loader = "fabric"
    elif "quilt-loader" in text or "quilt" in text:
        inferred_loader = "quilt"
    inferred_mc_version = None
    version_match = re.search(r"\b1\.\d+(?:\.\d+)?\b", text)
    if version_match:
        inferred_mc_version = version_match.group(0)
    java_hint = infer_java_from_runtime_feedback(text, current_java_version)
    return {
        "inferred_loader": inferred_loader,
        "inferred_mc_version": inferred_mc_version,
        "java_hint": java_hint,
        "raw": text[:800],
    }


def select_next_recognition_plan(
    *,
    start_res: dict[str, object],
    log_info: dict[str, object],
    plans: list[RecognitionFallbackPlan],
    recognition_attempts: list[dict[str, Any]],
    current_java_version: int,
    preflight: Callable[[RecognitionFallbackPlan], dict[str, object]],
) -> RecognitionFallbackPlan | None:
    runtime = recognition_runtime_feedback(start_res, log_info, current_java_version)
    tried = {
        (str(item.get("loader")), str(item.get("loader_version")), str(item.get("mc_version")), str(item.get("start_mode")))
        for item in recognition_attempts
    }
    inferred_loader = runtime.get("inferred_loader")
    inferred_mc_version = runtime.get("inferred_mc_version")
    runtime_java_hint = runtime.get("java_hint")
    boosted: list[RecognitionFallbackPlan] = []
    for plan in plans:
        if (plan.loader, str(plan.loader_version), str(plan.mc_version), plan.start_mode) in tried:
            continue
        preflight_result = preflight(plan)
        if not preflight_result.get("allowed"):
            continue
        preflight_score = float(cast(float | int, preflight_result.get("score") or 0))
        preflight_checks = _string_list(preflight_result.get("checks") or [])
        confidence = plan.confidence + (0.25 if inferred_loader and plan.loader == inferred_loader else 0.0)
        confidence += 0.12 if inferred_mc_version and plan.mc_version == inferred_mc_version else 0.0
        confidence += 0.08 if runtime_java_hint and plan.java_version == runtime_java_hint else 0.0
        confidence += min(preflight_score * 0.03, 0.15)
        boosted.append(
            RecognitionFallbackPlan(
                loader=plan.loader,
                loader_version=plan.loader_version,
                mc_version=plan.mc_version,
                build=plan.build,
                start_mode=plan.start_mode,
                java_version=int(cast(int, runtime_java_hint or plan.java_version)),
                confidence=min(1.0, round(confidence, 3)),
                reason=(
                    f"{plan.reason}; runtime_loader={inferred_loader or 'unknown'}; "
                    f"runtime_mc={inferred_mc_version or 'unknown'}; "
                    f"runtime_java={runtime_java_hint or 'unknown'}; "
                    f"preflight={','.join(preflight_checks) or 'none'}"
                ),
                source_candidates=list(plan.source_candidates),
            )
        )
    if not boosted:
        return None
    return sorted(boosted, key=lambda item: (-item.confidence, item.java_version))[0]


def build_ai_context(builder: ServerBuilder, start_res: dict[str, object], log_info: dict[str, object]) -> dict[str, object]:
    session = builder._coerce_bisect_session()
    manifest = builder.manifest
    recognition_summary = builder._build_recognition_summary() if manifest else {}
    rollback_state = dict(getattr(builder, "last_rollback_remove_mods", {}) or {})
    remove_validation_state = dict(getattr(builder, "remove_validation_state", {}) or {})
    current_crash_reports = _string_list(start_res.get("crash_reports_snapshot") or [])
    last_crash_reports = _string_list(rollback_state.get("crash_reports_after_validation") or [])
    crash_report_delta = sorted(set(current_crash_reports).symmetric_difference(set(last_crash_reports)))
    crash_reports_changed = bool(rollback_state.get("triggered")) and bool(crash_report_delta)
    if rollback_state:
        rollback_state["crash_reports_changed_since_last_context"] = crash_reports_changed
        builder.last_rollback_remove_mods = rollback_state
    return {
        "mc_version": manifest.mc_version if manifest else "unknown",
        "loader": manifest.loader if manifest else "unknown",
        "loader_version": getattr(manifest, "loader_version", None) if manifest else None,
        "build": getattr(manifest, "build", None) if manifest else None,
        "start_mode": getattr(manifest, "start_mode", "unknown") if manifest else "unknown",
        "recognition_summary": recognition_summary,
        "jvm_args": f"Xmx={builder.jvm_xmx} Xms={builder.jvm_xms}",
        "available_ram": builder.get_system_memory(),
        "mod_count": len(builder.list_mods()),
        "current_installed_mods": builder.list_mods(),
        "current_installed_client_mods": builder.list_current_installed_client_mods(),
        "known_deleted_client_mods": sorted(builder.known_deleted_client_mods),
        "deleted_mod_evidence": builder.deleted_mod_evidence,
        "dependency_cleanup_rule_enabled": True,
        "recent_actions": builder.operations[-20:],
        "last_rollback_remove_mods": rollback_state,
        "remove_validation_state": remove_validation_state,
        "crash_reports_changed_since_last_rollback_remove": crash_reports_changed,
        "last_crash_reports": last_crash_reports,
        "current_crash_reports": current_crash_reports,
        "crash_report_delta": crash_report_delta,
        "last_crash_excerpt": str(rollback_state.get("validation_crash_excerpt") or ""),
        "bisect_active": bool(getattr(session, "active", False)),
        "bisect_next_allowed_requests": list(getattr(session, "next_allowed_requests", []) or []),
        "bisect_feedback": dict(getattr(builder, "last_bisect_feedback", {}) or {}),
        "bisect_fallback_targets": list(getattr(session, "fallback_targets", []) or []),
        "bisect_suspects_invalidated": bool(getattr(session, "suspects_invalidated", False)),
        "bisect_phase": str(getattr(session, "phase", "initial") or "initial"),
        "bisect_stagnant_rounds": int(getattr(session, "stagnant_rounds", 0) or 0),
        "bisect_last_preflight_block_reason": str(getattr(session, "last_preflight_block_reason", "") or ""),
        "bisect_last_preflight_block_details": list(getattr(session, "last_preflight_block_details", []) or []),
        "bisect_success_ready": bool(getattr(session, "success_ready", False)),
        "bisect_success_guard_reason": str(getattr(session, "success_guard_reason", "") or ""),
        "bisect_success_guard_history": list(getattr(session, "success_guard_history", []) or []),
        "bisect_consecutive_same_issue_on_success": int(getattr(session, "consecutive_same_issue_on_success", 0) or 0),
        "done_detected": bool(start_res.get("done_detected", False)),
        "command_probe_detected": bool(start_res.get("command_probe_detected", False)),
        "port_open_detected": bool(start_res.get("port_open_detected", False)),
        "stdout_tail": str(start_res.get("stdout_tail") or ""),
        "stderr_tail": str(start_res.get("stderr_tail") or ""),
        **log_info,
    }
