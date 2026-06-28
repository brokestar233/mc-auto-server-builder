from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING

from .models import pack_manifest_from_dict, pack_manifest_to_dict

if TYPE_CHECKING:
    from .builder import ServerBuilder
    from .models import PackManifest


def load_resume_source_from_path(builder: ServerBuilder, resume_path: Path) -> str:
    state_path = resume_path / "run_state.json"
    if not state_path.exists() or not state_path.is_file():
        return ""
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ""
    return str(payload.get("source_input") or "").strip() if isinstance(payload, dict) else ""


def read_resume_state(builder: ServerBuilder) -> dict[str, object]:
    if not builder.resume_state_path.exists() or not builder.resume_state_path.is_file():
        return {}
    try:
        payload = json.loads(builder.resume_state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return dict(payload) if isinstance(payload, dict) else {}


def build_resume_state(builder: ServerBuilder, *, prepared_server: bool) -> dict[str, object]:
    return {
        "schema_version": 1,
        "source_input": builder.source_input,
        "prepared_server": prepared_server,
        "pack_cache_key": builder.pack_cache_key,
        "pack_input": {
            "input_type": builder.pack_input.input_type,
            "source": builder.pack_input.source,
            "file_id": builder.pack_input.file_id,
        },
        "manifest": pack_manifest_to_dict(builder.manifest) if builder.manifest else {},
        "current_java_version": builder.current_java_version,
        "java_params_mode_by_version": dict(builder.java_params_mode_by_version),
        "jvm_xmx": builder.jvm_xmx,
        "jvm_xms": builder.jvm_xms,
        "extra_jvm_flags": list(builder.extra_jvm_flags),
        "server_jar_name": builder.server_jar_name,
        "start_command_mode": builder.start_command_mode,
        "start_command_value": builder.start_command_value,
        "removed_mods": list(builder.removed_mods),
        "bisect_removed_mods": list(builder.bisect_removed_mods),
        "known_deleted_client_mods": sorted(builder.known_deleted_client_mods),
        "deleted_mod_evidence": dict(builder.deleted_mod_evidence),
        "deleted_mod_sources": dict(getattr(builder, "deleted_mod_sources", {})),
        "recognition_attempts": list(builder.recognition_attempts),
        "last_ai_manual_report": dict(builder.last_ai_manual_report),
        "last_rollback_remove_mods": dict(builder.last_rollback_remove_mods),
        "remove_validation_state": dict(builder.remove_validation_state),
    }


def persist_resume_state(builder: ServerBuilder, *, prepared_server: bool) -> None:
    payload = build_resume_state(builder, prepared_server=prepared_server)
    builder.resume_state = payload
    builder.resume_state_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def restore_resume_state(builder: ServerBuilder) -> None:
    state = read_resume_state(builder)
    builder.resume_state = state
    if not state:
        return

    manifest_payload = state.get("manifest")
    if isinstance(manifest_payload, dict) and manifest_payload:
        builder.manifest = pack_manifest_from_dict(manifest_payload)

    raw_current_java_version = state.get("current_java_version", builder.current_java_version)
    builder.current_java_version = (
        int(raw_current_java_version)
        if isinstance(raw_current_java_version, (int, float, str))
        else builder.current_java_version
    )

    raw_java_modes = state.get("java_params_mode_by_version", {})
    java_modes = raw_java_modes if isinstance(raw_java_modes, dict) else {}
    builder.java_params_mode_by_version = {
        int(key): str(value)
        for key, value in java_modes.items()
        if str(key).strip() and str(value).strip()
    } or dict(builder.java_params_mode_by_version)

    builder.jvm_xmx = str(state.get("jvm_xmx") or builder.jvm_xmx)
    builder.jvm_xms = str(state.get("jvm_xms") or builder.jvm_xms)

    raw_extra_jvm_flags = state.get("extra_jvm_flags", [])
    builder.extra_jvm_flags = (
        [str(item) for item in raw_extra_jvm_flags if str(item).strip()]
        if isinstance(raw_extra_jvm_flags, list)
        else list(builder.extra_jvm_flags)
    )

    builder.server_jar_name = str(state.get("server_jar_name") or builder.server_jar_name)
    builder.start_command_mode = str(state.get("start_command_mode") or builder.start_command_mode)
    builder.start_command_value = str(state.get("start_command_value") or builder.start_command_value)

    raw_removed_mods = state.get("removed_mods", [])
    builder.removed_mods = (
        [str(item) for item in raw_removed_mods if str(item).strip()]
        if isinstance(raw_removed_mods, list)
        else []
    )
    raw_bisect_removed_mods = state.get("bisect_removed_mods", [])
    builder.bisect_removed_mods = (
        [str(item) for item in raw_bisect_removed_mods if str(item).strip()]
        if isinstance(raw_bisect_removed_mods, list)
        else []
    )
    raw_known_deleted_mods = state.get("known_deleted_client_mods", [])
    builder.known_deleted_client_mods = (
        {str(item) for item in raw_known_deleted_mods if str(item).strip()}
        if isinstance(raw_known_deleted_mods, list)
        else set()
    )

    raw_deleted_mod_evidence = state.get("deleted_mod_evidence", {})
    builder.deleted_mod_evidence = (
        {
            str(key): [str(item) for item in value if str(item).strip()]
            for key, value in raw_deleted_mod_evidence.items()
            if isinstance(value, list)
        }
        if isinstance(raw_deleted_mod_evidence, dict)
        else {}
    )

    raw_deleted_mod_sources = state.get("deleted_mod_sources", {})
    if isinstance(raw_deleted_mod_sources, dict):
        builder.deleted_mod_sources = dict(raw_deleted_mod_sources)

    raw_recognition_attempts = state.get("recognition_attempts", [])
    builder.recognition_attempts = (
        [dict(item) for item in raw_recognition_attempts if isinstance(item, dict)]
        if isinstance(raw_recognition_attempts, list)
        else []
    )

    raw_last_ai_manual_report = state.get("last_ai_manual_report", {})
    builder.last_ai_manual_report = (
        dict(raw_last_ai_manual_report)
        if isinstance(raw_last_ai_manual_report, dict)
        else {}
    )
    raw_last_rollback_remove_mods = state.get("last_rollback_remove_mods", {})
    builder.last_rollback_remove_mods = (
        dict(raw_last_rollback_remove_mods)
        if isinstance(raw_last_rollback_remove_mods, dict)
        else {}
    )
    raw_remove_validation_state = state.get("remove_validation_state", {})
    builder.remove_validation_state = (
        dict(raw_remove_validation_state)
        if isinstance(raw_remove_validation_state, dict)
        else {}
    )
    builder.pack_cache_key = str(state.get("pack_cache_key") or "")
    java_bin = builder._java_bin_path(builder.current_java_version)
    if java_bin.exists():
        builder.current_java_bin = java_bin


def resume_prepared_server_available(builder: ServerBuilder) -> bool:
    if not builder.resume_requested:
        return False
    if not bool(builder.resume_state.get("prepared_server", False)):
        return False
    if not builder.workdirs.server.exists() or not builder.workdirs.server.is_dir():
        return False
    try:
        return any(builder.workdirs.server.iterdir())
    except OSError:
        return False


def build_pack_cache_key(builder: ServerBuilder, *, source_hint: str | None = None) -> str:
    if builder.pack_input.input_type == "local_zip":
        path = Path(source_hint or builder.pack_input.source).resolve()
        stat = path.stat()
        raw = f"local_zip:{path}:{stat.st_size}:{stat.st_mtime_ns}"
    else:
        raw = (
            f"{builder.pack_input.input_type}:"
            f"{source_hint or builder.pack_input.source}:"
            f"{builder.pack_input.file_id or ''}"
        )
    return sha256(raw.encode("utf-8")).hexdigest()[:24]


def pack_cache_zip_path(builder: ServerBuilder, cache_key: str) -> Path:
    return builder.cache_dirs.packs / f"{cache_key}.zip"


def manifest_cache_path(builder: ServerBuilder, cache_key: str) -> Path:
    return builder.cache_dirs.manifests / f"{cache_key}.json"


def load_manifest_from_cache(builder: ServerBuilder, cache_key: str) -> PackManifest | None:
    cache_path = manifest_cache_path(builder, cache_key)
    if not cache_path.exists() or not cache_path.is_file():
        return None
    try:
        payload = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    return pack_manifest_from_dict(payload)


def persist_manifest_cache(builder: ServerBuilder, cache_key: str, manifest: PackManifest) -> None:
    manifest_cache_path(builder, cache_key).write_text(
        json.dumps(pack_manifest_to_dict(manifest), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def download_pack_to_cache(builder: ServerBuilder, url: str, cache_key: str, *, stage: str = "install.download") -> Path:
    out = pack_cache_zip_path(builder, cache_key)
    if out.exists() and out.is_file():
        builder.operations.append(f"pack_cache_hit:{cache_key}")
        return out
    builder._download_file(url, out, stage=stage)
    builder.operations.append(f"pack_cache_store:{cache_key}")
    return out
