from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    tomllib = None


def _normalize_token(value: str) -> str:
    token = str(value or "").strip().lower()
    token = token.removesuffix(".jar")
    token = re.sub(r"[\s_\-\.]+", "", token)
    return token


def _read_jar_member_text(jar_path: Path, member_name: str) -> str:
    with zipfile.ZipFile(jar_path, "r") as zf:
        try:
            return zf.read(member_name).decode("utf-8", errors="ignore")
        except KeyError:
            return ""


def _read_first_existing_member(jar_path: Path, member_names: list[str]) -> tuple[str, str]:
    with zipfile.ZipFile(jar_path, "r") as zf:
        for member_name in member_names:
            try:
                return member_name, zf.read(member_name).decode("utf-8", errors="ignore")
            except KeyError:
                continue
    return "", ""


def _parse_fabric_like_metadata(file_name: str, raw_text: str, metadata_type: str) -> dict[str, object]:
    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError:
        return {
            "file_name": file_name,
            "metadata_type": metadata_type,
            "mod_ids": [],
            "display_name": "",
            "environment": "unknown",
            "client_only": False,
            "dependencies": [],
            "parsing_error": "invalid_json",
        }

    mod_ids: list[str] = []
    dependency_ids: list[dict[str, object]] = []
    environment = "unknown"
    display_name = ""

    if metadata_type == "fabric":
        mod_id = str(payload.get("id") or "").strip()
        if mod_id:
            mod_ids.append(mod_id)
        display_name = str(payload.get("name") or "")
        environment = str(payload.get("environment") or "unknown")
        depends = payload.get("depends")
        if isinstance(depends, dict):
            for dep_id, constraint in depends.items():
                text = str(dep_id or "").strip()
                if text:
                    dependency_ids.append(
                        {
                            "mod_id": text,
                            "mandatory": True,
                            "side": "both",
                            "constraint": str(constraint or "").strip(),
                        }
                    )
    else:
        loader = payload.get("quilt_loader")
        if isinstance(loader, dict):
            mod_id = str(loader.get("id") or "").strip()
            if mod_id:
                mod_ids.append(mod_id)
            metadata = loader.get("metadata")
            if isinstance(metadata, dict):
                display_name = str(metadata.get("name") or "")
            depends = loader.get("depends")
            if isinstance(depends, list):
                for item in depends:
                    if isinstance(item, str):
                        dependency_ids.append({"mod_id": item, "mandatory": True, "side": "both", "constraint": ""})
                    elif isinstance(item, dict):
                        dep_id = str(item.get("id") or "").strip()
                        if dep_id:
                            dependency_ids.append(
                                {
                                    "mod_id": dep_id,
                                    "mandatory": True,
                                    "side": str(item.get("unless") or "both"),
                                    "constraint": str(item.get("versions") or "").strip(),
                                }
                            )
        environment = (
            str(payload.get("minecraft", {}).get("environment") or "unknown")
            if isinstance(payload.get("minecraft"), dict)
            else "unknown"
        )

    return {
        "file_name": file_name,
        "metadata_type": metadata_type,
        "mod_ids": sorted(dict.fromkeys(mod_ids)),
        "display_name": display_name,
        "environment": environment,
        "client_only": environment == "client",
        "dependencies": dependency_ids,
    }


def _parse_toml_with_fallback(raw_text: str) -> tuple[dict[str, object], str]:
    if tomllib is not None:
        try:
            return tomllib.loads(raw_text), ""
        except Exception as exc:  # pragma: no cover - parser fallback
            return {}, type(exc).__name__
    return {}, "tomllib_unavailable"


def _parse_forge_like_metadata(file_name: str, raw_text: str, metadata_type: str) -> dict[str, object]:
    parsed, parsing_error = _parse_toml_with_fallback(raw_text)
    mod_ids: list[str] = []
    display_name = ""
    dependency_entries: list[dict[str, object]] = []
    client_only = False

    if parsed:
        mods = parsed.get("mods")
        if isinstance(mods, list):
            for item in mods:
                if not isinstance(item, dict):
                    continue
                mod_id = str(item.get("modId") or "").strip()
                if mod_id:
                    mod_ids.append(mod_id)
                if not display_name:
                    display_name = str(item.get("displayName") or "")
        dependencies = parsed.get("dependencies")
        if isinstance(dependencies, dict):
            for owner_mod, values in dependencies.items():
                for item in values if isinstance(values, list) else []:
                    if not isinstance(item, dict):
                        continue
                    dep_id = str(item.get("modId") or "").strip()
                    side = str(item.get("side") or "BOTH").lower()
                    dependency_entries.append(
                        {
                            "owner_mod": str(owner_mod),
                            "mod_id": dep_id,
                            "mandatory": bool(item.get("mandatory", False)),
                            "side": side,
                            "constraint": str(item.get("versionRange") or "").strip(),
                        }
                    )
                    if side == "client":
                        client_only = True

    if not mod_ids:
        mod_ids.extend(re.findall(r'(?m)^\s*modId\s*=\s*"([^"]+)"', raw_text))
    if not display_name:
        match = re.search(r'(?m)^\s*displayName\s*=\s*"([^"]+)"', raw_text)
        display_name = match.group(1).strip() if match else ""
    if not dependency_entries:
        dep_blocks = re.finditer(r"(?ms)^\s*\[\[dependencies\.([^\]]+)\]\]\s*(.*?)(?=^\s*\[\[|\Z)", raw_text)
        for block in dep_blocks:
            owner_mod = block.group(1).strip()
            body = block.group(2)
            dep_match = re.search(r'(?m)^\s*modId\s*=\s*"([^"]+)"', body)
            side_match = re.search(r'(?m)^\s*side\s*=\s*"([^"]+)"', body)
            mandatory_match = re.search(r"(?m)^\s*mandatory\s*=\s*(true|false)", body, flags=re.IGNORECASE)
            if not dep_match:
                continue
            side = side_match.group(1).strip().lower() if side_match else "both"
            dependency_entries.append(
                {
                    "owner_mod": owner_mod,
                    "mod_id": dep_match.group(1).strip(),
                    "mandatory": bool(mandatory_match and mandatory_match.group(1).lower() == "true"),
                    "side": side,
                    "constraint": "",
                }
            )
            if side == "client":
                client_only = True

    return {
        "file_name": file_name,
        "metadata_type": metadata_type,
        "mod_ids": sorted(dict.fromkeys(mod_ids)),
        "display_name": display_name,
        "environment": "client" if client_only else "unknown",
        "client_only": client_only,
        "dependencies": dependency_entries,
        "parsing_error": parsing_error,
    }


def inspect_mod_metadata(mods_dir: Path) -> dict[str, object]:
    if not mods_dir.exists() or not mods_dir.is_dir():
        return {"files": [], "mod_id_to_files": {}, "client_only_mods": []}

    files: list[dict[str, object]] = []
    mod_id_to_files: dict[str, list[str]] = {}
    client_only_mods: list[str] = []

    for jar_path in sorted(mods_dir.glob("*.jar"), key=lambda item: item.name.lower()):
        try:
            member_name, raw_text = _read_first_existing_member(
                jar_path,
                [
                    "fabric.mod.json",
                    "quilt.mod.json",
                    "META-INF/mods.toml",
                    "META-INF/neoforge.mods.toml",
                ],
            )
        except (OSError, zipfile.BadZipFile):
            files.append(
                {
                    "file_name": jar_path.name,
                    "metadata_type": "invalid_archive",
                    "mod_ids": [],
                    "display_name": "",
                    "environment": "unknown",
                    "client_only": False,
                    "dependencies": [],
                }
            )
            continue
        if member_name == "fabric.mod.json":
            entry = _parse_fabric_like_metadata(jar_path.name, raw_text, "fabric")
        elif member_name == "quilt.mod.json":
            entry = _parse_fabric_like_metadata(jar_path.name, raw_text, "quilt")
        elif member_name in {"META-INF/mods.toml", "META-INF/neoforge.mods.toml"}:
            entry = _parse_forge_like_metadata(
                jar_path.name,
                raw_text,
                "neoforge" if member_name.endswith("neoforge.mods.toml") else "forge",
            )
        else:
            entry = {
                "file_name": jar_path.name,
                "metadata_type": "unknown",
                "mod_ids": [],
                "display_name": "",
                "environment": "unknown",
                "client_only": False,
                "dependencies": [],
            }
        files.append(entry)
        if bool(entry.get("client_only")):
            client_only_mods.append(jar_path.name)
        raw_mod_ids = entry.get("mod_ids", [])
        for mod_id in raw_mod_ids if isinstance(raw_mod_ids, list) else []:
            clean_id = str(mod_id).strip()
            if not clean_id:
                continue
            mod_id_to_files.setdefault(clean_id, [])
            if jar_path.name not in mod_id_to_files[clean_id]:
                mod_id_to_files[clean_id].append(jar_path.name)

    return {
        "files": files,
        "mod_id_to_files": {key: sorted(values) for key, values in sorted(mod_id_to_files.items())},
        "client_only_mods": sorted(dict.fromkeys(client_only_mods)),
    }


def build_dependency_graph(mod_metadata: dict[str, object], known_deleted_mods: list[str]) -> dict[str, object]:
    raw_file_entries = mod_metadata.get("files", [])
    file_entries = raw_file_entries if isinstance(raw_file_entries, list) else []
    deleted_tokens = {_normalize_token(item) for item in known_deleted_mods if str(item).strip()}
    raw_mod_id_to_files = mod_metadata.get("mod_id_to_files", {})
    mod_id_to_files = raw_mod_id_to_files if isinstance(raw_mod_id_to_files, dict) else {}
    deleted_dependency_hits: list[dict[str, object]] = []
    dependency_edges: list[dict[str, object]] = []

    for entry in file_entries:
        if not isinstance(entry, dict):
            continue
        file_name = str(entry.get("file_name") or "")
        dependencies = entry.get("dependencies")
        for dep in dependencies if isinstance(dependencies, list) else []:
            if not isinstance(dep, dict):
                continue
            dep_id = str(dep.get("mod_id") or "").strip()
            if not dep_id:
                continue
            edge = {
                "file_name": file_name,
                "mod_ids": (
                    [str(item) for item in entry.get("mod_ids", []) if str(item).strip()]
                    if isinstance(entry.get("mod_ids"), list)
                    else []
                ),
                "dependency_id": dep_id,
                "mandatory": bool(dep.get("mandatory", False)),
                "side": str(dep.get("side") or "both"),
                "provider_files": [str(item) for item in mod_id_to_files.get(dep_id, []) if str(item).strip()],
            }
            dependency_edges.append(edge)
            provider_files = edge["provider_files"] if isinstance(edge["provider_files"], list) else []
            dep_tokens = {_normalize_token(dep_id), *(_normalize_token(str(item)) for item in provider_files)}
            matched_deleted = sorted(deleted_tokens.intersection(dep_tokens))
            if matched_deleted:
                deleted_dependency_hits.append(
                    {
                        "file_name": file_name,
                        "dependency_id": dep_id,
                        "matched_deleted_tokens": matched_deleted,
                        "provider_files": edge["provider_files"],
                    }
                )

    return {
        "dependency_edges": dependency_edges[:200],
        "deleted_dependency_hits": deleted_dependency_hits[:100],
    }


def inspect_crash_report(crash_content: str, refined_log: str, crash_mod_issue: str) -> dict[str, object]:
    combined = "\n".join([str(crash_content or ""), str(refined_log or ""), str(crash_mod_issue or "")])
    caused_by = re.findall(r"(?m)^\s*Caused by:\s*([^\n]+)", combined)
    mixin_errors = re.findall(r"(?im)(mixin[^\n]*(?:failed|error)[^\n]*)", combined)
    missing_dependency_hints = re.findall(
        r"(?im)(?:requires|depends on)\s+([a-z0-9_\-.]+)\s+(?:but it is missing|which is missing)",
        combined,
    )
    mentioned_mod_ids = re.findall(r"(?im)\b(?:mod(?:id)?|for)\s*[:=]?\s*([a-z0-9_\-.]+)\b", combined)
    header_matches = re.findall(r"(?im)^--\s+Mod loading issue for:\s+([^\s]+)", crash_mod_issue or "")
    if header_matches:
        mentioned_mod_ids.extend(header_matches)

    preview_lines: list[str] = []
    for raw_line in combined.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lowered = line.lower()
        if any(marker in lowered for marker in ("caused by", "missing", "mixin", "exception", "error")):
            preview_lines.append(line)
        if len(preview_lines) >= 12:
            break

    return {
        "caused_by": caused_by[:6],
        "mixin_errors": mixin_errors[:6],
        "missing_dependency_hints": sorted(dict.fromkeys(missing_dependency_hints))[:20],
        "mentioned_mod_ids": sorted(dict.fromkeys(mentioned_mod_ids))[:30],
        "signal_preview": preview_lines,
    }


def verify_start_command_artifacts(server_dir: Path, mode: str, value: str, *, server_jar_name: str = "server.jar") -> dict[str, object]:
    normalized_mode = str(mode or "").strip().lower()
    normalized_value = str(value or "").strip()
    issues: list[str] = []
    candidate_server_jars = sorted(path.name for path in server_dir.glob("*.jar") if path.is_file())
    argsfile_candidates = sorted(
        str(path.relative_to(server_dir)).replace("\\", "/")
        for path in [*server_dir.glob("libraries/**/unix_args.txt"), *server_dir.glob("libraries/**/win_args.txt")]
        if path.is_file()
    )
    run_script_candidates = sorted(
        path.name
        for path in server_dir.glob("*")
        if path.is_file() and path.suffix.lower() in {".sh", ".bat", ".cmd", ".ps1"}
    )

    referenced_jars: list[str] = []
    missing_references: list[str] = []
    target_path = server_dir / normalized_value if normalized_value else server_dir / server_jar_name

    if normalized_mode == "jar":
        if not target_path.exists():
            issues.append("jar_missing")
    elif normalized_mode == "argsfile":
        if not target_path.exists():
            issues.append("argsfile_missing")
        else:
            raw_text = target_path.read_text(encoding="utf-8", errors="ignore")
            referenced_jars = re.findall(r'([A-Za-z0-9_./\\-]+\.jar)', raw_text)
            for jar_name in referenced_jars:
                jar_path = server_dir / jar_name
                if not jar_path.exists():
                    missing_references.append(jar_name)
            if missing_references:
                issues.append("argsfile_references_missing_jar")
    elif normalized_mode == "script":
        if not target_path.exists():
            issues.append("script_missing")
    else:
        issues.append("unknown_start_mode")

    return {
        "mode": normalized_mode or "unknown",
        "value": normalized_value or server_jar_name,
        "target_exists": target_path.exists(),
        "issues": issues,
        "candidate_server_jars": candidate_server_jars[:20],
        "argsfile_candidates": argsfile_candidates[:20],
        "run_script_candidates": run_script_candidates[:20],
        "referenced_jars": referenced_jars[:20],
        "missing_references": missing_references[:20],
    }
