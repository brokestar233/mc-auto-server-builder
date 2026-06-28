from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from .util import normalize_client_relative_path, replace_path

if TYPE_CHECKING:
    from .builder import ServerBuilder


def extract_curseforge_type_hints(builder: ServerBuilder, file_data: dict) -> list[str]:
    hints: list[str] = []
    for key in ("gameVersions", "displayName", "fileName"):
        value = file_data.get(key)
        if isinstance(value, list):
            hints.extend(str(item) for item in value if str(item).strip())
        elif value is not None and str(value).strip():
            hints.append(str(value))
    return hints


def extract_modrinth_type_hints(builder: ServerBuilder, item: dict) -> list[str]:
    hints: list[str] = []
    for key in ("project_type", "projectType", "file_type", "fileType", "tags"):
        value = item.get(key)
        if isinstance(value, list):
            hints.extend(str(x) for x in value if str(x).strip())
        elif value is not None and str(value).strip():
            hints.append(str(value))
    return hints


def classify_manifest_file_type(
    builder: ServerBuilder,
    *,
    platform: str,
    file_name: str,
    rel_path: str | None,
    platform_hints: list[str],
) -> tuple[str, bool, str]:
    def _contains_any(text: str, patterns: set[str]) -> bool:
        return any(pattern in text for pattern in patterns)

    shader_patterns = {"shader", "shaders", "shaderpack", "shaderpacks"}
    resource_patterns = {
        "resourcepack",
        "resourcepacks",
        "resource-pack",
        "resource_pack",
        "texturepack",
        "texturepacks",
        "texture-pack",
        "texture_pack",
    }
    plugin_patterns = {"plugin", "plugins", "bukkit", "spigot", "paper", "purpur", "bungeecord", "velocity"}
    datapack_patterns = {"datapack", "datapacks", "data-pack", "data_pack", "pack.mcmeta"}
    mod_patterns = {"mod", "mods"}

    normalized_hints = " ".join(str(x).strip().lower() for x in platform_hints if str(x).strip())
    if normalized_hints:
        if _contains_any(normalized_hints, shader_patterns):
            return "shader", False, "platform_hint:shader"
        if _contains_any(normalized_hints, resource_patterns):
            return "resourcepack", False, "platform_hint:resourcepack"
        if _contains_any(normalized_hints, plugin_patterns):
            return "plugin", True, "platform_hint:plugin"
        if _contains_any(normalized_hints, datapack_patterns):
            return "datapack", True, "platform_hint:datapack"
        if _contains_any(normalized_hints, mod_patterns):
            return "mod", True, "platform_hint:mod"

    merged = " ".join(filter(None, [file_name, rel_path or ""])).strip().lower()
    if merged:
        if _contains_any(merged, shader_patterns):
            return "shader", False, "name_or_path:shader"
        if _contains_any(merged, resource_patterns):
            return "resourcepack", False, "name_or_path:resourcepack"
        if _contains_any(merged, plugin_patterns):
            return "plugin", True, "name_or_path:plugin"
        if _contains_any(merged, datapack_patterns):
            return "datapack", True, "name_or_path:datapack"
        if _contains_any(merged, mod_patterns):
            return "mod", True, "name_or_path:mod"

    if platform == "modrinth" and rel_path:
        normalized_rel = normalize_client_relative_path(rel_path)
        rel_lower = normalized_rel.lower()
        if rel_lower.startswith("mods/"):
            return "mod", True, "modrinth_path:mods_dir"
        if rel_lower.startswith("plugins/"):
            return "plugin", True, "modrinth_path:plugins_dir"
        if "datapack" in rel_lower or rel_lower.startswith("datapacks/"):
            return "datapack", True, "modrinth_path:datapacks_dir"
        if "resourcepack" in rel_lower or rel_lower.startswith("resourcepacks/"):
            return "resourcepack", False, "modrinth_path:resourcepacks_dir"
        if "shader" in rel_lower or rel_lower.startswith("shaderpacks/"):
            return "shader", False, "modrinth_path:shaderpacks_dir"

    return "mod", True, "default:mod"


def extract_full_pack_version_payload_if_needed(builder: ServerBuilder) -> None:
    if not builder.manifest:
        return
    full_pack = builder.manifest.raw.get("full_pack") if isinstance(builder.manifest.raw, dict) else None
    if not isinstance(full_pack, dict):
        return

    version_name = str(full_pack.get("version_name") or "").strip()
    version_dir = builder.workdirs.client_temp / ".minecraft" / "versions" / version_name
    if not version_name or not version_dir.exists() or not version_dir.is_dir():
        return

    copied = 0
    for child in sorted(version_dir.iterdir(), key=lambda p: p.name.lower()):
        if child.name in {f"{version_name}.jar", f"{version_name}.json"}:
            continue
        destination = builder.workdirs.client_temp / child.name
        replace_path(child, destination)
        copied += 1

    builder.operations.append(f"full_pack_extract:{version_name}:copied={copied}")
    builder._log("install.unpack", f"全量包版本目录提取完成: version={version_name}, copied={copied}")


def copy_client_files_with_blacklist(builder: ServerBuilder, blacklist: set[str]) -> tuple[int, int]:
    copied = 0
    skipped = 0

    base = builder.workdirs.client_temp
    roots: list[Path] = [base]
    base_files = [path for path in base.iterdir() if path.is_file()]

    top_dirs = [path for path in base.iterdir() if path.is_dir()]
    if len(top_dirs) == 1:
        nested_root = top_dirs[0]
        if nested_root.name.lower() not in {
            "overrides",
            "override",
            "server-overrides",
            "server_overrides",
            "serveroverrides",
            "server",
            "serverfiles",
            "server-files",
            "serverpack",
            "server_pack",
            "resourcepacks",
        }:
            if not base_files:
                roots = [nested_root]
            else:
                roots.append(nested_root)

    dedup_roots: list[Path] = []
    seen: set[Path] = set()
    for root in roots:
        if root not in seen and root.exists() and root.is_dir():
            dedup_roots.append(root)
            seen.add(root)

    for root in dedup_roots:
        for src in root.iterdir():
            name_lc = src.name.lower()
            if name_lc in {"overrides", "override", "server-overrides", "server_overrides", "serveroverrides"}:
                skipped += 1
                continue
            if name_lc == "resourcepacks" and src.is_dir():
                kept = builder._extract_server_resourcepacks(src)
                copied += kept
                continue
            if name_lc in blacklist:
                skipped += 1
                continue
            dst = builder.workdirs.server / src.name
            if src.is_file():
                dst.parent.mkdir(parents=True, exist_ok=True)
                replace_path(src, dst)
                copied += 1
                continue

            for item in src.rglob("*"):
                if not item.is_file():
                    continue
                rel = item.relative_to(src)
                rel_parts_lower = [part.lower() for part in rel.parts]
                if any(part in blacklist for part in rel_parts_lower):
                    skipped += 1
                    continue
                target_root = builder.workdirs.server / src.name
                target_root.mkdir(parents=True, exist_ok=True)
                target = target_root / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                replace_path(item, target)
                copied += 1

    return copied, skipped


def manifest_target_path(builder: ServerBuilder, file_type: str, file_name: str, rel_path: str | None = None) -> Path:
    clean_name = (file_name or "").strip() or "unnamed.bin"
    if file_type == "plugin":
        return builder.workdirs.client_temp / "plugins" / clean_name
    if file_type == "datapack":
        return builder.workdirs.client_temp / "datapacks" / clean_name
    if file_type == "mod":
        return builder.workdirs.client_temp / "mods" / clean_name

    normalized_rel = normalize_client_relative_path(rel_path or "")
    if normalized_rel:
        return builder.workdirs.client_temp / normalized_rel
    return builder.workdirs.client_temp / clean_name
