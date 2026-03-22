from __future__ import annotations

import json
import re
from pathlib import Path
from typing import cast
from zipfile import ZipFile

from .models import LoaderType, ModInfo, PackInput, PackManifest
from .util import is_http_url, normalize_loader_name

CURSEFORGE_DOWNLOAD_RE = re.compile(r"curseforge\.com/.*/download/(\d+)", re.IGNORECASE)
CURSEFORGE_FILES_RE = re.compile(r"curseforge\.com/.*/files/(\d+)", re.IGNORECASE)
CURSEFORGE_PROJECT_ID_RE = re.compile(r"curseforge\.com/.*/projects/(\d+)", re.IGNORECASE)
CURSEFORGE_SLUG_RE = re.compile(r"curseforge\.com/minecraft/modpacks/([A-Za-z0-9\-_]+)", re.IGNORECASE)
MODRINTH_VERSION_RE = re.compile(
    r"modrinth\.com/(?:mod|modpack|resourcepack|shader|plugin|datapack)/([A-Za-z0-9\-_]+)/version/([A-Za-z0-9]+)",
    re.IGNORECASE,
)
MODRINTH_PROJECT_RE = re.compile(
    r"modrinth\.com/(?:mod|modpack|resourcepack|shader|plugin|datapack)/([A-Za-z0-9\-_]+)",
    re.IGNORECASE,
)


def _zip_dir_exists(names: set[str], target: str) -> bool:
    normalized = target.strip("/")
    if not normalized:
        return False
    prefix = f"{normalized}/"
    return any(name == normalized or name.startswith(prefix) for name in names)


def _find_full_pack_version_entries(names: set[str]) -> tuple[str, list[str]] | None:
    version_roots: dict[str, list[str]] = {}
    for name in sorted(names):
        parts = [part for part in name.split("/") if part]
        if len(parts) < 3:
            continue
        if parts[0] != ".minecraft" or parts[1] != "versions":
            continue
        version_name = parts[2]
        version_roots.setdefault(version_name, []).append(name)

    if not version_roots:
        return None

    first_version = sorted(version_roots)[0]
    return first_version, version_roots[first_version]


def _infer_loader_from_version_json(version_json: dict) -> tuple[LoaderType, str | None]:
    release_time = str(version_json.get("releaseTime") or "")
    if "neoforge" in release_time.lower():
        return "neoforge", None

    libraries = version_json.get("libraries")
    if not isinstance(libraries, list):
        return "unknown", None

    for lib in libraries:
        if not isinstance(lib, dict):
            continue
        name = str(lib.get("name") or "")
        if not name:
            continue
        lowered = name.lower()
        parts = name.split(":")
        version = parts[-1] if len(parts) >= 3 else None
        if lowered.startswith("net.neoforged:neoforge"):
            return "neoforge", version
        if lowered.startswith("net.minecraftforge:forge"):
            return "forge", version
        if lowered.startswith("net.fabricmc:fabric-loader"):
            return "fabric", version
        if lowered.startswith("org.quiltmc:quilt-loader"):
            return "quilt", version

    return "unknown", None


def _from_full_pack_zip(zf: ZipFile, names: set[str]) -> PackManifest:
    if not _zip_dir_exists(names, ".minecraft"):
        raise ValueError("ZIP 不包含 .minecraft 目录")

    version_info = _find_full_pack_version_entries(names)
    if not version_info:
        raise ValueError("ZIP 未找到 .minecraft/versions 下的版本目录")

    version_name, version_entries = version_info
    version_json_path = f".minecraft/versions/{version_name}/{version_name}.json"
    if version_json_path not in names:
        raise ValueError(f"ZIP 未找到版本元数据: {version_json_path}")

    version_json = json.loads(zf.read(version_json_path).decode("utf-8"))
    mc_version = str(
        version_json.get("clientVersion")
        or version_json.get("inheritsFrom")
        or version_json.get("id")
        or version_name
        or "unknown"
    )
    loader, loader_version = _infer_loader_from_version_json(version_json)

    return PackManifest(
        pack_name=version_name,
        mc_version=mc_version,
        loader=loader,
        loader_version=loader_version,
        mods=[],
        raw={
            "pack_type": "full_pack",
            "full_pack": {
                "version_name": version_name,
                "version_dir": f".minecraft/versions/{version_name}",
                "version_entries": sorted(version_entries),
                "remove_files": [
                    f"{version_name}.jar",
                    f"{version_name}.json",
                ],
            },
            "version_json": version_json,
        },
    )


def parse_pack_input(value: str) -> PackInput:
    value = value.strip()
    p = Path(value)
    if p.exists() and p.suffix.lower() == ".zip":
        return PackInput(input_type="local_zip", source=str(p.resolve()))

    if is_http_url(value):
        cf_project = CURSEFORGE_PROJECT_ID_RE.search(value)
        cf_slug = CURSEFORGE_SLUG_RE.search(value)
        if cf_project or cf_slug:
            file_match = CURSEFORGE_DOWNLOAD_RE.search(value) or CURSEFORGE_FILES_RE.search(value)
            file_id = file_match.group(1) if file_match else None
            source = cf_project.group(1) if cf_project else cf_slug.group(1)
            return PackInput(input_type="curseforge", source=source, file_id=file_id)
        mr_version = MODRINTH_VERSION_RE.search(value)
        if mr_version:
            return PackInput(input_type="modrinth", source=mr_version.group(1), file_id=mr_version.group(2))
        mr_project = MODRINTH_PROJECT_RE.search(value)
        if mr_project:
            return PackInput(input_type="modrinth", source=mr_project.group(1))
        return PackInput(input_type="url", source=value)

    if value.lower().startswith("modrinth:"):
        body = value.split(":", 1)[1]
        if ":" in body:
            project, version = body.split(":", 1)
            if project:
                return PackInput(input_type="modrinth", source=project, file_id=version or None)
        if body:
            return PackInput(input_type="modrinth", source=body)

    if ":" in value:
        left, right = value.split(":", 1)
        if left.isdigit() and right.isdigit():
            return PackInput(input_type="curseforge", source=left, file_id=right)

    if value.isdigit():
        return PackInput(input_type="curseforge", source=value, file_id=None)

    return PackInput(input_type="modrinth", source=value)


def parse_manifest_from_zip(zip_path: str | Path) -> PackManifest:
    zpath = Path(zip_path)
    with ZipFile(zpath, "r") as zf:
        names = set(zf.namelist())
        if "manifest.json" in names:
            data = json.loads(zf.read("manifest.json").decode("utf-8"))
            return _from_curseforge_manifest(data)
        if "modrinth.index.json" in names:
            data = json.loads(zf.read("modrinth.index.json").decode("utf-8"))
            return _from_modrinth_manifest(data)
        if _zip_dir_exists(names, ".minecraft"):
            return _from_full_pack_zip(zf, names)

    raise ValueError(f"ZIP 内未找到 manifest.json 或 modrinth.index.json: {zpath}")


def _from_curseforge_manifest(data: dict) -> PackManifest:
    minecraft = data.get("minecraft", {})
    version = minecraft.get("version", "unknown")
    loaders = minecraft.get("modLoaders", [])
    loader_id = loaders[0].get("id", "unknown") if loaders else "unknown"

    loader = cast(LoaderType, normalize_loader_name(loader_id))
    loader_version = None
    if "-" in loader_id:
        loader_version = loader_id.split("-", 1)[1]

    mods = [
        ModInfo(name=f"cf-{m.get('projectID')}-{m.get('fileID')}.jar", project_id=str(m.get("projectID")), file_id=str(m.get("fileID")))
        for m in data.get("files", [])
    ]

    return PackManifest(
        pack_name=data.get("name", "curseforge-pack"),
        mc_version=version,
        loader=loader,
        loader_version=loader_version,
        mods=mods,
        raw=data,
    )


def _from_modrinth_manifest(data: dict) -> PackManifest:
    deps = data.get("dependencies", {})
    mc_version = deps.get("minecraft", "unknown")
    loader = "unknown"
    loader_version = None

    for key in ("neoforge", "forge", "fabric-loader", "quilt-loader"):
        if key in deps:
            loader = cast(LoaderType, normalize_loader_name(key))
            loader_version = str(deps.get(key))
            break

    mods = []
    for f in data.get("files", []):
        path = f.get("path", "unknown.jar")
        mods.append(ModInfo(name=Path(path).name))

    return PackManifest(
        pack_name=data.get("name", "modrinth-pack"),
        mc_version=mc_version,
        loader=loader,
        loader_version=loader_version,
        mods=mods,
        raw=data,
    )
