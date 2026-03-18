from __future__ import annotations

import json
import re
from pathlib import Path
from zipfile import ZipFile

from .models import LoaderType, ModInfo, PackInput, PackManifest


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
URL_RE = re.compile(r"^https?://", re.IGNORECASE)


def parse_pack_input(value: str) -> PackInput:
    value = value.strip()
    p = Path(value)
    if p.exists() and p.suffix.lower() == ".zip":
        return PackInput(input_type="local_zip", source=str(p.resolve()))

    if URL_RE.search(value):
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

    raise ValueError(f"ZIP 内未找到 manifest.json 或 modrinth.index.json: {zpath}")


def _normalize_loader(raw_loader: str) -> LoaderType:
    text = raw_loader.lower()
    if "neoforge" in text:
        return "neoforge"
    if "forge" in text:
        return "forge"
    if "fabric" in text:
        return "fabric"
    if "quilt" in text:
        return "quilt"
    return "unknown"


def _from_curseforge_manifest(data: dict) -> PackManifest:
    minecraft = data.get("minecraft", {})
    version = minecraft.get("version", "unknown")
    loaders = minecraft.get("modLoaders", [])
    loader_id = loaders[0].get("id", "unknown") if loaders else "unknown"

    loader = _normalize_loader(loader_id)
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
            loader = _normalize_loader(key)
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
