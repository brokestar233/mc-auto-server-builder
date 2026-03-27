from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, TypedDict
from zipfile import ZipFile

from .models import (
    DetectionCandidate,
    DetectionEvidence,
    LoaderType,
    ModInfo,
    PackInput,
    PackManifest,
    StartMode,
)
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
VERSION_RE = re.compile(r"\b1\.\d+(?:\.\d+)?\b")
FORGE_JAR_RE = re.compile(r"(?:^|/)(forge)-((?:1\.\d+(?:\.\d+)?)-([\w.\-]+))\.jar$", re.IGNORECASE)
NEOFORGE_JAR_RE = re.compile(r"(?:^|/)(neoforge)-((?:\d+\.\d+\.\d+)|(?:1\.\d+(?:\.\d+)?-[\w.\-]+))\.jar$", re.IGNORECASE)
FABRIC_JAR_RE = re.compile(r"(?:^|/)(fabric)(?:-server)?-mc\.?(1\.\d+(?:\.\d+)?)[-.]loader[.-]([\w.\-]+)\.jar$", re.IGNORECASE)
GENERIC_SCRIPT_VERSION_RE = re.compile(r"(?:minecraft|mc)[^\n\r\d]*(1\.\d+(?:\.\d+)?)", re.IGNORECASE)
SERVER_PACK_HINT_RE = re.compile(r"(?:^|[^a-z])(server(?:[\s._-]?files?|[\s._-]?pack)?)(?:[^a-z]|$)", re.IGNORECASE)
SCRIPT_VAR_RE = re.compile(r"(?:\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?|%([A-Za-z_][A-Za-z0-9_]*)%)")


def _normalize_confidence(value: float) -> float:
    return max(0.0, min(1.0, round(value, 3)))


def _yaml_simple_load(text: str) -> dict[str, Any]:
    data: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, data)]
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        stripped = line.strip()
        if ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        key = key.strip()
        value = value.strip()
        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()
        current = stack[-1][1]
        if not value:
            child: dict[str, Any] = {}
            current[key] = child
            stack.append((indent, child))
            continue
        current[key] = value.strip("\"'")
    return data


def _parse_key_value_lines(text: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        delimiter = "=" if "=" in stripped else (":" if ":" in stripped else None)
        if not delimiter:
            continue
        key, value = stripped.split(delimiter, 1)
        clean_key = key.strip().lower()
        clean_value = value.strip().strip("\"'")
        if clean_key:
            parsed[clean_key] = clean_value
    return parsed


def _infer_loader_from_text(text: str, default: LoaderType = "forge") -> LoaderType:
    matches = {
        "forge": len(re.findall(r"\bforge\b", text, flags=re.IGNORECASE)),
        "fabric": len(re.findall(r"\bfabric\b", text, flags=re.IGNORECASE)),
        "neoforge": len(re.findall(r"\bneoforge\b", text, flags=re.IGNORECASE)),
        "quilt": len(re.findall(r"\bquilt\b", text, flags=re.IGNORECASE)),
    }
    ranked = sorted(matches.items(), key=lambda item: (-item[1], item[0]))
    best_loader, best_count = ranked[0]
    if best_count <= 0:
        return default
    if best_loader == "fabric" and matches["quilt"] > matches["fabric"]:
        return "quilt"
    if best_loader == "forge" and matches["neoforge"] > matches["forge"]:
        return "neoforge"
    if best_loader == "forge":
        return "forge"
    if best_loader == "fabric":
        return "fabric"
    if best_loader == "neoforge":
        return "neoforge"
    if best_loader == "quilt":
        return "quilt"
    return default


def _normalize_loader_type(raw_loader: str | None, default: LoaderType = "unknown") -> LoaderType:
    normalized = normalize_loader_name(raw_loader or "")
    if normalized == "forge":
        return "forge"
    if normalized == "neoforge":
        return "neoforge"
    if normalized == "fabric":
        return "fabric"
    if normalized == "quilt":
        return "quilt"
    return default


def _normalize_start_mode(raw_mode: str | None, default: StartMode = "unknown") -> StartMode:
    normalized = (raw_mode or "").strip().lower()
    if normalized == "jar":
        return "jar"
    if normalized == "args_file":
        return "args_file"
    if normalized == "script":
        return "script"
    if normalized == "unknown":
        return "unknown"
    return default


class DetectionState(TypedDict, total=False):
    loader_bucket: dict[str, list[DetectionEvidence]]
    mc_bucket: dict[str, list[DetectionEvidence]]
    loader_ver_bucket: dict[str, list[DetectionEvidence]]
    build_bucket: dict[str, list[DetectionEvidence]]
    start_bucket: dict[str, list[DetectionEvidence]]
    evidence: list[DetectionEvidence]
    warnings: list[str]
    script_variables: dict[str, str]
    phase_hits: list[str]
    phase_details: dict[str, list[str]]
    server_pack_hint_names: list[str]
    additional_resource_urls: list[str]
    pack_name: str


def _make_evidence(
    source_type: str,
    evidence_type: str,
    file: str,
    matched_text: str,
    weight: float,
    reason: str,
) -> DetectionEvidence:
    return DetectionEvidence(
        source_type=source_type,
        evidence_type=evidence_type,
        file=file,
        matched_text=matched_text,
        weight=weight,
        reason=reason,
    )


def _append_candidate(
    bucket: dict[str, list[DetectionEvidence]],
    value: str | None,
    evidence: DetectionEvidence,
) -> None:
    normalized = str(value or "").strip()
    if not normalized:
        return
    bucket.setdefault(normalized, []).append(evidence)


def _rank_candidates(bucket: dict[str, list[DetectionEvidence]]) -> list[DetectionCandidate]:
    ranked: list[DetectionCandidate] = []
    for value, evidence in bucket.items():
        total = sum(max(0.0, item.weight) for item in evidence)
        ranked.append(
            DetectionCandidate(
                value=value,
                confidence=_normalize_confidence(total),
                evidence=sorted(evidence, key=lambda item: item.weight, reverse=True),
                reason=(sorted(evidence, key=lambda item: item.weight, reverse=True)[0].reason if evidence else ""),
            )
        )
    ranked.sort(key=lambda item: (-item.confidence, item.value))
    return ranked


def _extract_build_from_loader_version(loader: str, loader_version: str | None) -> str | None:
    if not loader_version:
        return None
    if loader == "forge" and "-" in loader_version:
        return loader_version.split("-", 1)[1]
    if loader == "neoforge":
        parts = loader_version.split("-")
        return parts[-1] if parts else loader_version
    return None


def _candidate_value(candidates: list[DetectionCandidate], default: str | None = None) -> str | None:
    if candidates:
        return candidates[0].value
    return default


def _candidate_loader(candidates: list[DetectionCandidate], default: LoaderType = "unknown") -> LoaderType:
    if not candidates:
        return default
    return _normalize_loader_type(candidates[0].value, default)


def _manifest_from_detection(
    *,
    pack_name: str,
    mods: list[ModInfo],
    raw: dict[str, Any],
    loader_candidates: list[DetectionCandidate],
    mc_version_candidates: list[DetectionCandidate],
    loader_version_candidates: list[DetectionCandidate],
    build_candidates: list[DetectionCandidate],
    start_mode_candidates: list[DetectionCandidate],
    evidence: list[DetectionEvidence],
    warnings: list[str] | None = None,
) -> PackManifest:
    loader = _candidate_loader(loader_candidates)
    mc_version = _candidate_value(mc_version_candidates, "unknown") or "unknown"
    loader_version = _candidate_value(loader_version_candidates)
    build = _candidate_value(build_candidates) or _extract_build_from_loader_version(loader, loader_version)
    start_mode = _normalize_start_mode(_candidate_value(start_mode_candidates, "unknown"), "unknown")
    top = [*loader_candidates[:1], *mc_version_candidates[:1], *start_mode_candidates[:1]]
    confidence = _normalize_confidence(sum(item.confidence for item in top) / len(top)) if top else 0.0
    return PackManifest(
        pack_name=pack_name,
        mc_version=mc_version,
        loader=loader,
        loader_version=loader_version,
        mods=mods,
        start_mode=start_mode,
        build=build,
        loader_candidates=loader_candidates,
        mc_version_candidates=mc_version_candidates,
        loader_version_candidates=loader_version_candidates,
        build_candidates=build_candidates,
        start_mode_candidates=start_mode_candidates,
        evidence=sorted(evidence, key=lambda item: item.weight, reverse=True),
        confidence=confidence,
        warnings=warnings or [],
        raw=raw,
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


def _collect_full_pack_version_roots(names: set[str]) -> dict[str, list[str]]:
    version_roots: dict[str, list[str]] = {}
    for name in sorted(names):
        parts = [part for part in name.split("/") if part]
        if len(parts) < 3:
            continue
        if parts[0] != ".minecraft" or parts[1] != "versions":
            continue
        version_roots.setdefault(parts[2], []).append(name)
    return version_roots


def _choose_full_pack_version_root(version_roots: dict[str, list[str]]) -> tuple[str, list[str]]:
    def score_version(item: tuple[str, list[str]]) -> tuple[int, int, int, str]:
        version_name, entries = item
        lower = version_name.lower()
        score = 0
        if any(path.endswith(f"/{version_name}.json") for path in entries):
            score += 6
        if any("/mods/" in path.lower() for path in entries):
            score += 5
        if any("/config/" in path.lower() for path in entries):
            score += 4
        if any(token in lower for token in ("forge", "fabric", "quilt", "neoforge")):
            score += 3
        if VERSION_RE.search(version_name):
            score += 2
        return (score, len(entries), -len(version_name), version_name)

    return sorted(version_roots.items(), key=score_version, reverse=True)[0]


def _resolve_script_variable(value: str, variables: dict[str, str]) -> str:
    resolved = value
    for _ in range(4):
        changed = False

        def repl(match: re.Match[str]) -> str:
            nonlocal changed
            key = (match.group(1) or match.group(2) or "").lower()
            if key in variables:
                changed = True
                return variables[key]
            return match.group(0)

        resolved = SCRIPT_VAR_RE.sub(repl, resolved)
        if not changed:
            break
    return resolved


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

    version_roots = _collect_full_pack_version_roots(names)
    if not version_roots:
        raise ValueError("ZIP 未找到 .minecraft/versions 下的版本目录")

    version_name, version_entries = _choose_full_pack_version_root(version_roots)
    version_json_path = f".minecraft/versions/{version_name}/{version_name}.json"
    if version_json_path not in names:
        raise ValueError(f"ZIP 未找到版本元数据: {version_json_path}")

    version_json = json.loads(zf.read(version_json_path).decode("utf-8"))
    mc_version = str(
        version_json.get("clientVersion") or version_json.get("inheritsFrom") or version_json.get("id") or version_name or "unknown"
    )
    loader, loader_version = _infer_loader_from_version_json(version_json)

    evidence = [
        _make_evidence("full_pack", "version_json", version_json_path, mc_version, 0.95, "从版本 JSON 解析 Minecraft 版本"),
        _make_evidence(
            "full_pack", "version_json", version_json_path, loader, 0.95 if loader != "unknown" else 0.2, "从版本 JSON 解析 loader"
        ),
    ]
    loader_version_evidence = []
    if loader_version:
        loader_version_evidence.append(
            _make_evidence(
                "full_pack",
                "version_json",
                version_json_path,
                loader_version,
                0.95,
                "从版本 JSON 解析 loader 版本",
            )
        )
    build = _extract_build_from_loader_version(loader, loader_version)
    return _manifest_from_detection(
        pack_name=version_name,
        mods=[],
        loader_candidates=[
            DetectionCandidate(
                value=loader,
                confidence=0.95 if loader != "unknown" else 0.2,
                evidence=[evidence[1]],
                reason="版本 JSON",
            )
        ],
        mc_version_candidates=[
            DetectionCandidate(
                value=mc_version,
                confidence=0.95,
                evidence=[evidence[0]],
                reason="版本 JSON",
            )
        ],
        loader_version_candidates=[
            DetectionCandidate(
                value=loader_version,
                confidence=0.95,
                evidence=loader_version_evidence,
                reason="版本 JSON",
            )
        ]
        if loader_version
        else [],
        build_candidates=[
            DetectionCandidate(
                value=build,
                confidence=0.9,
                evidence=loader_version_evidence,
                reason="由 loader_version 推导 build",
            )
        ]
        if build
        else [],
        start_mode_candidates=[
            DetectionCandidate(
                value="jar",
                confidence=0.35,
                evidence=[
                    _make_evidence(
                        "full_pack",
                        "default",
                        version_json_path,
                        "jar",
                        0.35,
                        "全量包默认回退为 jar 启动",
                    )
                ],
                reason="默认 jar",
            )
        ],
        evidence=evidence + loader_version_evidence,
        raw={
            "pack_type": "full_pack",
            "full_pack": {
                "version_name": version_name,
                "version_dir": f".minecraft/versions/{version_name}",
                "candidate_versions": sorted(version_roots),
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
            source_match = cf_project if cf_project is not None else cf_slug
            if source_match is None:
                raise ValueError("无法从 CurseForge URL 提取项目标识")
            source = source_match.group(1)
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
        return _detect_manifest_from_generic_zip(zf, names, zpath)


def _new_detection_state() -> DetectionState:
    return {
        "loader_bucket": {},
        "mc_bucket": {},
        "loader_ver_bucket": {},
        "build_bucket": {},
        "start_bucket": {},
        "evidence": [],
        "warnings": [],
        "script_variables": {},
        "phase_hits": [],
        "phase_details": {},
        "server_pack_hint_names": [],
        "pack_name": "",
    }


def _record_phase_hit(state: DetectionState, phase: str, detail: str) -> None:
    phase_hits = state["phase_hits"]
    phase_details = state["phase_details"]
    if phase not in phase_hits:
        phase_hits.append(phase)
    phase_details.setdefault(phase, [])
    if detail not in phase_details[phase]:
        phase_details[phase].append(detail)


def _scan_explicit_metadata_phase(zf: ZipFile, top_names: list[str], state: DetectionState) -> None:
    loader_bucket = state["loader_bucket"]
    mc_bucket = state["mc_bucket"]
    loader_ver_bucket = state["loader_ver_bucket"]
    build_bucket = state["build_bucket"]
    start_bucket = state["start_bucket"]
    evidence = state["evidence"]
    pack_name = str(state["pack_name"] or "")

    server_pack_hint_names = [
        name
        for name in top_names
        if SERVER_PACK_HINT_RE.search(name.lower())
        and any(name.lower().endswith(ext) for ext in (".zip", ".mrpack", ".txt", ".md", ".html"))
    ]
    state["server_pack_hint_names"] = server_pack_hint_names
    for hint_name in server_pack_hint_names:
        item = _make_evidence(
            "server_pack_hint",
            "filename_hint",
            hint_name,
            "server_pack",
            0.7,
            "命中 Server Pack / Server Files 命名特征",
        )
        evidence.append(item)
        _record_phase_hit(state, "explicit_metadata", f"server_pack_hint:{hint_name}")

    for name in top_names:
        lower = name.lower()
        if lower.endswith((".yml", ".yaml")):
            raw = zf.read(name).decode("utf-8", errors="ignore")
            if "serverstarter" in raw.lower() or "modpack:" in raw.lower() or "install:" in raw.lower() or "_specver:" in raw.lower():
                data = _yaml_simple_load(raw)
                modpack = data.get("modpack", {}) if isinstance(data.get("modpack"), dict) else {}
                install = data.get("install", {}) if isinstance(data.get("install"), dict) else {}
                launch = data.get("launch", {}) if isinstance(data.get("launch"), dict) else {}
                if isinstance(modpack, dict) and modpack.get("name"):
                    state["pack_name"] = str(modpack.get("name"))
                if isinstance(install, dict):
                    mc_version = str(install.get("mcVersion") or "").strip()
                    loader_version = str(install.get("loaderVersion") or "").strip()
                    modpack_url = str(install.get("modpackUrl") or "").strip()
                    if mc_version:
                        item = _make_evidence("serverstarter", "yaml_field", name, mc_version, 0.98, "ServerStarter install.mcVersion")
                        evidence.append(item)
                        _append_candidate(mc_bucket, mc_version, item)
                    if loader_version:
                        loader = _infer_loader_from_text(raw.lower(), default="forge")
                        item = _make_evidence("serverstarter", "yaml_field", name, loader, 0.96, "ServerStarter loaderVersion/上下文")
                        evidence.append(item)
                        _append_candidate(loader_bucket, loader, item)
                        item_ver = _make_evidence(
                            "serverstarter",
                            "yaml_field",
                            name,
                            loader_version,
                            0.96,
                            "ServerStarter install.loaderVersion",
                        )
                        evidence.append(item_ver)
                        _append_candidate(loader_ver_bucket, loader_version, item_ver)
                        build = _extract_build_from_loader_version(loader, loader_version)
                        if build:
                            build_item = _make_evidence(
                                "serverstarter",
                                "derived_build",
                                name,
                                build,
                                0.86,
                                "由 ServerStarter loaderVersion 推导 build",
                            )
                            evidence.append(build_item)
                            _append_candidate(build_bucket, build, build_item)
                    if modpack_url:
                        item = _make_evidence(
                            "serverstarter",
                            "yaml_field",
                            name,
                            modpack_url,
                            0.42,
                            "ServerStarter install.modpackUrl 可作为二级资源线索",
                        )
                        evidence.append(item)
                        additional_urls = state.setdefault("additional_resource_urls", [])
                        if modpack_url not in additional_urls:
                            additional_urls.append(modpack_url)
                if isinstance(launch, dict) and str(launch.get("javaArgs") or "").strip():
                    item = _make_evidence(
                        "serverstarter",
                        "launch_config",
                        name,
                        "script",
                        0.9,
                        "ServerStarter launch.javaArgs 表示脚本驱动启动",
                    )
                    evidence.append(item)
                    _append_candidate(start_bucket, "script", item)
                _record_phase_hit(state, "explicit_metadata", f"serverstarter:{name}")

        if lower.endswith("variables.txt"):
            raw = zf.read(name).decode("utf-8", errors="ignore")
            variables = _parse_key_value_lines(raw)
            detected_mc_version = variables.get("minecraft_version")
            loader = _normalize_loader_type(variables.get("modloader"))
            detected_loader_version = variables.get("modloader_version")
            java_args = variables.get("java_args")
            if detected_mc_version:
                item = _make_evidence("variables", "key_value", name, detected_mc_version, 0.97, "variables.txt minecraft_version")
                evidence.append(item)
                _append_candidate(mc_bucket, detected_mc_version, item)
            if loader and loader != "unknown":
                item = _make_evidence("variables", "key_value", name, loader, 0.97, "variables.txt modloader")
                evidence.append(item)
                _append_candidate(loader_bucket, loader, item)
            if detected_loader_version:
                item = _make_evidence("variables", "key_value", name, detected_loader_version, 0.95, "variables.txt modloader_version")
                evidence.append(item)
                _append_candidate(loader_ver_bucket, detected_loader_version, item)
            build = _extract_build_from_loader_version(loader, detected_loader_version)
            if build:
                item = _make_evidence("variables", "derived_build", name, build, 0.85, "由 variables.txt loader_version 推导 build")
                evidence.append(item)
                _append_candidate(build_bucket, build, item)
            if java_args is not None:
                item = _make_evidence("variables", "key_value", name, "script", 0.45, "variables.txt java_args 表示存在脚本启动")
                evidence.append(item)
                _append_candidate(start_bucket, "script", item)
            _record_phase_hit(state, "explicit_metadata", f"variables:{name}")

    if not state["pack_name"]:
        state["pack_name"] = pack_name


def _detect_manifest_from_generic_zip(zf: ZipFile, names: set[str], zpath: Path) -> PackManifest:
    state = _new_detection_state()
    top_names = sorted(names)
    state["pack_name"] = zpath.stem
    _scan_explicit_metadata_phase(zf, top_names, state)

    loader_bucket = state["loader_bucket"]
    mc_bucket = state["mc_bucket"]
    loader_ver_bucket = state["loader_ver_bucket"]
    build_bucket = state["build_bucket"]
    start_bucket = state["start_bucket"]
    evidence = state["evidence"]
    warnings = state["warnings"]
    script_variables = state["script_variables"]

    for name in top_names:
        lower = name.lower()
        if lower.endswith((".sh", ".bat", ".ps1", ".cmd")):
            _record_phase_hit(state, "startup_script", f"script:{name}")
            raw = zf.read(name).decode("utf-8", errors="ignore")
            compact = raw.lower()
            for line in raw.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or stripped.startswith("::"):
                    continue
                match = re.match(r"(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.+)", stripped)
                if match:
                    script_variables[match.group(1).lower()] = match.group(2).strip().strip('"\'')
                    continue
                match = re.match(r"set\s+([A-Za-z_][A-Za-z0-9_]*)=(.+)", stripped, flags=re.IGNORECASE)
                if match:
                    script_variables[match.group(1).lower()] = match.group(2).strip().strip('"\'')

            resolved_raw = _resolve_script_variable(raw, script_variables)
            resolved_compact = resolved_raw.lower()
            if "@libraries/net/minecraftforge/forge/" in compact:
                item = _make_evidence("script", "args_path", name, "forge", 0.94, "启动脚本命中 Forge args 路径")
                evidence.append(item)
                _append_candidate(loader_bucket, "forge", item)
                _append_candidate(
                    start_bucket,
                    "args_file",
                    _make_evidence(
                        "script",
                        "args_path",
                        name,
                        "args_file",
                        0.94,
                        "启动脚本使用 @args 文件",
                    ),
                )
                version_part = compact.split("@libraries/net/minecraftforge/forge/", 1)[1].split("/", 1)[0]
                if "-" in version_part:
                    mc_version, build = version_part.split("-", 1)
                    _append_candidate(
                        mc_bucket,
                        mc_version,
                        _make_evidence(
                            "script",
                            "args_path",
                            name,
                            mc_version,
                            0.92,
                            "Forge args 路径包含 mc 版本",
                        ),
                    )
                    _append_candidate(
                        loader_ver_bucket,
                        version_part,
                        _make_evidence(
                            "script",
                            "args_path",
                            name,
                            version_part,
                            0.92,
                            "Forge args 路径包含 loader_version",
                        ),
                    )
                    _append_candidate(
                        build_bucket,
                        build,
                        _make_evidence(
                            "script",
                            "args_path",
                            name,
                            build,
                            0.88,
                            "Forge args 路径包含 build",
                        ),
                    )
            elif "@libraries/net/minecraftforge/forge/" in resolved_compact:
                item = _make_evidence("script", "resolved_args_path", name, "forge", 0.88, "变量展开后命中 Forge args 路径")
                evidence.append(item)
                _append_candidate(loader_bucket, "forge", item)
                _append_candidate(
                    start_bucket,
                    "args_file",
                    _make_evidence("script", "resolved_args_path", name, "args_file", 0.88, "变量展开后使用 @args 文件"),
                )
                version_part = resolved_compact.split("@libraries/net/minecraftforge/forge/", 1)[1].split("/", 1)[0]
                if "-" in version_part:
                    mc_version, build = version_part.split("-", 1)
                    _append_candidate(
                        mc_bucket,
                        mc_version,
                        _make_evidence("script", "resolved_args_path", name, mc_version, 0.84, "变量展开后的 Forge args 路径包含 mc 版本"),
                    )
                    _append_candidate(
                        loader_ver_bucket,
                        version_part,
                        _make_evidence(
                            "script",
                            "resolved_args_path",
                            name,
                            version_part,
                            0.84,
                            "变量展开后的 Forge args 路径包含 loader_version",
                        ),
                    )
                    _append_candidate(
                        build_bucket,
                        build,
                        _make_evidence("script", "resolved_args_path", name, build, 0.8, "变量展开后的 Forge args 路径包含 build"),
                    )
            if "@libraries/net/neoforged/neoforge/" in compact:
                item = _make_evidence("script", "args_path", name, "neoforge", 0.94, "启动脚本命中 NeoForge args 路径")
                evidence.append(item)
                _append_candidate(loader_bucket, "neoforge", item)
                _append_candidate(
                    start_bucket,
                    "args_file",
                    _make_evidence(
                        "script",
                        "args_path",
                        name,
                        "args_file",
                        0.94,
                        "启动脚本使用 @args 文件",
                    ),
                )
            elif "@libraries/net/neoforged/neoforge/" in resolved_compact:
                item = _make_evidence("script", "resolved_args_path", name, "neoforge", 0.88, "变量展开后命中 NeoForge args 路径")
                evidence.append(item)
                _append_candidate(loader_bucket, "neoforge", item)
                _append_candidate(
                    start_bucket,
                    "args_file",
                    _make_evidence("script", "resolved_args_path", name, "args_file", 0.88, "变量展开后使用 @args 文件"),
                )
            if "quilt-server-launch.jar" in compact:
                item = _make_evidence("script", "jar_name", name, "quilt", 0.92, "启动脚本命中 quilt-server-launch.jar")
                evidence.append(item)
                _append_candidate(loader_bucket, "quilt", item)
                _append_candidate(start_bucket, "jar", _make_evidence("script", "jar_name", name, "jar", 0.85, "启动脚本直接使用 jar"))
            elif "quilt-server-launch.jar" in resolved_compact:
                item = _make_evidence("script", "resolved_jar_name", name, "quilt", 0.86, "变量展开后命中 quilt-server-launch.jar")
                evidence.append(item)
                _append_candidate(loader_bucket, "quilt", item)
                _append_candidate(
                    start_bucket,
                    "jar",
                    _make_evidence("script", "resolved_jar_name", name, "jar", 0.8, "变量展开后直接使用 jar"),
                )
            if "fabric" in compact:
                _append_candidate(
                    loader_bucket,
                    "fabric",
                    _make_evidence(
                        "script",
                        "keyword",
                        name,
                        "fabric",
                        0.62,
                        "启动脚本文本命中 fabric",
                    ),
                )
            elif "fabric" in resolved_compact:
                _append_candidate(
                    loader_bucket,
                    "fabric",
                    _make_evidence("script", "resolved_keyword", name, "fabric", 0.56, "变量展开后的启动脚本文本命中 fabric"),
                )
            if re.search(r"(?:^|\s)(?:java|%java%|\$java)\b", compact):
                _append_candidate(
                    start_bucket,
                    "script",
                    _make_evidence(
                        "script",
                        "launch_command",
                        name,
                        "script",
                        0.18,
                        "存在 Java 启动命令",
                    ),
                )
            for match in VERSION_RE.findall(raw):
                _append_candidate(mc_bucket, match, _make_evidence("script", "version_text", name, match, 0.45, "启动脚本文本中出现版本号"))
            match = GENERIC_SCRIPT_VERSION_RE.search(raw)
            if match:
                _append_candidate(
                    mc_bucket,
                    match.group(1),
                    _make_evidence("script", "version_text", name, match.group(1), 0.55, "启动脚本提及 Minecraft 版本"),
                )

    for name in top_names:
        lower = name.lower()
        if lower.endswith(".jar"):
            _record_phase_hit(state, "file_pattern", f"jar:{name}")
            if match := FORGE_JAR_RE.search(lower):
                loader_version = match.group(2)
                mc_version = loader_version.split("-", 1)[0]
                build = match.group(3)
                _append_candidate(
                    loader_bucket,
                    "forge",
                    _make_evidence(
                        "jar_name",
                        "file_pattern",
                        name,
                        "forge",
                        0.88,
                        "JAR 文件名命中 Forge 模式",
                    ),
                )
                _append_candidate(
                    mc_bucket, mc_version, _make_evidence("jar_name", "file_pattern", name, mc_version, 0.84, "JAR 文件名命中 mc 版本")
                )
                _append_candidate(
                    loader_ver_bucket,
                    loader_version,
                    _make_evidence("jar_name", "file_pattern", name, loader_version, 0.86, "JAR 文件名命中 loader_version"),
                )
                _append_candidate(build_bucket, build, _make_evidence("jar_name", "file_pattern", name, build, 0.8, "JAR 文件名命中 build"))
                _append_candidate(
                    start_bucket, "jar", _make_evidence("jar_name", "file_pattern", name, "jar", 0.72, "检测到可直接启动 jar")
                )
            if match := NEOFORGE_JAR_RE.search(lower):
                loader_version = match.group(2)
                _append_candidate(
                    loader_bucket,
                    "neoforge",
                    _make_evidence("jar_name", "file_pattern", name, "neoforge", 0.9, "JAR 文件名命中 NeoForge 模式"),
                )
                _append_candidate(
                    loader_ver_bucket,
                    loader_version,
                    _make_evidence("jar_name", "file_pattern", name, loader_version, 0.86, "JAR 文件名命中 NeoForge 版本"),
                )
                _append_candidate(
                    start_bucket, "jar", _make_evidence("jar_name", "file_pattern", name, "jar", 0.72, "检测到可直接启动 jar")
                )
            if match := FABRIC_JAR_RE.search(lower):
                _append_candidate(
                    loader_bucket, "fabric", _make_evidence("jar_name", "file_pattern", name, "fabric", 0.88, "JAR 文件名命中 Fabric 模式")
                )
                _append_candidate(
                    mc_bucket,
                    match.group(2),
                    _make_evidence("jar_name", "file_pattern", name, match.group(2), 0.84, "JAR 文件名命中 mc 版本"),
                )
                _append_candidate(
                    loader_ver_bucket,
                    match.group(3),
                    _make_evidence("jar_name", "file_pattern", name, match.group(3), 0.84, "JAR 文件名命中 Fabric loader 版本"),
                )
                _append_candidate(
                    start_bucket, "jar", _make_evidence("jar_name", "file_pattern", name, "jar", 0.72, "检测到可直接启动 jar")
                )

        if lower.startswith("libraries/net/minecraftforge/forge/"):
            _record_phase_hit(state, "directory_feature", "libraries/net/minecraftforge/forge")
            _append_candidate(
                loader_bucket, "forge", _make_evidence("directory", "path_feature", name, "forge", 0.68, "目录结构命中 Forge 库路径")
            )
            _append_candidate(
                start_bucket,
                "args_file",
                _make_evidence("directory", "path_feature", name, "args_file", 0.62, "Forge 现代目录通常伴随 args 文件启动"),
            )
        if lower.startswith("libraries/net/neoforged/neoforge/"):
            _record_phase_hit(state, "directory_feature", "libraries/net/neoforged/neoforge")
            _append_candidate(
                loader_bucket,
                "neoforge",
                _make_evidence("directory", "path_feature", name, "neoforge", 0.68, "目录结构命中 NeoForge 库路径"),
            )
            _append_candidate(
                start_bucket,
                "args_file",
                _make_evidence("directory", "path_feature", name, "args_file", 0.62, "NeoForge 现代目录通常伴随 args 文件启动"),
            )
        if lower.startswith(".fabric/"):
            _record_phase_hit(state, "directory_feature", ".fabric")
            _append_candidate(
                loader_bucket, "fabric", _make_evidence("directory", "path_feature", name, "fabric", 0.64, "目录结构命中 .fabric")
            )
        if lower.startswith("versions/") or lower.startswith(".minecraft/versions/"):
            for match in VERSION_RE.findall(name):
                _append_candidate(
                    mc_bucket, match, _make_evidence("directory", "path_feature", name, match, 0.42, "版本目录命中 Minecraft 版本")
                )

    text_hits = {"forge": 0, "fabric": 0, "neoforge": 0, "quilt": 0}
    version_hits: dict[str, int] = {}
    scanned = 0
    for name in top_names:
        lower = name.lower()
        if not lower.endswith((".txt", ".cfg", ".conf", ".properties", ".json", ".toml", ".md", ".log")):
            continue
        raw = zf.read(name).decode("utf-8", errors="ignore")[:20000]
        scanned += 1
        for loader in text_hits:
            text_hits[loader] += len(re.findall(rf"\b{re.escape(loader)}\b", raw, flags=re.IGNORECASE))
        for match in VERSION_RE.findall(raw):
            version_hits[match] = version_hits.get(match, 0) + 1
    if scanned:
        _record_phase_hit(state, "text_heuristic", f"scanned_text_files:{scanned}")
        for loader, count in text_hits.items():
            if count > 0:
                _append_candidate(
                    loader_bucket,
                    loader,
                    _make_evidence(
                        "text_scan",
                        "keyword_frequency",
                        f"{scanned}_files",
                        loader,
                        min(0.15 + count * 0.05, 0.55),
                        f"文本扫描命中 {count} 次 {loader}",
                    ),
                )
        for version, count in sorted(version_hits.items(), key=lambda item: (-item[1], item[0]))[:3]:
            _append_candidate(
                mc_bucket,
                version,
                _make_evidence(
                    "text_scan",
                    "keyword_frequency",
                    f"{scanned}_files",
                    version,
                    min(0.12 + count * 0.04, 0.5),
                    f"文本扫描命中版本 {version} 共 {count} 次",
                ),
            )

    loader_candidates = _rank_candidates(loader_bucket)
    mc_version_candidates = _rank_candidates(mc_bucket)
    loader_version_candidates = _rank_candidates(loader_ver_bucket)
    build_candidates = _rank_candidates(build_bucket)
    start_mode_candidates = _rank_candidates(start_bucket)
    if not loader_candidates:
        warnings.append("未能高置信识别 loader，已回退 unknown")
    if not mc_version_candidates:
        warnings.append("未能高置信识别 Minecraft 版本，已回退 unknown")
    if not start_mode_candidates:
        start_mode_candidates = [
            DetectionCandidate(
                value="jar",
                confidence=0.2,
                evidence=[_make_evidence("fallback", "default", str(zpath.name), "jar", 0.2, "保底使用 jar 启动")],
                reason="默认 jar",
            )
        ]

    manifest = _manifest_from_detection(
        pack_name=str(state["pack_name"] or zpath.stem),
        mods=[],
        raw={
            "pack_type": "generic_detected",
            "archive_name": zpath.name,
            "scanned_entries": len(top_names),
            "server_pack_hints": list(state["server_pack_hint_names"]),
            "additional_resource_urls": list(state.get("additional_resource_urls", [])),
            "script_variables": dict(sorted(script_variables.items())),
            "recognition_pipeline": [
                "explicit_metadata",
                "startup_script",
                "file_pattern",
                "directory_feature",
                "text_heuristic",
                "runtime_feedback",
            ],
            "recognition_phase_hits": list(state["phase_hits"]),
            "recognition_phase_details": dict(state["phase_details"]),
            "warnings": warnings,
        },
        loader_candidates=loader_candidates,
        mc_version_candidates=mc_version_candidates,
        loader_version_candidates=loader_version_candidates,
        build_candidates=build_candidates,
        start_mode_candidates=start_mode_candidates,
        evidence=evidence
        + [
            ev
            for cand in [*loader_candidates, *mc_version_candidates, *loader_version_candidates, *build_candidates, *start_mode_candidates]
            for ev in cand.evidence
        ],
        warnings=warnings,
    )
    if manifest.loader == "unknown" and manifest.mc_version == "unknown":
        raise ValueError(
            "ZIP 既不包含 manifest.json / modrinth.index.json，也不包含 .minecraft 目录，"
            "且未能从 ServerStarter/variables.txt/脚本/目录结构中识别: "
            f"{zpath}"
        )
    return manifest


def _from_curseforge_manifest(data: dict) -> PackManifest:
    minecraft = data.get("minecraft", {})
    version = minecraft.get("version", "unknown")
    loaders = minecraft.get("modLoaders", [])
    loader_id = loaders[0].get("id", "unknown") if loaders else "unknown"

    loader = _normalize_loader_type(loader_id)
    loader_version = None
    if "-" in loader_id:
        loader_version = loader_id.split("-", 1)[1]

    mods = [
        ModInfo(name=f"cf-{m.get('projectID')}-{m.get('fileID')}.jar", project_id=str(m.get("projectID")), file_id=str(m.get("fileID")))
        for m in data.get("files", [])
    ]

    loader_evidence = _make_evidence("manifest", "manifest_json", "manifest.json", loader_id, 1.0, "CurseForge manifest 显式声明 loader")
    version_evidence = _make_evidence(
        "manifest", "manifest_json", "manifest.json", version, 1.0, "CurseForge manifest 显式声明 Minecraft 版本"
    )
    loader_version_evidence = (
        _make_evidence(
            "manifest", "manifest_json", "manifest.json", loader_version or "", 0.98, "CurseForge manifest 显式声明 loader_version"
        )
        if loader_version
        else None
    )
    build = _extract_build_from_loader_version(loader, loader_version)
    return _manifest_from_detection(
        pack_name=data.get("name", "curseforge-pack"),
        mc_version_candidates=[DetectionCandidate(value=str(version), confidence=1.0, evidence=[version_evidence], reason="manifest.json")],
        loader_candidates=[DetectionCandidate(value=loader, confidence=1.0, evidence=[loader_evidence], reason="manifest.json")],
        loader_version_candidates=[
            DetectionCandidate(value=loader_version, confidence=0.98, evidence=[loader_version_evidence], reason="manifest.json")
        ]
        if loader_version and loader_version_evidence
        else [],
        build_candidates=[
            DetectionCandidate(
                value=build,
                confidence=0.94,
                evidence=[loader_version_evidence],
                reason="由 manifest loader_version 推导 build",
            )
        ]
        if loader_version and loader_version_evidence and build
        else [],
        start_mode_candidates=[
            DetectionCandidate(
                value="jar",
                confidence=0.3,
                evidence=[_make_evidence("manifest", "default", "manifest.json", "jar", 0.3, "标准 manifest 未提供启动模式，默认 jar")],
                reason="默认 jar",
            )
        ],
        evidence=[item for item in [loader_evidence, version_evidence, loader_version_evidence] if item],
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
            loader = _normalize_loader_type(key)
            loader_version = str(deps.get(key))
            break

    mods = []
    for f in data.get("files", []):
        path = f.get("path", "unknown.jar")
        mods.append(ModInfo(name=Path(path).name))

    evidence = [
        _make_evidence("manifest", "modrinth_index", "modrinth.index.json", str(mc_version), 1.0, "Modrinth dependencies.minecraft"),
    ]
    if loader != "unknown":
        evidence.append(
            _make_evidence("manifest", "modrinth_index", "modrinth.index.json", str(loader), 1.0, "Modrinth dependencies loader")
        )
    if loader_version:
        evidence.append(
            _make_evidence(
                "manifest", "modrinth_index", "modrinth.index.json", str(loader_version), 0.98, "Modrinth dependencies loader_version"
            )
        )
    build = _extract_build_from_loader_version(loader, loader_version)
    return _manifest_from_detection(
        pack_name=data.get("name", "modrinth-pack"),
        mc_version_candidates=[
            DetectionCandidate(value=str(mc_version), confidence=1.0, evidence=[evidence[0]], reason="modrinth.index.json")
        ],
        loader_candidates=[DetectionCandidate(value=str(loader), confidence=1.0, evidence=[evidence[1]], reason="modrinth.index.json")]
        if loader != "unknown" and len(evidence) > 1
        else [],
        loader_version_candidates=[
            DetectionCandidate(value=str(loader_version), confidence=0.98, evidence=[evidence[-1]], reason="modrinth.index.json")
        ]
        if loader_version
        else [],
        build_candidates=[
            DetectionCandidate(
                value=build,
                confidence=0.9,
                evidence=[evidence[-1]],
                reason="由 modrinth loader_version 推导 build",
            )
        ]
        if loader_version and build
        else [],
        start_mode_candidates=[
            DetectionCandidate(
                value="jar",
                confidence=0.3,
                evidence=[
                    _make_evidence("manifest", "default", "modrinth.index.json", "jar", 0.3, "标准 manifest 未提供启动模式，默认 jar")
                ],
                reason="默认 jar",
            )
        ],
        evidence=evidence,
        mods=mods,
        raw=data,
    )
