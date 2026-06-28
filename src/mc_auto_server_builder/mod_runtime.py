from __future__ import annotations

import json
import re
import shutil
from typing import TYPE_CHECKING

from .util import backup_directory

if TYPE_CHECKING:
    from .builder import ServerBuilder


def list_mods(builder: ServerBuilder) -> list[str]:
    mods_dir = builder.workdirs.server / "mods"
    if not mods_dir.exists():
        return []
    return sorted([path.name for path in mods_dir.glob("*.jar") if path.is_file()])


def record_deleted_client_mod(builder: ServerBuilder, mod_name: str, source: str, reason: str) -> None:
    clean = str(mod_name or "").strip()
    if not clean:
        return
    builder.known_deleted_client_mods.add(clean)
    evidence = f"{source}:{reason}"
    existing = builder.deleted_mod_evidence.setdefault(clean, [])
    if evidence not in existing:
        existing.append(evidence)


def record_deleted_mod_detail(builder: ServerBuilder, mod_name: str, category: str, source: str, reason: str) -> None:
    clean = str(mod_name or "").strip()
    if not clean:
        return
    detail_map = getattr(builder, "deleted_mod_sources", None)
    if not isinstance(detail_map, dict):
        detail_map = {}
        builder.deleted_mod_sources = detail_map
    entry = detail_map.setdefault(
        clean,
        {
            "builtin_rule": [],
            "user_rule": [],
            "ai_suggested": [],
            "dependency_cleanup": [],
            "bisect": [],
            "other": [],
        },
    )
    bucket = category if category in entry else "other"
    payload = f"{source}:{reason}"
    if payload not in entry[bucket]:
        entry[bucket].append(payload)


def normalize_mod_token(builder: ServerBuilder, value: str) -> str:
    token = str(value or "").strip().lower()
    token = token.removesuffix(".jar")
    token = re.sub(r"[\s_\-\.]+", "", token)
    return token


def resolve_mod_names_to_installed(builder: ServerBuilder, names: list[str], candidates: list[str] | None = None) -> list[str]:
    mods = candidates if candidates is not None else builder.list_mods()
    if not mods:
        return []

    exact = {mod: mod for mod in mods}
    lower_map = {mod.lower(): mod for mod in mods}
    token_map = {builder._normalize_mod_token(mod): mod for mod in mods}
    resolved: list[str] = []
    for raw in names:
        value = str(raw or "").strip()
        if not value:
            continue
        if value in exact:
            pick = exact[value]
        elif value.lower() in lower_map:
            pick = lower_map[value.lower()]
        else:
            token = builder._normalize_mod_token(value)
            pick = token_map.get(token) or ""
            if not pick and token:
                for tk, mod_name in token_map.items():
                    if token in tk or tk in token:
                        pick = mod_name
                        break
        if pick and pick not in resolved:
            resolved.append(pick)
    return resolved


def list_current_installed_client_mods(builder: ServerBuilder) -> list[str]:
    mods = builder.list_mods()
    if not mods:
        return []

    patterns = builder.rule_db.list_rules()
    compiled: list[tuple[str, re.Pattern[str]]] = []
    for pattern in patterns:
        try:
            compiled.append((pattern, re.compile(pattern)))
        except re.error:
            continue

    matched: list[str] = []
    for mod in mods:
        if any(cre.search(mod) for _, cre in compiled):
            matched.append(mod)
    return sorted(dict.fromkeys(matched))


def remove_mods_by_name(builder: ServerBuilder, names: list[str], source: str = "manual", reason: str = "") -> None:
    mods_dir = builder.workdirs.server / "mods"
    for name in names:
        target = mods_dir / name
        if target.exists():
            target.unlink()
            if source == "bisect":
                builder.bisect_removed_mods.append(name)
            else:
                builder.removed_mods.append(name)
            builder.operations.append(f"remove_mod_by_name:{name}")
            if source == "ai":
                builder._log("install.remove_mod", f"删除mod:{name} 原因:{reason}")
            builder._record_deleted_client_mod(name, source=source, reason=reason or "explicit_name")
            category = "other"
            if source == "bisect":
                category = "bisect"
            elif source == "builtin_rule":
                category = "builtin_rule"
            elif source in {"regex_rule", "user_rule"}:
                category = "user_rule"
            elif source == "ai":
                category = "ai_suggested"
            elif source == "dependency_cleanup":
                category = "dependency_cleanup"
            builder._record_deleted_mod_detail(name, category=category, source=source, reason=reason or "explicit_name")


def remove_mods_by_regex(builder: ServerBuilder, patterns: list[str], source: str = "regex_rule") -> None:
    for pattern in patterns:
        try:
            cre = re.compile(pattern)
        except re.error:
            builder._log("install.blacklist", f"忽略非法正则规则: {pattern}", level="WARN")
            builder.operations.append(f"remove_mods_by_regex_invalid:{pattern}")
            continue

        mods = builder.list_mods()
        if not mods:
            break

        matched = [mod for mod in mods if cre.search(mod)]
        for mod_name in matched:
            builder._log("install.blacklist.match", f"命中黑名单规则: pattern={pattern} -> mod={mod_name}")
        builder.remove_mods_by_name(matched, source=source, reason=f"pattern={pattern}")


def add_remove_regex(builder: ServerBuilder, pattern: str, desc: str = "") -> None:
    builder.rule_db.add_rule(pattern, desc)
    builder.operations.append(f"add_remove_regex:{pattern}")


def apply_known_client_blacklist(builder: ServerBuilder) -> None:
    patterns = builder.rule_db.list_rules()
    builder.remove_mods_by_regex(patterns, source="builtin_rule")


def apply_recognition_based_client_cleanup(builder: ServerBuilder) -> list[str]:
    manifest = getattr(builder, "manifest", None)
    if not manifest:
        return []
    mods_dir = builder.workdirs.server / "mods"
    if not mods_dir.exists():
        return []

    removal_patterns = (
        (
            re.compile(r"(?:fancymenu|embeddiumplus|oculus|rubidium|sodiumextras|reeses[_\-.]?sodium)", re.IGNORECASE),
            "client_visual_mod",
        ),
        (re.compile(r"(?:xaeros[_\-.]?minimap|journeymap|controlling|notenoughanimations)", re.IGNORECASE), "client_utility_mod"),
        (re.compile(r"(?:presencefootsteps|entityculling|3dskinlayers|skinlayers)", re.IGNORECASE), "client_render_mod"),
    )
    removed: list[str] = []
    for mod_path in sorted(mods_dir.glob("*.jar"), key=lambda p: p.name.lower()):
        for pattern, reason in removal_patterns:
            if pattern.search(mod_path.name):
                builder.remove_mods_by_name(
                    [mod_path.name],
                    source="dependency_cleanup",
                    reason=f"recognition_prior_cleanup:{reason}",
                )
                removed.append(mod_path.name)
                break
    if removed:
        builder.operations.append(f"recognition_prior_cleanup:removed={json.dumps(removed, ensure_ascii=False)}")
    return removed


def backup_mods(builder: ServerBuilder, tag: str) -> None:
    mods_dir = builder.workdirs.server / "mods"
    if not mods_dir.exists():
        return

    signature = tuple(
        sorted(
            str(path.relative_to(mods_dir)).replace("\\", "/")
            for path in mods_dir.rglob("*")
            if path.is_file()
        )
    )
    previous_signature = builder._mods_backup_signatures.get(tag)
    if previous_signature == signature:
        builder.operations.append(f"backup_mods_skip_unchanged:{tag}")
        return

    backup_directory(mods_dir, builder.workdirs.backups, f"mods_{tag}")
    builder._mods_backup_signatures[tag] = signature
    builder.operations.append(f"backup_mods:{tag}")


def rollback_mods(builder: ServerBuilder, tag: str) -> None:
    src = builder.workdirs.backups / f"mods_{tag}"
    dst = builder.workdirs.server / "mods"
    if src.exists():
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(src, dst)
        builder.operations.append(f"rollback_mods:{tag}")


def resolve_dependency_cleanup_targets(
    builder: ServerBuilder,
    dependency_chains: list[list[str]],
    installed_mods: list[str],
) -> tuple[list[str], list[str], list[list[str]]]:
    if not dependency_chains or not installed_mods or not builder.known_deleted_client_mods:
        return [], [], []

    known_deleted_tokens = {builder._normalize_mod_token(item) for item in builder.known_deleted_client_mods if str(item).strip()}
    forced_names: list[str] = []
    rationale: list[str] = []
    matched_chains: list[list[str]] = []

    for chain in dependency_chains:
        clean_chain = [str(item).strip() for item in chain if str(item).strip()]
        if len(clean_chain) < 2:
            continue

        hit_indexes = [idx for idx, node in enumerate(clean_chain) if builder._normalize_mod_token(node) in known_deleted_tokens]
        if not hit_indexes:
            continue

        matched_chains.append(clean_chain)
        for hit_idx in hit_indexes:
            deleted_node = clean_chain[hit_idx]
            dependents = clean_chain[:hit_idx]
            resolved = builder._resolve_mod_names_to_installed(dependents, candidates=installed_mods)
            for dep in resolved:
                if dep not in forced_names:
                    forced_names.append(dep)
                rationale.append(f"{dep} 依赖已删除客户端mod {deleted_node}，触发强制删除")

    return forced_names, rationale, matched_chains
