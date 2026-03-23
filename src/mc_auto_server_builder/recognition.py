from __future__ import annotations

import re
from dataclasses import dataclass

from .models import DetectionCandidate, PackManifest

LATEST_LTS_JAVA_VERSION = 21

JAVA_MISMATCH_PATTERNS: tuple[tuple[str, int], ...] = (
    (r"requires java\s*8", 8),
    (r"java\s*8", 8),
    (r"requires java\s*11", 11),
    (r"java\s*11", 11),
    (r"requires java\s*17", 17),
    (r"java\s*17", 17),
    (r"requires java\s*21", 21),
    (r"java\s*21", 21),
)


@dataclass(slots=True)
class RecognitionFallbackPlan:
    loader: str
    loader_version: str | None
    mc_version: str | None
    build: str | None
    start_mode: str
    java_version: int
    confidence: float
    reason: str
    source_candidates: list[str]


def top_candidate_values(candidates: list[DetectionCandidate], *, limit: int = 3) -> list[str]:
    return [str(item.value) for item in list(candidates or [])[:limit] if str(item.value or "").strip()]


def choose_java_version(manifest: PackManifest | None, *, loader: str | None = None, mc_version: str | None = None) -> int:
    chosen_loader = str(loader or getattr(manifest, "loader", "unknown") or "unknown").lower()
    chosen_mc = str(mc_version or getattr(manifest, "mc_version", "unknown") or "unknown")
    if chosen_loader == "forge":
        if chosen_mc.startswith(("1.7", "1.12", "1.16")):
            return 8
        if chosen_mc.startswith(("1.18", "1.19", "1.20")):
            return 17
    if chosen_loader in {"fabric", "quilt"}:
        if chosen_mc.startswith(("1.20.5", "1.21")):
            return 21
        return 17
    if chosen_loader == "neoforge":
        return 21
    if chosen_mc.startswith("1.21"):
        return 21
    if chosen_mc.startswith(("1.18", "1.19", "1.20")):
        return 17
    if chosen_mc.startswith("1.17"):
        return 16
    return 8


def choose_latest_lts_java_version() -> int:
    return LATEST_LTS_JAVA_VERSION


def infer_java_from_runtime_feedback(text: str, current_version: int) -> int | None:
    lowered = (text or "").lower()
    for pattern, version in JAVA_MISMATCH_PATTERNS:
        if re.search(pattern, lowered):
            return version
    if "class file version 65" in lowered:
        return 21
    if "class file version 61" in lowered:
        return 17
    if "class file version 55" in lowered:
        return 11
    if "class file version 52" in lowered:
        return 8
    if "unsupportedclassversionerror" in lowered and current_version < 21:
        return 21
    return None
