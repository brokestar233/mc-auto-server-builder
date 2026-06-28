from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .models import CacheDirs, WorkDirs
from .util import ensure_dirs


def create_cache_dirs(base_dir: str | Path = ".") -> CacheDirs:
    root = Path(base_dir).resolve() / ".mcasb_cache"
    runs = Path(base_dir).resolve() / "runs"
    packs = root / "packs"
    manifests = root / "manifests"
    java_bins = root / "java_bins"
    ensure_dirs((root, runs, packs, manifests, java_bins))
    return CacheDirs(
        root=root,
        runs=runs,
        packs=packs,
        manifests=manifests,
        java_bins=java_bins,
    )


def create_workdirs(
    base_dir: str | Path = ".",
    *,
    resume_dir: str | Path | None = None,
    cache_dirs: CacheDirs | None = None,
) -> WorkDirs:
    cache = cache_dirs or create_cache_dirs(base_dir)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    root = Path(resume_dir).resolve() if resume_dir is not None else (cache.runs / f"workdir_{ts}")
    client_temp = root / "client_temp"
    server = root / "server"
    backups = root / "backups"
    logs = root / "logs"
    java_bins = cache.java_bins
    db = root / "db"

    ensure_dirs((root, client_temp, server, backups, logs, java_bins, db))

    return WorkDirs(
        root=root,
        client_temp=client_temp,
        server=server,
        backups=backups,
        logs=logs,
        java_bins=java_bins,
        db=db,
    )
