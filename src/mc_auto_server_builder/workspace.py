from __future__ import annotations

from datetime import datetime
import shutil
from pathlib import Path

from .models import WorkDirs


def create_workdirs(base_dir: str | Path = ".") -> WorkDirs:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    root = Path(base_dir).resolve() / f"workdir_{ts}"
    client_temp = root / "client_temp"
    server = root / "server"
    backups = root / "backups"
    logs = root / "logs"
    java_bins = root / "java_bins"
    db = root / "db"

    for d in (root, client_temp, server, backups, logs, java_bins, db):
        d.mkdir(parents=True, exist_ok=True)

    return WorkDirs(
        root=root,
        client_temp=client_temp,
        server=server,
        backups=backups,
        logs=logs,
        java_bins=java_bins,
        db=db,
    )


def backup_directory(src: Path, dst_root: Path, tag: str) -> Path:
    target = dst_root / tag
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(src, target)
    return target

