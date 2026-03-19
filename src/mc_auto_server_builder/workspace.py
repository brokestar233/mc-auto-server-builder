from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .models import WorkDirs
from .util import ensure_dirs


def create_workdirs(base_dir: str | Path = ".") -> WorkDirs:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    root = Path(base_dir).resolve() / f"workdir_{ts}"
    client_temp = root / "client_temp"
    server = root / "server"
    backups = root / "backups"
    logs = root / "logs"
    java_bins = root / "java_bins"
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
