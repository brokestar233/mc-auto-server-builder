from __future__ import annotations

import sqlite3
from pathlib import Path

from .defaults import KNOWN_CLIENT_MOD_REGEX


class RuleDB:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.conn = sqlite3.connect(str(db_path))
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS remove_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern TEXT NOT NULL UNIQUE,
                description TEXT DEFAULT ''
            )
            """
        )
        self.conn.commit()

    def seed_defaults(self) -> None:
        for pattern in KNOWN_CLIENT_MOD_REGEX:
            self.add_rule(pattern, "builtin client-only rule")

    def add_rule(self, pattern: str, description: str = "") -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO remove_rules(pattern, description) VALUES(?, ?)",
            (pattern, description),
        )
        self.conn.commit()

    def list_rules(self) -> list[str]:
        rows = self.conn.execute("SELECT pattern FROM remove_rules ORDER BY id ASC").fetchall()
        return [r[0] for r in rows]

    def close(self) -> None:
        self.conn.close()

