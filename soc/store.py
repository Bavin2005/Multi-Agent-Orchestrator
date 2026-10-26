"""SQLite persistence: incidents, dead-letter list, human-review queue, reports."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .util import _default


class StateStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path))
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS incidents(incident_id TEXT PRIMARY KEY, version INT, status TEXT, data TEXT);
            CREATE TABLE IF NOT EXISTS dead_letter(alert_id TEXT, reason TEXT, data TEXT);
            CREATE TABLE IF NOT EXISTS human_review(alert_id TEXT, reason TEXT, data TEXT);
            CREATE TABLE IF NOT EXISTS reports(incident_id TEXT, version INT, data TEXT, PRIMARY KEY(incident_id, version));
        """)

    @staticmethod
    def _j(obj) -> str:
        return json.dumps(obj, default=_default)

    def save_incident(self, inc_dict: dict) -> None:
        self.db.execute("INSERT OR REPLACE INTO incidents VALUES (?,?,?,?)",
                        (inc_dict["incident_id"], inc_dict["version"], inc_dict["status"], self._j(inc_dict)))
        self.db.commit()

    def dead_letter(self, alert, reason: str) -> None:
        aid = alert.get("alert_id", "?") if isinstance(alert, dict) else "?"
        self.db.execute("INSERT INTO dead_letter VALUES (?,?,?)", (aid, reason, self._j(alert)))
        self.db.commit()

    def human_review(self, alert: dict, reason: str) -> None:
        self.db.execute("INSERT INTO human_review VALUES (?,?,?)", (alert["alert_id"], reason, self._j(alert)))
        self.db.commit()

    def save_report(self, report: dict) -> None:
        self.db.execute("INSERT OR REPLACE INTO reports VALUES (?,?,?)",
                        (report["header"]["incident_id"], report["header"]["version"], self._j(report)))
        self.db.commit()

    def count(self, table: str) -> int:
        return self.db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

    def rows(self, table: str) -> list[tuple]:
        return self.db.execute(f"SELECT * FROM {table}").fetchall()

    def close(self) -> None:
        self.db.close()
