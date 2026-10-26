"""Case memory (Stage 9 step 3 / Stage 13).

Two kinds of cases live in one SQLite table:
  reference - historical attacks / CVEs seeded from knowledge/reference_attacks.json
  confirmed - incidents an analyst marked CONFIRMED_ATTACK / CONFIRMED_FALSE_POSITIVE (Stage 13)

Both are only ever *hints* handed to the agent (similarity >= threshold); neither decides a
verdict. Unconfirmed agent verdicts are never stored, so one wrong verdict cannot spread.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path


def _jac(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    return len(a & b) / len(a | b)


def similarity(fp: dict, case: dict) -> float:
    """Weighted structural similarity: attack type 0.5, stage names 0.3, ports 0.2.
    When the incident has no ports (e.g. HTTP without a dst_port) the port term is dropped."""
    t = 1.0 if fp["attack_type"] in case["attack_types"] else 0.0
    s = _jac(set(fp["stages"]), set(case["stages"]))
    if fp.get("ports") and case.get("ports"):
        p = _jac(set(fp["ports"]), set(case["ports"]))
        return 0.5 * t + 0.3 * s + 0.2 * p
    return (0.5 * t + 0.3 * s) / 0.8


class CaseMemory:
    def __init__(self, db_path: Path, reference: list[dict]):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(db_path))
        self.db.execute("""CREATE TABLE IF NOT EXISTS cases(
            id TEXT PRIMARY KEY, kind TEXT, name TEXT, year INT, attack_types TEXT, stages TEXT,
            ports TEXT, verdict TEXT, cves TEXT, mitre TEXT, summary TEXT, lesson TEXT)""")
        for r in reference:
            self.db.execute("INSERT OR REPLACE INTO cases VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (
                r["id"], "reference", r["name"], r.get("year"), json.dumps(r["attack_types"]),
                json.dumps(r["stages"]), json.dumps(r.get("ports", [])), "TRUE_POSITIVE",
                json.dumps(r.get("cves", [])), json.dumps(r.get("mitre", [])), r["summary"], r.get("lesson", "")))
        self.db.commit()

    def _rows(self) -> list[dict]:
        cur = self.db.execute("SELECT id,kind,name,year,attack_types,stages,ports,verdict,cves,mitre,summary,lesson FROM cases")
        out = []
        for (i, k, n, y, at, st, po, v, cv, mi, su, le) in cur.fetchall():
            out.append({"id": i, "kind": k, "name": n, "year": y, "attack_types": json.loads(at),
                        "stages": json.loads(st), "ports": json.loads(po), "verdict": v,
                        "cves": json.loads(cv), "mitre": json.loads(mi), "summary": su, "lesson": le})
        return out

    def lookup(self, fp: dict, threshold: float, k: int = 3, kind: str | None = None) -> list[dict]:
        """Cases with similarity >= threshold, best first (confirmed beats reference on ties)."""
        scored = []
        for c in self._rows():
            if kind and c["kind"] != kind:
                continue
            s = similarity(fp, c)
            if s >= threshold:
                scored.append(({**c, "similarity": round(s, 2)}, c["kind"] == "confirmed", c["year"] or 0))
        scored.sort(key=lambda x: (x[0]["similarity"], x[1], x[2]), reverse=True)
        return [c for c, _, _ in scored[:k]]

    def add_confirmed(self, case_id: str, name: str, fp: dict, verdict: str, summary: str) -> None:
        self.db.execute("INSERT OR REPLACE INTO cases VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (
            case_id, "confirmed", name, None, json.dumps([fp["attack_type"]]), json.dumps(fp["stages"]),
            json.dumps(fp.get("ports", [])), verdict, "[]", "[]", summary, ""))
        self.db.commit()

    def count(self, kind: str) -> int:
        return self.db.execute("SELECT COUNT(*) FROM cases WHERE kind=?", (kind,)).fetchone()[0]

    def close(self) -> None:
        self.db.close()
