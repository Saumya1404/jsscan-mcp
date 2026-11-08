"""SQLite persistence shared by the MCP server and the web view.

Secret values are never stored: only a redacted preview, a short sha256
fingerprint and the location. Re-verification re-fetches the source.
"""
from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans(
  id TEXT PRIMARY KEY, target TEXT, kind TEXT, started REAL, finished REAL, status TEXT, summary TEXT);
CREATE TABLE IF NOT EXISTS assets(
  scan_id TEXT, url TEXT, kind TEXT, page TEXT, idx INTEGER, status INTEGER, size INTEGER, note TEXT);
CREATE TABLE IF NOT EXISTS findings(
  id TEXT PRIMARY KEY, scan_id TEXT, type TEXT, rule_id TEXT, title TEXT, severity TEXT,
  status TEXT, confidence INTEGER, asset_url TEXT, line INTEGER, col INTEGER,
  fingerprint TEXT, occurrences INTEGER, data TEXT);
CREATE INDEX IF NOT EXISTS f_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS a_scan ON assets(scan_id);
"""

SEV_ORDER = "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"
FINDING_COLS = ("id", "scan_id", "type", "rule_id", "title", "severity", "status", "confidence",
                "asset_url", "line", "col", "fingerprint", "occurrences")


class Store:
    def __init__(self, path: Path):
        self.path = path
        with self._conn() as c:
            c.executescript(SCHEMA)

    @contextmanager
    def _conn(self):
        c = sqlite3.connect(self.path, timeout=10)
        c.row_factory = sqlite3.Row
        try:
            yield c
            c.commit()
        finally:
            c.close()

    # scans
    def new_scan(self, scan_id: str, target: str, kind: str) -> None:
        with self._conn() as c:
            c.execute("INSERT INTO scans VALUES(?,?,?,?,?,?,?)",
                      (scan_id, target, kind, time.time(), None, "running", "{}"))

    def finish_scan(self, scan_id: str, status: str, summary: dict) -> None:
        with self._conn() as c:
            c.execute("UPDATE scans SET finished=?, status=?, summary=? WHERE id=?",
                      (time.time(), status, json.dumps(summary), scan_id))

    def get_scan(self, scan_id: str) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not r:
            return None
        d = dict(r)
        d["summary"] = json.loads(d["summary"] or "{}")
        return d

    def list_scans(self, limit: int = 20) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM scans ORDER BY started DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["summary"] = json.loads(d["summary"] or "{}")
            out.append(d)
        return out

    # assets
    def add_assets(self, scan_id: str, assets: list[dict]) -> None:
        with self._conn() as c:
            c.executemany("INSERT INTO assets VALUES(?,?,?,?,?,?,?,?)",
                          [(scan_id, a["url"], a["kind"], a.get("page"), a.get("idx", 0),
                            a.get("status", 0), a.get("size", 0), a.get("note", "")) for a in assets])

    def list_assets(self, scan_id: str) -> list[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM assets WHERE scan_id=?", (scan_id,))]

    def get_asset(self, scan_id: str, url: str) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM assets WHERE scan_id=? AND url=?", (scan_id, url)).fetchone()
        return dict(r) if r else None

    # findings
    def add_findings(self, findings: list[dict]) -> None:
        with self._conn() as c:
            c.executemany(
                "INSERT INTO findings VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [tuple(f[k] for k in FINDING_COLS) + (json.dumps(f["data"]),) for f in findings])

    def query_findings(self, scan_id: str, type: str | None = None, severity: str | None = None,
                       min_confidence: int = 0, include_rejected: bool = False,
                       limit: int = 20, offset: int = 0) -> tuple[list[dict], int]:
        where, args = ["scan_id=?", "confidence>=?"], [scan_id, min_confidence]
        if type:
            where.append("type=?"); args.append(type)
        if severity:
            where.append("severity=?"); args.append(severity)
        if not include_rejected:
            where.append("status!='rejected'")
        clause = " AND ".join(where)
        with self._conn() as c:
            total = c.execute(f"SELECT COUNT(*) FROM findings WHERE {clause}", args).fetchone()[0]
            rows = c.execute(
                f"SELECT * FROM findings WHERE {clause} ORDER BY {SEV_ORDER}, confidence DESC, id LIMIT ? OFFSET ?",
                args + [limit, offset]).fetchall()
        return [self._row(r) for r in rows], total

    def get_finding(self, finding_id: str) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        return self._row(r) if r else None

    def update_finding(self, finding_id: str, status: str, confidence: int, data: dict) -> None:
        with self._conn() as c:
            c.execute("UPDATE findings SET status=?, confidence=?, data=? WHERE id=?",
                      (status, confidence, json.dumps(data), finding_id))

    def counts(self, scan_id: str) -> dict:
        with self._conn() as c:
            rows = c.execute(
                "SELECT type, severity, status, COUNT(*) n FROM findings WHERE scan_id=? GROUP BY type, severity, status",
                (scan_id,)).fetchall()
        by_type: dict = {}
        by_sev: dict = {}
        rejected = 0
        for r in rows:
            if r["status"] == "rejected":
                rejected += r["n"]
                continue
            by_type[r["type"]] = by_type.get(r["type"], 0) + r["n"]
            by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + r["n"]
        return {"by_type": by_type, "by_severity": by_sev, "suppressed_false_positives": rejected}

    @staticmethod
    def _row(r: sqlite3.Row) -> dict:
        d = dict(r)
        d["data"] = json.loads(d["data"])
        return d
