"""Ingest JSONL traces into a SQL decision store (DB-API 2.0: PostgreSQL, SQLite, ...).

Stores sessions, decisions and violations so a SOC can query blocked flows alongside the
OCSF/SIEM export. The Postgres schema is deploy/sql/schema.sql; this module can also create a
SQLite-compatible schema for local use and tests. Ingestion is idempotent per
``(session_id, call_id)``.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Protocol

from sluice.trace.writer import read_trace

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS sluice_session (
    session_id TEXT PRIMARY KEY, mode TEXT NOT NULL, started_at REAL,
    policy TEXT NOT NULL, tools TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sluice_decision (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES sluice_session(session_id) ON DELETE CASCADE,
    call_id TEXT NOT NULL, ts REAL NOT NULL, tool TEXT NOT NULL, verdict TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '', args TEXT NOT NULL DEFAULT '{}',
    UNIQUE (session_id, call_id)
);
CREATE TABLE IF NOT EXISTS sluice_violation (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_id INTEGER NOT NULL REFERENCES sluice_decision(id) ON DELETE CASCADE,
    arg TEXT NOT NULL, label TEXT NOT NULL, rule TEXT NOT NULL,
    sources TEXT NOT NULL DEFAULT '[]', failures TEXT NOT NULL DEFAULT '[]',
    tags TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS sluice_decision_verdict_idx ON sluice_decision (verdict);
"""


class Cursor(Protocol):
    def execute(self, sql: str, params: Any = ..., /) -> Any: ...
    def fetchone(self) -> Any: ...
    def fetchall(self) -> list[Any]: ...
    @property
    def lastrowid(self) -> int | None: ...


class Connection(Protocol):
    def cursor(self) -> Cursor: ...
    def commit(self) -> None: ...


class TraceStore:
    """Wraps a DB-API 2.0 connection. ``paramstyle`` is ``qmark`` (SQLite) or ``pyformat``
    (psycopg); pass ``dialect="postgres"`` for the latter."""

    def __init__(self, conn: Connection, *, dialect: str = "sqlite") -> None:
        self.conn = conn
        self.dialect = dialect
        self._ph = "%s" if dialect == "postgres" else "?"

    def _sql(self, sql: str) -> str:
        return sql.replace("?", self._ph) if self._ph != "?" else sql

    def ensure_schema(self) -> None:
        """Create the tables if missing. For Postgres, run deploy/sql/schema.sql instead."""
        if self.dialect == "postgres":
            raise RuntimeError(
                "run deploy/sql/schema.sql for Postgres; ensure_schema is SQLite-only"
            )
        cur = self.conn.cursor()
        for stmt in filter(str.strip, SQLITE_SCHEMA.split(";")):
            cur.execute(stmt)
        self.conn.commit()

    def ingest(self, events: Iterable[dict[str, Any]]) -> dict[str, int]:
        cur = self.conn.cursor()
        counts = {"sessions": 0, "decisions": 0, "violations": 0}
        session_id = "unknown"
        for ev in events:
            kind = ev.get("type")
            if kind == "session":
                session_id = str(ev.get("session_id", "unknown"))
                cur.execute(
                    self._sql(
                        "INSERT INTO sluice_session (session_id, mode, started_at, policy, tools) "
                        "VALUES (?, ?, ?, ?, ?) ON CONFLICT (session_id) DO NOTHING"
                    ),
                    (
                        session_id,
                        ev.get("mode", ""),
                        ev.get("ts", 0.0),
                        json.dumps(ev.get("policy", {})),
                        json.dumps(ev.get("tools", [])),
                    ),
                )
                counts["sessions"] += 1
            elif kind == "call":
                counts["decisions"] += 1
                counts["violations"] += self._insert_call(cur, session_id, ev)
        self.conn.commit()
        return counts

    def _insert_call(self, cur: Cursor, session_id: str, ev: dict[str, Any]) -> int:
        decision = ev.get("decision", {})
        cur.execute(
            self._sql(
                "INSERT INTO sluice_decision "
                "(session_id, call_id, ts, tool, verdict, reason, args) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (session_id, call_id) DO NOTHING"
            ),
            (
                session_id,
                str(ev.get("id", "")),
                float(ev.get("ts", 0.0)),
                ev.get("tool", ""),
                decision.get("verdict", ""),
                decision.get("reason", ""),
                json.dumps(ev.get("args", {}), default=str),
            ),
        )
        cur.execute(
            self._sql("SELECT id FROM sluice_decision WHERE session_id = ? AND call_id = ?"),
            (session_id, str(ev.get("id", ""))),
        )
        row = cur.fetchone()
        if row is None:
            return 0
        decision_id = row[0]
        # Replace this decision's violations so re-ingesting the same trace is idempotent.
        cur.execute(self._sql("DELETE FROM sluice_violation WHERE decision_id = ?"), (decision_id,))
        n = 0
        for v in decision.get("violations", []):
            cur.execute(
                self._sql(
                    "INSERT INTO sluice_violation "
                    "(decision_id, arg, label, rule, sources, failures, tags) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)"
                ),
                (
                    decision_id,
                    v.get("arg", ""),
                    v.get("label", ""),
                    v.get("rule", ""),
                    json.dumps(v.get("sources", [])),
                    json.dumps(v.get("failures", [])),
                    json.dumps(v.get("tags", [])),
                ),
            )
            n += 1
        return n

    def blocked(self) -> list[dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT d.session_id, d.call_id, d.tool, d.verdict, v.arg, v.rule "
            "FROM sluice_decision d JOIN sluice_violation v ON v.decision_id = d.id "
            "WHERE d.verdict IN ('block', 'ask') ORDER BY d.ts DESC"
        )
        cols = ["session_id", "call_id", "tool", "verdict", "arg", "rule"]
        return [dict(zip(cols, r, strict=True)) for r in cur.fetchall()]


def ingest_file(conn: Connection, path: str | Path, *, dialect: str = "sqlite") -> dict[str, int]:
    store = TraceStore(conn, dialect=dialect)
    if dialect == "sqlite":
        store.ensure_schema()
    return store.ingest(read_trace(path))
