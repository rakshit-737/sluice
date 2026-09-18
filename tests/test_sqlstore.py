from __future__ import annotations

import sqlite3
from pathlib import Path

from sluice.agent import Agent
from sluice.labels import reset_ids
from sluice.monitor import Monitor
from sluice.policy import Policy
from sluice.scenario import load_scenario
from sluice.trace import TraceWriter
from sluice.trace.sqlstore import TraceStore, ingest_file

INBOX = Path(__file__).parents[1] / "examples" / "inbox-assistant"


def record(path: Path) -> None:
    reset_ids()
    sc = load_scenario(INBOX)()
    assert sc.policy_path is not None
    with TraceWriter(path) as t:
        mon = Monitor(Policy.load(sc.policy_path), sc.registry, trace=t)
        Agent(sc.llm, sc.registry, mon).run(sc.user_prompt)


def test_ingest_and_query(tmp_path: Path) -> None:
    trace = tmp_path / "trace.jsonl"
    record(trace)
    conn = sqlite3.connect(":memory:")
    counts = ingest_file(conn, trace)
    assert counts["sessions"] == 1
    assert counts["decisions"] == 2  # read_inbox allow, send_email block
    assert counts["violations"] == 2  # to, body

    store = TraceStore(conn)
    blocked = store.blocked()
    assert {b["arg"] for b in blocked} == {"to", "body"}
    assert all(b["tool"] == "send_email" and b["verdict"] == "block" for b in blocked)

    cur = conn.cursor()
    cur.execute("SELECT mode FROM sluice_session")
    assert cur.fetchone()[0] == "monitor"
    cur.execute("SELECT tags FROM sluice_violation WHERE arg = 'to'")
    assert "LLM01:2025" in cur.fetchone()[0]


def test_ingest_is_idempotent(tmp_path: Path) -> None:
    trace = tmp_path / "trace.jsonl"
    record(trace)
    conn = sqlite3.connect(":memory:")
    ingest_file(conn, trace)
    ingest_file(conn, trace)  # second ingest of the same trace
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM sluice_decision")
    assert cur.fetchone()[0] == 2  # not duplicated
    cur.execute("SELECT COUNT(*) FROM sluice_violation")
    assert cur.fetchone()[0] == 2


def test_postgres_dialect_uses_placeholders() -> None:
    store = TraceStore(object(), dialect="postgres")  # type: ignore[arg-type]
    assert store._sql("WHERE a = ? AND b = ?") == "WHERE a = %s AND b = %s"
    try:
        store.ensure_schema()
    except RuntimeError as e:
        assert "schema.sql" in str(e)
    else:  # pragma: no cover
        raise AssertionError("expected ensure_schema to refuse for postgres")
