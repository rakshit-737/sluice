from __future__ import annotations

import io
import json
from pathlib import Path

from sluice.agent import Agent
from sluice.export.ocsf import (
    ACTION_DENIED,
    CLASS_UID,
    DISPOSITION_BLOCKED,
    DISPOSITION_LOGGED,
    SEVERITY_HIGH,
    OcsfExporter,
    ocsf_finding,
)
from sluice.labels import reset_ids
from sluice.monitor import Monitor
from sluice.policy import Policy
from sluice.scenario import load_scenario
from sluice.trace import TraceWriter

INBOX = Path(__file__).parents[1] / "examples" / "inbox-assistant"


def run_inbox(exporter: OcsfExporter) -> None:
    reset_ids()
    sc = load_scenario(INBOX)()
    assert sc.policy_path is not None
    mon = Monitor(Policy.load(sc.policy_path), sc.registry, trace=TraceWriter(listeners=[exporter]))
    Agent(sc.llm, sc.registry, mon).run(sc.user_prompt)


def test_blocked_call_becomes_detection_finding() -> None:
    buf = io.StringIO()
    exp = OcsfExporter(buf)
    run_inbox(exp)
    assert exp.count == 1  # the allowed read_inbox call is not exported
    f = json.loads(buf.getvalue())
    assert f["class_uid"] == CLASS_UID and f["type_uid"] == 200401 and f["category_uid"] == 2
    assert f["action_id"] == ACTION_DENIED and f["disposition_id"] == DISPOSITION_BLOCKED
    assert f["severity_id"] == SEVERITY_HIGH
    assert f["metadata"]["product"]["name"] == "sluice"
    assert "LLM01:2025 Prompt Injection" in f["finding_info"]["types"]
    assert {a["technique"]["uid"] for a in f["finding_info"]["attacks"]} == {
        "AML.T0051.001",
        "AML.T0057",
    }
    assert f["unmapped"]["sluice"]["tool"] == "send_email"
    assert isinstance(f["time"], int) and f["time"] > 0
    session, call_id = f["finding_info"]["uid"].split(":")
    assert len(session) == 32 and call_id == "c2"  # unique across runs


def test_include_allowed_and_file_sink(tmp_path: Path) -> None:
    exp = OcsfExporter(tmp_path / "siem" / "ocsf.jsonl", include_allowed=True)
    run_inbox(exp)
    exp.close()
    lines = (tmp_path / "siem" / "ocsf.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2 and json.loads(lines[0])["severity_id"] == 1


def test_logged_violation() -> None:
    f = ocsf_finding({"tool": "t", "decision": {"verdict": "log", "violations": [{"arg": "a"}]}})
    assert f["disposition_id"] == DISPOSITION_LOGGED and f["severity_id"] == 3
    unparseable = ocsf_finding({"tool": "t", "decision": {"verdict": "block", "violations": []}})
    assert (
        unparseable["severity_id"] == 3
        and unparseable["finding_info"]["desc"] == "policy violation"
    )
