from __future__ import annotations

from pathlib import Path

import pytest

from sluice.agent import Agent
from sluice.labels import reset_ids
from sluice.llm import ToolCall
from sluice.monitor import Monitor
from sluice.policy import Policy
from sluice.scenario import load_scenario
from sluice.trace import TraceWriter, read_trace
from sluice.trace.replay import ReplayError, parse_label, replay

INBOX = Path(__file__).parents[1] / "examples" / "inbox-assistant"


def record(tmp_path: Path) -> Path:
    reset_ids()
    sc = load_scenario(INBOX)()
    assert sc.policy_path is not None
    path = tmp_path / "trace.jsonl"
    with TraceWriter(path) as t:
        mon = Monitor(Policy.load(sc.policy_path), sc.registry, trace=t)
        Agent(sc.llm, sc.registry, mon).run(sc.user_prompt)
        mon.check(ToolCall("z", "send_email", {}, parse_error="bad JSON"))
    return path


def test_replay_under_recorded_policy_matches(tmp_path: Path) -> None:
    r = replay(read_trace(record(tmp_path)))
    assert [c.tool for c in r.calls] == ["read_inbox", "send_email", "send_email"]
    assert r.changed == []
    assert r.calls[1].decision.verdict == "block"
    assert "tool.read_inbox" in r.calls[1].decision.explain()
    assert "send_email" in r.graph.to_dot()


def test_what_if_policy(tmp_path: Path) -> None:
    lax = Policy.from_yaml("sinks: {read_inbox: {}, send_email: {}}")
    r = replay(read_trace(record(tmp_path)), lax)
    assert [c.id for c in r.changed] == ["c2"]
    assert r.calls[1].decision.verdict == "allow"
    assert r.calls[2].decision.verdict == "block"  # unparseable stays blocked


def test_replay_errors() -> None:
    with pytest.raises(ReplayError, match="no session"):
        replay([{"type": "call"}])
    with pytest.raises(ReplayError, match="malformed"):
        parse_label({"label": "trusted"})
    r = replay([{"type": "session"}])  # no policy recorded: deny-all
    assert r.policy.deny_all
