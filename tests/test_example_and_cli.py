from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sluice.agent import Agent
from sluice.cli import app
from sluice.graph import ProvenanceGraph
from sluice.monitor import Monitor
from sluice.policy import Policy
from sluice.scenario import ScenarioError, load_scenario
from sluice.trace import TraceWriter, read_trace

ROOT = Path(__file__).parents[1]
INBOX = ROOT / "examples" / "inbox-assistant"


def test_vanilla_loop_is_hijacked() -> None:
    sc = load_scenario(INBOX)()
    res = Agent(sc.llm, sc.registry).run(sc.user_prompt)
    assert any(
        name == "send_email" and args["to"] == "attacker@example.com" for name, args in res.executed
    )


def test_sluice_blocks_exfiltration() -> None:
    sc = load_scenario(INBOX)()
    assert sc.policy_path is not None
    mon = Monitor(Policy.load(sc.policy_path), sc.registry)
    res = Agent(sc.llm, sc.registry, mon).run(sc.user_prompt)
    assert [n for n, _ in res.executed] == ["read_inbox"]
    (d,) = res.blocked
    assert {v.arg for v in d.violations} == {"to", "body"}
    to = next(v for v in d.violations if v.arg == "to")
    assert "tool.read_inbox" in to.label.sources


def test_cli_run_writes_trace_and_graph(tmp_path: Path) -> None:
    r = CliRunner().invoke(app, ["run", str(INBOX), "--out", str(tmp_path), "--no-open"])
    assert r.exit_code == 0, r.output
    assert "BLOCK send_email" in r.output
    assert "attacker@example.com" in r.output  # vanilla run shows the exfiltration
    run_dir = tmp_path / "inbox-assistant"
    events = list(read_trace(run_dir / "trace.jsonl"))
    assert any(e["type"] == "call" and e["decision"]["verdict"] == "block" for e in events)
    html = (run_dir / "graph.html").read_text(encoding="utf-8")
    assert 'class="edge blocked"' in html and "<script" not in html
    assert "digraph" in (run_dir / "graph.dot").read_text(encoding="utf-8")


def test_cli_run_without_policy_is_deny_all(tmp_path: Path) -> None:
    d = tmp_path / "sc"
    d.mkdir()
    (d / "scenario.py").write_text(
        "from sluice.scenario import Scenario\n"
        "from sluice.tools import ToolRegistry\n"
        "from sluice.llm import MockLLM, call, say\n"
        "def f() -> str:\n    return 'x'\n"
        "def build():\n"
        "    return Scenario('s', ToolRegistry([f]), MockLLM([call('f'), say('ok')]), 'hi')\n",
        encoding="utf-8",
    )
    r = CliRunner().invoke(
        app, ["run", str(d), "--out", str(tmp_path / "o"), "--no-open", "--no-vanilla"]
    )
    assert r.exit_code == 0, r.output
    assert "deny-all" in r.output


def test_cli_bad_scenario(tmp_path: Path) -> None:
    r = CliRunner().invoke(app, ["run", str(tmp_path), "--no-open"])
    assert r.exit_code == 2
    (tmp_path / "scenario.py").write_text("x = 1\n", encoding="utf-8")
    with pytest.raises(ScenarioError, match="no build"):
        load_scenario(tmp_path)
    (tmp_path / "scenario.py").write_text("def build():\n    return 1\n", encoding="utf-8")
    with pytest.raises(ScenarioError, match="must return"):
        load_scenario(tmp_path)()


def test_cli_policy_check(tmp_path: Path) -> None:
    r = CliRunner().invoke(app, ["policy", "check", str(INBOX / "policy.yaml")])
    assert r.exit_code == 0 and "send_email" in r.output and "require_integrity=trusted" in r.output
    bad = tmp_path / "p.yaml"
    bad.write_text("on_violation: yolo", encoding="utf-8")
    assert CliRunner().invoke(app, ["policy", "check", str(bad)]).exit_code == 1
    ok = tmp_path / "q.yaml"
    ok.write_text("sinks: {sh: {all_args: {require_integrity: trusted}}}", encoding="utf-8")
    assert "*" in CliRunner().invoke(app, ["policy", "check", str(ok)]).output


def test_graph_exports_and_escaping(tmp_path: Path) -> None:
    with TraceWriter(tmp_path / "t.jsonl") as t:
        t.emit("value", id="v1", origin="<b>evil</b>", label="untrusted/secret", sources=["x"])
        t.emit("value", id="v2", origin="leaf", label="untrusted/secret", parents=["v1"])
        t.emit(
            "call",
            id="c1",
            tool="send",
            args={"to": "a"},
            attribution={"to": {"matches": ["v1", "ghost"]}},
            decision={"verdict": "block", "violations": [{"arg": "to"}]},
            explanation="BLOCK send",
        )
        t.emit("other")
    g = ProvenanceGraph.from_events(read_trace(tmp_path / "t.jsonl"))
    assert set(g.nodes) == {"v1", "v2", "c1"}
    p = g.pruned()
    assert set(p.nodes) == {"v1", "c1"}
    html = p.to_html("<t>")
    assert "&lt;b&gt;evil" in html and "<b>evil" not in html and "&lt;t&gt;" in html
    assert "BLOCK send" in html
    assert "penwidth=3" in p.to_dot()
    assert json.dumps(p.to_json())
    assert ProvenanceGraph().to_html().count("<svg") == 1


def test_graph_layout_handles_cycles() -> None:
    from sluice.graph import Edge, Node

    g = ProvenanceGraph(
        {"a": Node("a", "value", "a"), "b": Node("b", "value", "b")},
        [Edge("a", "b", "derived"), Edge("b", "a", "derived")],
    )
    assert set(g.layout()) == {"a", "b"}
