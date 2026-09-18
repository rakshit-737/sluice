from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

pytest.importorskip("agentdojo")

from sluice.bench.agentdojo import (
    BenchResult,
    Outcome,
    load_suites,
    run_benchmark,
)
from sluice.bench.policies import SINKS, policy_dict
from sluice.cli import app
from sluice.llm import MockLLM, say
from sluice.policy import Policy
from sluice.providers import llm_from_spec


def test_policies_compile_for_every_suite() -> None:
    for name, suite in load_suites().items():
        tools = [t.name for t in suite.tools]
        assert set(SINKS[name]) <= set(tools), name
        for tool_name, args in SINKS[name].items():
            params = next(t for t in suite.tools if t.name == tool_name).parameters.model_fields
            assert set(args) <= set(params), (name, tool_name)
        pol = Policy.from_dict(policy_dict(name, tools))
        assert set(pol.sinks) == set(tools)


def test_oracle_smoke_baseline_is_fully_compromised() -> None:
    r = run_benchmark(["banking"], ["none", "monitor"], limit=2)
    assert not [o for o in r.outcomes if o.error]
    none = [o for o in r.outcomes if o.mode == "none" and o.injection_task]
    mon = [o for o in r.outcomes if o.mode == "monitor" and o.injection_task]
    # The obedient oracle with no defence performs every injection task...
    assert none and all(o.attack_success for o in none)
    # ...and monitor mode stops them on this slice.
    assert mon and not any(o.attack_success for o in mon)


def test_llm_agent_modes_with_mock_models() -> None:
    def factory() -> MockLLM:
        return MockLLM([say("```python\nanswer(get_balance())\n```")] * 5)

    r = run_benchmark(["banking"], ["none", "monitor", "strict"], "llm", factory, limit=1)
    assert {o.mode for o in r.outcomes} == {"none", "monitor", "strict"}
    assert not [o for o in r.outcomes if o.error]


def test_errors_and_argument_checks() -> None:
    with pytest.raises(ValueError, match="unknown suites"):
        load_suites(["nope"])
    with pytest.raises(ValueError, match="unknown modes"):
        run_benchmark(["banking"], ["yolo"])
    with pytest.raises(ValueError, match="planner"):
        run_benchmark(["banking"], ["strict"])
    with pytest.raises(ValueError, match="needs a model"):
        run_benchmark(["banking"], ["none"], "llm")


def test_summary_and_save(tmp_path: Path) -> None:
    r = BenchResult(
        [
            Outcome("s", "u1", None, "none", "oracle", True, None),
            Outcome("s", "u1", "i1", "none", "oracle", False, True),
            Outcome("s", "u1", "i1", "monitor", "oracle", True, False, 1),
            Outcome("s", "u2", "i1", "monitor", "oracle", False, None, 0, "boom"),
        ]
    )
    md = r.markdown()
    header, rule = md.splitlines()[:2]
    assert header.count("|") == rule.count("|") == 7 and header.endswith("errors |")
    assert "| s | none | 100.0% (1) | 0.0% | 100.0% (1) | 0 |" in md
    assert "| s | monitor | n/a (0) | 100.0% | 0.0% (1) | 1 |" in md
    r.save(tmp_path)
    assert len((tmp_path / "outcomes.jsonl").read_text(encoding="utf-8").splitlines()) == 4


def test_cli_bench(tmp_path: Path) -> None:
    runner = CliRunner()
    r = runner.invoke(app, ["bench", "--suites", "banking", "--limit", "1", "--out", str(tmp_path)])
    assert r.exit_code == 0, r.output
    assert (tmp_path / "summary.md").exists()
    assert runner.invoke(app, ["bench", "--modes", "strict"]).exit_code == 2


def test_llm_from_spec() -> None:
    with pytest.raises(ValueError, match="provider:model"):
        llm_from_spec("gpt")
    with pytest.raises(ValueError, match="unknown provider"):
        llm_from_spec("acme:model")
    pytest.importorskip("ollama")
    assert type(llm_from_spec("ollama:llama3")).__name__ == "OllamaLLM"
