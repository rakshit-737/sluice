from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from sluice.cli import app
from sluice.export.sarif import trifecta_sarif
from sluice.policy import Policy
from sluice.policy.trifecta import analyze
from sluice.tools import COMMS, FS_READ, ToolRegistry, tool

INBOX = Path(__file__).parents[1] / "examples" / "inbox-assistant"

POLICY_TEXT = """sources:
  tool.read_file: {integrity: untrusted, confidentiality: secret}
sinks:
  send:
    args:
      to: {require_integrity: trusted}
"""


@tool(caps=[FS_READ])
def read_file(path: str) -> str:
    return ""


@tool(caps=[COMMS])
def send(to: str, body: str) -> str:
    return ""


@tool()
def helper(x: str) -> str:
    return ""


def test_sarif_results() -> None:
    report = analyze(ToolRegistry([read_file, send, helper]), Policy.from_yaml(POLICY_TEXT))
    doc = trifecta_sarif(report, "agent/policy.yaml", POLICY_TEXT)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {"SLU001", "SLU002", "SLU003"}
    by_rule = {r["ruleId"]: r for r in run["results"]}
    unguarded = by_rule["SLU001"]
    assert unguarded["level"] == "error" and "`send.body`" in unguarded["message"]["text"]
    loc = unguarded["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "agent/policy.yaml"
    assert loc["region"]["startLine"] == 4  # `send:` (body is not listed under it)
    to_line = trifecta_sarif(
        analyze(ToolRegistry([send]), Policy.from_yaml("sinks: {send: {}}")),
        policy_text="sinks:\n  other:\n    to: x\n  send:\n    args:\n      to: {}\n",
    )["runs"][0]["results"][0]
    assert to_line["locations"][0]["physicalLocation"]["region"]["startLine"] == 6
    assert by_rule["SLU002"]["level"] == "note"
    assert by_rule["SLU003"]["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
    assert json.dumps(doc)


def test_sarif_logged_sink_and_clean() -> None:
    # Declare send's own output source so its fail-closed label doesn't complete a trifecta.
    text = (
        "sources: {tool.send: {integrity: trusted, confidentiality: public}}\n"
        "sinks: {send: {all_args: {require_integrity: trusted}, on_violation: log}}"
    )
    report = analyze(ToolRegistry([send]), Policy.from_yaml(text))
    results = trifecta_sarif(report, policy_text=text)["runs"][0]["results"]
    assert all(r["level"] == "warning" for r in results)  # no trifecta: warnings only
    assert "verdict is 'log'" in results[0]["message"]["text"]
    clean = analyze(
        ToolRegistry([send]),
        Policy.from_yaml(text.replace(", on_violation: log", "")),
    )
    assert trifecta_sarif(clean)["runs"][0]["results"] == []


def test_cli_writes_sarif(tmp_path: Path) -> None:
    out = tmp_path / "trifecta.sarif"
    r = CliRunner().invoke(app, ["trifecta", str(INBOX), "--sarif", str(out)])
    assert r.exit_code == 0, r.output
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert [x["ruleId"] for x in doc["runs"][0]["results"]] == ["SLU002"]
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ]
    assert uri.endswith("policy.yaml") and "\\" not in uri
