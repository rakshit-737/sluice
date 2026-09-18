from __future__ import annotations

from sluice.policy import Policy
from sluice.policy.trifecta import analyze
from sluice.tools import COMMS, FS_READ, NET_IN, NET_OUT, SHELL, ToolRegistry, tool


@tool(caps=[FS_READ])
def read_file(path: str) -> str:
    return ""


@tool(caps=[NET_IN], source="tool.web")
def fetch(url: str) -> str:
    return ""


@tool(caps=[COMMS])
def send_email(to: str, subject: str, body: str) -> str:
    return ""


@tool(caps=[NET_OUT])
def post(url: str, data: str) -> str:
    return ""


@tool(caps=[SHELL])
def sh(cmd: str) -> str:
    return ""


@tool()
def calc(expr: str) -> str:
    return ""


@tool(caps=[NET_OUT])
def ping() -> str:
    return ""


REG = ToolRegistry([read_file, fetch, send_email, post, sh, calc, ping])

POLICY = Policy.from_yaml(
    """
sources:
  tool.read_file: {integrity: trusted, confidentiality: secret}
  tool.web: {integrity: untrusted, confidentiality: public}
  tool.calc: {integrity: trusted, confidentiality: public}
sinks:
  send_email:
    args: {to: {require_integrity: trusted}, body: {max_confidentiality: internal}}
  post: {all_args: {require_integrity: trusted}, on_violation: log}
  sh: {all_args: {require_integrity: trusted}}
  calc: {}
"""
)


def test_classification() -> None:
    r = analyze(REG, POLICY)
    assert r.present
    assert set(r.private) >= {"read_file", "sh"}
    assert "source:tool.read_file is secret" in r.private["read_file"]
    assert set(r.untrusted) >= {"fetch", "sh"}
    assert set(r.exfil) == {"send_email", "post", "sh", "ping"}
    assert r.unclassified == ["calc"]
    # undeclared source: fail-closed label makes a tool count as private and untrusted
    assert "source:tool.send_email is secret" in r.private["send_email"]


def test_coverage() -> None:
    paths = {p.tool: p for p in analyze(REG, POLICY).paths}
    email = paths["send_email"]
    assert email.status == "partial"  # subject is unconstrained
    assert [a.arg for a in email.args if not a.guarded] == ["subject"]
    assert paths["post"].status == "uncovered"  # log verdict does not enforce
    assert paths["post"].verdict == "log"
    assert paths["sh"].status == "covered"
    assert paths["ping"].status == "covered"  # no arguments, nothing flows out
    assert {p.tool for p in analyze(REG, POLICY).exposed} == {"send_email", "post"}


def test_undeclared_sink_is_fail_closed_covered() -> None:
    p = next(x for x in analyze(REG, Policy.from_yaml("{}")).paths if x.tool == "send_email")
    assert p.status == "covered" and p.args[0].rule.startswith("fail-closed")


def test_deny_all() -> None:
    r = analyze(REG, Policy.deny())
    assert all(p.status == "covered" for p in r.paths)
    assert r.paths[0].args[0].rule == "deny-all policy"


def test_no_trifecta() -> None:
    r = analyze(ToolRegistry([calc]), POLICY)
    assert not r.present and r.paths == []
