from __future__ import annotations

from pathlib import Path

import pytest

from sluice.labels import Confidentiality, Integrity, Label
from sluice.labels.requirement import Requirement
from sluice.policy import Policy, PolicyError
from sluice.tools import COMMS, SHELL, ToolRegistry, tool

POLICY = """
version: 1
sources:
  user: {integrity: trusted, confidentiality: internal}
  tool.read_email: {integrity: untrusted, confidentiality: secret}
  tool.web_fetch: {integrity: untrusted, confidentiality: public}
sinks:
  send_email:
    args:
      to: {require_integrity: trusted}
      body: {max_confidentiality: internal}
  shell: {all_args: {require_integrity: trusted}, on_violation: log}
  search: {}
on_violation: block
"""

TRUSTED = Label(Integrity.TRUSTED, Confidentiality.INTERNAL, frozenset({"user"}))
UNTRUSTED = Label(Integrity.UNTRUSTED, Confidentiality.PUBLIC, frozenset({"tool.web_fetch"}))
SECRET = Label(Integrity.TRUSTED, Confidentiality.SECRET, frozenset({"vault"}))


@tool(caps=[COMMS])
def send_email(to: str, body: str, subject: str = "") -> str:
    return "ok"


@tool(caps=[SHELL])
def shell(cmd: str) -> str:
    return ""


@tool()
def search(q: str) -> list[str]:
    return []


@tool()
def mystery(x: str) -> str:
    return x


@tool(
    sink={"path": Requirement.trusted()},
    all_args=Requirement(max_confidentiality=Confidentiality.INTERNAL),
)
def write_file(path: str, data: str) -> None:
    return None


@pytest.fixture
def reg() -> ToolRegistry:
    return ToolRegistry([send_email, shell, search, mystery, write_file])


@pytest.fixture
def pol() -> Policy:
    return Policy.from_yaml(POLICY)


def test_source_labels(pol: Policy) -> None:
    lab = pol.source_label("tool.read_email")
    assert lab.integrity is Integrity.UNTRUSTED and lab.confidentiality is Confidentiality.SECRET
    assert lab.sources == {"tool.read_email"}


def test_unknown_source_fails_closed(pol: Policy) -> None:
    assert pol.source_label("tool.nope") == Label.unknown("tool.nope")


def test_allow_trusted(pol: Policy, reg: ToolRegistry) -> None:
    d = pol.decide("send_email", {"to": TRUSTED, "body": TRUSTED}, reg)
    assert d.verdict == "allow" and d.allowed and not d.violations


def test_block_untrusted_recipient(pol: Policy, reg: ToolRegistry) -> None:
    d = pol.decide("send_email", {"to": UNTRUSTED, "body": TRUSTED}, reg, {"to": ["from web"]})
    assert d.verdict == "block" and not d.allowed
    (v,) = d.violations
    assert v.arg == "to" and v.rule == "policy.sinks.send_email.args.to"
    text = d.explain()
    assert "BLOCK send_email" in text and "integrity untrusted < required trusted" in text
    assert "evidence: from web" in text
    js = d.to_json()
    assert js["violations"][0]["sources"] == ["tool.web_fetch"]


def test_block_secret_body(pol: Policy, reg: ToolRegistry) -> None:
    d = pol.decide("send_email", {"to": TRUSTED, "body": SECRET}, reg)
    assert [v.arg for v in d.violations] == ["body"]
    assert "confidentiality secret > allowed internal" in d.explain()


def test_unlisted_arg_of_declared_sink_is_unconstrained(pol: Policy, reg: ToolRegistry) -> None:
    d = pol.decide("send_email", {"to": TRUSTED, "body": TRUSTED, "subject": UNTRUSTED}, reg)
    assert d.allowed


def test_sink_on_violation_override(pol: Policy, reg: ToolRegistry) -> None:
    d = pol.decide("shell", {"cmd": UNTRUSTED}, reg)
    assert d.verdict == "log" and d.allowed
    assert d.violations[0].rule == "policy.sinks.shell.all_args"


def test_declared_empty_sink_allows(pol: Policy, reg: ToolRegistry) -> None:
    assert pol.decide("search", {"q": Label.unknown()}, reg).allowed


def test_undeclared_sink_requires_trusted(pol: Policy, reg: ToolRegistry) -> None:
    d = pol.decide("mystery", {"x": UNTRUSTED}, reg)
    assert d.verdict == "block"
    assert d.violations[0].rule.startswith("fail-closed")
    assert pol.decide("mystery", {"x": SECRET}, reg).allowed


def test_unknown_tool_blocks(pol: Policy, reg: ToolRegistry) -> None:
    d = pol.decide("rm_rf", {}, reg)
    assert d.verdict == "block" and d.reason == "unknown tool"


def test_missing_policy_blocks_everything(reg: ToolRegistry) -> None:
    d = Policy.deny().decide("search", {"q": TRUSTED}, reg)
    assert d.verdict == "block" and "deny-all" in d.reason


def test_tool_declared_requirements_combine(pol: Policy, reg: ToolRegistry) -> None:
    d = pol.decide("write_file", {"path": UNTRUSTED, "data": SECRET}, reg)
    rules = {v.arg: v.rule for v in d.violations}
    assert rules["path"] == "tool.write_file.sink.path + tool.write_file.all_args"
    assert rules["data"] == "tool.write_file.all_args"


def test_meet_policy_and_tool() -> None:
    pol = Policy.from_yaml("sinks: {write_file: {args: {data: {require_integrity: trusted}}}}")
    reg = ToolRegistry([write_file])
    d = pol.decide(
        "write_file",
        {"path": TRUSTED, "data": Label(Integrity.UNTRUSTED, Confidentiality.SECRET)},
        reg,
    )
    (v,) = d.violations
    assert len(v.failures) == 2


def test_ask_verdict_is_not_allowed() -> None:
    pol = Policy.from_yaml("on_violation: ask")
    d = pol.decide("mystery", {"x": UNTRUSTED}, ToolRegistry([mystery]))
    assert d.verdict == "ask" and not d.allowed
    r = d.resolved("block", "denied")
    assert r.verdict == "block" and "denied" in r.reason


@pytest.mark.parametrize(
    "text",
    [
        "sources: [1, 2]",
        "- a",
        "sources: {user: {integrity: sorta, confidentiality: public}}",
        "sinks: {x: {args: {a: {require_integrity: trusted, extra: 1}}}}",
        "on_violation: allow",
        "version: 2",
        "sources: {a: [",
    ],
)
def test_invalid_policies_rejected(text: str) -> None:
    with pytest.raises(PolicyError):
        Policy.from_yaml(text)


def test_empty_yaml_rejected() -> None:
    with pytest.raises(PolicyError):
        Policy.from_yaml("")


def test_load_example_policy() -> None:
    p = Policy.load(Path(__file__).parents[1] / "examples" / "inbox-assistant" / "policy.yaml")
    assert "send_email" in p.sinks
