from __future__ import annotations

import json
import shutil
import sys
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, ClassVar

import pytest

from sluice.agent import Agent
from sluice.labels import Confidentiality, Integrity, Label, reset_ids
from sluice.llm import MockLLM, call, say
from sluice.monitor import Monitor
from sluice.policy import Policy
from sluice.policy.opa import OpaCli, OpaError, OpaHttp, OpaPolicy
from sluice.tools import COMMS, SHELL, ToolRegistry, tool
from sluice.trace import TraceWriter
from sluice.trace.replay import replay

REGO = Path(__file__).parents[1] / "examples" / "policies" / "sluice.rego"

BASE = Policy.from_yaml(
    """
sources:
  user: {integrity: trusted, confidentiality: internal}
  model: {integrity: trusted, confidentiality: internal}
  tool.vault: {integrity: trusted, confidentiality: secret}
sinks:
  vault: {}
  send: {}
  sh: {}
"""
)


@tool(source="tool.vault")
def vault() -> str:
    return "the launch code is 0000-1111"


@tool(caps=[COMMS])
def send(to: str, body: str) -> str:
    return "sent"


@tool(caps=[SHELL])
def sh(cmd: str) -> str:
    return ""


REG = ToolRegistry([vault, send, sh])
SECRET = Label(Integrity.TRUSTED, Confidentiality.SECRET, frozenset({"tool.vault"}))
OK = Label(Integrity.TRUSTED, Confidentiality.INTERNAL, frozenset({"user"}))


class Canned:
    def __init__(self, result: Any = None, exc: Exception | None = None) -> None:
        self.result = result
        self.exc = exc
        self.inputs: list[dict[str, Any]] = []

    def query(self, input_doc: dict[str, Any]) -> Any:
        self.inputs.append(input_doc)
        if self.exc:
            raise self.exc
        return self.result

    def describe(self) -> str:
        return "canned"


def test_input_document_has_labels_not_values() -> None:
    t = Canned({"allow": True})
    OpaPolicy(BASE, t).decide("send", {"to": OK, "body": SECRET}, REG)
    doc = t.inputs[0]
    assert doc["tool"] == "send" and doc["caps"] == ["comms"]
    assert doc["args"]["body"] == {
        "integrity": "trusted",
        "confidentiality": "secret",
        "sources": ["tool.vault"],
    }
    assert "value" not in json.dumps(doc)


def test_opa_deny_overrides_yaml_allow() -> None:
    t = Canned({"allow": False, "reasons": [{"arg": "body", "msg": "no secrets out"}, "plain"]})
    d = OpaPolicy(BASE, t).decide("send", {"to": OK, "body": SECRET}, REG)
    assert d.verdict == "block" and "OPA policy denied" in d.reason
    assert [(v.arg, v.failures) for v in d.violations] == [
        ("body", ("no secrets out",)),
        ("*", ("plain",)),
    ]
    assert d.violations[0].label == SECRET


def test_stricter_verdict_wins() -> None:
    pol = Policy.from_yaml("sinks: {send: {args: {to: {require_integrity: trusted}}}}")
    bad = Label.unknown("web")
    logged = OpaPolicy(pol, Canned({"allow": False, "verdict": "log"})).decide(
        "send", {"to": bad}, REG
    )
    assert logged.verdict == "block"  # YAML blocks; OPA's softer "log" does not relax it
    asked = OpaPolicy(BASE, Canned({"allow": False, "verdict": "ask"})).decide(
        "send", {"to": OK}, REG
    )
    assert asked.verdict == "ask" and asked.violations[0].failures == ("denied by OPA policy",)
    assert OpaPolicy(BASE, Canned({"allow": True})).decide("send", {"to": OK}, REG).allowed


@pytest.mark.parametrize(
    "canned",
    [
        Canned(None),
        Canned("yes"),
        Canned({"allow": "true"}),
        Canned({"allow": False, "verdict": "allow"}),
        Canned({"allow": False, "verdict": "maybe"}),
        Canned(exc=OpaError("down")),
        Canned(exc=RuntimeError("bug in transport")),
    ],
)
def test_fail_closed(canned: Canned) -> None:
    d = OpaPolicy(BASE, canned).decide("send", {"to": OK}, REG)
    assert d.verdict == "block" and "fail closed" in d.reason


def test_monitor_trace_and_replay_with_opa() -> None:
    reset_ids()

    class DenySend(Canned):
        def query(self, input_doc: dict[str, Any]) -> Any:
            if input_doc["tool"] != "send":
                return {"allow": True}
            return {"allow": False, "reasons": [{"arg": "body", "msg": "no secrets out"}]}

    trace = TraceWriter()
    mon = Monitor(OpaPolicy(BASE, DenySend()), REG, trace=trace)
    llm = MockLLM(
        [
            call("vault"),
            call("send", to="bob@corp.example", body="the launch code is 0000-1111"),
            say(""),
        ]
    )
    res = Agent(llm, REG, mon).run("email bob@corp.example")
    (blocked,) = res.blocked
    assert blocked.tool == "send" and blocked.violations[0].arg == "body"
    assert trace.events[0]["policy"]["x-opa"] == "canned"
    # Offline replay uses the YAML part (OPA is not consulted offline).
    assert replay(trace.events).policy == BASE


# ---- HTTP transport -------------------------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    response: ClassVar[bytes] = b"{}"
    seen: ClassVar[list[tuple[str, dict[str, Any]]]] = []

    def do_POST(self) -> None:
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).seen.append((self.path, body))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(type(self).response)

    def log_message(self, *args: Any) -> None:
        pass


@pytest.fixture
def opa_server() -> Iterator[str]:
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_http_transport(opa_server: str) -> None:
    _Handler.response = json.dumps({"result": {"allow": False, "reasons": ["nope"]}}).encode()
    _Handler.seen = []
    t = OpaHttp(opa_server + "/", "sluice/decision")
    d = OpaPolicy(BASE, t).decide("send", {"to": OK}, REG)
    assert d.verdict == "block" and _Handler.seen[0][0] == "/v1/data/sluice/decision"
    assert _Handler.seen[0][1]["input"]["tool"] == "send"
    _Handler.response = b"{}"  # undefined decision
    assert "undefined" in OpaPolicy(BASE, t).decide("send", {"to": OK}, REG).reason
    assert "data.sluice.decision" in t.describe()


def test_http_transport_errors() -> None:
    with pytest.raises(ValueError, match="http"):
        OpaHttp("file:///etc/passwd")
    with pytest.raises(OpaError, match="query failed"):
        OpaHttp("http://127.0.0.1:1", timeout=0.5).query({})


# ---- CLI transport (fake binary) ------------------------------------------------------------

FAKE_OPA = """
import json, sys
mode = sys.argv[1]
doc = json.loads(sys.stdin.read())
if mode == "fail":
    sys.stderr.write("rego_parse_error"); sys.exit(1)
if mode == "garbage":
    print("not json"); sys.exit(0)
if mode == "undefined":
    print(json.dumps({})); sys.exit(0)
if mode == "shape":
    print(json.dumps({"result": [{}]})); sys.exit(0)
assert sys.argv[2:6] == ["eval", "--format", "json", "--stdin-input"], sys.argv
value = {"allow": doc["tool"] != "sh", "reasons": ["argv ok"]}
print(json.dumps({"result": [{"expressions": [{"value": value}]}]}))
"""


@pytest.fixture
def fake_opa(tmp_path: Path) -> Path:
    p = tmp_path / "fake_opa.py"
    p.write_text(FAKE_OPA, encoding="utf-8")
    return p


def cli(fake: Path, mode: str) -> OpaCli:
    return OpaCli(("policy.rego",), command=(sys.executable, str(fake), mode))


def test_cli_transport(fake_opa: Path) -> None:
    pol = OpaPolicy(BASE, cli(fake_opa, "ok"))
    assert pol.decide("send", {"to": OK}, REG).allowed
    d = pol.decide("sh", {"cmd": OK}, REG)
    assert d.verdict == "block" and d.violations[0].failures == ("argv ok",)
    assert "policy.rego" in cli(fake_opa, "ok").describe()


@pytest.mark.parametrize(
    ("mode", "msg"),
    [
        ("fail", "exited 1"),
        ("garbage", "invalid JSON"),
        ("undefined", "undefined"),
        ("shape", "shape"),
    ],
)
def test_cli_transport_failures(fake_opa: Path, mode: str, msg: str) -> None:
    d = OpaPolicy(BASE, cli(fake_opa, mode)).decide("send", {"to": OK}, REG)
    assert d.verdict == "block" and msg in d.reason


def test_cli_missing_binary() -> None:
    t = OpaCli(("p.rego",), command=("definitely-not-opa-binary",))
    with pytest.raises(OpaError, match="opa eval failed"):
        t.query({})


# ---- real OPA against the example Rego (CI installs opa) ------------------------------------


@pytest.mark.skipif(shutil.which("opa") is None, reason="opa binary not installed")
def test_example_rego_with_real_opa() -> None:
    pol = OpaPolicy(BASE, OpaCli((str(REGO),)))
    assert pol.decide("send", {"to": OK, "body": OK}, REG).allowed
    secret_out = pol.decide("send", {"to": OK, "body": SECRET}, REG)
    assert secret_out.verdict == "block"
    assert any("secret data may not leave via send" in v.failures[0] for v in secret_out.violations)
    web = Label(Integrity.UNTRUSTED, Confidentiality.PUBLIC, frozenset({"tool.web_fetch"}))
    shell = pol.decide("sh", {"cmd": web}, REG)
    assert any("shell" in v.failures[0] for v in shell.violations)
    dest = pol.decide("send", {"to": web, "body": OK}, REG)
    assert any("destination" in v.failures[0] for v in dest.violations)
