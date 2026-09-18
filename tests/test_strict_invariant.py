"""Property tests for strict mode's core guarantee.

Whatever plan the (untrusted-content-free) planner emits:

1. no data from an untrusted source reaches a sink argument that requires trusted integrity
   or bounds confidentiality below secret (checked on the raw values the sink receives), and
2. untrusted data cannot change which sink calls execute: across two untrusted "worlds", the
   executed sink calls of one run are a prefix of the other's (they may only differ by one run
   stopping earlier - the termination channel documented in docs/strict-mode.md).
"""

from __future__ import annotations

from typing import Any

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydantic import BaseModel

from sluice.labels import reset_ids
from sluice.policy import Policy
from sluice.strict.dsl import PlanSyntaxError, parse_plan
from sluice.strict.interpreter import Interpreter
from sluice.tools import COMMS, NET_IN, ToolRegistry, tool

MARK = "UNTRUSTED-MARK"

POLICY = Policy.from_yaml(
    """
sources:
  tool.fetch: {integrity: untrusted, confidentiality: secret}
  tool.contacts: {integrity: trusted, confidentiality: internal}
sinks:
  fetch: {}
  contacts: {}
  sink:
    args:
      to: {require_integrity: trusted}
      body: {max_confidentiality: internal}
"""
)

WORLDS: list[list[dict[str, Any]]] = [
    [{"to": f"{MARK}-a@evil.example", "body": f"{MARK} send it", "n": 1}],
    [
        {"to": f"{MARK}-b@evil.example", "body": f"{MARK} other", "n": 7},
        {"to": f"{MARK}-c@evil.example", "body": "", "n": 0},
        {"to": "boss@corp.example", "body": f"{MARK}", "n": 2},
    ],
]


class Echo(BaseModel):
    text: str


def make(world: list[dict[str, Any]]) -> tuple[ToolRegistry, list[dict[str, Any]]]:
    received: list[dict[str, Any]] = []

    @tool(caps=[NET_IN])
    def fetch() -> list[dict[str, Any]]:
        return [dict(x) for x in world]

    @tool()
    def contacts() -> list[str]:
        return ["alice@corp.example", "bob@corp.example"]

    @tool(caps=[COMMS])
    def sink(to: Any = "", body: Any = "") -> str:
        received.append({"to": to, "body": body})
        return "ok"

    return ToolRegistry([fetch, contacts, sink]), received


def quarantine(text: str, schema: type[BaseModel]) -> BaseModel:
    return Echo(text=text)


# ---- plan generator ---------------------------------------------------------------------------

VARS = ["a", "b", "c"]
CONSTS = ['"alice@corp.example"', '"hello"', "0", "1", '"x"', "True"]


@st.composite
def exprs(draw: st.DrawFn, depth: int = 0) -> str:
    leaves = [
        st.sampled_from(CONSTS),
        st.sampled_from(VARS),
        st.just("fetch()"),
        st.just("contacts()"),
    ]
    if depth >= 2:
        return draw(st.one_of(leaves))
    sub = exprs(depth + 1)
    # Half leaves, half compound: keeps most plans type-correct so they reach the sink.
    return draw(
        st.one_of(
            st.one_of(*leaves),
            st.one_of(
                *_compound(sub),
            ),
        )
    )


def _compound(sub: st.SearchStrategy[str]) -> list[st.SearchStrategy[str]]:
    return [
        st.builds(lambda x: f"({x})[0]", sub),
        st.builds(lambda x: f"({x})[1]", sub),
        st.builds(lambda x: f"({x}).to", sub),
        st.builds(lambda x: f"({x}).body", sub),
        st.builds(lambda x: f"({x}).text", sub),
        st.builds(lambda x, y: f'f"{{{x}}}{{{y}}}"', sub, sub),
        st.builds(lambda x, y: f"({x} + {y})", sub, sub),
        st.builds(lambda x, y: f"contains({x}, {y})", sub, sub),
        st.builds(lambda x: f"len({x})", sub),
        st.builds(lambda x: f"str({x})", sub),
        st.builds(lambda x: f'quarantine(str({x}), "Echo")', sub),
        st.builds(lambda c, x, y: f"({x} if {c} else {y})", sub, sub, sub),
        st.builds(lambda x, y: f"({x} and {y})", sub, sub),
        st.builds(lambda x, y: f"({x} or {y})", sub, sub),
        st.builds(lambda x, y: f"({x} == {y})", sub, sub),
        st.builds(lambda x: f"(not {x})", sub),
        st.builds(lambda x, y: f"[{x}, {y}]", sub, sub),
    ]


@st.composite
def stmts(draw: st.DrawFn, indent: int = 0, depth: int = 0) -> list[str]:
    pad = "    " * indent
    out: list[str] = []
    for _ in range(draw(st.integers(1, 4))):
        kind = draw(
            st.sampled_from(
                ["assign", "sink", "sink", "sink", "if", "for"]
                if depth < 2
                else ["assign", "sink", "sink"]
            )
        )
        if kind == "assign":
            out.append(f"{pad}{draw(st.sampled_from(VARS))} = {draw(exprs())}")
        elif kind == "sink":
            out.append(f"{pad}sink(to={draw(exprs())}, body={draw(exprs())})")
        elif kind == "if":
            out.append(f"{pad}if {draw(exprs())}:")
            out += draw(stmts(indent + 1, depth + 1))
            if draw(st.booleans()):
                out.append(f"{pad}else:")
                out += draw(stmts(indent + 1, depth + 1))
        else:
            out.append(f"{pad}for {draw(st.sampled_from(VARS))} in {draw(exprs())}:")
            out += draw(stmts(indent + 1, depth + 1))
    return out


PRELUDE = 'a = "alice@corp.example"\nb = "hello"\nc = 0\n'


def run(src: str, world: list[dict[str, Any]]) -> list[dict[str, Any]]:
    reset_ids()
    reg, received = make(world)
    interp = Interpreter(POLICY, reg, quarantine=quarantine, schemas={"Echo": Echo})
    interp.run(parse_plan(src, interp.callables))
    return received


def _contains_mark(v: Any) -> bool:
    return MARK in repr(v)


@settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(stmts())
def test_no_untrusted_data_reaches_guarded_sink_args(lines: list[str]) -> None:
    src = PRELUDE + "\n".join(lines) + "\n"
    try:
        parse_plan(src, ["fetch", "contacts", "sink", "quarantine", "len", "str", "contains"])
    except PlanSyntaxError:
        return
    runs = [run(src, w) for w in WORLDS]
    for received in runs:
        for call in received:
            assert not _contains_mark(call["to"]), (src, call)
            assert not _contains_mark(call["body"]), (src, call)
    a, b = runs
    shorter, longer = sorted((a, b), key=len)
    assert longer[: len(shorter)] == shorter, (src, a, b)


def test_generator_reaches_the_sink() -> None:
    """Sanity check that the property is not vacuous: some generated plans do call the sink."""
    src = (
        PRELUDE
        + 'sink(to=a, body=b)\nx = fetch()\nsink(to="bob@corp.example", body=len(contacts()))\n'
    )
    assert run(src, WORLDS[0]) == [
        {"to": "alice@corp.example", "body": "hello"},
        {"to": "bob@corp.example", "body": 2},
    ]


def test_same_plans_leak_without_enforcement() -> None:
    """The property has power: with sinks unconstrained, these plans do leak / diverge."""
    lax = Policy.from_yaml(
        "sources: {tool.fetch: {integrity: untrusted, confidentiality: secret}}\n"
        "sinks: {fetch: {}, contacts: {}, sink: {}}"
    )

    def run_with(src: str, world: list[dict[str, Any]], policy: Policy) -> list[dict[str, Any]]:
        reset_ids()
        reg, received = make(world)
        interp = Interpreter(policy, reg, quarantine=quarantine, schemas={"Echo": Echo})
        interp.run(parse_plan(src, interp.callables))
        return received

    direct = 'x = fetch()\nsink(to=(x[0]).to, body="hi")\n'
    implicit = 'x = fetch()\nif len(x) > 1:\n    sink(to="alice@corp.example", body="hi")\n'
    assert _contains_mark(run_with(direct, WORLDS[0], lax))
    assert run_with(direct, WORLDS[0], POLICY) == []
    assert run_with(implicit, WORLDS[0], lax) != run_with(implicit, WORLDS[1], lax)
    assert run_with(implicit, WORLDS[0], POLICY) == run_with(implicit, WORLDS[1], POLICY) == []
