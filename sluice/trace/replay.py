"""Offline replay of a JSONL trace.

A trace is self-contained: its ``session`` event carries the policy and the tool manifest,
and each ``call`` event carries every argument's label. Replay rebuilds the provenance graph
and re-decides every call, either under the recorded policy (a consistency check) or under a
different one ("would this new policy have blocked last week's incident?").
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from sluice.graph.provenance import ProvenanceGraph
from sluice.labels.label import Confidentiality, Integrity, Label, ValueId
from sluice.policy.compiler import Policy
from sluice.policy.decision import Decision
from sluice.tools.registry import ToolRegistry, spec_from_dict


class ReplayError(ValueError):
    pass


@dataclass(frozen=True)
class ReplayedCall:
    id: str
    tool: str
    original: str  # recorded verdict
    decision: Decision  # verdict under the replay policy

    @property
    def changed(self) -> bool:
        return self.original != self.decision.verdict


@dataclass
class Replay:
    policy: Policy
    registry: ToolRegistry
    calls: list[ReplayedCall] = field(default_factory=list)
    graph: ProvenanceGraph = field(default_factory=ProvenanceGraph)

    @property
    def changed(self) -> list[ReplayedCall]:
        return [c for c in self.calls if c.changed]


def parse_label(info: dict[str, Any]) -> Label:
    """Rebuild an argument label from its trace attribution record."""
    try:
        integ, conf = str(info["label"]).split("/")
        return Label(
            Integrity.parse(integ),
            Confidentiality.parse(conf),
            frozenset(info.get("sources", [])),
            frozenset(ValueId(v) for v in info.get("matches", [])),
        )
    except (KeyError, ValueError) as e:
        raise ReplayError(f"malformed attribution record: {info!r}") from e


def replay(events: Iterable[dict[str, Any]], policy: Policy | None = None) -> Replay:
    evs = list(events)
    session = next((e for e in evs if e.get("type") == "session"), None)
    if session is None:
        raise ReplayError("trace has no session event (recorded by an older sluice?)")
    registry = ToolRegistry(spec_from_dict(t) for t in session.get("tools", []))
    pol = policy or Policy.from_dict(session.get("policy") or {"deny_all": True})
    out = Replay(pol, registry, graph=ProvenanceGraph.from_events(evs))
    for ev in evs:
        if ev.get("type") != "call":
            continue
        original = ev.get("decision", {}).get("verdict", "")
        if ev.get("parse_error"):
            d = Decision(ev["tool"], "block", reason=f"unparseable arguments: {ev['parse_error']}")
        else:
            attribution = ev.get("attribution", {})
            labels = {arg: parse_label(info) for arg, info in attribution.items()}
            evidence = {arg: info.get("evidence", []) for arg, info in attribution.items()}
            d = pol.decide(ev["tool"], labels, registry, evidence)
        out.calls.append(ReplayedCall(ev["id"], ev["tool"], original, d))
    return out
