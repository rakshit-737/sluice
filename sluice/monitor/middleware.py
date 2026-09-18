"""Monitor-mode middleware: labels context, attributes tool-call args, enforces policy."""

from __future__ import annotations

import itertools
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sluice.labels.label import Label, ValueId, join_all
from sluice.labels.value import LabeledValue
from sluice.llm import ToolCall
from sluice.monitor.attribution import Attribution, Attributor, Match, as_text
from sluice.policy.compiler import Policy
from sluice.policy.decision import Decision
from sluice.tools.registry import ToolRegistry
from sluice.trace.writer import TraceWriter

AskHandler = Callable[[Decision], bool]

MODEL_SOURCE = "model"
REF_KEY = "$ref"


@dataclass(frozen=True)
class CheckedCall:
    call_id: str
    call: ToolCall
    decision: Decision
    args: dict[str, Any]  # $refs resolved to raw values
    arg_label: Label  # join of all argument labels


class Monitor:
    def __init__(
        self,
        policy: Policy | None,
        registry: ToolRegistry,
        *,
        attributor: Attributor | None = None,
        trace: TraceWriter | None = None,
        ask: AskHandler | None = None,
    ) -> None:
        self.policy = policy or Policy.deny()
        self.registry = registry
        self.attributor = attributor or Attributor()
        self.trace = trace or TraceWriter()
        self.ask = ask
        self.store: dict[ValueId, LabeledValue[Any]] = {}
        self.context: list[LabeledValue[Any]] = []
        self.decisions: list[Decision] = []
        self._calls = itertools.count(1)

    # ---- sources --------------------------------------------------------------------------

    def _add(
        self,
        value: Any,
        label: Label,
        origin: str,
        *,
        parents: list[str] | None = None,
        call_id: str = "",
        attributable: bool = True,
    ) -> LabeledValue[Any]:
        lv: LabeledValue[Any] = LabeledValue(value, label, origin=origin)
        self.store[lv.id] = lv
        if attributable:
            self.context.append(lv)
        self.trace.emit(
            "value",
            id=lv.id,
            origin=origin,
            label=label.short(),
            integrity=label.integrity.name.lower(),
            confidentiality=label.confidentiality.name.lower(),
            sources=sorted(label.sources),
            provenance=sorted(label.provenance),
            parents=parents or [],
            call=call_id,
            preview=as_text(value)[:200],
        )
        return lv

    def observe(self, text: str, source: str, origin: str | None = None) -> LabeledValue[str]:
        """Record content entering the context from ``source`` (e.g. ``user``)."""
        return self._add(text, self.policy.source_label(source), origin or source)

    def record_output(self, checked: CheckedCall, output: Any) -> LabeledValue[Any]:
        """Label a tool's output: its source class joined with its arguments' labels
        (a tool's output depends on its inputs). Structured outputs get per-leaf labels."""
        spec = self.registry.get(checked.call.name)
        assert spec is not None
        base = self.policy.source_label(spec.source).join(checked.arg_label)
        leaves = _leaf_paths(output)
        structured = not (len(leaves) == 1 and leaves[0][0] == "")
        root = self._add(
            output,
            base,
            f"{spec.name}()",
            call_id=checked.call_id,
            attributable=not structured,
        )
        if structured:
            for path, (key, leaf) in leaves:
                src = spec.fields.get(key, spec.source) if key else spec.source
                lab = self.policy.source_label(src).join(checked.arg_label).with_provenance(root.id)
                self._add(leaf, lab, f"{spec.name}(){path}", parents=[root.id])
        return root

    # ---- sinks ----------------------------------------------------------------------------

    def check(self, call: ToolCall) -> CheckedCall:
        call_id = f"c{next(self._calls)}"
        fallback = self.policy.source_label(MODEL_SOURCE)
        args: dict[str, Any] = {}
        labels: dict[str, Label] = {}
        attrib: dict[str, Attribution] = {}
        for name, raw in call.arguments.items():
            a, resolved = self._attribute(raw, fallback)
            args[name] = resolved
            labels[name] = a.label
            attrib[name] = a
        evidence = {
            k: [self._describe(m) for m in a.matches] or ["model-generated"]
            for k, a in attrib.items()
        }
        decision = self.policy.decide(call.name, labels, self.registry, evidence)
        decision = self._resolve(decision)
        self.decisions.append(decision)
        self.trace.emit(
            "call",
            id=call_id,
            tool=call.name,
            args=args,
            attribution={
                k: {
                    "label": a.label.short(),
                    "sources": sorted(a.label.sources),
                    "matches": a.value_ids,
                    "generated": a.generated,
                    "evidence": evidence[k],
                }
                for k, a in attrib.items()
            },
            decision=decision.to_json(),
            explanation=decision.explain(),
        )
        return CheckedCall(call_id, call, decision, args, join_all(labels.values()))

    def _attribute(self, raw: Any, fallback: Label) -> tuple[Attribution, Any]:
        ref = _ref(raw)
        if ref is not None:
            lv = self.store.get(ValueId(ref))
            if lv is None:
                # Dangling reference: unknown origin, fail closed.
                return Attribution(Label.unknown(f"ref:{ref}"), (), False), None
            lab = lv.label.with_provenance(lv.id)
            return Attribution(lab, (Match(lv.id, "ref", 1.0),), False), lv.value
        return self.attributor.attribute(raw, self.context, fallback), raw

    def _describe(self, m: Match) -> str:
        lv = self.store.get(m.value_id)
        return m.describe(f"{lv.origin}, {lv.label}" if lv else "")

    def _resolve(self, d: Decision) -> Decision:
        if d.verdict != "ask":
            return d
        if self.ask is None:
            return d.resolved("block", "ask: no interactive approver, fail closed")
        approved = self.ask(d)
        return d.resolved(
            "allow" if approved else "block", f"ask: user {'approved' if approved else 'denied'}"
        )


def _ref(raw: Any) -> str | None:
    if isinstance(raw, dict) and set(raw) == {REF_KEY} and isinstance(raw[REF_KEY], str):
        return str(raw[REF_KEY])
    return None


def _leaf_paths(value: Any, path: str = "", key: str = "") -> list[tuple[str, tuple[str, Any]]]:
    if isinstance(value, dict):
        return [x for k, v in value.items() for x in _leaf_paths(v, f"{path}.{k}", str(k))]
    if isinstance(value, list | tuple):
        return [x for i, v in enumerate(value) for x in _leaf_paths(v, f"{path}[{i}]", key)]
    return [(path, (key, value))]


def render_output(lv: LabeledValue[Any]) -> str:
    """Text shown to the model for a tool result; the id lets it pass values by $ref."""
    body = lv.value if isinstance(lv.value, str) else json.dumps(lv.value, default=str)
    return f"[{lv.id}] {body}"
