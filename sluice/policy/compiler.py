"""Compile a PolicyFile into a callable policy. Fails closed everywhere."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from sluice.labels.label import Confidentiality, Integrity, Label
from sluice.labels.requirement import Requirement
from sluice.policy.decision import Decision, Verdict, Violation
from sluice.policy.model import Action, ArgSpec, PolicyFile
from sluice.tools.registry import ToolRegistry, ToolSpec


class PolicyError(ValueError):
    pass


def _req(spec: ArgSpec | None) -> Requirement | None:
    if spec is None:
        return None
    return Requirement(
        Integrity.parse(spec.require_integrity) if spec.require_integrity else None,
        Confidentiality.parse(spec.max_confidentiality) if spec.max_confidentiality else None,
    )


@dataclass(frozen=True)
class CompiledSink:
    args: Mapping[str, Requirement]
    all_args: Requirement | None
    on_violation: Action | None


@dataclass(frozen=True)
class Policy:
    sources: Mapping[str, Label] = field(default_factory=dict)
    sinks: Mapping[str, CompiledSink] = field(default_factory=dict)
    on_violation: Action = "block"
    deny_all: bool = False

    # ---- construction -------------------------------------------------------------------

    @staticmethod
    def compile(pf: PolicyFile) -> Policy:
        sources = {
            name: Label(
                Integrity.parse(s.integrity),
                Confidentiality.parse(s.confidentiality),
                frozenset({name}),
            )
            for name, s in pf.sources.items()
        }
        sinks: dict[str, CompiledSink] = {}
        for name, s in pf.sinks.items():
            args: dict[str, Requirement] = {}
            for arg, a in s.args.items():
                r = _req(a)
                assert r is not None
                args[arg] = r
            sinks[name] = CompiledSink(args, _req(s.all_args), s.on_violation)
        return Policy(sources, sinks, pf.on_violation)

    @staticmethod
    def from_yaml(text: str) -> Policy:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as e:
            raise PolicyError(f"invalid YAML: {e}") from e
        if not isinstance(data, dict):
            raise PolicyError("policy must be a YAML mapping")
        try:
            return Policy.compile(PolicyFile.model_validate(data))
        except ValueError as e:
            raise PolicyError(str(e)) from e

    @staticmethod
    def load(path: str | Path) -> Policy:
        return Policy.from_yaml(Path(path).read_text(encoding="utf-8"))

    @staticmethod
    def deny() -> Policy:
        """The policy used when none is configured: every tool call is blocked."""
        return Policy(deny_all=True)

    def to_dict(self) -> dict[str, Any]:
        """Policy-file form of this policy (``Policy.from_dict`` inverts it)."""
        if self.deny_all:
            return {"deny_all": True}
        sinks: dict[str, Any] = {}
        for name, sink in self.sinks.items():
            d: dict[str, Any] = {"args": {a: r.to_dict() for a, r in sink.args.items()}}
            if sink.all_args is not None:
                d["all_args"] = sink.all_args.to_dict()
            if sink.on_violation is not None:
                d["on_violation"] = sink.on_violation
            sinks[name] = d
        return {
            "version": 1,
            "sources": {
                n: {
                    "integrity": lab.integrity.name.lower(),
                    "confidentiality": lab.confidentiality.name.lower(),
                }
                for n, lab in self.sources.items()
            },
            "sinks": sinks,
            "on_violation": self.on_violation,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> Policy:
        if data.get("deny_all"):
            return Policy.deny()
        # "x-" keys are annotations from wrapping engines (e.g. "x-opa"), not policy fields.
        core = {k: v for k, v in data.items() if not k.startswith("x-")}
        return Policy.compile(PolicyFile.model_validate(core))

    # ---- queries --------------------------------------------------------------------------

    def source_label(self, source: str) -> Label:
        """Label for data from ``source``. Unknown sources get the fail-closed label."""
        return self.sources.get(source) or Label.unknown(source)

    def requirements(
        self, spec: ToolSpec, arg_names: Sequence[str]
    ) -> dict[str, tuple[Requirement, str]]:
        """Per-argument requirement and the rule it came from."""
        sink = self.sinks.get(spec.name)
        declared = sink is not None or bool(spec.sink) or spec.all_args is not None
        out: dict[str, tuple[Requirement, str]] = {}
        for arg in arg_names:
            if not declared:
                out[arg] = (
                    Requirement.trusted(),
                    f"fail-closed: `{spec.name}` is not a declared sink",
                )
                continue
            req = Requirement()
            rules: list[str] = []
            if sink is not None and arg in sink.args:
                req = req.meet(sink.args[arg])
                rules.append(f"policy.sinks.{spec.name}.args.{arg}")
            if sink is not None and sink.all_args is not None:
                req = req.meet(sink.all_args)
                rules.append(f"policy.sinks.{spec.name}.all_args")
            if arg in spec.sink:
                req = req.meet(spec.sink[arg])
                rules.append(f"tool.{spec.name}.sink.{arg}")
            if spec.all_args is not None:
                req = req.meet(spec.all_args)
                rules.append(f"tool.{spec.name}.all_args")
            out[arg] = (req, " + ".join(rules) or "unconstrained")
        return out

    def decide(
        self,
        tool_name: str,
        arg_labels: Mapping[str, Label],
        registry: ToolRegistry,
        evidence: Mapping[str, Sequence[str]] | None = None,
    ) -> Decision:
        labels = dict(arg_labels)
        if self.deny_all:
            return Decision(
                tool_name, "block", reason="no policy configured (deny-all)", arg_labels=labels
            )
        spec = registry.get(tool_name)
        if spec is None:
            return Decision(tool_name, "block", reason="unknown tool", arg_labels=labels)
        evidence = evidence or {}
        violations: list[Violation] = []
        for arg, (req, rule) in self.requirements(spec, list(labels)).items():
            fails = req.failures(labels[arg])
            if fails:
                violations.append(
                    Violation(
                        arg, labels[arg], req, rule, tuple(fails), tuple(evidence.get(arg, ()))
                    )
                )
        if not violations:
            return Decision(tool_name, "allow", arg_labels=labels)
        sink = self.sinks.get(tool_name)
        verdict: Verdict = (
            sink.on_violation if sink and sink.on_violation else None
        ) or self.on_violation
        return Decision(tool_name, verdict, tuple(violations), "policy violation", labels)
