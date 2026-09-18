"""Policy decisions and their explanations."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from sluice.labels.label import Label
from sluice.labels.requirement import Requirement
from sluice.policy.frameworks import Tag, tags_for

Verdict = Literal["allow", "block", "ask", "log"]


@dataclass(frozen=True)
class Violation:
    arg: str
    label: Label
    requirement: Requirement
    rule: str  # where the requirement came from, e.g. "policy.sinks.send_email.args.to"
    failures: tuple[str, ...]
    evidence: tuple[str, ...] = ()  # how the arg's label was derived

    @property
    def tags(self) -> tuple[Tag, ...]:
        return tags_for(self.label, self.requirement)

    def explain(self) -> str:
        why = "; ".join(self.failures)
        srcs = ", ".join(sorted(self.label.sources)) or "-"
        lines = [f"argument `{self.arg}` is {self.label.short()} (from {srcs}): {why}"]
        lines.append(f"  rule: {self.rule} ({self.requirement.describe()})")
        lines.extend(f"  evidence: {e}" for e in self.evidence)
        if self.tags:
            lines.append(f"  maps to: {'; '.join(str(t) for t in self.tags)}")
        return "\n".join(lines)


@dataclass(frozen=True)
class Decision:
    tool: str
    verdict: Verdict
    violations: tuple[Violation, ...] = ()
    reason: str = ""
    arg_labels: dict[str, Label] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        """Whether the call may execute. ``ask`` must be resolved before this is consulted."""
        return self.verdict in ("allow", "log")

    def resolved(self, verdict: Verdict, note: str) -> Decision:
        return Decision(
            self.tool,
            verdict,
            self.violations,
            f"{self.reason} [{note}]".strip(),
            self.arg_labels,
        )

    def explain(self) -> str:
        head = f"{self.verdict.upper()} {self.tool}"
        if self.reason:
            head += f": {self.reason}"
        return "\n".join([head, *(v.explain() for v in self.violations)])

    def to_json(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "verdict": self.verdict,
            "reason": self.reason,
            "violations": [
                {
                    "arg": v.arg,
                    "label": v.label.short(),
                    "sources": sorted(v.label.sources),
                    "provenance": sorted(v.label.provenance),
                    "requirement": v.requirement.describe(),
                    "rule": v.rule,
                    "failures": list(v.failures),
                    "evidence": list(v.evidence),
                    "tags": [
                        {"framework": t.framework, "id": t.id, "name": t.name} for t in v.tags
                    ],
                }
                for v in self.violations
            ],
        }
