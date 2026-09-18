"""Static "lethal trifecta" analysis of a tool registry under a policy.

An agent is exposed when it has all three of: access to private data, exposure to untrusted
content, and a channel to the outside world (Willison, 2025). This module reports which
tools supply each leg and, for every exfiltration channel, which policy rules guard each of
its arguments.

Classification uses both capability tags and the policy's source labels, so a tool with an
undeclared source class counts as private *and* untrusted (fail-closed label).

An exfiltration argument is **guarded** if the effective rule blocks untrusted data
(``require_integrity: trusted``: the attacker cannot steer it) or blocks secret data
(``max_confidentiality`` below secret: private data cannot leave through it), and the sink's
verdict actually blocks (``log`` does not). A channel is covered when every argument is guarded.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from sluice.labels.label import Confidentiality, Integrity
from sluice.labels.requirement import Requirement
from sluice.policy.compiler import Policy
from sluice.tools.registry import (
    COMMS,
    FS_READ,
    NET_IN,
    NET_OUT,
    SECRETS,
    SHELL,
    ToolRegistry,
    ToolSpec,
)

PRIVATE_CAPS = frozenset({FS_READ, SECRETS, SHELL})
UNTRUSTED_CAPS = frozenset({NET_IN, SHELL})
EXFIL_CAPS = frozenset({NET_OUT, COMMS, SHELL})

Status = Literal["covered", "partial", "uncovered"]


@dataclass(frozen=True)
class ArgCoverage:
    arg: str
    requirement: Requirement
    rule: str
    blocks_untrusted: bool
    blocks_secret: bool
    enforced: bool

    @property
    def guarded(self) -> bool:
        return self.enforced and (self.blocks_untrusted or self.blocks_secret)


@dataclass(frozen=True)
class ExfilPath:
    tool: str
    reasons: tuple[str, ...]
    args: tuple[ArgCoverage, ...]
    verdict: str

    @property
    def status(self) -> Status:
        guarded = [a.guarded for a in self.args]
        if all(guarded):
            return "covered"
        return "partial" if any(guarded) else "uncovered"


@dataclass
class TrifectaReport:
    private: dict[str, list[str]] = field(default_factory=dict)  # tool -> reasons
    untrusted: dict[str, list[str]] = field(default_factory=dict)
    exfil: dict[str, list[str]] = field(default_factory=dict)
    paths: list[ExfilPath] = field(default_factory=list)
    unclassified: list[str] = field(default_factory=list)

    @property
    def present(self) -> bool:
        return bool(self.private and self.untrusted and self.exfil)

    @property
    def exposed(self) -> list[ExfilPath]:
        return [p for p in self.paths if p.status != "covered"]


def _sources(spec: ToolSpec) -> set[str]:
    return {spec.source, *spec.fields.values()}


def analyze(registry: ToolRegistry, policy: Policy) -> TrifectaReport:
    report = TrifectaReport()
    for spec in registry:
        labels = [(s, policy.source_label(s)) for s in sorted(_sources(spec))]
        private = [f"cap:{c}" for c in sorted(spec.caps & PRIVATE_CAPS)]
        private += [
            f"source:{s} is secret"
            for s, lab in labels
            if lab.confidentiality is Confidentiality.SECRET
        ]
        untrusted = [f"cap:{c}" for c in sorted(spec.caps & UNTRUSTED_CAPS)]
        untrusted += [
            f"source:{s} is untrusted" for s, lab in labels if lab.integrity is Integrity.UNTRUSTED
        ]
        exfil = [f"cap:{c}" for c in sorted(spec.caps & EXFIL_CAPS)]
        if private:
            report.private[spec.name] = private
        if untrusted:
            report.untrusted[spec.name] = untrusted
        if exfil:
            report.exfil[spec.name] = exfil
            report.paths.append(_path(spec, policy, exfil))
        if not spec.caps:
            report.unclassified.append(spec.name)
    return report


def _path(spec: ToolSpec, policy: Policy, reasons: list[str]) -> ExfilPath:
    if policy.deny_all:
        verdict = "block"
    else:
        sink = policy.sinks.get(spec.name)
        verdict = (sink.on_violation if sink and sink.on_violation else None) or policy.on_violation
    enforced = verdict != "log"
    args = []
    for arg, (req, rule) in policy.requirements(spec, list(spec.params)).items():
        conf = req.max_confidentiality
        args.append(
            ArgCoverage(
                arg,
                req,
                "deny-all policy" if policy.deny_all else rule,
                policy.deny_all or req.require_integrity is Integrity.TRUSTED,
                policy.deny_all or (conf is not None and conf < Confidentiality.SECRET),
                enforced,
            )
        )
    return ExfilPath(spec.name, tuple(reasons), tuple(args), verdict)
