"""Threat-framework tags for policy violations.

Each violation is tagged with the OWASP Top 10 for LLM Applications (2025) risks and MITRE
ATLAS techniques it corresponds to, so blocks can be triaged and reported in the vocabulary
security teams already use. See docs/frameworks.md.
"""

from __future__ import annotations

from dataclasses import dataclass

from sluice.labels.label import Label
from sluice.labels.requirement import Requirement


@dataclass(frozen=True)
class Tag:
    framework: str  # "OWASP-LLM" | "MITRE-ATLAS"
    id: str
    name: str

    def __str__(self) -> str:
        return f"{self.id} {self.name}"


LLM01 = Tag("OWASP-LLM", "LLM01:2025", "Prompt Injection")
LLM02 = Tag("OWASP-LLM", "LLM02:2025", "Sensitive Information Disclosure")
LLM06 = Tag("OWASP-LLM", "LLM06:2025", "Excessive Agency")
ATLAS_INDIRECT_INJECTION = Tag("MITRE-ATLAS", "AML.T0051.001", "LLM Prompt Injection: Indirect")
ATLAS_DATA_LEAKAGE = Tag("MITRE-ATLAS", "AML.T0057", "LLM Data Leakage")


def tags_for(label: Label, requirement: Requirement) -> tuple[Tag, ...]:
    """Tags for an argument with ``label`` failing ``requirement``."""
    out: list[Tag] = []
    if (
        requirement.require_integrity is not None
        and label.integrity < requirement.require_integrity
    ):
        # Attacker-influenced data steering a privileged action.
        out += [LLM01, ATLAS_INDIRECT_INJECTION, LLM06]
    if (
        requirement.max_confidentiality is not None
        and label.confidentiality > requirement.max_confidentiality
    ):
        out += [LLM02, ATLAS_DATA_LEAKAGE]
    return tuple(dict.fromkeys(out))
