"""Security labels and the label lattice.

A label pairs an integrity level (Biba: can we trust it?) with a confidentiality level
(Bell-LaPadula: who may see it?), plus the set of source classes and value ids it was
derived from. Labels form a lattice ordered by "may flow to"; ``join`` is the least upper
bound. See docs/lattice.md.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import IntEnum
from typing import NewType

ValueId = NewType("ValueId", str)


class Integrity(IntEnum):
    """Higher is more trustworthy. Join takes the minimum."""

    UNTRUSTED = 0
    TRUSTED = 1

    @classmethod
    def parse(cls, name: str) -> Integrity:
        return cls[name.upper()]


class Confidentiality(IntEnum):
    """Higher is more secret. Join takes the maximum."""

    PUBLIC = 0
    INTERNAL = 1
    SECRET = 2

    @classmethod
    def parse(cls, name: str) -> Confidentiality:
        return cls[name.upper()]


@dataclass(frozen=True, slots=True)
class Label:
    integrity: Integrity
    confidentiality: Confidentiality
    sources: frozenset[str] = field(default_factory=frozenset)
    provenance: frozenset[ValueId] = field(default_factory=frozenset)

    @staticmethod
    def bottom() -> Label:
        """Identity of join: trusted, public, derived from nothing (program constants)."""
        return Label(Integrity.TRUSTED, Confidentiality.PUBLIC)

    @staticmethod
    def unknown(source: str = "unknown") -> Label:
        """Fail-closed label for data of unknown origin."""
        return Label(Integrity.UNTRUSTED, Confidentiality.SECRET, frozenset({source}))

    def join(self, other: Label) -> Label:
        return Label(
            min(self.integrity, other.integrity),
            max(self.confidentiality, other.confidentiality),
            self.sources | other.sources,
            self.provenance | other.provenance,
        )

    def __or__(self, other: Label) -> Label:
        return self.join(other)

    def flows_to(self, other: Label) -> bool:
        """Partial order: ``self`` may flow into a context labelled ``other``."""
        return (
            self.integrity >= other.integrity
            and self.confidentiality <= other.confidentiality
            and self.sources <= other.sources
            and self.provenance <= other.provenance
        )

    def with_provenance(self, *ids: ValueId) -> Label:
        return Label(
            self.integrity, self.confidentiality, self.sources, self.provenance | frozenset(ids)
        )

    @property
    def trusted(self) -> bool:
        return self.integrity is Integrity.TRUSTED

    def short(self) -> str:
        return f"{self.integrity.name.lower()}/{self.confidentiality.name.lower()}"

    def __str__(self) -> str:
        srcs = ",".join(sorted(self.sources)) or "-"
        return f"{self.short()} [{srcs}]"


def join_all(labels: Iterable[Label]) -> Label:
    out = Label.bottom()
    for lab in labels:
        out = out.join(lab)
    return out
