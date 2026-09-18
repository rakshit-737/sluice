"""Sink requirements: predicates over labels."""

from __future__ import annotations

from dataclasses import dataclass

from sluice.labels.label import Confidentiality, Integrity, Label


@dataclass(frozen=True, slots=True)
class Requirement:
    """What a sink argument's label must satisfy. ``None`` fields are unconstrained."""

    require_integrity: Integrity | None = None
    max_confidentiality: Confidentiality | None = None

    @staticmethod
    def trusted() -> Requirement:
        return Requirement(require_integrity=Integrity.TRUSTED)

    def meet(self, other: Requirement) -> Requirement:
        """Strictest combination of two requirements (both must hold)."""
        integ = _max_opt(self.require_integrity, other.require_integrity)
        conf = _min_opt(self.max_confidentiality, other.max_confidentiality)
        return Requirement(
            Integrity(integ) if integ is not None else None,
            Confidentiality(conf) if conf is not None else None,
        )

    def failures(self, label: Label) -> list[str]:
        out: list[str] = []
        if self.require_integrity is not None and label.integrity < self.require_integrity:
            out.append(
                f"integrity {label.integrity.name.lower()} < required "
                f"{self.require_integrity.name.lower()}"
            )
        if (
            self.max_confidentiality is not None
            and label.confidentiality > self.max_confidentiality
        ):
            out.append(
                f"confidentiality {label.confidentiality.name.lower()} > allowed "
                f"{self.max_confidentiality.name.lower()}"
            )
        return out

    def describe(self) -> str:
        parts = []
        if self.require_integrity is not None:
            parts.append(f"require_integrity={self.require_integrity.name.lower()}")
        if self.max_confidentiality is not None:
            parts.append(f"max_confidentiality={self.max_confidentiality.name.lower()}")
        return ", ".join(parts) or "unconstrained"


def _max_opt(a: int | None, b: int | None) -> int | None:
    if a is None:
        return b
    if b is None:
        return a
    return max(a, b)


def _min_opt(a: int | None, b: int | None) -> int | None:
    if a is None:
        return b
    if b is None:
        return a
    return min(a, b)
