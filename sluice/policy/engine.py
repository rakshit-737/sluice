"""The interface the runtime needs from a policy (YAML ``Policy``, ``OpaPolicy``, ...)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Protocol

from sluice.labels.label import Label
from sluice.policy.decision import Decision, Verdict
from sluice.tools.registry import ToolRegistry

# Strictness order used when combining engines: the stricter verdict wins.
STRICTNESS: dict[Verdict, int] = {"allow": 0, "log": 1, "ask": 2, "block": 3}


def stricter(a: Verdict, b: Verdict) -> Verdict:
    return a if STRICTNESS[a] >= STRICTNESS[b] else b


class PolicyEngine(Protocol):
    def source_label(self, source: str) -> Label: ...

    def decide(
        self,
        tool_name: str,
        arg_labels: Mapping[str, Label],
        registry: ToolRegistry,
        evidence: Mapping[str, Sequence[str]] | None = None,
    ) -> Decision: ...

    def to_dict(self) -> dict[str, Any]: ...
