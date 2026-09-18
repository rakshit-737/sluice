"""Pydantic schema for policy YAML files."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

IntegrityName = Literal["trusted", "untrusted"]
ConfidentialityName = Literal["public", "internal", "secret"]
Action = Literal["block", "ask", "log"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SourceSpec(_Strict):
    integrity: IntegrityName
    confidentiality: ConfidentialityName


class ArgSpec(_Strict):
    require_integrity: IntegrityName | None = None
    max_confidentiality: ConfidentialityName | None = None


class SinkSpec(_Strict):
    args: dict[str, ArgSpec] = Field(default_factory=dict)
    all_args: ArgSpec | None = None
    on_violation: Action | None = None


class PolicyFile(_Strict):
    version: Literal[1] = 1
    sources: dict[str, SourceSpec] = Field(default_factory=dict)
    sinks: dict[str, SinkSpec] = Field(default_factory=dict)
    on_violation: Action = "block"
