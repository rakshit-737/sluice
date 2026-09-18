"""Provider-neutral chat types, the LLM protocol, and a scripted mock LLM."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from sluice.tools.registry import ToolSpec

Role = Literal["system", "user", "assistant", "tool"]


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class Message:
    role: Role
    content: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    tool_call_id: str | None = None


class LLMClient(Protocol):
    def complete(self, messages: Sequence[Message], tools: Sequence[ToolSpec]) -> Message: ...


Turn = Message | Callable[[Sequence[Message]], Message]


@dataclass
class MockLLM:
    """Plays back a script. A turn may be a fixed Message or a function of the transcript,
    which lets tests model an LLM that obeys instructions found in its context."""

    script: list[Turn]
    calls: list[list[Message]] = field(default_factory=list)

    def complete(self, messages: Sequence[Message], tools: Sequence[ToolSpec]) -> Message:
        self.calls.append(list(messages))
        if not self.script:
            return Message("assistant", "(mock LLM: script exhausted)")
        turn = self.script.pop(0)
        return turn(messages) if callable(turn) else turn


def say(text: str) -> Message:
    return Message("assistant", text)


def call(name: str, call_id: str = "", **arguments: Any) -> Message:
    return Message("assistant", tool_calls=(ToolCall(call_id or f"call_{name}", name, arguments),))
