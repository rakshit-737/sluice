"""Provider-neutral guard for an existing agent loop.

Provider adapters convert each request's messages into neutral ``Message`` objects and call
``ingest``; they convert the model's reply and call ``review``, which checks every tool call
and returns the reply with blocked calls removed. The caller's loop then only ever sees
tool calls that passed policy.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from typing import Any

from sluice.llm import Message
from sluice.monitor.middleware import CheckedCall, Monitor
from sluice.policy.decision import Decision


class SluiceBlocked(RuntimeError):
    """Raised by a guard configured with ``raise_on_block=True``."""

    def __init__(self, decisions: Sequence[Decision]) -> None:
        self.decisions = list(decisions)
        super().__init__("\n\n".join(d.explain() for d in self.decisions))


@dataclass(frozen=True)
class Review:
    message: Message  # the reply with blocked tool calls removed
    allowed: list[CheckedCall] = field(default_factory=list)
    blocked: list[CheckedCall] = field(default_factory=list)

    @property
    def notice(self) -> str:
        """Text appended to the reply so the model and the user see what happened."""
        if not self.blocked:
            return ""
        lines = [f"[sluice blocked {c.call.name}]\n{c.decision.explain()}" for c in self.blocked]
        return "\n\n".join(lines)


def parse_output(content: str) -> Any:
    """Tool results arrive as text; JSON objects/arrays are labelled per field."""
    s = content.strip()
    if s[:1] in "[{":
        try:
            return json.loads(s)
        except ValueError:
            pass
    return content


class Guard:
    def __init__(self, monitor: Monitor, *, raise_on_block: bool = False) -> None:
        self.monitor = monitor
        self.raise_on_block = raise_on_block
        self._seen: set[tuple[str, str]] = set()
        self._pending: dict[str, CheckedCall] = {}

    def ingest(self, messages: Sequence[Message]) -> None:
        """Label everything new in the conversation. Safe to call with the full history on
        every request: each message is recorded once."""
        for m in messages:
            if m.role in ("system", "user"):
                key: tuple[str, str] = (m.role, m.content)
                if m.content and key not in self._seen:
                    self._seen.add(key)
                    self.monitor.observe(m.content, m.role)
            elif m.role == "tool":
                key = ("tool", m.tool_call_id or f"anon:{m.name}:{m.content}")
                if key in self._seen:
                    continue
                self._seen.add(key)
                checked = self._pending.pop(m.tool_call_id or "", None)
                output = parse_output(m.content)
                if checked is not None:
                    self.monitor.record_output(checked, output)
                else:
                    self.monitor.record_unreviewed_output(m.name, output)
            # Assistant text is the model's own output; its tool calls are reviewed in review().

    def review(self, reply: Message) -> Review:
        allowed: list[CheckedCall] = []
        blocked: list[CheckedCall] = []
        for tc in reply.tool_calls:
            checked = self.monitor.check(tc)
            if checked.decision.allowed:
                allowed.append(checked)
                self._pending[tc.id] = checked
            else:
                blocked.append(checked)
        if blocked and self.raise_on_block:
            raise SluiceBlocked([c.decision for c in blocked])
        kept = tuple(c.call for c in allowed)
        review = Review(replace(reply, tool_calls=kept), allowed, blocked)
        if blocked:
            content = "\n\n".join(x for x in (reply.content, review.notice) if x)
            review = replace(review, message=replace(review.message, content=content))
        return review
