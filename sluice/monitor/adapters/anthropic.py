"""Anthropic Messages API adapter.

Two ways in:

- ``guard_anthropic(client, monitor)``: wraps an ``anthropic.Anthropic`` client for an
  existing loop. ``.messages.create(...)`` has the same signature and return type; tool_use
  blocks that violate policy are removed from the response and replaced by an explanation.
- ``AnthropicLLM``: an ``LLMClient`` for sluice's own agent loop.

Formats follow the installed SDK: assistant ``tool_use`` blocks (id, name, input dict) and
user ``tool_result`` blocks (tool_use_id, content as str or text blocks).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from sluice._access import field, text_of
from sluice.llm import Message, ToolCall
from sluice.monitor.guard import Guard, SluiceBlocked
from sluice.monitor.middleware import Monitor
from sluice.tools.registry import ToolSpec


def to_neutral(system: Any, messages: Iterable[Any]) -> list[Message]:
    out: list[Message] = []
    if system:
        out.append(Message("system", text_of(system)))
    names: dict[str, str] = {}
    for m in messages:
        role = field(m, "role")
        content = field(m, "content")
        if isinstance(content, str):
            out.append(Message("user" if role == "user" else "assistant", content))
            continue
        texts: list[str] = []
        calls: list[ToolCall] = []
        for block in content or []:
            kind = field(block, "type")
            if kind == "text":
                texts.append(str(field(block, "text") or ""))
            elif kind == "tool_use":
                tc = ToolCall(
                    str(field(block, "id")),
                    str(field(block, "name")),
                    dict(field(block, "input") or {}),
                )
                names[tc.id] = tc.name
                calls.append(tc)
            elif kind == "tool_result":
                tid = str(field(block, "tool_use_id"))
                out.append(
                    Message(
                        "tool",
                        text_of(field(block, "content")),
                        tool_call_id=tid,
                        name=names.get(tid, ""),
                    )
                )
        if role == "assistant":
            out.append(Message("assistant", "\n".join(texts), tuple(calls)))
        elif texts:
            out.append(Message("user", "\n".join(texts)))
    return out


def from_response(resp: Any) -> Message:
    return to_neutral(None, [{"role": "assistant", "content": field(resp, "content")}])[0]


def rewrite_response(resp: Any, blocked_ids: set[str], notice: str) -> Any:
    """Copy of the SDK response without the blocked tool_use blocks."""
    from anthropic.types import TextBlock

    content = [b for b in resp.content if not (b.type == "tool_use" and b.id in blocked_ids)]
    content.append(TextBlock(type="text", text=notice))
    update: dict[str, Any] = {"content": content}
    if not any(b.type == "tool_use" for b in content):
        update["stop_reason"] = "end_turn"
    return resp.model_copy(update=update)


class _GuardedMessages:
    def __init__(self, inner: Any, guard: Guard) -> None:
        self._inner = inner
        self._guard = guard

    def create(self, **kwargs: Any) -> Any:
        if kwargs.get("stream"):
            # Tool input arrives as partial JSON deltas; reviewing a partial call is unsound.
            raise NotImplementedError("sluice: streaming is not supported by the guard yet")
        self._guard.ingest(to_neutral(kwargs.get("system"), kwargs.get("messages", [])))
        resp = self._inner.create(**kwargs)
        review = self._guard.review(from_response(resp))
        if not review.blocked:
            return resp
        return rewrite_response(resp, {c.call.id for c in review.blocked}, review.notice)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class GuardedAnthropic:
    """Proxy for ``anthropic.Anthropic``: guards ``messages.create``, passes the rest through."""

    def __init__(self, client: Any, guard: Guard) -> None:
        self._client = client
        self.guard = guard
        self.messages = _GuardedMessages(client.messages, guard)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


def guard_anthropic(
    client: Any, monitor: Monitor, *, raise_on_block: bool = False
) -> GuardedAnthropic:
    return GuardedAnthropic(client, Guard(monitor, raise_on_block=raise_on_block))


# ---- sluice's own loop ----------------------------------------------------------------------


def to_request(messages: Sequence[Message]) -> tuple[str, list[dict[str, Any]]]:
    system = "\n".join(m.content for m in messages if m.role == "system")
    out: list[dict[str, Any]] = []
    for m in messages:
        if m.role == "system":
            continue
        if m.role == "tool":
            block = {
                "type": "tool_result",
                "tool_use_id": m.tool_call_id or "",
                "content": m.content,
            }
            if out and out[-1]["role"] == "user" and isinstance(out[-1]["content"], list):
                out[-1]["content"].append(block)  # consecutive results share one user turn
            else:
                out.append({"role": "user", "content": [block]})
        elif m.role == "assistant":
            blocks: list[dict[str, Any]] = (
                [{"type": "text", "text": m.content}] if m.content else []
            )
            blocks += [
                {"type": "tool_use", "id": c.id, "name": c.name, "input": c.arguments}
                for c in m.tool_calls
            ]
            out.append({"role": "assistant", "content": blocks})
        else:
            out.append({"role": "user", "content": m.content})
    return system, out


def tool_param(spec: ToolSpec) -> dict[str, Any]:
    s = spec.json_schema()
    return {"name": s["name"], "description": s["description"], "input_schema": s["input_schema"]}


class AnthropicLLM:
    def __init__(self, client: Any, model: str, *, max_tokens: int = 4096) -> None:
        self.client = client
        self.model = model
        self.max_tokens = max_tokens

    def complete(self, messages: Sequence[Message], tools: Sequence[ToolSpec]) -> Message:
        system, msgs = to_request(messages)
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": msgs,
        }
        if system:
            kwargs["system"] = system
        if tools:
            kwargs["tools"] = [tool_param(t) for t in tools]
        return from_response(self.client.messages.create(**kwargs))


__all__ = ["AnthropicLLM", "GuardedAnthropic", "SluiceBlocked", "guard_anthropic"]
