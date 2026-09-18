"""Ollama chat adapter.

- ``guard_ollama(client, monitor)``: wraps an ``ollama.Client``; the guarded ``chat``
  removes tool calls that violate policy from ``response.message.tool_calls``.
- ``OllamaLLM``: an ``LLMClient`` for sluice's own agent loop.

Ollama's protocol has no tool-call ids (installed SDK: ``Message.ToolCall.Function`` has only
``name`` and ``arguments`` as a dict; tool results carry ``tool_name``). sluice synthesises ids
from message position, ``ollama-<message index>-<call index>``, and pairs each tool result
with the oldest unanswered call of the same name. This is stable because chat histories are
append-only.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from sluice.llm import Message, ToolCall
from sluice.monitor.adapters._util import field, text_of
from sluice.monitor.guard import Guard, SluiceBlocked
from sluice.monitor.middleware import Monitor
from sluice.tools.registry import ToolSpec


def _calls(raw_calls: Any, index: int) -> tuple[ToolCall, ...]:
    out: list[ToolCall] = []
    for j, tc in enumerate(raw_calls or []):
        fn = field(tc, "function")
        args = field(fn, "arguments") or {}
        tid = f"ollama-{index}-{j}"
        if not isinstance(args, dict):
            out.append(
                ToolCall(tid, str(field(fn, "name")), {}, parse_error="arguments are not an object")
            )
        else:
            out.append(ToolCall(tid, str(field(fn, "name")), dict(args)))
    return tuple(out)


def to_neutral(messages: Iterable[Any]) -> list[Message]:
    out: list[Message] = []
    unanswered: list[ToolCall] = []
    for i, m in enumerate(messages):
        role = field(m, "role")
        content = text_of(field(m, "content"))
        if role in ("system", "user"):
            out.append(Message(role, content))
        elif role == "assistant":
            calls = _calls(field(m, "tool_calls"), i)
            unanswered.extend(calls)
            out.append(Message("assistant", content, calls))
        elif role == "tool":
            name = field(m, "tool_name") or ""
            match = next((c for c in unanswered if not name or c.name == name), None)
            if match is not None:
                unanswered.remove(match)
            out.append(
                Message(
                    "tool",
                    content,
                    tool_call_id=match.id if match else None,
                    name=name or (match.name if match else ""),
                )
            )
    return out


def rewrite_response(resp: Any, kept_idx: list[int], notice: str) -> Any:
    msg = resp.message
    kept = [tc for j, tc in enumerate(msg.tool_calls or []) if j in kept_idx]
    content = "\n\n".join(x for x in (msg.content, notice) if x)
    new_msg = msg.model_copy(update={"tool_calls": kept or None, "content": content})
    return resp.model_copy(update={"message": new_msg})


class GuardedOllama:
    """Proxy for ``ollama.Client``: guards ``chat``, passes the rest through."""

    def __init__(self, client: Any, guard: Guard) -> None:
        self._client = client
        self.guard = guard

    def chat(self, *args: Any, **kwargs: Any) -> Any:
        if kwargs.get("stream"):
            raise NotImplementedError("sluice: streaming is not supported by the guard yet")
        messages = list(kwargs.get("messages") or (args[1] if len(args) > 1 else []) or [])
        self.guard.ingest(to_neutral(messages))
        resp = self._client.chat(*args, **kwargs)
        calls = _calls(field(resp.message, "tool_calls"), len(messages))
        review = self.guard.review(Message("assistant", text_of(resp.message.content), calls))
        if not review.blocked:
            return resp
        kept = {c.call.id for c in review.allowed}
        return rewrite_response(
            resp, [j for j, c in enumerate(calls) if c.id in kept], review.notice
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


def guard_ollama(client: Any, monitor: Monitor, *, raise_on_block: bool = False) -> GuardedOllama:
    return GuardedOllama(client, Guard(monitor, raise_on_block=raise_on_block))


# ---- sluice's own loop ----------------------------------------------------------------------


def to_request(messages: Sequence[Message]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in messages:
        d: dict[str, Any] = {"role": m.role, "content": m.content}
        if m.tool_calls:
            d["tool_calls"] = [
                {"function": {"name": c.name, "arguments": c.arguments}} for c in m.tool_calls
            ]
        if m.role == "tool" and m.name:
            d["tool_name"] = m.name
        out.append(d)
    return out


def tool_param(spec: ToolSpec) -> dict[str, Any]:
    s = spec.json_schema()
    return {
        "type": "function",
        "function": {
            "name": s["name"],
            "description": s["description"],
            "parameters": s["input_schema"],
        },
    }


class OllamaLLM:
    def __init__(self, client: Any, model: str) -> None:
        self.client = client
        self.model = model

    def complete(self, messages: Sequence[Message], tools: Sequence[ToolSpec]) -> Message:
        # sluice's loop keeps its own ids; name the tool results so Ollama can pair them.
        names = {c.id: c.name for m in messages for c in m.tool_calls}
        named = [
            Message(
                m.role,
                m.content,
                m.tool_calls,
                m.tool_call_id,
                names.get(m.tool_call_id or "", m.name),
            )
            for m in messages
        ]
        kwargs: dict[str, Any] = {"model": self.model, "messages": to_request(named)}
        if tools:
            kwargs["tools"] = [tool_param(t) for t in tools]
        resp = self.client.chat(**kwargs)
        calls = _calls(field(resp.message, "tool_calls"), len(messages))
        return Message("assistant", text_of(resp.message.content), calls)


__all__ = ["GuardedOllama", "OllamaLLM", "SluiceBlocked", "guard_ollama"]
