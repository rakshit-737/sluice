"""Register MCP (Model Context Protocol) server tools in a sluice ToolRegistry.

MCP sessions are async; sluice's tool callables are sync. The caller supplies a sync
``call(name, arguments)`` function, e.g. through an anyio blocking portal::

    with anyio.from_thread.start_blocking_portal() as portal:
        tools = portal.call(list_all_tools, session)
        register_mcp_tools(registry, tools, portal_caller(portal, session), server="files",
                           caps={"read_file": [FS_READ]})

Security choices (docs/DECISIONS.md D11):

- Source class is ``mcp.<server>.<tool>``. A policy that does not name it gets the
  fail-closed label, so an unvetted server's output is untrusted/secret by default.
- Capability tags come only from the deployer. Server-supplied ``annotations`` (read-only,
  open-world hints) are claims by the server, so they are never trusted for classification.
- Tool descriptions come from the server and are shown to the model; they are untrusted
  content too, which is why policy is enforced at the call, not by trusting the description.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from typing import Any

from sluice._access import field
from sluice.labels.requirement import Requirement
from sluice.tools.registry import KNOWN_CAPS, ToolRegistry, ToolSpec

Caller = Callable[[str, dict[str, Any]], Any]


class McpToolError(RuntimeError):
    """The MCP server reported ``is_error`` for a tool call."""


def result_value(result: Any) -> Any:
    """Convert a ``CallToolResult`` into a value: structured content if present, else text."""
    content = field(result, "content") or []
    text = "\n".join(str(field(b, "text")) for b in content if field(b, "type") == "text")
    if field(result, "is_error"):
        raise McpToolError(text or "MCP tool error")
    structured = field(result, "structured_content")
    return structured if structured is not None else text


def mcp_tool_spec(
    tool: Any,
    call: Caller,
    *,
    server: str,
    caps: Iterable[str] = (),
    sink: Mapping[str, Requirement] | None = None,
    all_args: Requirement | None = None,
    fields: Mapping[str, str] | None = None,
) -> ToolSpec:
    name = str(field(tool, "name"))
    schema = field(tool, "input_schema") or field(tool, "inputSchema") or {}
    caps_set = frozenset(caps)
    if caps_set - KNOWN_CAPS:
        raise ValueError(f"unknown capability tags for {name}: {sorted(caps_set - KNOWN_CAPS)}")

    def invoke(**arguments: Any) -> Any:
        return result_value(call(name, arguments))

    invoke.__name__ = name
    return ToolSpec(
        name=name,
        fn=invoke,
        source=f"mcp.{server}.{name}",
        caps=caps_set,
        sink=dict(sink or {}),
        all_args=all_args,
        fields=dict(fields or {}),
        description=str(field(tool, "description") or ""),
        params=dict(schema.get("properties") or {}),
        required=tuple(schema.get("required") or ()),
    )


def register_mcp_tools(
    registry: ToolRegistry,
    tools: Iterable[Any],
    call: Caller,
    *,
    server: str,
    caps: Mapping[str, Iterable[str]] | None = None,
    sinks: Mapping[str, Mapping[str, Requirement]] | None = None,
) -> list[ToolSpec]:
    caps = caps or {}
    sinks = sinks or {}
    specs = []
    for t in tools:
        name = str(field(t, "name"))
        spec = mcp_tool_spec(t, call, server=server, caps=caps.get(name, ()), sink=sinks.get(name))
        specs.append(registry.register(spec))
    return specs


async def list_all_tools(session: Any) -> list[Any]:
    """All tools from an ``mcp.ClientSession``, following pagination cursors."""
    from mcp.types import PaginatedRequestParams

    out: list[Any] = []
    cursor: str | None = None
    while True:
        params = PaginatedRequestParams(cursor=cursor) if cursor else None
        page = await session.list_tools(params=params)
        out.extend(page.tools)
        cursor = page.next_cursor
        if not cursor:
            return out


def portal_caller(portal: Any, session: Any) -> Caller:
    """Sync caller over an async MCP session via an ``anyio`` blocking portal."""

    def call(name: str, arguments: dict[str, Any]) -> Any:
        return portal.call(session.call_tool, name, arguments)

    return call
