"""Tool registry.

Each tool declares its source class (which policy entry labels its outputs), optional sink
requirements per argument, and capability tags used by the trifecta check.
"""

from __future__ import annotations

import inspect
import typing
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any

from sluice.labels.label import Confidentiality, Integrity
from sluice.labels.requirement import Requirement

# Capability tags.
FS_READ = "fs.read"
FS_WRITE = "fs.write"
NET_OUT = "net.out"
NET_IN = "net.in"
SHELL = "shell"
COMMS = "comms"
SECRETS = "secrets"
KNOWN_CAPS = frozenset({FS_READ, FS_WRITE, NET_OUT, NET_IN, SHELL, COMMS, SECRETS})

_SPEC_ATTR = "__sluice_tool__"

_JSON_TYPES: dict[Any, str] = {str: "string", int: "integer", float: "number", bool: "boolean"}


@dataclass(frozen=True)
class ToolSpec:
    name: str
    fn: Callable[..., Any]
    source: str
    caps: frozenset[str] = frozenset()
    sink: Mapping[str, Requirement] = field(default_factory=dict)
    all_args: Requirement | None = None
    fields: Mapping[str, str] = field(default_factory=dict)
    description: str = ""
    params: Mapping[str, dict[str, Any]] = field(default_factory=dict)
    required: tuple[str, ...] = ()

    def json_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": {
                "type": "object",
                "properties": dict(self.params),
                "required": list(self.required),
            },
        }


def _req_dict(r: Requirement) -> dict[str, str]:
    d: dict[str, str] = {}
    if r.require_integrity is not None:
        d["require_integrity"] = r.require_integrity.name.lower()
    if r.max_confidentiality is not None:
        d["max_confidentiality"] = r.max_confidentiality.name.lower()
    return d


def _req_from(d: Mapping[str, str] | None) -> Requirement | None:
    if d is None:
        return None
    integ = d.get("require_integrity")
    conf = d.get("max_confidentiality")
    return Requirement(
        Integrity.parse(integ) if integ else None,
        Confidentiality.parse(conf) if conf else None,
    )


def spec_to_dict(spec: ToolSpec) -> dict[str, Any]:
    """Manifest entry for traces: everything except the callable."""
    return {
        "name": spec.name,
        "source": spec.source,
        "caps": sorted(spec.caps),
        "sink": {a: _req_dict(r) for a, r in spec.sink.items()},
        "all_args": _req_dict(spec.all_args) if spec.all_args is not None else None,
        "fields": dict(spec.fields),
        "description": spec.description,
        "params": dict(spec.params),
        "required": list(spec.required),
    }


def _replay_only(*args: Any, **kwargs: Any) -> Any:
    raise RuntimeError("tool reconstructed from a trace manifest cannot be executed")


def spec_from_dict(d: Mapping[str, Any]) -> ToolSpec:
    sink = {a: r for a, v in d.get("sink", {}).items() if (r := _req_from(v)) is not None}
    return ToolSpec(
        name=d["name"],
        fn=_replay_only,
        source=d["source"],
        caps=frozenset(d.get("caps", [])),
        sink=sink,
        all_args=_req_from(d.get("all_args")),
        fields=dict(d.get("fields", {})),
        description=d.get("description", ""),
        params=dict(d.get("params", {})),
        required=tuple(d.get("required", [])),
    )


def _param_schema(fn: Callable[..., Any]) -> tuple[dict[str, dict[str, Any]], tuple[str, ...]]:
    sig = inspect.signature(fn)
    hints = typing.get_type_hints(fn)
    props: dict[str, dict[str, Any]] = {}
    required: list[str] = []
    for name, p in sig.parameters.items():
        hint = hints.get(name, str)
        origin = typing.get_origin(hint) or hint
        if origin in (list, tuple):
            props[name] = {"type": "array"}
        elif origin is dict:
            props[name] = {"type": "object"}
        else:
            props[name] = {"type": _JSON_TYPES.get(hint, "string")}
        if p.default is inspect.Parameter.empty:
            required.append(name)
    return props, tuple(required)


def make_spec(
    fn: Callable[..., Any],
    *,
    name: str | None = None,
    source: str | None = None,
    caps: Iterable[str] = (),
    sink: Mapping[str, Requirement] | None = None,
    all_args: Requirement | None = None,
    fields: Mapping[str, str] | None = None,
    description: str | None = None,
) -> ToolSpec:
    tool_name = name or fn.__name__
    caps_set = frozenset(caps)
    unknown = caps_set - KNOWN_CAPS
    if unknown:
        raise ValueError(f"unknown capability tags for {tool_name}: {sorted(unknown)}")
    params, required = _param_schema(fn)
    return ToolSpec(
        name=tool_name,
        fn=fn,
        source=source or f"tool.{tool_name}",
        caps=caps_set,
        sink=dict(sink or {}),
        all_args=all_args,
        fields=dict(fields or {}),
        description=description or inspect.getdoc(fn) or "",
        params=params,
        required=required,
    )


def tool(
    name: str | None = None,
    *,
    source: str | None = None,
    caps: Iterable[str] = (),
    sink: Mapping[str, Requirement] | None = None,
    all_args: Requirement | None = None,
    fields: Mapping[str, str] | None = None,
    description: str | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator attaching a ToolSpec to a plain callable."""

    def wrap(fn: Callable[..., Any]) -> Callable[..., Any]:
        spec = make_spec(
            fn,
            name=name,
            source=source,
            caps=caps,
            sink=sink,
            all_args=all_args,
            fields=fields,
            description=description,
        )
        setattr(fn, _SPEC_ATTR, spec)
        return fn

    return wrap


class ToolRegistry:
    def __init__(self, tools: Iterable[Callable[..., Any] | ToolSpec] = ()) -> None:
        self._tools: dict[str, ToolSpec] = {}
        for t in tools:
            self.register(t)

    def register(self, t: Callable[..., Any] | ToolSpec) -> ToolSpec:
        spec = t if isinstance(t, ToolSpec) else getattr(t, _SPEC_ATTR, None) or make_spec(t)
        if spec.name in self._tools:
            raise ValueError(f"tool already registered: {spec.name}")
        self._tools[spec.name] = spec
        return spec

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def __contains__(self, name: object) -> bool:
        return name in self._tools

    def __iter__(self) -> Iterator[ToolSpec]:
        return iter(self._tools.values())

    def __len__(self) -> int:
        return len(self._tools)

    def schemas(self) -> list[dict[str, Any]]:
        return [t.json_schema() for t in self]
