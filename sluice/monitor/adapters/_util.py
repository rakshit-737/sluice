"""Helpers shared by provider adapters: SDK objects and plain dicts are both accepted."""

from __future__ import annotations

from typing import Any


def field(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def text_of(content: Any) -> str:
    """Flatten a str or a list of text-bearing blocks to text. Non-text blocks are skipped."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    parts = [field(b, "text") for b in content]
    return "\n".join(str(p) for p in parts if p is not None)
