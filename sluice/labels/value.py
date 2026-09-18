"""LabeledValue and label propagation rules."""

from __future__ import annotations

import itertools
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

from sluice.labels.label import Label, ValueId, join_all

T = TypeVar("T")

_lock = threading.Lock()
_counter = itertools.count(1)


def new_id() -> ValueId:
    with _lock:
        return ValueId(f"v{next(_counter)}")


def reset_ids() -> None:
    """Restart id numbering (tests and reproducible demo traces)."""
    global _counter
    with _lock:
        _counter = itertools.count(1)


@dataclass(frozen=True, slots=True)
class LabeledValue(Generic[T]):
    value: T
    label: Label
    id: ValueId = field(default_factory=new_id)
    origin: str = ""  # human-readable note, e.g. "read_inbox[1].body"

    def derive(self, value: Any, *others: LabeledValue[Any], origin: str = "") -> LabeledValue[Any]:
        return derive(value, self, *others, origin=origin)


def lift(value: Any) -> LabeledValue[Any]:
    """Wrap a program constant. Constants are chosen by the programmer: bottom label."""
    if isinstance(value, LabeledValue):
        return value
    return LabeledValue(value, Label.bottom(), origin="const")


def derive(value: Any, *parents: LabeledValue[Any], origin: str = "") -> LabeledValue[Any]:
    """New value computed from ``parents``: label is their join, provenance their ids."""
    label = join_all(p.label for p in parents).with_provenance(*(p.id for p in parents))
    return LabeledValue(value, label, origin=origin)


def lconcat(*parts: LabeledValue[Any] | str) -> LabeledValue[str]:
    lifted = [lift(p) for p in parts]
    return derive("".join(str(p.value) for p in lifted), *lifted, origin="concat")


def lformat(
    template: LabeledValue[str] | str, **kwargs: LabeledValue[Any] | Any
) -> LabeledValue[str]:
    tpl = lift(template)
    args = {k: lift(v) for k, v in kwargs.items()}
    text = str(tpl.value).format(**{k: v.value for k, v in args.items()})
    return derive(text, tpl, *args.values(), origin="format")


def llist(items: Sequence[LabeledValue[Any] | Any]) -> LabeledValue[list[Any]]:
    lifted = [lift(i) for i in items]
    return derive([i.value for i in lifted], *lifted, origin="list")


def ldict(items: Mapping[str, LabeledValue[Any] | Any]) -> LabeledValue[dict[str, Any]]:
    lifted = {k: lift(v) for k, v in items.items()}
    return derive({k: v.value for k, v in lifted.items()}, *lifted.values(), origin="dict")
