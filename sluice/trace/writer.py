"""JSONL trace: one event per line, append-only."""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import IO, Any

Listener = Callable[[dict[str, Any]], None]


class TraceWriter:
    """Writes events to JSONL and forwards each one to ``listeners`` (SIEM exporters etc.).

    A listener that raises does not stop the trace: telemetry must never be able to break
    enforcement. The error is recorded as a ``listener_error`` event instead.
    """

    def __init__(self, path: str | Path | None = None, listeners: Iterable[Listener] = ()) -> None:
        self.listeners = list(listeners)
        self.path = Path(path) if path else None
        self._fh: IO[str] | None = None
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = self.path.open("w", encoding="utf-8")
        self.events: list[dict[str, Any]] = []
        self._seq = 0

    def emit(self, type_: str, **data: Any) -> None:
        self._seq += 1
        ev = {"seq": self._seq, "ts": time.time(), "type": type_, **data}
        self.events.append(ev)
        if self._fh:
            self._fh.write(json.dumps(ev, default=str) + "\n")
            self._fh.flush()
        if type_ == "listener_error":
            return
        for listener in self.listeners:
            try:
                listener(ev)
            except Exception as e:
                self.emit(
                    "listener_error", listener=repr(listener), error=f"{type(e).__name__}: {e}"
                )

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None

    def __enter__(self) -> TraceWriter:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def read_trace(path: str | Path) -> Iterator[dict[str, Any]]:
    with Path(path).open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                ev: dict[str, Any] = json.loads(line)
                yield ev
