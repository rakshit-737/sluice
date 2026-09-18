"""Interactive approval for ``on_violation: ask``.

The handler shows the decision's explanation and asks y/N. It fails closed: no TTY, EOF,
Ctrl-C or anything but an explicit yes means the call is blocked.
"""

from __future__ import annotations

import sys
from collections.abc import Callable

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.text import Text

from sluice.monitor.middleware import AskHandler
from sluice.policy.decision import Decision


def _stdin_is_tty() -> bool:
    return sys.stdin is not None and sys.stdin.isatty()


def rich_ask(
    console: Console | None = None,
    *,
    is_tty: Callable[[], bool] = _stdin_is_tty,
    confirm: Callable[[Console], bool] | None = None,
) -> AskHandler:
    con = console or Console()

    def _confirm(c: Console) -> bool:
        return Confirm.ask("[bold]Allow this tool call?[/]", default=False, console=c)

    prompt = confirm or _confirm

    def ask(decision: Decision) -> bool:
        if not is_tty():
            return False
        con.print(
            Panel(Text(decision.explain()), title="sluice: approval needed", border_style="yellow")
        )
        try:
            return bool(prompt(con))
        except (EOFError, KeyboardInterrupt):
            return False

    return ask
