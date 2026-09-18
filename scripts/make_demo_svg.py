"""Generate docs/demo.svg: an animated terminal of the inbox-assistant demo.

Reproducible and dependency-free. It runs the real CLI, captures the output, and renders it as
a self-contained animated SVG (CSS line-by-line reveal) that animates inline on GitHub.

    uv run python scripts/make_demo_svg.py
"""

from __future__ import annotations

import html
import io
from pathlib import Path

from rich.console import Console
from typer.testing import CliRunner

import sluice.cli as cli

ROOT = Path(__file__).resolve().parents[1]
CHAR_W, LINE_H, PAD, FONT_SIZE = 8.4, 20.0, 20.0, 14.0
BG, FG, DIM, RED, GREEN = "#16171a", "#e6e6e6", "#9a9aa2", "#ff6b6b", "#4ec9a3"
STEP = 0.18  # seconds between line reveals


def capture() -> str:
    buf = io.StringIO()
    cli.console = Console(file=buf, width=88, no_color=True)
    CawRunner = CliRunner()
    CawRunner.invoke(
        cli.app, ["run", "examples/inbox-assistant", "--out", "sluice-out", "--no-open"]
    )
    return buf.getvalue().rstrip("\n")


def colour(line: str) -> str:
    if line.startswith("BLOCK ") or "blocked" in line or "attacker@example.com" in line:
        return RED
    if "argument" in line or "rule:" in line or "evidence:" in line or "maps to:" in line:
        return DIM
    if "final answer" in line or "Summary" in line:
        return GREEN
    return FG


def build(text: str) -> str:
    lines = text.split("\n")
    width = int(max((len(x) for x in lines), default=80) * CHAR_W + 2 * PAD)
    height = int(len(lines) * LINE_H + 2 * PAD + 24)
    total = len(lines) * STEP + 2.5  # full cycle: reveal, hold, restart
    rows = []
    for i, line in enumerate(lines):
        y = PAD + 24 + i * LINE_H
        # Reveal at i*STEP, hold until the end of the cycle, then reset.
        on = (i * STEP) / total * 100
        rows.append(
            f'<text x="{PAD:.0f}" y="{y:.0f}" fill="{colour(line)}" '
            f'style="animation:l{i} {total:.1f}s infinite">{html.escape(line) or " "}</text>'
        )
        rows.append(
            f"<style>@keyframes l{i}{{0%,{on:.2f}%{{opacity:0}}{on + 0.5:.2f}%,100%"
            f"{{opacity:1}}}}</style>"
        )
    keyframes = ""
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'font-family="Consolas,Menlo,monospace" font-size="{FONT_SIZE}">'
        f"<style>{keyframes}</style>"
        f'<rect width="100%" height="100%" rx="8" fill="{BG}"/>'
        f'<circle cx="20" cy="16" r="5" fill="#ff5f56"/><circle cx="38" cy="16" r="5" '
        f'fill="#ffbd2e"/><circle cx="56" cy="16" r="5" fill="#27c93f"/>'
        f'<text x="{width / 2:.0f}" y="20" fill="{DIM}" text-anchor="middle" '
        f'font-size="12">sluice run examples/inbox-assistant</text>'
        f'{"".join(rows)}</svg>'
    )


def main() -> None:
    svg = build(capture())
    out = ROOT / "docs" / "demo.svg"
    out.write_text(svg, encoding="utf-8")
    print(f"wrote {out} ({len(svg)} bytes)")


if __name__ == "__main__":
    main()
