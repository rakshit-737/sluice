"""Provenance DAG built from trace events, with DOT / JSON / HTML export."""

from __future__ import annotations

import html
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Literal

NodeKind = Literal["value", "call"]


@dataclass
class Node:
    id: str
    kind: NodeKind
    title: str
    label: str = ""  # e.g. "untrusted/secret"
    sources: list[str] = field(default_factory=list)
    detail: str = ""
    verdict: str = ""  # calls only


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    kind: Literal["derived", "arg", "output"]
    text: str = ""
    blocked: bool = False


@dataclass
class ProvenanceGraph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    explanations: list[str] = field(default_factory=list)

    @staticmethod
    def from_events(events: Iterable[dict[str, Any]]) -> ProvenanceGraph:
        g = ProvenanceGraph()
        for ev in events:
            t = ev.get("type")
            if t == "value":
                g.nodes[ev["id"]] = Node(
                    ev["id"],
                    "value",
                    ev.get("origin") or ev["id"],
                    ev.get("label", ""),
                    list(ev.get("sources", [])),
                    ev.get("preview", ""),
                )
                for parent in ev.get("parents", []):
                    g.edges.append(Edge(parent, ev["id"], "derived"))
                if ev.get("call"):
                    g.edges.append(Edge(ev["call"], ev["id"], "output"))
            elif t == "call":
                decision = ev.get("decision", {})
                verdict = decision.get("verdict", "")
                bad_args = {v["arg"] for v in decision.get("violations", [])}
                g.nodes[ev["id"]] = Node(
                    ev["id"],
                    "call",
                    ev["tool"],
                    verdict,
                    detail=json.dumps(ev.get("args", {}), default=str)[:300],
                    verdict=verdict,
                )
                for arg, info in ev.get("attribution", {}).items():
                    for src in info.get("matches", []):
                        if src in g.nodes:
                            blocked = arg in bad_args and verdict == "block"
                            g.edges.append(Edge(src, ev["id"], "arg", arg, blocked))
                if ev.get("explanation") and verdict != "allow":
                    g.explanations.append(ev["explanation"])
        return g

    def pruned(self) -> ProvenanceGraph:
        """Drop derived leaf values that flowed nowhere (e.g. unused email fields)."""
        has_in = {e.dst for e in self.edges if e.kind == "derived"}
        has_out = {e.src for e in self.edges}
        drop = {
            nid
            for nid, n in self.nodes.items()
            if n.kind == "value" and nid in has_in and nid not in has_out
        }
        return ProvenanceGraph(
            {k: v for k, v in self.nodes.items() if k not in drop},
            [e for e in self.edges if e.src not in drop and e.dst not in drop],
            list(self.explanations),
        )

    # ---- exports --------------------------------------------------------------------------

    def to_json(self) -> dict[str, Any]:
        return {
            "nodes": [n.__dict__ for n in self.nodes.values()],
            "edges": [e.__dict__ for e in self.edges],
            "explanations": self.explanations,
        }

    def to_dot(self) -> str:
        lines = ["digraph provenance {", "  rankdir=LR;", "  node [fontname=Helvetica];"]
        for n in self.nodes.values():
            shape = "box" if n.kind == "call" else "ellipse"
            color = _color(n)
            text = f"{n.title}\\n{n.label}".replace('"', "'")
            lines.append(f'  "{n.id}" [label="{text}", shape={shape}, color="{color}"];')
        for e in self.edges:
            attrs = [f'label="{e.text}"'] if e.text else []
            if e.blocked:
                attrs += ['color="#d62828"', "penwidth=3", "style=dashed"]
            lines.append(f'  "{e.src}" -> "{e.dst}" [{", ".join(attrs)}];')
        lines.append("}")
        return "\n".join(lines)

    def layout(self) -> dict[str, tuple[int, int]]:
        """Layered layout: column = longest path from a root, row = order within column."""
        preds: dict[str, list[str]] = {nid: [] for nid in self.nodes}
        for e in self.edges:
            if e.src in self.nodes and e.dst in self.nodes:
                preds[e.dst].append(e.src)
        depth: dict[str, int] = {}

        def d(nid: str, stack: frozenset[str]) -> int:
            if nid in depth:
                return depth[nid]
            ps = [p for p in preds[nid] if p not in stack]
            depth[nid] = 0 if not ps else 1 + max(d(p, stack | {nid}) for p in ps)
            return depth[nid]

        for nid in self.nodes:
            d(nid, frozenset())
        rows: dict[int, int] = {}
        pos: dict[str, tuple[int, int]] = {}
        for nid in self.nodes:
            col = depth[nid]
            pos[nid] = (col, rows.get(col, 0))
            rows[col] = rows.get(col, 0) + 1
        return pos

    def to_html(self, title: str = "sluice provenance") -> str:
        w, h, gx, gy, pad = 230, 64, 90, 26, 30
        pos = self.layout()
        cols = max((c for c, _ in pos.values()), default=0) + 1
        rows = max((r for _, r in pos.values()), default=0) + 1
        width = pad * 2 + cols * w + (cols - 1) * gx
        height = pad * 2 + rows * h + (rows - 1) * gy

        def xy(nid: str) -> tuple[int, int]:
            c, r = pos[nid]
            return pad + c * (w + gx), pad + r * (h + gy)

        parts: list[str] = []
        for e in self.edges:
            if e.src not in pos or e.dst not in pos:
                continue
            x1, y1 = xy(e.src)
            x2, y2 = xy(e.dst)
            x1, y1, x2, y2 = x1 + w, y1 + h // 2, x2, y2 + h // 2
            mx = (x1 + x2) // 2
            cls = "edge blocked" if e.blocked else f"edge {e.kind}"
            parts.append(
                f'<path class="{cls}" d="M{x1},{y1} C{mx},{y1} {mx},{y2} {x2},{y2}">'
                f"<title>{_e(e.src)} → {_e(e.dst)} {_e(e.text)}</title></path>"
            )
            if e.text:
                # Label at the source end: many args converge on one call node.
                tx, ty = x1 + 8, y1 - 6
                mark = " ✗" if e.blocked else ""
                parts.append(
                    f'<text class="elabel{" blocked" if e.blocked else ""}" x="{tx}" y="{ty}">'
                    f"{_e(e.text)}{mark}</text>"
                )
        for n in self.nodes.values():
            x, y = xy(n.id)
            cls = f"node {n.kind} {_css(n)}"
            rx = 4 if n.kind == "call" else 14
            tip = f"{n.id} {n.title}\n{n.label} {', '.join(n.sources)}\n{n.detail}"
            parts.append(
                f'<g class="{cls}"><title>{_e(tip)}</title>'
                f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}"/>'
                f'<text x="{x + 10}" y="{y + 22}" class="t1">{_e(_trunc(n.title, 30))}</text>'
                f'<text x="{x + 10}" y="{y + 42}" class="t2">{_e(n.id)} · {_e(n.label)}</text>'
                f'<text x="{x + 10}" y="{y + 56}" class="t3">{_e(_trunc(n.detail, 38))}</text></g>'
            )
        expl = (
            "".join(f"<pre>{_e(x)}</pre>" for x in self.explanations) or "<p>No blocked flows.</p>"
        )
        return _HTML.format(
            title=_e(title), width=width, height=height, svg="".join(parts), explanations=expl
        )


def _e(s: str) -> str:
    return html.escape(s, quote=True)


def _trunc(s: str, n: int) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _css(n: Node) -> str:
    if n.kind == "call":
        return {"allow": "ok", "log": "ok"}.get(n.verdict, "bad")
    return "trusted" if n.label.startswith("trusted") else "untrusted"


def _color(n: Node) -> str:
    return {"ok": "#2a9d8f", "bad": "#d62828", "trusted": "#2a9d8f", "untrusted": "#e76f51"}[
        _css(n)
    ]


_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{ --bg:#fbfaf7; --fg:#1d1d1f; --muted:#6b6b70; --ok:#2a9d8f; --bad:#d62828;
  --warn:#e76f51; --card:#ffffff; --line:#b8b8bd; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#16171a; --fg:#ececef; --muted:#9a9aa2;
  --card:#202226; --line:#55575e; }} }}
body {{ margin:0; padding:24px 16px; background:var(--bg); color:var(--fg);
  font:14px/1.45 system-ui, sans-serif; }}
h1 {{ font-size:18px; margin:0 0 4px; }} .sub {{ color:var(--muted); margin:0 0 16px; }}
.wrap {{ overflow:auto; border:1px solid var(--line); border-radius:8px; background:var(--card); }}
.node rect {{ fill:var(--card); stroke-width:2; }}
.node.trusted rect {{ stroke:var(--ok); }} .node.untrusted rect {{ stroke:var(--warn); }}
.node.call.ok rect {{ stroke:var(--ok); fill:color-mix(in srgb, var(--ok) 10%, var(--card)); }}
.node.call.bad rect {{ stroke:var(--bad); stroke-width:3;
  fill:color-mix(in srgb, var(--bad) 12%, var(--card)); }}
.t1 {{ font-weight:600; fill:var(--fg); font-size:13px; }}
.t2 {{ fill:var(--muted); font-size:11px; font-family:ui-monospace, monospace; }}
.t3 {{ fill:var(--muted); font-size:10px; }}
.edge {{ fill:none; stroke:var(--line); stroke-width:1.5; }}
.edge.arg {{ stroke:var(--ok); }}
.edge.blocked {{ stroke:var(--bad); stroke-width:3.5; stroke-dasharray:7 4; }}
.elabel {{ font-size:11px; fill:var(--muted); font-family:ui-monospace, monospace; }}
.elabel.blocked {{ fill:var(--bad); font-weight:700; }}
pre {{ background:var(--card); border-left:3px solid var(--bad); padding:10px 12px;
  white-space:pre-wrap; border-radius:4px; }}
.legend span {{ margin-right:14px; }} .sw {{ display:inline-block; width:10px; height:10px;
  border-radius:2px; margin-right:4px; vertical-align:middle; }}
</style></head><body>
<h1>{title}</h1>
<p class="sub legend"><span><i class="sw" style="background:var(--ok)"></i>trusted / allowed</span>
<span><i class="sw" style="background:var(--warn)"></i>untrusted</span>
<span><i class="sw" style="background:var(--bad)"></i>blocked flow</span></p>
<div class="wrap"><svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}"
 role="img" aria-label="provenance graph">{svg}</svg></div>
<h2 style="font-size:15px">Decisions</h2>
{explanations}
</body></html>
"""
