"""sluice command-line interface."""

from __future__ import annotations

import webbrowser
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from sluice.agent import Agent, RunResult
from sluice.graph.provenance import ProvenanceGraph
from sluice.labels.value import reset_ids
from sluice.monitor.ask import rich_ask
from sluice.monitor.middleware import Monitor
from sluice.policy.compiler import Policy, PolicyError
from sluice.scenario import ScenarioError, load_scenario
from sluice.trace.replay import replay as replay_trace
from sluice.trace.writer import TraceWriter, read_trace

app = typer.Typer(help="Information-flow control runtime for LLM agents.", no_args_is_help=True)
policy_app = typer.Typer(help="Policy utilities.", no_args_is_help=True)
app.add_typer(policy_app, name="policy")
console = Console()


def _executed(title: str, result: RunResult) -> Table:
    t = Table(title=title, show_lines=False)
    t.add_column("tool")
    t.add_column("arguments", overflow="fold")
    for name, args in result.executed:
        t.add_row(name, ", ".join(f"{k}={str(v)[:60]!r}" for k, v in args.items()))
    return t


@app.command()
def run(
    scenario_dir: Path = typer.Argument(..., help="Directory with scenario.py and policy.yaml"),
    out: Path = typer.Option(Path("sluice-out"), help="Where to write trace and graph"),
    vanilla: bool = typer.Option(True, help="Also run without sluice, for comparison"),
    open_graph: bool = typer.Option(True, "--open/--no-open", help="Open the provenance graph"),
) -> None:
    """Run a scenario under monitor mode (and, for comparison, without sluice)."""
    try:
        build = load_scenario(scenario_dir)
    except ScenarioError as e:
        console.print(f"[red]error:[/] {e}")
        raise typer.Exit(2) from e

    if vanilla:
        sc = build()
        res = Agent(sc.llm, sc.registry, system_prompt=sc.system_prompt).run(sc.user_prompt)
        console.print(Panel.fit(f"[bold]{sc.name}[/] - vanilla agent loop (no sluice)"))
        console.print(_executed("tool calls executed", res))

    reset_ids()
    sc = build()
    policy = Policy.load(sc.policy_path) if sc.policy_path else None
    if policy is None:
        console.print("[yellow]no policy.yaml: fail-closed deny-all policy in effect[/]")
    run_dir = out / sc.name
    with TraceWriter(run_dir / "trace.jsonl") as trace:
        monitor = Monitor(policy, sc.registry, trace=trace, ask=rich_ask(console))
        agent = Agent(sc.llm, sc.registry, monitor, system_prompt=sc.system_prompt)
        res = agent.run(sc.user_prompt)
    console.print(Panel.fit(f"[bold]{sc.name}[/] - under sluice (monitor mode)"))
    console.print(_executed("tool calls executed", res))
    for d in res.blocked:
        console.print(Panel(Text(d.explain()), title="[red]blocked[/]", border_style="red"))
    graph = ProvenanceGraph.from_events(trace.events).pruned()
    html_path = run_dir / "graph.html"
    html_path.write_text(graph.to_html(f"sluice · {sc.name}"), encoding="utf-8")
    (run_dir / "graph.dot").write_text(graph.to_dot(), encoding="utf-8")
    console.print(f"trace: {run_dir / 'trace.jsonl'}\ngraph: {html_path}")
    console.print(f"final answer: {res.final}")
    if open_graph:
        webbrowser.open(html_path.resolve().as_uri())


@app.command()
def replay(
    trace_path: Path = typer.Argument(..., help="trace.jsonl written by sluice"),
    policy_path: Path | None = typer.Option(None, "--policy", help="Re-decide under this policy"),
    graph_out: Path | None = typer.Option(None, "--graph", help="Write provenance HTML here"),
    open_graph: bool = typer.Option(False, "--open/--no-open", help="Open the graph"),
) -> None:
    """Rebuild decisions and the provenance graph from a trace, offline."""
    try:
        policy = Policy.load(policy_path) if policy_path else None
        result = replay_trace(read_trace(trace_path), policy)
    except (OSError, ValueError) as e:
        console.print(f"[red]cannot replay:[/] {e}")
        raise typer.Exit(1) from e
    t = Table(title=f"replay of {trace_path}" + (f" under {policy_path}" if policy_path else ""))
    for col in ("call", "tool", "recorded", "replayed"):
        t.add_column(col)
    for c in result.calls:
        style = "bold yellow" if c.changed else ""
        t.add_row(c.id, c.tool, c.original, c.decision.verdict, style=style)
    console.print(t)
    for c in result.calls:
        if not c.decision.allowed:
            console.print(Panel(Text(c.decision.explain()), title=c.id, border_style="red"))
    console.print(f"{len(result.changed)} of {len(result.calls)} decisions changed")
    if graph_out:
        graph_out.write_text(
            result.graph.pruned().to_html(f"sluice replay - {trace_path.name}"), encoding="utf-8"
        )
        console.print(f"graph: {graph_out}")
        if open_graph:
            webbrowser.open(graph_out.resolve().as_uri())


@policy_app.command("check")
def policy_check(path: Path) -> None:
    """Validate and compile a policy file."""
    try:
        p = Policy.load(path)
    except (PolicyError, OSError) as e:
        console.print(f"[red]invalid policy:[/] {e}")
        raise typer.Exit(1) from e
    t = Table(title=f"sources ({path})")
    t.add_column("source")
    t.add_column("label")
    for name, lab in p.sources.items():
        t.add_row(name, lab.short())
    console.print(t)
    s = Table(title="sinks")
    s.add_column("sink")
    s.add_column("argument")
    s.add_column("requirement")
    for name, sink in p.sinks.items():
        if not sink.args and sink.all_args is None:
            s.add_row(name, "-", "unconstrained")
        for arg, req in sink.args.items():
            s.add_row(name, arg, req.describe())
        if sink.all_args is not None:
            s.add_row(name, "*", sink.all_args.describe())
    console.print(s)
    console.print(f"on_violation: {p.on_violation}")


if __name__ == "__main__":  # pragma: no cover
    app()
