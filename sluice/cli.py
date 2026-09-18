"""sluice command-line interface."""

from __future__ import annotations

import json
import webbrowser
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from sluice.agent import Agent, RunResult
from sluice.export.ocsf import OcsfExporter
from sluice.export.sarif import trifecta_sarif
from sluice.graph.provenance import ProvenanceGraph
from sluice.labels.value import reset_ids
from sluice.llm import LLMClient
from sluice.monitor.ask import rich_ask
from sluice.monitor.middleware import Monitor
from sluice.policy.compiler import Policy, PolicyError
from sluice.policy.decision import Decision
from sluice.policy.trifecta import analyze as analyze_trifecta
from sluice.scenario import Scenario, ScenarioError, load_scenario
from sluice.strict.agent import StrictAgent
from sluice.strict.interpreter import Interpreter
from sluice.strict.planner import Planner
from sluice.strict.quarantine import LLMQuarantine
from sluice.trace.replay import replay as replay_trace
from sluice.trace.writer import TraceWriter, read_trace

app = typer.Typer(help="Information-flow control runtime for LLM agents.", no_args_is_help=True)
policy_app = typer.Typer(help="Policy utilities.", no_args_is_help=True)
app.add_typer(policy_app, name="policy")
console = Console()


def _repo_uri(path: Path) -> str:
    """Forward-slash path relative to the working directory, as SARIF consumers expect."""
    p = path.resolve()
    return (p.relative_to(Path.cwd()) if p.is_relative_to(Path.cwd()) else p).as_posix()


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
    ocsf: Path | None = typer.Option(None, help="Append OCSF findings (JSONL) for a SIEM"),
    mode: str = typer.Option("monitor", help="monitor (drop-in) or strict (planner + interpreter)"),
) -> None:
    """Run a scenario under sluice (and, for comparison, without it)."""
    if mode not in ("monitor", "strict"):
        console.print(f"[red]error:[/] unknown mode {mode!r}")
        raise typer.Exit(2)
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
    if mode == "strict" and (sc.planner_llm is None or sc.quarantine_llm is None):
        console.print(
            "[red]error:[/] scenario defines no planner_llm/quarantine_llm for strict mode"
        )
        raise typer.Exit(2)
    run_dir = out / (sc.name if mode == "monitor" else f"{sc.name}-strict")
    exporter = OcsfExporter(ocsf) if ocsf else None
    listeners = [exporter] if exporter else []
    with TraceWriter(run_dir / "trace.jsonl", listeners) as trace:
        if mode == "monitor":
            blocked, final = _run_monitor(sc, policy, trace)
        else:
            blocked, final = _run_strict(sc, policy or Policy.deny(), trace)
    if exporter:
        exporter.close()
        console.print(f"ocsf: {exporter.count} finding(s) appended to {ocsf}")
    for d in blocked:
        console.print(Panel(Text(d.explain()), title="[red]blocked[/]", border_style="red"))
    graph = ProvenanceGraph.from_events(trace.events).pruned()
    html_path = run_dir / "graph.html"
    html_path.write_text(graph.to_html(f"sluice · {sc.name} ({mode})"), encoding="utf-8")
    (run_dir / "graph.dot").write_text(graph.to_dot(), encoding="utf-8")
    console.print(f"trace: {run_dir / 'trace.jsonl'}\ngraph: {html_path}")
    console.print(Text(f"final answer: {final}"))
    if open_graph:
        webbrowser.open(html_path.resolve().as_uri())


def _run_monitor(
    sc: Scenario, policy: Policy | None, trace: TraceWriter
) -> tuple[list[Decision], str]:
    monitor = Monitor(policy, sc.registry, trace=trace, ask=rich_ask(console))
    res = Agent(sc.llm, sc.registry, monitor, system_prompt=sc.system_prompt).run(sc.user_prompt)
    console.print(Panel.fit(f"[bold]{sc.name}[/] - under sluice (monitor mode)"))
    console.print(_executed("tool calls executed", res))
    return res.blocked, res.final


def _run_strict(sc: Scenario, policy: Policy, trace: TraceWriter) -> tuple[list[Decision], str]:
    assert sc.planner_llm is not None and sc.quarantine_llm is not None
    interp = Interpreter(
        policy,
        sc.registry,
        quarantine=LLMQuarantine(sc.quarantine_llm),
        schemas=sc.schemas,
        trace=trace,
        ask=rich_ask(console),
    )
    run = StrictAgent(Planner(sc.planner_llm, sc.registry, sc.schemas), interp).run(sc.user_prompt)
    console.print(Panel.fit(f"[bold]{sc.name}[/] - under sluice (strict mode)"))
    if run.plan is not None:
        console.print(
            Panel(Syntax(run.plan.source, "python"), title="plan (from the request only)")
        )
    result = run.result
    colour = {"completed": "green", "blocked": "red", "error": "yellow"}[result.status]
    console.print(f"plan status: [{colour}]{result.status}[/]")
    if result.status == "error":
        console.print(Text(result.error))
    if result.answers:
        console.print(Text(f"answer label: {result.answer_label}"))
    return result.blocked, result.answer


@app.command()
def bench(
    suites: str = typer.Option("all", help="Comma-separated AgentDojo suites, or 'all'"),
    modes: str = typer.Option("none,monitor", help="Comma-separated: none, monitor, strict"),
    agent: str = typer.Option("oracle", help="oracle (no API key) or llm"),
    model: str | None = typer.Option(None, help="provider:model for --agent llm"),
    limit: int | None = typer.Option(None, help="Max user and injection tasks per suite"),
    out: Path = typer.Option(Path("bench/results/latest"), help="Output directory"),
) -> None:
    """Run the AgentDojo benchmark (needs the `bench` extra)."""
    try:
        from sluice.bench.agentdojo import run_benchmark
    except ImportError as e:
        console.print(f"[red]error:[/] {e}. Install with: uv sync --extra bench")
        raise typer.Exit(2) from e
    factory = None
    if model:
        from sluice.providers import llm_from_spec

        def factory() -> LLMClient:
            return llm_from_spec(model)

    try:
        result = run_benchmark(
            None if suites == "all" else suites.split(","),
            modes.split(","),
            agent,
            factory,
            limit,
        )
    except ValueError as e:
        console.print(f"[red]error:[/] {e}")
        raise typer.Exit(2) from e
    result.save(out)
    console.print(result.markdown())
    errors = sum(1 for o in result.outcomes if o.error)
    console.print(f"{len(result.outcomes)} runs, {errors} errors; results in {out}")


@app.command()
def replay(
    trace_path: Path = typer.Argument(..., help="trace.jsonl written by sluice"),
    policy_path: Path | None = typer.Option(None, "--policy", help="Re-decide under this policy"),
    graph_out: Path | None = typer.Option(None, "--graph", help="Write provenance HTML here"),
    open_graph: bool = typer.Option(False, "--open/--no-open", help="Open the graph"),
    ocsf: Path | None = typer.Option(None, help="Backfill the recorded findings as OCSF JSONL"),
) -> None:
    """Rebuild decisions and the provenance graph from a trace, offline."""
    try:
        policy = Policy.load(policy_path) if policy_path else None
        events = list(read_trace(trace_path))
        result = replay_trace(events, policy)
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
    if ocsf:
        exporter = OcsfExporter(ocsf)
        for ev in events:
            exporter(ev)
        exporter.close()
        console.print(f"ocsf: {exporter.count} recorded finding(s) appended to {ocsf}")
    if graph_out:
        graph_out.write_text(
            result.graph.pruned().to_html(f"sluice replay - {trace_path.name}"), encoding="utf-8"
        )
        console.print(f"graph: {graph_out}")
        if open_graph:
            webbrowser.open(graph_out.resolve().as_uri())


@app.command()
def trifecta(
    scenario_dir: Path = typer.Argument(..., help="Directory with scenario.py (tool registry)"),
    policy_path: Path | None = typer.Option(None, "--policy", help="Default: <dir>/policy.yaml"),
    strict: bool = typer.Option(False, help="Exit 1 if any exfiltration path is not covered"),
    sarif: Path | None = typer.Option(None, help="Write findings as SARIF 2.1.0"),
) -> None:
    """Report private-data / untrusted-content / exfiltration exposure and its coverage."""
    try:
        sc = load_scenario(scenario_dir)()
        path = policy_path or sc.policy_path
        policy = Policy.load(path) if path else Policy.deny()
    except (ScenarioError, PolicyError, OSError) as e:
        console.print(f"[red]error:[/] {e}")
        raise typer.Exit(2) from e
    report = analyze_trifecta(sc.registry, policy)
    legs = Table(title=f"lethal trifecta: {sc.name}")
    legs.add_column("leg")
    legs.add_column("tools", overflow="fold")
    for leg, tools in (
        ("private data", report.private),
        ("untrusted content", report.untrusted),
        ("exfiltration", report.exfil),
    ):
        rows = [f"{t}  ({', '.join(r)})" for t, r in tools.items()]
        legs.add_row(leg, Text("\n".join(rows) or "-"))
    console.print(legs)
    verdict = "[red]PRESENT[/]" if report.present else "[green]not present[/]"
    console.print(f"trifecta: {verdict}")
    paths = Table(title="exfiltration paths")
    for col in ("tool", "argument", "guard", "rule", "status"):
        paths.add_column(col, overflow="fold")
    colors = {"covered": "green", "partial": "yellow", "uncovered": "red"}
    for p in report.paths:
        status = f"[{colors[p.status]}]{p.status}[/]"
        if not p.args:
            paths.add_row(p.tool, "-", "no arguments", "-", status)
        for a in p.args:
            guard = a.requirement.describe() + ("" if a.enforced else f" (verdict {p.verdict})")
            mark = "" if a.guarded else " [red]UNGUARDED[/]"
            paths.add_row(p.tool, a.arg + mark, Text(guard), Text(a.rule), status)
    console.print(paths)
    if report.unclassified:
        console.print(
            f"[yellow]no capability tags (not classified):[/] {', '.join(report.unclassified)}"
        )
    if sarif:
        text = path.read_text(encoding="utf-8") if path else None
        uri = _repo_uri(path) if path else "policy.yaml"
        sarif.write_text(json.dumps(trifecta_sarif(report, uri, text), indent=2), encoding="utf-8")
        console.print(f"sarif: {sarif}")
    if strict and report.present and report.exposed:
        raise typer.Exit(1)


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
