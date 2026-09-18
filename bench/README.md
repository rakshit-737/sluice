# AgentDojo benchmark

sluice is evaluated on [AgentDojo](https://github.com/ethz-spylab/agentdojo) (suite version
`v1.2.1`: the `workspace`, `travel`, `banking` and `slack` suites). We measure three things per
suite and defence:

- **utility, no attack** — fraction of user tasks solved with no injection present (does the
  defence break normal work?)
- **utility under attack** — fraction of injected runs where the user task still succeeds
- **attack success** — fraction of injected runs where the *injection* task succeeds (lower is
  better; this is what a defence must drive down)

Runs are scored with AgentDojo's own `utility` and `security` checks. Injection text is
AgentDojo's `important_instructions` attack template — sluice ships no attack content of its own.

## Two agents

**oracle** (default, no API keys). A worst-case obedient model: it performs the user task's
ground-truth tool calls and then the injection task's ground-truth calls, exactly as a model
fully taken over by the injection would. This is deterministic and isolates the *enforcement
layer* from any particular model's susceptibility — the "attack success" under no defence is
100% by construction, so the interesting number is how far each defence drives it down while
retaining utility. Only user tasks whose own tool calls actually surface the injected text are
attacked (AgentDojo's `get_injection_candidates`), because a model cannot be injected by text
it never reads. Strict mode is not run with the oracle (its planner never reads tool output, so
the "obedient model" premise does not apply); use `--agent llm` for strict-mode numbers.

**llm** (`--agent llm --model provider:model`). A real model through sluice's provider adapters,
across `none`, `monitor` and `strict`. Needs an API key; results depend on the model.

## Reproduce

```
uv sync --extra bench
uv run sluice bench                                   # oracle, none + monitor, all suites
uv run sluice bench --suites banking --limit 5        # a quick slice
uv run sluice bench --agent llm --model anthropic:claude-sonnet-5 --modes none,monitor,strict
```

Each run writes `outcomes.jsonl` (one row per run) and `summary.md` (the table) to the output
directory. The table in the top-level README is produced by this harness; see
[docs/limitations.md](../docs/limitations.md) for how to read it.
