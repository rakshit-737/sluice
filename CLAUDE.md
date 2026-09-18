# sluice — IFC runtime for LLM agents

Labels every value an agent touches (integrity × confidentiality), tracks flows through
reasoning and tool calls, blocks policy violations at sinks. CaMeL-style.

## Commands
```
uv sync --all-extras
uv run pytest --cov=sluice
uv run ruff check . && uv run ruff format --check .
uv run mypy
uv run sluice run examples/inbox-assistant
```

## Architecture
- `sluice/labels/` — Label lattice, LabeledValue, propagation helpers
- `sluice/tools/` — tool registry, `@tool` decorator, MCP adapter
- `sluice/policy/` — YAML loader → compiled rules, Decision + Explanation, trifecta check
- `sluice/monitor/` — attribution middleware (monitor mode) + provider adapters
- `sluice/strict/` — planner, AST-whitelist parser, interpreter, quarantine
- `sluice/graph/` — provenance DAG, DOT/JSON export, self-contained HTML viewer
- `sluice/trace/` — JSONL writer/reader, replay
- `sluice/agent.py` — minimal agent loop; `sluice/llm.py` — LLM protocol + MockLLM
- `sluice/cli.py` — run, replay, policy check, trifecta, bench
- `bench/`, `examples/`, `docs/`

## Hard rules
- FAIL CLOSED. Unknown source → untrusted/secret. Unknown sink → every arg must be trusted.
  Missing policy blocks, never allows. Non-TTY `ask` → block.
- NEVER exec/eval/compile model output. Strict mode is a hand-written AST walker over a whitelist.
- Planner never sees untrusted content.
- No novel attack payloads. Only test fixtures and the AgentDojo suite.
- Tests need no API keys (MockLLM).
- Monitor heuristic misattributes in a test → fix the heuristic, not the test.
- Read installed SDK source before touching provider tool-call formats.
- Non-obvious design choice → record in docs/DECISIONS.md with rejected alternatives.

## Conventions
- Python 3.11+, `mypy --strict`, ruff clean. Pydantic v2 for schemas (policy, trace, quarantine);
  frozen dataclasses for hot-path values (Label, LabeledValue).
- Hypothesis for lattice + interpreter invariants. ≥90% coverage on labels/, policy/, strict/.
- Small conventional commits. Phase done only when suite green, lint + types clean, coverage shown.
- Never touch anything outside the repo.
