# sluice

Information-flow control runtime for LLM agents. Every value an agent touches carries a
security label; flows are tracked through reasoning and tool calls; policy violations are
blocked at the sink. Prompt injection can still fool the model — it can no longer make the
model do anything dangerous.

![sluice blocking an indirect prompt injection in the inbox-assistant demo](docs/demo.svg)

Status: pre-alpha. See `docs/` for the threat model and design.

## How it works

![sluice architecture: monitor mode wraps an existing agent loop and enforces policy at each tool-call sink; strict mode plans with a model that never sees untrusted content and interprets the plan with exact labels; both share the policy, provenance graph, trace, exports and framework tags](docs/architecture.svg)

## Provenance graph

Every run writes a self-contained HTML graph of how data flowed. Here the demo's `read_inbox`
output reaches `send_email`, and the `to` and `body` edges are drawn in red — the blocked flow:

![Provenance graph: read_inbox output flows to send_email; the to and body edges are drawn in red as blocked](docs/screenshots/provenance-graph.png)

## Quickstart

```
uv sync
uv run sluice run examples/inbox-assistant
```

The demo runs the same scripted agent twice. An email in the inbox carries an injected
instruction to forward all invoices to `attacker@example.com`, and the (mock) model obeys it.

- **Vanilla loop:** `send_email(to="attacker@example.com", body=<invoice>)` executes.
- **Under sluice:** the call is blocked. `to` is traced to the untrusted email body, and
  `body` to secret inbox content. The explanation is printed, and a provenance graph
  (`sluice-out/inbox-assistant/graph.html`) opens with the blocked edges in red.

```python
from sluice.agent import Agent
from sluice.monitor import Monitor
from sluice.policy import Policy
from sluice.tools import COMMS, ToolRegistry, tool


@tool(caps=[COMMS])
def send_email(to: str, body: str) -> str: ...


registry = ToolRegistry([send_email, ...])
monitor = Monitor(Policy.load("policy.yaml"), registry)
Agent(llm, registry, monitor).run("Summarize my inbox")
```

### Strict mode

```
uv run sluice run examples/inbox-assistant --mode strict
```

A planner model writes a program from the request alone and never sees an email. The
interpreter runs that program with exact labels. A quarantined model with no tools turns
email text into typed data. In the demo the quarantined model *is* fooled into extracting
`attacker@example.com` as a forwarding address. That value carries the email's untrusted label,
so `send_email` is blocked, while the inbox summary still reaches the user.
See [strict mode](docs/strict-mode.md).

## What's in the box

- **Labels and policy:** an integrity × confidentiality lattice with property-tested laws, and a
  YAML policy that fails closed and explains every decision.
- **Strict mode:** a whitelisted plan language, a label-tracking interpreter with implicit-flow
  labels, and a tool-less quarantine model. Property tests over random plans check that no
  untrusted data reaches a guarded sink and that untrusted data cannot change which calls run.
- **Monitor mode:** drop-in guards for the Anthropic, OpenAI-compatible and Ollama SDKs; MCP tool
  registration; interactive `ask` approvals.
- **Forensics:** self-contained JSONL traces, `sluice replay` with what-if policies, and an
  offline provenance graph.
- **Static audit:** `sluice trifecta` reports whether an agent combines private data, untrusted
  input and exfiltration, and whether each exfiltration argument is guarded (`--strict` for CI,
  `--sarif` for code scanning).
- **Security operations:**
  - OCSF findings for SIEMs and OpenTelemetry spans.
  - Violations tagged with OWASP LLM Top 10 (2025) and MITRE ATLAS IDs.
  - An optional OPA/Rego sink-policy backend.
- **Supply chain:** CI runs CodeQL, pip-audit, gitleaks, Dependabot, and ruff's Bandit rules.
- **TypeScript SDK** (`sdk/typescript`, `@sluice/ifc`): the labels + policy + monitor guard,
  ported for Node/browser agents, plus a language-agnostic **MCP guard proxy**. The same
  `policy.yaml` drives both runtimes.

## Benchmark results

AgentDojo (suite version `v1.2.1`, all four suites), scored with AgentDojo's own utility and
security checks, attacked with its `important_instructions` template. The agent here is a
**worst-case obedient oracle** (no API keys): it performs the user task and then the injection
task's actions, as a fully hijacked model would — so "attack success" with no defence is the
ceiling, and the question is how far each defence drives it down while keeping utility. Run it
yourself with `sluice bench`; see [bench/README.md](bench/README.md) and
[docs/limitations.md](docs/limitations.md) for how to read this.

| suite | defence | utility, no attack | utility under attack | attack success | n (attack) |
|-------|---------|-------------------:|---------------------:|---------------:|-----------:|
| all | none | 100.0% | 61.0% | 61.4% | 949 |
| all | **monitor** | **82.5%** | 79.2% | **8.3%** | 949 |
| banking | none | 100.0% | 86.8% | 100.0% | 144 |
| banking | monitor | 81.2% | 87.5% | 0.0% | 144 |
| travel | none | 100.0% | 18.6% | 82.9% | 140 |
| travel | monitor | 100.0% | 85.7% | 12.1% | 140 |
| workspace | none | 100.0% | 58.2% | 38.9% | 560 |
| workspace | monitor | 87.5% | 80.0% | 7.1% | 560 |
| slack | none | 100.0% | 97.1% | 100.0% | 105 |
| slack | monitor | 57.1% | 55.2% | 21.0% | 105 |

Monitor mode cuts attack success from **61.4% to 8.3%** overall while keeping 82.5% of benign
utility. The residual attack success (highest on slack) is monitor mode's documented heuristic
limit — paraphrased or beacon-style exfiltration that textual attribution misses; strict mode
closes that gap at a further utility cost. The utility cost is real and visible (slack's
destination-guarding is the most aggressive). These are oracle numbers measuring the
*enforcement layer*; real-model numbers need API keys (`sluice bench --agent llm`).

Docs:
- [lattice semantics](docs/lattice.md)
- [strict mode](docs/strict-mode.md)
- [monitor-mode limits](docs/monitor-limits.md)
- [adapters](docs/adapters.md)
- [SIEM / OTel / SARIF](docs/siem.md)
- [OPA](docs/opa.md)
- [framework mapping](docs/frameworks.md)
- [design decisions](docs/DECISIONS.md)
- [security policy](SECURITY.md)
