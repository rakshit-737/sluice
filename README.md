# sluice

Information-flow control runtime for LLM agents. Every value an agent touches carries a
security label; flows are tracked through reasoning and tool calls; policy violations are
blocked at the sink. Prompt injection can still fool the model — it can no longer make the
model do anything dangerous.

Status: pre-alpha. See `docs/` for the threat model and design.

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
