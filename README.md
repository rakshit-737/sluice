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

Docs: [lattice semantics](docs/lattice.md) · [monitor-mode limits](docs/monitor-limits.md) ·
[design decisions](docs/DECISIONS.md)
