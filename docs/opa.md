# OPA / Rego sink policies

Teams that already manage authorization in Open Policy Agent can express sluice's sink rules
in Rego. The YAML policy still defines **source labels**; OPA adds sink rules on top.

```python
from sluice.policy import Policy
from sluice.policy.opa import OpaCli, OpaHttp, OpaPolicy

base = Policy.load("policy.yaml")
engine = OpaPolicy(base, OpaHttp("http://opa.internal:8181"))  # OPA server
engine = OpaPolicy(base, OpaCli(("examples/policies/sluice.rego",)))  # local `opa eval`
monitor = Monitor(engine, registry)
```

## Contract

Input, one document per tool call (labels only, never argument values):

```json
{"tool": "send_email", "caps": ["comms"], "source": "tool.send_email",
 "args": {"to": {"integrity": "untrusted", "confidentiality": "secret",
                 "sources": ["tool.read_inbox"]}}}
```

Output at `data.sluice.decision`:

```json
{"allow": false, "verdict": "block", "reasons": [{"arg": "to", "msg": "..."}]}
```

`verdict` is optional (`block` by default when `allow` is false). See
[`examples/policies/sluice.rego`](../examples/policies/sluice.rego); CI runs it against a real
`opa` binary.

## Combination and failure semantics

- A call must pass **both** engines; the stricter verdict wins
  (`block` > `ask` > `log` > `allow`). OPA cannot relax a YAML block.
- Fail closed: a transport error, timeout, undefined decision, non-boolean `allow`, or an
  unknown verdict blocks the call and says why.
- `OpaCli` runs `opa eval` with a fixed argv, no shell, and the input on stdin.
- Traces record the YAML policy plus an `x-opa` note naming the Rego source; offline
  `sluice replay` re-decides with the YAML part only.
