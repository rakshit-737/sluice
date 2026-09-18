# Deploying sluice with an OPA sidecar

A deployable topology where sluice enforces sink policy through an [Open Policy
Agent](https://www.openpolicyagent.org/) (Rego) sidecar. The YAML policy still defines source
labels; OPA adds sink rules, and the stricter verdict wins (see [../docs/opa.md](../docs/opa.md)).

```
docker compose -f deploy/docker-compose.yml up --build
```

- **`opa`** serves [`../examples/policies/sluice.rego`](../examples/policies/sluice.rego) on
  `:8181`.
- **`sluice-opa-demo`** builds an `OpaPolicy` pointed at the `opa` service, decides a tool call,
  and prints the block. Point its command at `sluice run …` or `sluice bench …` to run a real
  agent through the same engine.

Fail-closed by design: if OPA is unreachable, sluice blocks the call (`opa_demo.py` demonstrates
this too).

## Files

| file | purpose |
|------|---------|
| `Dockerfile` | sluice runtime image (uv, frozen lockfile) |
| `docker-compose.yml` | OPA sidecar + a demo sluice service |
| `opa_demo.py` | queries the running OPA server and prints a decision |

> Not run in CI (needs Docker); validated for syntax and the fail-closed code path. Adapt the
> image tags and resource limits for your environment before production use.
