# Security operations integration

sluice emits its decisions in the formats SOC tooling already ingests.

| output | for | how |
|--------|-----|-----|
| OCSF Detection Finding (class 2004) JSONL | Splunk, Elastic, Sentinel, Security Lake, Datadog | `sluice run --ocsf findings.jsonl`, `OcsfExporter` listener, or `sluice replay trace.jsonl --ocsf ...` to backfill |
| OpenTelemetry spans | Jaeger, Tempo, Honeycomb, Datadog APM | `OtelExporter()` listener (`pip install sluice[otel]`) |
| SARIF 2.1.0 | GitHub code scanning, any SARIF viewer | `sluice trifecta <dir> --sarif trifecta.sarif` |
| JSONL trace | forensics, replay | always written by `sluice run` |

## Listeners

Exporters subscribe to the trace:

```python
from sluice.export.ocsf import OcsfExporter
from sluice.export.otel import OtelExporter
from sluice.trace import TraceWriter

trace = TraceWriter("trace.jsonl", listeners=[OcsfExporter("/var/log/sluice/ocsf.jsonl"),
                                               OtelExporter()])
monitor = Monitor(policy, registry, trace=trace)
```

A listener that raises cannot break enforcement: the error is recorded as a
`listener_error` trace event and the decision stands.

## OCSF mapping

| OCSF field | value |
|------------|-------|
| `class_uid` / `category_uid` / `type_uid` | 2004 Detection Finding / 2 Findings / 200401 |
| `action_id` | 2 Denied for `block`/`ask`, 1 Allowed otherwise |
| `disposition_id` | 2 Blocked, 17 Logged (`log` verdict), 1 Allowed |
| `severity_id` | 4 High for enforced label violations, 3 Medium for logged or structural blocks |
| `finding_info.uid` | `<session uuid>:<call id>` |
| `finding_info.types` | OWASP LLM Top 10 / ATLAS tags ([frameworks.md](frameworks.md)) |
| `finding_info.attacks` | MITRE ATLAS techniques |
| `unmapped.sluice` | tool, verdict, violations, per-argument attribution |

By default only non-allowed calls are exported; pass `include_allowed=True` for full audit.

## OpenTelemetry

One span per decision, `sluice.decide <tool>`, with `gen_ai.tool.name`, `sluice.verdict`,
`sluice.session_id`, `sluice.tags`; blocked calls get ERROR status and a
`sluice.violation` event per failing argument.

## CI

`.github/workflows/security.yml` runs pip-audit, gitleaks and `sluice trifecta --strict`
and uploads the SARIF (to code scanning when the repository is public; as a build artifact
always). `codeql.yml` runs CodeQL `security-extended`.
