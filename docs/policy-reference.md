# Policy reference

A sluice policy is a YAML file with three sections. It is validated (unknown keys are
rejected) and compiled to rules. Everything not covered fails closed.

```yaml
version: 1

sources:
  user:            {integrity: trusted,   confidentiality: internal}
  system:          {integrity: trusted,   confidentiality: internal}
  model:           {integrity: trusted,   confidentiality: internal}
  tool.read_email: {integrity: untrusted, confidentiality: secret}
  tool.web_fetch:  {integrity: untrusted, confidentiality: public}

sinks:
  read_email: {}                                   # declared, no constraints
  send_email:
    args:
      to:   {require_integrity: trusted}
      body: {max_confidentiality: internal}
  shell:
    all_args: {require_integrity: trusted}
    on_violation: log

on_violation: block                                # default when a sink does not override
```

## `sources`

Maps a **source class** to the label its data receives.

- `integrity`: `trusted` | `untrusted`
- `confidentiality`: `public` | `internal` | `secret`

Source-class names: `user`, `system`, `model` (text the model wrote itself, used by monitor
mode), and `tool.<name>` for a tool's output. Per-field classes are `tool.<name>.<field>` when
a tool declares `fields=`. MCP tools use `mcp.<server>.<tool>`.

**Any source not listed here gets the fail-closed label `untrusted` / `secret`.** List a source
only to make it *less* restrictive than that.

## `sinks`

Maps a **tool name** to the requirements its arguments must satisfy.

- `args: {<arg>: <requirement>}` — per-argument requirements.
- `all_args: <requirement>` — applies to every argument (combined with any `args` entry by
  taking the stricter of the two).
- `on_violation: block | ask | log` — overrides the top-level default for this sink.

A **requirement** has either or both of:

- `require_integrity: trusted` — the argument's label must be trusted (a Biba check: attacker-
  influenced data cannot reach it).
- `max_confidentiality: public | internal` — the argument's label must be at or below this
  (a Bell-LaPadula check: secret data cannot leave through it).

Rules from the policy and rules declared in tool code (`@tool(sink=...)`) both apply; neither
can weaken the other.

### Fail-closed sink rules

- A tool that is **not** a declared sink (absent from `sinks`, with no in-code requirement) has
  **every argument required trusted**.
- A **declared** sink (even `{}`) constrains only the arguments it names; unlisted arguments are
  unconstrained. A zero-argument tool therefore passes.
- An **unknown tool** (not in the registry) is blocked.

## `on_violation`

What happens when a requirement fails: `block` (default), `ask` (prompt a human; no TTY → block)
or `log` (record and allow). A missing policy blocks everything.

## Decisions

Every decision carries an explanation: the failing argument, its label and sources, the rule
that fired, the provenance/attribution evidence, and the OWASP LLM Top 10 / MITRE ATLAS tags.
See `Decision.explain()` and `Decision.to_json()`.

## Tooling

- `sluice policy check policy.yaml` — validate and print the compiled sources and sinks.
- `sluice trifecta <scenario> --policy policy.yaml` — report whether the policy leaves any
  exfiltration path unguarded.
- `sluice replay trace.jsonl --policy other.yaml` — re-decide a recorded run under a different
  policy.
