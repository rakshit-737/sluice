# Design decisions

Each entry: decision, why, alternatives rejected.

## D1. License: Apache-2.0
Patent grant matters for a security library adopted by companies. Rejected: MIT (no patent grant).

## D2. LabeledValue is a frozen dataclass, not a Pydantic model
Labels are created and joined on every string op and tool call; Pydantic validation cost is
wasted there. Pydantic is used at trust boundaries only (policy files, traces, quarantine output).
Rejected: Pydantic everywhere (slow, and mutable-by-default models invite label tampering).

## D3. Integrity and confidentiality as IntEnums
Ordering is then plain integer comparison, which keeps the lattice ops obviously correct.
Integrity: untrusted=0 < trusted=1. Confidentiality: public=0 < internal=1 < secret=2.
Rejected: string enums with lookup tables (more code, same semantics).

## D4. Tool-declared and policy-declared sink requirements are combined with `meet`
A tool author can declare requirements in code (`@tool(sink=...)`); the deployer can declare
them in YAML. Both must hold, so neither party can weaken the other's rule.
Rejected: policy overrides tool (lets a sloppy YAML silently drop a tool author's guard).

## D5. Undeclared sink → every argument must be trusted; declared sink → unlisted args free
A tool with no requirements anywhere is unknown, so it fails closed. Once a sink is declared
(even as `{}`), the policy author has made an explicit decision about it, and arguments they
did not list are unconstrained. Tools called with zero arguments carry no attacker data in,
so they pass. Rejected: unlisted args of a declared sink also require trusted (makes every
policy enumerate every argument; authors then write `all_args: {}` workarounds).

## D6. Monitor mode: model-generated text gets the policy's `model` source label
Monitor mode cannot see how the model produced text that matches nothing in its context.
Labelling it with the join of the whole context is sound but blocks nearly every useful
action once any untrusted content has been read (that is what strict mode is for). So
unexplained text gets the `model` source label, which the policy sets explicitly; if the
policy omits `model`, it fails closed to untrusted/secret. Documented in monitor-limits.md.

## D7. Monitor mode: trusted containment endorses integrity
If the whole argument appears verbatim in a trusted value (e.g. the user prompt), the
attacker cannot have chosen it, so its integrity is trusted even if an untrusted email also
mentions it. Confidentiality is still the join over every match. Without this, a user asking
to "email bob@corp.example" is blocked whenever Bob's address also appears in an email.
Rejected: plain join (breaks benign tasks, which the brief says to fix in the heuristic).

## D8. Tool output label = source label ⊔ labels of the call's arguments
A tool's output depends on its inputs (fetching an attacker-chosen URL returns attacker
content even from a "trusted" tool). Rejected: source label only (launders integrity).

## D9. Structured tool outputs: every leaf is its own labelled value
Leaves get their own ids, so attribution and the provenance graph point at the exact field
(`read_inbox()[2].body`) and `fields:` can give different fields different source classes.
The root is kept in the trace but not used for attribution (it would duplicate every match).

## D10. Provenance HTML is static SVG, no JavaScript, no CDN
The viewer must open offline from a trace, and a security tool's report should not execute
code. All text is HTML-escaped (tool outputs are attacker-controlled).
Rejected: d3/dagre via CDN (network dependency, script execution in the report).
