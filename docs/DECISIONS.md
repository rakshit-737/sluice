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

## D11. MCP tools: capability tags from the deployer only, source class per server+tool
MCP servers supply tool names, descriptions and `annotations` (read-only / open-world hints).
Everything a server says about itself is a claim by a party we may not trust, so sluice never
derives capability tags or labels from it. Each tool's source class is `mcp.<server>.<tool>`;
if the policy does not name it, outputs get the fail-closed untrusted/secret label.
Rejected: mapping `readOnlyHint`/`openWorldHint` to caps (a malicious server would declare
itself harmless).

## D12. Drop-in guards remove blocked tool calls from the provider response
The guard cannot execute tools (the caller's loop does), so enforcement means the caller's
loop never *sees* a blocked call. The response keeps its SDK type; blocked calls are removed
and replaced by a text notice with the explanation; if no calls remain, the stop/finish
reason becomes a normal end of turn so loops terminate cleanly. `raise_on_block=True` raises
`SluiceBlocked` instead. Rejected: raising by default (breaks existing loops on every block);
leaving calls in with a flag (an unaware loop would still execute them).

## D13. Streaming is refused by the guards
Tool-call arguments arrive as partial JSON deltas; a guard that passes chunks through cannot
review a call before the caller starts acting on it. `stream=True` raises
`NotImplementedError` rather than silently passing unreviewed output.
Rejected: passthrough with a warning (fail-open).

## D14. Ollama: synthesised call ids
Ollama tool calls carry no id. sluice names them `ollama-<message index>-<call index>` and
pairs each tool result with the oldest unanswered call of the same `tool_name`. This is
stable because chat histories are append-only. Results that cannot be paired are labelled as
unreviewed outputs (source label only).

## D15. Traces are self-contained
The first event of every trace (`session`) carries the compiled policy and the tool manifest
(everything but the callables). `sluice replay` therefore needs nothing but the file, and can
re-decide every call under a different policy for incident review.

## D16. Trifecta coverage criterion
An exfiltration argument is guarded if its effective rule blocks untrusted data or blocks
secret data, and the sink's verdict actually blocks (`log` does not; `ask` does, because it
fails closed). A channel is covered when every argument is guarded; zero-argument channels
carry no data and are covered. Classification uses capability tags *and* policy source
labels, so undeclared sources (fail-closed untrusted/secret) count toward the trifecta.

## D17. Telemetry is a listener, and listener failures cannot affect enforcement
Exporters (OCSF, OpenTelemetry) subscribe to trace events. A raising listener is caught and
recorded as `listener_error`; the decision already taken stands. Rejected: exporting inside
the decision path (a SIEM outage would become an agent outage, or worse, a bypass if the
error were swallowed at the wrong place).

## D18. OCSF Detection Finding (2004) as the SIEM schema
OCSF is the vendor-neutral schema ingested natively by the major SIEMs and AWS Security Lake.
A blocked tool call is a finding with a disposition, which matches Detection Finding better
than an activity class. sluice-specific detail lives in `unmapped`, as OCSF recommends.
Rejected: CEF/LEEF (lossy, no nested evidence), a custom JSON schema (every SIEM needs a parser).

## D19. OPA sees labels, never argument values; stricter verdict wins
Sending values would copy whatever private data the agent handles to the policy service.
Rules over labels (integrity, confidentiality, sources, tool caps) cover the IFC use case.
OPA is combined with the YAML policy by taking the stricter verdict, so adding OPA can only
tighten enforcement. Rejected: OPA-only mode (loses fail-closed YAML defaults), OPA overriding
YAML (a permissive Rego rule could silently relax a block).

## D20. Framework tags are derived from the violated requirement
Integrity failures map to OWASP LLM01/LLM06 and ATLAS AML.T0051.001; confidentiality failures
to LLM02 and AML.T0057. Tags come from *what the rule prevented*, not from guessing the
attacker's intent, so they are deterministic and testable.

## D21. The planner never sees MCP tool descriptions
Descriptions of local tools are written by the deployer and shown to the planner. MCP
descriptions come from the server, so they are untrusted content, and a malicious one is a
prompt injection aimed straight at the privileged model. For `mcp.*` tools the planner sees
only the signature. Rejected: showing all descriptions (defeats the planner's isolation).

## D22. List structure is labelled by the source; record structure by the arguments
A list's length and order come from the data (the attacker decides how many emails arrive),
so iterating it or taking `len()` carries the source label. A record's keys come from the
tool's schema, so `profile().email` keeps the field's own label and per-field `fields:`
sources stay precise. Rejected: labelling containers with the join of their children (loses
field precision) or leaving structure unlabelled (makes loop counts an unlabelled channel).

## D23. Implicit flows are tracked with a pc label; termination is not
`if`, `for`, `a if c else b` and short-circuit `and`/`or` raise the pc label for whatever runs
under them, and tool arguments, assignments and answers join it. The plan stops at the first
block or runtime error, which leaks about one bit through termination. CaMeL accepts the same
channel. Rejected: continuing after a block (changes plan semantics in surprising ways) and
padding execution (not meaningful when tools have side effects).

## D24. The quarantine result inherits the text's label, and quarantine is not a policy sink
The Q-LLM has no tools, and its output is validated against a Pydantic schema, so it can only
produce data. That data is labelled like its input. Quarantine calls are not checked against
sink rules. Deployers must still treat the Q-LLM provider as a processor of whatever text is
sent to it (documented in strict-mode.md).
