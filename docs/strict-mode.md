# Strict mode

Strict mode is sluice's CaMeL-style enforcement. Monitor mode *infers* where a tool argument
came from; strict mode *knows*, because the model never touches untrusted data and the
program that does is interpreted with exact labels.

```
user request ─▶ Planner LLM ─▶ plan (restricted Python) ─▶ Interpreter ─▶ tools
                  ▲  sees only: request, tool signatures,      │  every value labelled,
                  │  schema names, its own parse errors         │  policy checked at every call
                                                                ▼
                       untrusted text ─▶ quarantine(text, "Schema") ─▶ Q-LLM (no tools)
                                          result inherits the text's label
```

```
sluice run examples/inbox-assistant --mode strict
```

## The plan language

A whitelisted subset of Python, checked node by node (`sluice/strict/dsl.py`). Allowed:
assignments to plain names, calls by plain name to registered tools and builtins, literals,
f-strings, lists, dicts, `x[i]`, `x.field`, `+`, comparisons, `and`/`or`/`not`,
`a if c else b`, `if`/`elif`/`else`, `for name in ...:`, `pass`.

Builtins: `len str int float lower upper strip split join contains startswith endswith`,
plus `answer(value)` and `quarantine(text, "Schema")`.

Everything else is a `PlanSyntaxError`: imports, def/lambda/class, while, comprehensions,
method calls, `*`/`**`, slicing, names or attributes starting with `_`, assignment to tool
names. The plan is parsed with `ast.parse`; it is never compiled or executed by Python.

## Labels at run time

- Tool outputs are label trees. Scalars carry the tool's (or field's) source label joined with
  the call's argument labels. A list's *structure* (length, order) carries the source label;
  a record's structure carries only the argument labels, because its keys come from the schema.
- Indexing joins the child's label with the container's structure label and the index's label.
- Operators and builtins join their operands' labels.
- **Implicit flows:** `if`, `for`, conditional expressions and short-circuit `and`/`or` raise
  the pc label. Assignments, tool arguments and answers made under a raised pc carry it.
- **Quarantine:** the result is labelled with the input text's label, joined with the pc.
  A quarantined model that gets fooled produces wrong data with an untrusted label. It
  cannot produce an action.

## What is guaranteed (and tested)

`tests/test_strict_invariant.py` generates hundreds of random plans over an untrusted
source, a trusted source, quarantine and a guarded sink, and checks two properties:

1. **No untrusted-to-sink flow.** The sink never receives data derived from the untrusted
   source in an argument that requires trusted integrity or bounds confidentiality.
2. **Noninterference up to termination.** Two runs of the same plan over different untrusted
   data execute the same sink calls, except that one run may stop earlier.

As a control, the same generator run with enforcement disabled finds leaking plans (about 1
in 9) and diverging plans (about 1 in 13). With enforcement on, it finds none.

## Limits

- **Termination channel.** A plan stops at the first blocked call, and a runtime error (such as
  an index past the end of an untrusted list) also stops it. *Whether* later calls happen can
  therefore depend on untrusted data, leaking about one bit per run. CaMeL has the same channel.
- **The answer is labelled, not filtered.** `answer()` returns untrusted content to the user
  with its label (`StrictResult.answer_label`). Showing it to the user is the point; the label
  lets the UI warn.
- **The quarantine is a data sink too.** Text given to `quarantine()` is sent to the Q-LLM
  provider. Choose the provider as you would any processor of that data.
- **Utility cost.** A plan written without seeing the data cannot adapt to it. Tasks that need
  to act on untrusted content (for example "reply to whoever emailed me") are blocked by design
  unless the policy allows that flow or a human approves it (`on_violation: ask`).
- **The planner must be honest.** Strict mode protects against *content*, not against a
  compromised planner provider or a malicious user request.
