# Monitor mode: how it attributes, and where it fails

Monitor mode is a drop-in middleware for an existing tool-calling loop. It cannot observe how
the model turned its context into a tool call, so it **infers** each argument's origin:

1. **Lineage** — the model passed `{"$ref": "v12"}` for a value it was shown as `[v12] ...`.
   The label is exact. A reference to an unknown id fails closed.
2. **Containment** — after NFKC normalisation, casefolding and whitespace collapsing, the
   argument is a substring of a context value (`contained`), equal to it (`exact`), or embeds
   it (`embeds`). Strings shorter than `min_len` (default 4) match only exactly.
3. **n-gram overlap** — character 5-gram containment in either direction ≥ `threshold`
   (default 0.6).

The argument's label is the join of every match. If no match covers the whole argument, the
rest is model-written text and the policy's `model` source label is joined in too. If a
trusted value contains the whole argument, integrity is endorsed as trusted (DECISIONS D7).

## Known evasions (by design, not bugs)

- **Paraphrase.** "Revenue came in around four point two M" is not attributed to "revenue
  was 4.2 million". A test pins this (`test_paraphrase_evades_monitor_mode`).
- **Encoding/transformation.** Base64, translation, character-by-character spelling,
  summarisation all break textual matching.
- **Implicit flows.** "If the email says X, call tool A, else tool B" leaks one bit per
  decision through *which* call happens, with no data in the arguments.
- **Small fragments.** Exfiltrating a secret a few characters per call stays under the
  thresholds.

These are why **strict mode** exists: there the untrusted text never reaches the planning
model, and labels are tracked exactly by the interpreter instead of inferred.

## What monitor mode is good for

It stops the common, literal case — an injected instruction that makes the model copy an
attacker-chosen address, URL or command into a sink, or paste private data verbatim into an
outbound message — with no change to the agent's architecture, and it produces an
explainable trace and provenance graph for every decision.
