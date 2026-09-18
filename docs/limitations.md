# Limitations

sluice is an architectural defence, not a detector. It is worth being precise about what it
does and does not give you.

## What sluice does not do

- **It does not stop the model being fooled.** A prompt injection can still make the model say
  or plan the wrong thing. sluice constrains what that wrong thing can *reach*: a labelled sink.
- **It does not classify or detect attacks.** There is no scanner, no model of "malicious"
  text. A benign string and an attack string with the same provenance get the same label.
- **It does not protect against a compromised model provider, a malicious user request, or a
  buggy tool.** The trust boundary is *content*, not the operator or the code.

## Monitor mode

Attribution is heuristic (see [monitor-mode limits](monitor-limits.md)). Paraphrase, encoding,
translation, summarisation and character-level splitting all break textual matching, and
implicit flows ("if the email says X, call tool A") are not tracked at all. Monitor mode stops
the common literal case with no change to your agent; strict mode is the answer when you need
a guarantee.

## Strict mode

- **Termination channel.** A plan halts at its first blocked call or runtime error, so *whether*
  later calls run can depend on untrusted data — roughly one bit per run. CaMeL has the same
  channel. It is not a general exfiltration primitive, but it is not zero.
- **Utility cost.** A plan written without seeing the data cannot adapt to it. Tasks whose point
  is to act on untrusted content ("reply to whoever emailed me", "pay the invoice in this PDF")
  are blocked unless the policy allows that specific flow or a human approves it. The benchmark
  numbers make this cost visible.
- **The quarantine model is a data processor.** Text handed to `quarantine()` is sent to that
  model's provider; treat it accordingly.
- **The answer is labelled, not withheld.** Untrusted content still reaches the user through
  `answer()`; the label is for the UI to act on.

## Policy is the hard part

sluice enforces the policy you write. A policy that forgets to guard an exfiltration argument
does not protect it — which is why `sluice trifecta` exists and why the fail-closed defaults
matter. Getting the source classification right (which tool outputs are untrusted, which are
secret) is a real modelling task, not a default.

## Scope of the benchmark

The AgentDojo numbers below use one attack (`important_instructions`) and, for the keyless CI
run, a *worst-case obedient oracle* rather than a real model. That measures the enforcement
layer, not a specific model's susceptibility. Real-model numbers depend on the model and need
API keys; `sluice bench --agent llm --model provider:model` reproduces them.

## Comparison

| approach | mechanism | stops paraphrased exfiltration | needs no policy | drop-in |
|----------|-----------|:-:|:-:|:-:|
| guardrail / input scanners | classify text as malicious | probabilistic | ✓ | ✓ |
| sluice monitor mode | label + attribute + enforce at sinks | ✗ (documented) | ✗ | ✓ |
| sluice strict mode / CaMeL | planner isolated from content, exact labels | ✓ | ✗ | ✗ |

sluice is complementary to scanners: use a scanner to reduce how often the model is fooled,
and sluice to bound what happens when it is.
