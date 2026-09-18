# Threat model

## Assets

- **Private data** the agent can read (inbox, files, balances, secrets).
- **The ability to act** through tools with side effects (send, pay, delete, share, post).
- **Integrity of decisions**: which tool runs, with which arguments.

## Adversary

An attacker who controls **content the agent ingests** but not the agent's code, its policy,
the user's request, or the model provider. The canonical vector is *indirect prompt
injection*: text in an email, web page, file or tool result that the model reads and treats as
instructions. The attacker's goals are the "lethal trifecta" outcomes: exfiltrate private data
to a channel they control, or drive a privileged action (pay, delete, grant access) with
attacker-chosen arguments.

Out of scope: a compromised or malicious model provider, a malicious user, supply-chain
compromise of sluice or its dependencies, side channels below the label model (timing, tokens
billed), and the physical/host layer. sluice is one control in a defence in depth.

## Trust boundary

The boundary is **provenance of data, not the model's intent**. Every value is labelled by
where it came from:

- integrity — `trusted` (user, system, program constants) vs `untrusted` (anything derived
  from ingested content);
- confidentiality — `public` / `internal` / `secret`.

Labels propagate through reasoning and tool calls (exactly in strict mode, heuristically in
monitor mode) and are enforced at **sinks**: a tool argument must satisfy the policy's
requirement, or the call is blocked / asked / logged.

## Why injection becomes harmless

A successful injection still changes what the model *wants* to do. It cannot change the
**label** of the data it is working with. If the attacker's address is untrusted, it fails the
`require_integrity: trusted` check on `send_money.recipient` no matter how the model was
convinced to use it. The model is fooled; the flow is refused.

## Assumptions the guarantee rests on

- **The policy is correct.** sluice enforces the policy you write; a missing sink rule is an
  open door. Fail-closed defaults and `sluice trifecta` reduce, but do not remove, this burden.
- **Source classification is correct.** A tool whose output is really attacker-influenced must
  be labelled untrusted. Unknown sources fail closed to untrusted/secret.
- **Monitor mode's heuristics hold for the case at hand.** They can be evaded (see
  [monitor-mode limits](monitor-limits.md)); strict mode removes the heuristic.
- **In strict mode, the planner and quarantine models are the isolation they claim to be:** the
  planner never receives ingested content, and the quarantine model has no tools.

## Residual channels

- **Termination** in strict mode (about one bit per run; see [limitations](limitations.md)).
- **Policy-permitted flows.** If the policy allows a flow, sluice allows it; `ask` mode puts a
  human in that loop.
- **The labelled answer.** Untrusted content still reaches the user through the final answer,
  carrying its label for the UI to act on.
