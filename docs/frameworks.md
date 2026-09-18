# Threat-framework mapping

Every violation sluice reports is tagged so SOC tooling and reports can use standard IDs.
Tags appear in `Decision.explain()` ("maps to: ..."), in trace `call` events, and in the
OCSF export.

| violation                                              | OWASP LLM Top 10 (2025)                 | MITRE ATLAS                               |
|--------------------------------------------------------|-----------------------------------------|-------------------------------------------|
| untrusted data reaches an argument requiring trusted   | LLM01 Prompt Injection; LLM06 Excessive Agency | AML.T0051.001 LLM Prompt Injection: Indirect |
| data above an argument's confidentiality bound         | LLM02 Sensitive Information Disclosure  | AML.T0057 LLM Data Leakage                 |

How sluice relates to each risk:

- **LLM01 / AML.T0051.001** — sluice does not detect injections; it makes them harmless at
  the sink by refusing to let attacker-influenced data drive privileged arguments.
- **LLM06** — per-argument sink rules bound what an agent may do with data of each label,
  which is the "least privilege for tools" mitigation OWASP recommends.
- **LLM02 / AML.T0057** — confidentiality bounds stop private data from leaving through
  outbound tools, including when an injection asks for it.

The lethal-trifecta check (`sluice trifecta`) is a static audit for LLM06: it lists every
exfiltration channel and whether each argument is guarded.

ATLAS IDs are taken from the ATLAS matrix at the time of writing; check the current release
at https://atlas.mitre.org before relying on them in reports.
