# Security policy

sluice is a security control, so bugs that let a policy-violating flow through are treated as
vulnerabilities, including:

- a tool call executing although its policy verdict is `block` (or `ask` without approval)
- a label being lost or raised in integrity / lowered in confidentiality during propagation
- a fail-closed default (unknown source, undeclared sink, missing policy, dangling `$ref`,
  unparseable arguments, non-TTY `ask`) resolving to *allow*
- model output being executed or evaluated anywhere in sluice

Known, documented limitations are **not** vulnerabilities: monitor-mode attribution can be
evaded by paraphrase, encoding and implicit flows (see `docs/monitor-limits.md`).

## Reporting

Please report privately via GitHub's "Report a vulnerability" (Security tab) rather than a
public issue. Include a minimal reproduction: policy, tool registry, and the scripted
`MockLLM` turns that trigger the bypass. Do not include live credentials or real victims'
data. Expect an acknowledgement within 7 days.
