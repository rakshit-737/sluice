# @sluice/ifc

Information-flow control for LLM agents, in TypeScript. Every value an agent touches carries a
security label; a YAML policy is enforced at the sinks (tool calls); a drop-in guard removes
policy-violating calls from what the model asked to do. This is a faithful port of the
[sluice](../../README.md) monitor-mode core — same label lattice, same policy files.

Scope: labels + lattice, YAML policy compiler with fail-closed decisions, monitor-mode
attribution, and a guard for a tool-calling loop. Strict mode and provider adapters live in the
Python package.

## Install

```
npm install @sluice/ifc yaml
```

## Use

```ts
import { Policy, Monitor, Guard, type Message } from "@sluice/ifc";
import { readFileSync } from "node:fs";

const registry = new Map([
  ["read_inbox", { name: "read_inbox", source: "tool.read_inbox" }],
  ["send_email", { name: "send_email", source: "tool.send_email" }],
]);

const policy = Policy.fromYaml(readFileSync("policy.yaml", "utf8"));
const guard = new Guard(new Monitor(policy, registry));

// Each turn, before calling the model:
guard.ingest(messages);            // labels new user/tool content
const review = guard.review(reply); // reply = the model's message with tool calls
for (const call of review.allowed) { /* execute — these passed policy */ }
if (review.blocked.length) console.log(review.notice); // explanations for the rest
```

The same `policy.yaml` works in the Python and TypeScript runtimes. See the
[policy reference](../../docs/policy-reference.md) and, for what monitor-mode attribution can
and cannot catch, the [monitor-mode limits](../../docs/monitor-limits.md).

## Semantics (identical to the Python core)

- **Lattice.** integrity `untrusted < trusted`, confidentiality `public < internal < secret`;
  join takes the lower integrity and higher confidentiality and unions the source/provenance
  sets. Property-tested with fast-check.
- **Fail closed.** Unknown source → untrusted/secret. Undeclared sink → every argument must be
  trusted. Missing policy → block. Dangling `$ref` / unparseable args → block.
- **Attribution.** `$ref` lineage, normalised containment, and character n-gram overlap; a
  trusted value containing the whole argument endorses integrity.

## Develop

```
npm install
npm run typecheck
npm test        # vitest, incl. fast-check property tests
npm run build
```

Apache-2.0.

## MCP guard proxy (language-agnostic)

Put sluice in front of any MCP server, so an agent in *any* language gets enforcement by
routing its MCP traffic through the proxy:

```
npx sluice-mcp-guard --policy policy.yaml --server files -- \
  npx -y @modelcontextprotocol/server-filesystem /data
```

The proxy learns the tool set from `tools/list`, labels every `tools/call` result as untrusted
output of that tool (`mcp.<server>.<tool>`), attributes each new call's arguments against prior
results, and answers a policy-violating call with a JSON-RPC error instead of forwarding it. The
enforcement core (`McpGuard`) is a pure message processor, exported from `@sluice/ifc/mcp`.
