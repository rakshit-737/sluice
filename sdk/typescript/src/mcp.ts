/**
 * A language-agnostic enforcement point: a guard that sits between an MCP client (the agent)
 * and an MCP server, and blocks policy-violating `tools/call` requests before they reach the
 * server. Any agent in any language gets sluice by routing its MCP traffic through this.
 *
 * `McpGuard` is a pure message processor over JSON-RPC 2.0 messages, so it is testable without
 * a live server; `bin/sluice-mcp-guard.ts` wires it to stdio and spawns the real server.
 *
 * What it does:
 *  - learns the tool set from `tools/list` results (source class `mcp.<server>.<tool>`);
 *  - labels each `tools/call` result as untrusted output of that tool;
 *  - attributes each new `tools/call`'s arguments against prior results and enforces the policy;
 *  - answers a blocked call with a JSON-RPC error instead of forwarding it.
 *
 * A pure MCP boundary has no trusted user prompt, so an argument that matches a prior tool
 * result is untrusted, and model-generated arguments get the policy's `model` source label.
 */

import { Monitor, type ToolCall } from "./monitor.js";
import { Policy, type ToolSpec } from "./policy.js";

export interface JsonRpcMessage {
  jsonrpc: "2.0";
  id?: string | number | null;
  method?: string;
  params?: Record<string, unknown>;
  result?: Record<string, unknown>;
  error?: { code: number; message: string; data?: unknown };
}

/** What the guard decides to do with a message travelling from the client to the server. */
export interface GuardAction {
  /** The message to forward on (unchanged), or undefined to drop it. */
  forward?: JsonRpcMessage;
  /** A message to send straight back to the origin (a synthesised block response). */
  respond?: JsonRpcMessage;
  /** The decision, when a tools/call was checked. */
  blocked?: boolean;
}

const BLOCK_CODE = -32001; // implementation-defined server error range

export class McpGuard {
  readonly registry = new Map<string, ToolSpec>();
  readonly monitor: Monitor;
  private pending = new Map<string | number, string>(); // request id -> tool name

  constructor(
    policy: Policy | null,
    readonly server = "mcp",
  ) {
    this.monitor = new Monitor(policy ?? Policy.deny(), this.registry);
  }

  /** Process a message from the client (agent) heading to the server. */
  fromClient(msg: JsonRpcMessage): GuardAction {
    if (msg.method === "tools/call" && msg.params) {
      const name = String(msg.params["name"]);
      const args = (msg.params["arguments"] as Record<string, unknown>) ?? {};
      const call: ToolCall = { id: String(msg.id ?? name), name, arguments: args };
      const checked = this.monitor.check(call);
      if (!checked.decision.allowed) {
        return {
          blocked: true,
          respond: {
            jsonrpc: "2.0",
            id: msg.id ?? null,
            result: {
              isError: true,
              content: [{ type: "text", text: `Blocked by sluice policy.\n${checked.decision.explain()}` }],
            },
          },
        };
      }
      if (msg.id !== undefined && msg.id !== null) this.pending.set(msg.id, name);
      return { forward: msg, blocked: false };
    }
    return { forward: msg };
  }

  /** Process a message from the server heading to the client. */
  fromServer(msg: JsonRpcMessage): GuardAction {
    if (msg.result) {
      const tools = msg.result["tools"];
      if (Array.isArray(tools)) this.learnTools(tools);
      if (msg.id !== undefined && msg.id !== null && this.pending.has(msg.id)) {
        const name = this.pending.get(msg.id)!;
        this.pending.delete(msg.id);
        this.recordResult(name, msg.result);
      }
    }
    return { forward: msg };
  }

  private learnTools(tools: unknown[]): void {
    for (const t of tools) {
      const tool = t as { name?: string };
      if (tool.name && !this.registry.has(tool.name)) {
        this.registry.set(tool.name, { name: tool.name, source: `mcp.${this.server}.${tool.name}` });
      }
    }
  }

  private recordResult(name: string, result: Record<string, unknown>): void {
    const content = result["structuredContent"] ?? textOf(result["content"]);
    // Synthesise a CheckedCall-shaped record so recordOutput labels the output correctly.
    this.monitor.recordUnreviewedOutput(name, content);
  }
}

function textOf(content: unknown): string {
  if (!Array.isArray(content)) return "";
  return content
    .map((b) => (b && typeof b === "object" && "text" in b ? String((b as { text: unknown }).text) : ""))
    .join("\n");
}

export { BLOCK_CODE };
