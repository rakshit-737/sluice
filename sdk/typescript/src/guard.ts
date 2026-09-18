/**
 * A drop-in guard for a TypeScript tool-calling loop.
 *
 * `ingest` labels new conversation content; `review` checks the model's tool calls and returns
 * only the ones that pass policy, with an explanation for the blocked ones. The caller's loop
 * then only ever executes calls sluice allowed.
 */

import { Label } from "./labels.js";
import { Monitor, type CheckedCall, type ToolCall } from "./monitor.js";
import type { Decision } from "./policy.js";

export type Role = "system" | "user" | "assistant" | "tool";

export interface Message {
  role: Role;
  content?: string;
  toolCalls?: ToolCall[];
  toolCallId?: string;
  name?: string;
}

export class SluiceBlocked extends Error {
  constructor(readonly decisions: Decision[]) {
    super(decisions.map((d) => d.explain()).join("\n\n"));
    this.name = "SluiceBlocked";
  }
}

export interface Review {
  readonly allowed: CheckedCall[];
  readonly blocked: CheckedCall[];
  /** Text describing blocked calls, to append to the reply the model and user see. */
  readonly notice: string;
}

export function parseOutput(content: string): unknown {
  const s = content.trim();
  if (s.startsWith("[") || s.startsWith("{")) {
    try {
      return JSON.parse(s);
    } catch {
      /* fall through */
    }
  }
  return content;
}

export class Guard {
  private seen = new Set<string>();
  private pending = new Map<string, CheckedCall>();

  constructor(
    readonly monitor: Monitor,
    readonly options: { raiseOnBlock?: boolean } = {},
  ) {}

  /** Label everything new in the conversation. Safe to call with the full history each turn. */
  ingest(messages: Message[]): void {
    for (const m of messages) {
      if (m.role === "system" || m.role === "user") {
        const key = `${m.role}:${m.content ?? ""}`;
        if (m.content && !this.seen.has(key)) {
          this.seen.add(key);
          this.monitor.observe(m.content, m.role);
        }
      } else if (m.role === "tool") {
        const key = `tool:${m.toolCallId ?? `${m.name}:${m.content}`}`;
        if (this.seen.has(key)) continue;
        this.seen.add(key);
        const checked = m.toolCallId ? this.pending.get(m.toolCallId) : undefined;
        const output = parseOutput(m.content ?? "");
        if (checked) {
          this.monitor.recordOutput(checked, output);
          this.pending.delete(m.toolCallId!);
        } else {
          this.monitor.recordUnreviewedOutput(m.name ?? "", output);
        }
      }
    }
  }

  review(reply: Message): Review {
    const allowed: CheckedCall[] = [];
    const blocked: CheckedCall[] = [];
    for (const tc of reply.toolCalls ?? []) {
      const checked = this.monitor.check(tc);
      if (checked.decision.allowed) {
        allowed.push(checked);
        this.pending.set(tc.id, checked);
      } else {
        blocked.push(checked);
      }
    }
    if (blocked.length && this.options.raiseOnBlock) {
      throw new SluiceBlocked(blocked.map((c) => c.decision));
    }
    const notice = blocked.map((c) => `[sluice blocked ${c.call.name}]\n${c.decision.explain()}`).join("\n\n");
    return { allowed, blocked, notice };
  }
}

export { Label };
