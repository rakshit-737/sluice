/**
 * Monitor-mode attribution and guard (port of sluice/monitor).
 *
 * The guard cannot see inside the model, so it infers where each tool-call argument came from
 * by matching it against labelled context values (lineage refs, containment, n-gram overlap),
 * then enforces the policy. See docs/monitor-limits.md in the Python repo for the known
 * evasions this shares by design.
 */

import {
  Integrity,
  Label,
  joinAll,
  labeled,
  type LabeledValue,
} from "./labels.js";
import { Decision, Policy, type ToolSpec } from "./policy.js";

const MODEL_SOURCE = "model";
const REF_KEY = "$ref";

export interface ToolCall {
  readonly id: string;
  readonly name: string;
  readonly arguments: Record<string, unknown>;
  readonly parseError?: string;
}

export function normalise(text: string): string {
  return text.normalize("NFKC").toLowerCase().split(/\s+/).filter(Boolean).join(" ");
}

export function ngrams(text: string, n: number): Set<string> {
  if (text.length < n) return text ? new Set([text]) : new Set();
  const out = new Set<string>();
  for (let i = 0; i <= text.length - n; i++) out.add(text.slice(i, i + n));
  return out;
}

/** Deterministic JSON with sorted object keys (matches Python's json.dumps(sort_keys=True)). */
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const entries = Object.keys(value as Record<string, unknown>)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${stableStringify((value as Record<string, unknown>)[k])}`);
  return `{${entries.join(",")}}`;
}

function asText(value: unknown): string {
  if (typeof value === "string") return value;
  try {
    return stableStringify(value);
  } catch {
    return String(value);
  }
}

type Method = "ref" | "exact" | "contained" | "embeds" | "ngram";

export interface Match {
  readonly valueId: string;
  readonly method: Method;
  readonly score: number;
  readonly path: string;
}

export interface Attribution {
  readonly label: Label;
  readonly matches: Match[];
  readonly generated: boolean;
}

interface Leaf {
  path: string;
  value: unknown;
}

function leaves(value: unknown, path = ""): Leaf[] {
  if (Array.isArray(value)) return value.flatMap((v, i) => leaves(v, `${path}[${i}]`));
  if (value && typeof value === "object") {
    return Object.entries(value).flatMap(([k, v]) => leaves(v, `${path}.${k}`));
  }
  return [{ path, value }];
}

export class Attributor {
  private cache = new Map<string, [string, Set<string>]>();

  constructor(
    readonly n = 5,
    readonly threshold = 0.6,
    readonly minLen = 4,
  ) {
    if (!(threshold > 0 && threshold <= 1)) throw new Error("threshold must be in (0, 1]");
  }

  private prep(lv: LabeledValue<unknown>): [string, Set<string>] {
    let hit = this.cache.get(lv.id);
    if (!hit) {
      const norm = normalise(asText(lv.value));
      hit = [norm, ngrams(norm, this.n)];
      this.cache.set(lv.id, hit);
    }
    return hit;
  }

  attribute(arg: unknown, context: LabeledValue<unknown>[], fallback: Label): Attribution {
    const results = leaves(arg).map((l) => this.attributeLeaf(l.value, l.path, context, fallback));
    if (results.length === 0) return { label: Label.bottom(), matches: [], generated: false };
    return {
      label: joinAll(results.map((r) => r.label)),
      matches: results.flatMap((r) => r.matches),
      generated: results.some((r) => r.generated),
    };
  }

  private attributeLeaf(value: unknown, path: string, context: LabeledValue<unknown>[], fallback: Label): Attribution {
    if (value === null || typeof value === "boolean") return { label: fallback, matches: [], generated: true };
    const arg = normalise(asText(value));
    const byId = new Map(context.map((lv) => [lv.id, lv]));
    const argGrams = ngrams(arg, this.n);
    const matches: Match[] = [];
    let endorsed = false;
    let covered = false;
    for (const lv of context) {
      const [text, grams] = this.prep(lv);
      if (!text) continue;
      if (arg === text) {
        matches.push({ valueId: lv.id, method: "exact", score: 1, path });
        covered = true;
        endorsed ||= lv.label.trusted;
        continue;
      }
      if (arg.length < this.minLen) continue;
      if (text.includes(arg)) {
        matches.push({ valueId: lv.id, method: "contained", score: 1, path });
        covered = true;
        endorsed ||= lv.label.trusted;
      } else if (text.length >= this.minLen && arg.includes(text)) {
        matches.push({ valueId: lv.id, method: "embeds", score: text.length / arg.length, path });
      } else if (argGrams.size && grams.size) {
        let inter = 0;
        for (const g of argGrams) if (grams.has(g)) inter++;
        const score = Math.max(inter / argGrams.size, inter / grams.size);
        if (score >= this.threshold) matches.push({ valueId: lv.id, method: "ngram", score, path });
      }
    }
    const parts = matches.map((m) => byId.get(m.valueId)!.label.withProvenance(m.valueId));
    const generated = !covered;
    if (generated) parts.push(fallback);
    let label = joinAll(parts);
    if (endorsed && label.integrity !== Integrity.Trusted) {
      label = new Label(Integrity.Trusted, label.confidentiality, label.sources, label.provenance);
    }
    return { label, matches, generated };
  }
}

export interface CheckedCall {
  readonly call: ToolCall;
  readonly decision: Decision;
  readonly args: Record<string, unknown>;
  readonly argLabel: Label;
}

/** Monitor-mode middleware: labels context, attributes tool-call args, enforces policy. */
export class Monitor {
  readonly policy: Policy;
  private attributor: Attributor;
  readonly store = new Map<string, LabeledValue<unknown>>();
  readonly context: LabeledValue<unknown>[] = [];
  readonly decisions: Decision[] = [];

  constructor(
    policy: Policy | null,
    readonly registry: Map<string, ToolSpec>,
    attributor?: Attributor,
  ) {
    this.policy = policy ?? Policy.deny();
    this.attributor = attributor ?? new Attributor();
  }

  private add(value: unknown, label: Label, origin: string, attributable = true): LabeledValue<unknown> {
    const lv = labeled(value, label, origin);
    this.store.set(lv.id, lv);
    if (attributable) this.context.push(lv);
    return lv;
  }

  /** Record content entering the context from `source` (e.g. `user`). */
  observe(text: string, source: string, origin?: string): LabeledValue<unknown> {
    return this.add(text, this.policy.sourceLabel(source), origin ?? source);
  }

  /** Label a tool's output: source class joined with its arguments' labels. */
  recordOutput(checked: CheckedCall, output: unknown): LabeledValue<unknown> {
    const spec = this.registry.get(checked.call.name)!;
    const base = this.policy.sourceLabel(spec.source).join(checked.argLabel);
    return this.add(output, base, `${spec.name}()`);
  }

  /** Label a tool result whose call sluice never checked; only the source label applies. */
  recordUnreviewedOutput(toolName: string, output: unknown): LabeledValue<unknown> {
    const spec = this.registry.get(toolName);
    const source = spec ? spec.source : `tool.${toolName || "unknown"}`;
    return this.add(output, this.policy.sourceLabel(source), `${toolName || "?"}() [unreviewed]`);
  }

  check(call: ToolCall): CheckedCall {
    if (call.parseError) {
      const decision = new Decision(call.name, "block", [], `unparseable arguments: ${call.parseError}`);
      this.decisions.push(decision);
      return { call, decision, args: {}, argLabel: Label.bottom() };
    }
    const fallback = this.policy.sourceLabel(MODEL_SOURCE);
    const args: Record<string, unknown> = {};
    const labels = new Map<string, Label>();
    const evidence = new Map<string, string[]>();
    for (const [name, raw] of Object.entries(call.arguments)) {
      const [attr, resolved] = this.attributeArg(raw, fallback);
      args[name] = resolved;
      labels.set(name, attr.label);
      evidence.set(
        name,
        attr.matches.length
          ? attr.matches.map((m) => `${m.method} <- ${m.valueId} score=${m.score.toFixed(2)}`)
          : ["model-generated"],
      );
    }
    const decision = this.policy.decide(call.name, labels, this.registry, evidence);
    this.decisions.push(decision);
    return { call, decision, args, argLabel: joinAll(labels.values()) };
  }

  private attributeArg(raw: unknown, fallback: Label): [Attribution, unknown] {
    const ref = refOf(raw);
    if (ref !== null) {
      const lv = this.store.get(ref);
      if (!lv) return [{ label: Label.unknown(`ref:${ref}`), matches: [], generated: false }, null];
      const label = lv.label.withProvenance(lv.id);
      return [{ label, matches: [{ valueId: lv.id, method: "ref", score: 1, path: "" }], generated: false }, lv.value];
    }
    return [this.attributor.attribute(raw, this.context, fallback), raw];
  }
}

function refOf(raw: unknown): string | null {
  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    const keys = Object.keys(raw);
    if (keys.length === 1 && keys[0] === REF_KEY && typeof (raw as Record<string, unknown>)[REF_KEY] === "string") {
      return (raw as Record<string, string>)[REF_KEY]!;
    }
  }
  return null;
}
