/**
 * YAML policy loader, compiler, and fail-closed decisions (port of sluice/policy).
 */

import { parse as parseYaml } from "yaml";
import {
  Confidentiality,
  Integrity,
  Label,
  parseConfidentiality,
  parseIntegrity,
} from "./labels.js";

export type Verdict = "allow" | "block" | "ask" | "log";
export type Action = "block" | "ask" | "log";

export class PolicyError extends Error {}

export interface Requirement {
  readonly requireIntegrity?: Integrity;
  readonly maxConfidentiality?: Confidentiality;
}

export function requirementFailures(req: Requirement, label: Label): string[] {
  const out: string[] = [];
  if (req.requireIntegrity !== undefined && label.integrity < req.requireIntegrity) {
    out.push(
      `integrity ${Integrity[label.integrity].toLowerCase()} < required ${Integrity[req.requireIntegrity].toLowerCase()}`,
    );
  }
  if (req.maxConfidentiality !== undefined && label.confidentiality > req.maxConfidentiality) {
    out.push(
      `confidentiality ${Confidentiality[label.confidentiality].toLowerCase()} > allowed ${Confidentiality[req.maxConfidentiality].toLowerCase()}`,
    );
  }
  return out;
}

export function describeRequirement(req: Requirement): string {
  const parts: string[] = [];
  if (req.requireIntegrity !== undefined) parts.push(`require_integrity=${Integrity[req.requireIntegrity].toLowerCase()}`);
  if (req.maxConfidentiality !== undefined)
    parts.push(`max_confidentiality=${Confidentiality[req.maxConfidentiality].toLowerCase()}`);
  return parts.join(", ") || "unconstrained";
}

/** Strictest combination of two requirements (both must hold). */
function meet(a: Requirement, b: Requirement): Requirement {
  const req: { requireIntegrity?: Integrity; maxConfidentiality?: Confidentiality } = {};
  const integ = maxOpt(a.requireIntegrity, b.requireIntegrity);
  const conf = minOpt(a.maxConfidentiality, b.maxConfidentiality);
  if (integ !== undefined) req.requireIntegrity = integ;
  if (conf !== undefined) req.maxConfidentiality = conf;
  return req;
}
const maxOpt = (a?: number, b?: number) => (a === undefined ? b : b === undefined ? a : Math.max(a, b));
const minOpt = (a?: number, b?: number) => (a === undefined ? b : b === undefined ? a : Math.min(a, b));

export interface Violation {
  readonly arg: string;
  readonly label: Label;
  readonly requirement: Requirement;
  readonly rule: string;
  readonly failures: string[];
  readonly evidence: string[];
}

export interface ToolSpec {
  readonly name: string;
  readonly source: string;
  readonly sink?: Record<string, Requirement>;
  readonly allArgs?: Requirement;
}

export class Decision {
  constructor(
    readonly tool: string,
    readonly verdict: Verdict,
    readonly violations: Violation[] = [],
    readonly reason = "",
  ) {}

  /** Whether the call may execute. `ask` must be resolved before this is consulted. */
  get allowed(): boolean {
    return this.verdict === "allow" || this.verdict === "log";
  }

  explain(): string {
    const head = `${this.verdict.toUpperCase()} ${this.tool}${this.reason ? `: ${this.reason}` : ""}`;
    const lines = [head];
    for (const v of this.violations) {
      const srcs = [...v.label.sources].sort().join(", ") || "-";
      lines.push(`argument \`${v.arg}\` is ${v.label.short()} (from ${srcs}): ${v.failures.join("; ")}`);
      lines.push(`  rule: ${v.rule} (${describeRequirement(v.requirement)})`);
      for (const e of v.evidence) lines.push(`  evidence: ${e}`);
    }
    return lines.join("\n");
  }
}

interface RawArg {
  require_integrity?: string;
  max_confidentiality?: string;
}
interface RawSink {
  args?: Record<string, RawArg>;
  all_args?: RawArg;
  on_violation?: Action;
}
interface RawPolicy {
  version?: number;
  sources?: Record<string, { integrity: string; confidentiality: string }>;
  sinks?: Record<string, RawSink>;
  on_violation?: Action;
}

function compileRequirement(raw: RawArg): Requirement {
  const req: { requireIntegrity?: Integrity; maxConfidentiality?: Confidentiality } = {};
  if (raw.require_integrity) req.requireIntegrity = parseIntegrity(raw.require_integrity);
  if (raw.max_confidentiality) req.maxConfidentiality = parseConfidentiality(raw.max_confidentiality);
  return req;
}

interface CompiledSink {
  args: Record<string, Requirement>;
  allArgs?: Requirement;
  onViolation?: Action;
}

export class Policy {
  private constructor(
    readonly sources: Map<string, Label>,
    readonly sinks: Map<string, CompiledSink>,
    readonly onViolation: Action,
    readonly denyAll: boolean,
  ) {}

  static fromYaml(text: string): Policy {
    let data: unknown;
    try {
      data = parseYaml(text);
    } catch (e) {
      throw new PolicyError(`invalid YAML: ${(e as Error).message}`);
    }
    if (data === null || data === undefined) throw new PolicyError("policy must be a mapping");
    if (typeof data !== "object" || Array.isArray(data)) throw new PolicyError("policy must be a mapping");
    return Policy.fromObject(data as RawPolicy);
  }

  static fromObject(raw: RawPolicy): Policy {
    try {
      return Policy.compile(raw);
    } catch (e) {
      if (e instanceof PolicyError) throw e;
      throw new PolicyError((e as Error).message);
    }
  }

  private static compile(raw: RawPolicy): Policy {
    if (raw.version !== undefined && raw.version !== 1) throw new PolicyError(`unsupported version: ${raw.version}`);
    if (raw.on_violation && !["block", "ask", "log"].includes(raw.on_violation))
      throw new PolicyError(`invalid on_violation: ${raw.on_violation}`);
    const sources = new Map<string, Label>();
    for (const [name, s] of Object.entries(raw.sources ?? {})) {
      sources.set(name, new Label(parseIntegrity(s.integrity), parseConfidentiality(s.confidentiality), [name]));
    }
    const sinks = new Map<string, CompiledSink>();
    for (const [name, sraw] of Object.entries(raw.sinks ?? {})) {
      const s = sraw as RawSink;
      const args: Record<string, Requirement> = {};
      for (const [arg, a] of Object.entries(s.args ?? {})) args[arg] = compileRequirement(a);
      const sink: CompiledSink = { args };
      if (s.all_args) sink.allArgs = compileRequirement(s.all_args);
      if (s.on_violation) sink.onViolation = s.on_violation;
      sinks.set(name, sink);
    }
    return new Policy(sources, sinks, raw.on_violation ?? "block", false);
  }

  /** The policy used when none is configured: every tool call is blocked. */
  static deny(): Policy {
    return new Policy(new Map(), new Map(), "block", true);
  }

  /** Label for data from `source`. Unknown sources get the fail-closed label. */
  sourceLabel(source: string): Label {
    return this.sources.get(source) ?? Label.unknown(source);
  }

  requirements(spec: ToolSpec, argNames: string[]): Map<string, [Requirement, string]> {
    const sink = this.sinks.get(spec.name);
    const declared = sink !== undefined || (spec.sink && Object.keys(spec.sink).length > 0) || spec.allArgs !== undefined;
    const out = new Map<string, [Requirement, string]>();
    for (const arg of argNames) {
      if (!declared) {
        out.set(arg, [{ requireIntegrity: Integrity.Trusted }, `fail-closed: \`${spec.name}\` is not a declared sink`]);
        continue;
      }
      let req: Requirement = {};
      const rules: string[] = [];
      if (sink && arg in sink.args) {
        req = meet(req, sink.args[arg]!);
        rules.push(`policy.sinks.${spec.name}.args.${arg}`);
      }
      if (sink?.allArgs) {
        req = meet(req, sink.allArgs);
        rules.push(`policy.sinks.${spec.name}.all_args`);
      }
      if (spec.sink && arg in spec.sink) {
        req = meet(req, spec.sink[arg]!);
        rules.push(`tool.${spec.name}.sink.${arg}`);
      }
      if (spec.allArgs) {
        req = meet(req, spec.allArgs);
        rules.push(`tool.${spec.name}.all_args`);
      }
      out.set(arg, [req, rules.join(" + ") || "unconstrained"]);
    }
    return out;
  }

  decide(
    toolName: string,
    argLabels: Map<string, Label>,
    registry: Map<string, ToolSpec>,
    evidence: Map<string, string[]> = new Map(),
  ): Decision {
    if (this.denyAll) return new Decision(toolName, "block", [], "no policy configured (deny-all)");
    const spec = registry.get(toolName);
    if (!spec) return new Decision(toolName, "block", [], "unknown tool");
    const violations: Violation[] = [];
    for (const [arg, [req, rule]] of this.requirements(spec, [...argLabels.keys()])) {
      const label = argLabels.get(arg)!;
      const failures = requirementFailures(req, label);
      if (failures.length > 0) {
        violations.push({ arg, label, requirement: req, rule, failures, evidence: evidence.get(arg) ?? [] });
      }
    }
    if (violations.length === 0) return new Decision(toolName, "allow");
    const sink = this.sinks.get(toolName);
    const verdict: Verdict = sink?.onViolation ?? this.onViolation;
    return new Decision(toolName, verdict, violations, "policy violation");
  }
}
