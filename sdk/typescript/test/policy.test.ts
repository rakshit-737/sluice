import { describe, expect, it } from "vitest";
import { Confidentiality, Integrity, Label } from "../src/labels.js";
import { Policy, PolicyError, type ToolSpec } from "../src/policy.js";

const POLICY = `
version: 1
sources:
  user: {integrity: trusted, confidentiality: internal}
  tool.read_email: {integrity: untrusted, confidentiality: secret}
  tool.web_fetch: {integrity: untrusted, confidentiality: public}
sinks:
  send_email:
    args:
      to: {require_integrity: trusted}
      body: {max_confidentiality: internal}
  shell: {all_args: {require_integrity: trusted}, on_violation: log}
  search: {}
on_violation: block
`;

const registry = new Map<string, ToolSpec>([
  ["send_email", { name: "send_email", source: "tool.send_email" }],
  ["shell", { name: "shell", source: "tool.shell" }],
  ["search", { name: "search", source: "tool.search" }],
  ["mystery", { name: "mystery", source: "tool.mystery" }],
]);

const TRUSTED = new Label(Integrity.Trusted, Confidentiality.Internal, ["user"]);
const UNTRUSTED = new Label(Integrity.Untrusted, Confidentiality.Public, ["tool.web_fetch"]);
const SECRET = new Label(Integrity.Trusted, Confidentiality.Secret, ["vault"]);

function labels(o: Record<string, Label>): Map<string, Label> {
  return new Map(Object.entries(o));
}

describe("policy", () => {
  const pol = Policy.fromYaml(POLICY);

  it("source labels and fail-closed unknown source", () => {
    expect(pol.sourceLabel("tool.read_email").confidentiality).toBe(Confidentiality.Secret);
    expect(pol.sourceLabel("tool.nope").toString()).toBe(Label.unknown("tool.nope").toString());
  });

  it("allows trusted recipient", () => {
    const d = pol.decide("send_email", labels({ to: TRUSTED, body: TRUSTED }), registry);
    expect(d.verdict).toBe("allow");
    expect(d.allowed).toBe(true);
  });

  it("blocks untrusted recipient with explanation", () => {
    const d = pol.decide("send_email", labels({ to: UNTRUSTED, body: TRUSTED }), registry, new Map([["to", ["from web"]]]));
    expect(d.verdict).toBe("block");
    expect(d.violations.map((v) => v.arg)).toEqual(["to"]);
    expect(d.violations[0]!.rule).toBe("policy.sinks.send_email.args.to");
    const text = d.explain();
    expect(text).toContain("integrity untrusted < required trusted");
    expect(text).toContain("evidence: from web");
  });

  it("blocks secret body", () => {
    const d = pol.decide("send_email", labels({ to: TRUSTED, body: SECRET }), registry);
    expect(d.violations.map((v) => v.arg)).toEqual(["body"]);
    expect(d.explain()).toContain("confidentiality secret > allowed internal");
  });

  it("sink on_violation override to log allows", () => {
    const d = pol.decide("shell", labels({ cmd: UNTRUSTED }), registry);
    expect(d.verdict).toBe("log");
    expect(d.allowed).toBe(true);
    expect(d.violations[0]!.rule).toBe("policy.sinks.shell.all_args");
  });

  it("declared empty sink allows anything", () => {
    expect(pol.decide("search", labels({ q: Label.unknown() }), registry).allowed).toBe(true);
  });

  it("undeclared sink requires trusted", () => {
    expect(pol.decide("mystery", labels({ x: UNTRUSTED }), registry).verdict).toBe("block");
    expect(pol.decide("mystery", labels({ x: SECRET }), registry).allowed).toBe(true);
    expect(pol.decide("mystery", labels({ x: UNTRUSTED }), registry).violations[0]!.rule).toContain("fail-closed");
  });

  it("unknown tool blocks", () => {
    const d = pol.decide("rm_rf", new Map(), registry);
    expect(d.verdict).toBe("block");
    expect(d.reason).toBe("unknown tool");
  });

  it("missing policy blocks everything", () => {
    const d = Policy.deny().decide("search", labels({ q: TRUSTED }), registry);
    expect(d.verdict).toBe("block");
    expect(d.reason).toContain("deny-all");
  });

  it("rejects invalid policies", () => {
    for (const bad of [
      "sources: [1, 2]",
      "- a",
      "sources: {user: {integrity: sorta, confidentiality: public}}",
      "on_violation: allow",
      "version: 2",
      "",
    ]) {
      expect(() => Policy.fromYaml(bad)).toThrow(PolicyError);
    }
  });
});
