import { describe, expect, it } from "vitest";
import fc from "fast-check";
import {
  Confidentiality,
  Integrity,
  Label,
  derive,
  joinAll,
  labeled,
  lconcat,
  ldict,
  lift,
  llist,
  parseConfidentiality,
  parseIntegrity,
  resetIds,
} from "../src/labels.js";

const arbLabel = fc
  .record({
    i: fc.constantFrom(Integrity.Untrusted, Integrity.Trusted),
    c: fc.constantFrom(Confidentiality.Public, Confidentiality.Internal, Confidentiality.Secret),
    s: fc.subarray(["user", "web", "email", "fs"]),
    p: fc.subarray(["v1", "v2", "v3", "v4"]),
  })
  .map(({ i, c, s, p }) => new Label(i, c, s, p));

function labelEq(a: Label, b: Label): boolean {
  return (
    a.integrity === b.integrity &&
    a.confidentiality === b.confidentiality &&
    [...a.sources].sort().join() === [...b.sources].sort().join() &&
    [...a.provenance].sort().join() === [...b.provenance].sort().join()
  );
}

describe("label lattice", () => {
  it("join is commutative", () => {
    fc.assert(fc.property(arbLabel, arbLabel, (a, b) => labelEq(a.join(b), b.join(a))));
  });
  it("join is associative", () => {
    fc.assert(
      fc.property(arbLabel, arbLabel, arbLabel, (a, b, c) => labelEq(a.join(b).join(c), a.join(b.join(c)))),
    );
  });
  it("join is idempotent", () => {
    fc.assert(fc.property(arbLabel, (a) => labelEq(a.join(a), a)));
  });
  it("bottom is the identity", () => {
    fc.assert(fc.property(arbLabel, (a) => labelEq(Label.bottom().join(a), a)));
  });
  it("join is an upper bound", () => {
    fc.assert(
      fc.property(arbLabel, arbLabel, (a, b) => {
        const j = a.join(b);
        return a.flowsTo(j) && b.flowsTo(j);
      }),
    );
  });
  it("join is monotone", () => {
    fc.assert(
      fc.property(arbLabel, arbLabel, arbLabel, (a, b, c) => !a.flowsTo(b) || a.join(c).flowsTo(b.join(c))),
    );
  });
  it("order agrees with join", () => {
    fc.assert(fc.property(arbLabel, arbLabel, (a, b) => a.flowsTo(b) === labelEq(a.join(b), b)));
  });
  it("join never raises integrity or lowers confidentiality", () => {
    fc.assert(
      fc.property(arbLabel, arbLabel, (a, b) => {
        const j = a.join(b);
        return j.integrity <= Math.min(a.integrity, b.integrity) && j.confidentiality >= Math.max(a.confidentiality, b.confidentiality);
      }),
    );
  });
});

describe("labels basics", () => {
  it("unknown fails closed", () => {
    const u = Label.unknown("x");
    expect(u.integrity).toBe(Integrity.Untrusted);
    expect(u.confidentiality).toBe(Confidentiality.Secret);
    expect(u.toString()).toBe("untrusted/secret [x]");
    expect(Label.bottom().toString()).toBe("trusted/public [-]");
  });
  it("parses names and rejects garbage", () => {
    expect(parseIntegrity("Trusted")).toBe(Integrity.Trusted);
    expect(parseConfidentiality("secret")).toBe(Confidentiality.Secret);
    expect(() => parseIntegrity("maybe")).toThrow();
  });
});

describe("propagation", () => {
  const U = new Label(Integrity.Untrusted, Confidentiality.Public, ["web"]);
  const S = new Label(Integrity.Trusted, Confidentiality.Secret, ["vault"]);

  it("ids are unique and resettable, lift is idempotent", () => {
    resetIds();
    const a = lift(1);
    const b = lift(2);
    expect([a.id, b.id]).toEqual(["v1", "v2"]);
    expect(lift(a)).toBe(a);
  });

  it("concat joins and records provenance", () => {
    const a = labeled("hello ", U);
    const b = labeled("world", S);
    const c = lconcat(a, b, "!");
    expect(c.value).toBe("hello world!");
    expect(c.label.integrity).toBe(Integrity.Untrusted);
    expect(c.label.confidentiality).toBe(Confidentiality.Secret);
    expect(c.label.provenance.has(a.id) && c.label.provenance.has(b.id)).toBe(true);
    expect([...c.label.sources].sort()).toEqual(["vault", "web"]);
  });

  it("containers", () => {
    const xs = llist([labeled("a", U), "b"]);
    expect(xs.value).toEqual(["a", "b"]);
    expect(xs.label.trusted).toBe(false);
    const d = ldict({ k: labeled(1, S), c: 2 });
    expect(d.value).toEqual({ k: 1, c: 2 });
    expect(d.label.confidentiality).toBe(Confidentiality.Secret);
  });

  it("derived label dominates parents", () => {
    fc.assert(
      fc.property(fc.array(arbLabel, { minLength: 1, maxLength: 4 }), (ls) => {
        const parents = ls.map((lab, i) => labeled(i, lab));
        const out = derive("x", parents);
        return parents.every(
          (p) => p.label.integrity >= out.label.integrity && p.label.confidentiality <= out.label.confidentiality && out.label.provenance.has(p.id),
        );
      }),
    );
  });

  it("joinAll matches fold", () => {
    fc.assert(
      fc.property(fc.array(arbLabel, { maxLength: 5 }), (ls) => {
        let out = Label.bottom();
        for (const l of ls) out = out.join(l);
        return labelEq(joinAll(ls), out);
      }),
    );
  });
});
