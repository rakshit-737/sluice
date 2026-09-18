/**
 * Security labels and the label lattice (TypeScript port of sluice/labels).
 *
 * A label pairs an integrity level (Biba) with a confidentiality level (Bell-LaPadula), plus
 * the sets of source classes and value ids it was derived from. Labels form a lattice ordered
 * by "may flow to"; `join` is the least upper bound.
 */

export enum Integrity {
  Untrusted = 0,
  Trusted = 1,
}

export enum Confidentiality {
  Public = 0,
  Internal = 1,
  Secret = 2,
}

const INTEGRITY: Record<string, Integrity> = {
  untrusted: Integrity.Untrusted,
  trusted: Integrity.Trusted,
};
const CONFIDENTIALITY: Record<string, Confidentiality> = {
  public: Confidentiality.Public,
  internal: Confidentiality.Internal,
  secret: Confidentiality.Secret,
};

export function parseIntegrity(name: string): Integrity {
  const v = INTEGRITY[name.toLowerCase()];
  if (v === undefined) throw new Error(`unknown integrity: ${name}`);
  return v;
}

export function parseConfidentiality(name: string): Confidentiality {
  const v = CONFIDENTIALITY[name.toLowerCase()];
  if (v === undefined) throw new Error(`unknown confidentiality: ${name}`);
  return v;
}

function subset<T>(a: ReadonlySet<T>, b: ReadonlySet<T>): boolean {
  for (const x of a) if (!b.has(x)) return false;
  return true;
}

function union<T>(a: ReadonlySet<T>, b: ReadonlySet<T>): Set<T> {
  return new Set<T>([...a, ...b]);
}

export class Label {
  readonly integrity: Integrity;
  readonly confidentiality: Confidentiality;
  readonly sources: ReadonlySet<string>;
  readonly provenance: ReadonlySet<string>;

  constructor(
    integrity: Integrity,
    confidentiality: Confidentiality,
    sources: Iterable<string> = [],
    provenance: Iterable<string> = [],
  ) {
    this.integrity = integrity;
    this.confidentiality = confidentiality;
    this.sources = new Set(sources);
    this.provenance = new Set(provenance);
    Object.freeze(this);
  }

  /** Identity of join: trusted, public, derived from nothing. */
  static bottom(): Label {
    return new Label(Integrity.Trusted, Confidentiality.Public);
  }

  /** Fail-closed label for data of unknown origin. */
  static unknown(source = "unknown"): Label {
    return new Label(Integrity.Untrusted, Confidentiality.Secret, [source]);
  }

  join(other: Label): Label {
    return new Label(
      Math.min(this.integrity, other.integrity),
      Math.max(this.confidentiality, other.confidentiality),
      union(this.sources, other.sources),
      union(this.provenance, other.provenance),
    );
  }

  /** Partial order: may `this` flow into a context labelled `other`? */
  flowsTo(other: Label): boolean {
    return (
      this.integrity >= other.integrity &&
      this.confidentiality <= other.confidentiality &&
      subset(this.sources, other.sources) &&
      subset(this.provenance, other.provenance)
    );
  }

  withProvenance(...ids: string[]): Label {
    return new Label(this.integrity, this.confidentiality, this.sources, union(this.provenance, new Set(ids)));
  }

  get trusted(): boolean {
    return this.integrity === Integrity.Trusted;
  }

  short(): string {
    return `${Integrity[this.integrity].toLowerCase()}/${Confidentiality[this.confidentiality].toLowerCase()}`;
  }

  toString(): string {
    const srcs = [...this.sources].sort().join(",") || "-";
    return `${this.short()} [${srcs}]`;
  }
}

export function joinAll(labels: Iterable<Label>): Label {
  let out = Label.bottom();
  for (const l of labels) out = out.join(l);
  return out;
}

let counter = 1;
export function newId(): string {
  return `v${counter++}`;
}
export function resetIds(): void {
  counter = 1;
}

export interface LabeledValue<T> {
  readonly value: T;
  readonly label: Label;
  readonly id: string;
  readonly origin: string;
}

export function labeled<T>(value: T, label: Label, origin = ""): LabeledValue<T> {
  return Object.freeze({ value, label, id: newId(), origin });
}

/** Wrap a program constant (chosen by the programmer): bottom label. */
export function lift<T>(value: T | LabeledValue<T>): LabeledValue<T> {
  if (isLabeled(value)) return value;
  return labeled(value, Label.bottom(), "const");
}

export function isLabeled<T>(v: unknown): v is LabeledValue<T> {
  return typeof v === "object" && v !== null && "label" in v && "value" in v && "id" in v;
}

/** New value computed from `parents`: label is their join, provenance their ids. */
export function derive<T>(value: T, parents: LabeledValue<unknown>[], origin = ""): LabeledValue<T> {
  const label = joinAll(parents.map((p) => p.label)).withProvenance(...parents.map((p) => p.id));
  return labeled(value, label, origin);
}

export function lconcat(...parts: (LabeledValue<unknown> | string)[]): LabeledValue<string> {
  const lifted = parts.map((p) => lift(p as string));
  return derive(lifted.map((p) => String(p.value)).join(""), lifted, "concat");
}

export function llist(items: (LabeledValue<unknown> | unknown)[]): LabeledValue<unknown[]> {
  const lifted = items.map((i) => lift(i));
  return derive(
    lifted.map((i) => i.value),
    lifted,
    "list",
  );
}

export function ldict(items: Record<string, LabeledValue<unknown> | unknown>): LabeledValue<Record<string, unknown>> {
  const lifted = Object.entries(items).map(([k, v]) => [k, lift(v)] as const);
  const value: Record<string, unknown> = {};
  for (const [k, v] of lifted) value[k] = v.value;
  return derive(
    value,
    lifted.map(([, v]) => v),
    "dict",
  );
}
