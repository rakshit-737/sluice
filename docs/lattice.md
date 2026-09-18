# Label lattice semantics

sluice labels are pairs of an **integrity** level and a **confidentiality** level, plus the
set of source classes and value ids a value was derived from.

| component       | order                               | join (⊔) | model            |
|-----------------|-------------------------------------|----------|------------------|
| integrity       | untrusted < trusted                 | min      | Biba (1977)      |
| confidentiality | public < internal < secret          | max      | Bell-LaPadula (1973) |
| sources         | ⊆                                   | ∪        | provenance       |
| provenance      | ⊆                                   | ∪        | provenance       |

Following Denning (1976), a label L₁ **may flow to** L₂ (L₁ ⊑ L₂) iff
`L₁.integrity ≥ L₂.integrity`, `L₁.confidentiality ≤ L₂.confidentiality`, and both sets are
subsets. Join is the least upper bound in this order: combining data can only lose integrity
and gain confidentiality. `Label.bottom()` (trusted, public, no sources) is the identity for
join and labels program constants.

Integrity is Biba's dual of confidentiality: Bell-LaPadula forbids *reading up / writing
down* for secrecy; Biba forbids untrusted data *flowing up* into trusted decisions. A sink
argument with `require_integrity: trusted` is a Biba check; `max_confidentiality: internal`
is a Bell-LaPadula check.

## Properties (tested with hypothesis in `tests/test_labels.py`)

- join is commutative, associative, idempotent; bottom is its identity
- join is an upper bound of its arguments and monotone in each
- `a ⊑ b ⟺ a ⊔ b = b`
- a derived value's label dominates every parent's label, and records their ids

## Propagation

| operation                                    | result label                             |
|----------------------------------------------|------------------------------------------|
| `lconcat`, `lformat`, `llist`, `ldict`       | join of all parts (constants are bottom) |
| tool output                                  | source class ⊔ join of argument labels   |
| structured tool output leaf                  | field source class ⊔ argument labels     |
| monitor-mode tool argument                   | see `monitor-limits.md`                  |

## Fail-closed defaults

- unknown source class → `untrusted/secret`
- sink with no declared requirements → every argument must be `trusted`
- no policy → every call blocks
- `ask` with no interactive approver → block
