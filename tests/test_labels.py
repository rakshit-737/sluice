from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sluice.labels import (
    Confidentiality,
    Integrity,
    Label,
    LabeledValue,
    ValueId,
    derive,
    join_all,
    lconcat,
    ldict,
    lformat,
    lift,
    llist,
    reset_ids,
)
from sluice.labels.requirement import Requirement

labels = st.builds(
    Label,
    st.sampled_from(Integrity),
    st.sampled_from(Confidentiality),
    st.frozensets(st.sampled_from(["user", "web", "email", "fs"]), max_size=3),
    st.frozensets(st.sampled_from([ValueId(f"v{i}") for i in range(6)]), max_size=3),
)


@given(labels, labels)
def test_join_commutative(a: Label, b: Label) -> None:
    assert a.join(b) == b.join(a)


@given(labels, labels, labels)
def test_join_associative(a: Label, b: Label, c: Label) -> None:
    assert a.join(b).join(c) == a.join(b.join(c))


@given(labels)
def test_join_idempotent(a: Label) -> None:
    assert a.join(a) == a


@given(labels)
def test_bottom_is_identity(a: Label) -> None:
    assert Label.bottom().join(a) == a


@given(labels, labels)
def test_join_is_upper_bound(a: Label, b: Label) -> None:
    j = a | b
    assert a.flows_to(j) and b.flows_to(j)


@given(labels, labels, labels)
def test_join_monotone(a: Label, b: Label, c: Label) -> None:
    if a.flows_to(b):
        assert a.join(c).flows_to(b.join(c))


@given(labels, labels)
def test_order_agrees_with_join(a: Label, b: Label) -> None:
    assert a.flows_to(b) == (a.join(b) == b)


@given(labels, labels)
def test_join_never_raises_integrity_or_lowers_confidentiality(a: Label, b: Label) -> None:
    j = a | b
    assert j.integrity <= min(a.integrity, b.integrity)
    assert j.confidentiality >= max(a.confidentiality, b.confidentiality)


@given(st.lists(labels, max_size=5))
def test_join_all_matches_fold(ls: list[Label]) -> None:
    out = Label.bottom()
    for lab in ls:
        out = out | lab
    assert join_all(ls) == out


def test_unknown_is_fail_closed() -> None:
    u = Label.unknown("x")
    assert u.integrity is Integrity.UNTRUSTED
    assert u.confidentiality is Confidentiality.SECRET
    assert u.sources == {"x"}
    assert str(u) == "untrusted/secret [x]"
    assert str(Label.bottom()) == "trusted/public [-]"


def test_parse_names() -> None:
    assert Integrity.parse("trusted") is Integrity.TRUSTED
    assert Confidentiality.parse("Secret") is Confidentiality.SECRET
    with pytest.raises(KeyError):
        Integrity.parse("maybe")


# ---- propagation ------------------------------------------------------------------------

U = Label(Integrity.UNTRUSTED, Confidentiality.PUBLIC, frozenset({"web"}))
S = Label(Integrity.TRUSTED, Confidentiality.SECRET, frozenset({"vault"}))


def test_ids_are_unique_and_resettable() -> None:
    reset_ids()
    a, b = lift(1), lift(2)
    assert a.id == "v1" and b.id == "v2"
    assert lift(a) is a


def test_concat_joins_and_records_provenance() -> None:
    a = LabeledValue("hello ", U)
    b = LabeledValue("world", S)
    c = lconcat(a, b, "!")
    assert c.value == "hello world!"
    assert c.label.integrity is Integrity.UNTRUSTED
    assert c.label.confidentiality is Confidentiality.SECRET
    assert {a.id, b.id} <= c.label.provenance
    assert c.label.sources == {"web", "vault"}


def test_format_joins_template_and_args() -> None:
    t = LabeledValue("to: {x}", S)
    out = lformat(t, x=LabeledValue("a@b", U))
    assert out.value == "to: a@b"
    assert out.label.integrity is Integrity.UNTRUSTED
    assert out.label.confidentiality is Confidentiality.SECRET
    assert lformat("{n}", n=3).label.integrity is Integrity.TRUSTED


def test_containers() -> None:
    xs = llist([LabeledValue("a", U), "b"])
    assert xs.value == ["a", "b"] and not xs.label.trusted
    d = ldict({"k": LabeledValue(1, S), "c": 2})
    assert d.value == {"k": 1, "c": 2}
    assert d.label.confidentiality is Confidentiality.SECRET


def test_derive_method() -> None:
    a = LabeledValue("x", U)
    b = a.derive("y", LabeledValue("z", S), origin="t")
    assert b.origin == "t" and b.label == (U | S).with_provenance(a.id, *b.label.provenance)


@given(st.lists(labels, min_size=1, max_size=4))
def test_derived_label_dominates_parents(ls: list[Label]) -> None:
    parents = [LabeledValue(i, lab) for i, lab in enumerate(ls)]
    out = derive("x", *parents)
    for p in parents:
        assert p.label.integrity >= out.label.integrity
        assert p.label.confidentiality <= out.label.confidentiality
        assert p.id in out.label.provenance


# ---- requirements -------------------------------------------------------------------------


def test_requirement_failures() -> None:
    r = Requirement(Integrity.TRUSTED, Confidentiality.INTERNAL)
    assert r.failures(Label.bottom()) == []
    assert len(r.failures(Label.unknown())) == 2
    assert Requirement().failures(Label.unknown()) == []
    assert Requirement().describe() == "unconstrained"
    assert "require_integrity=trusted" in r.describe()


@given(
    st.one_of(st.none(), st.sampled_from(Integrity)),
    st.one_of(st.none(), st.sampled_from(Confidentiality)),
    st.one_of(st.none(), st.sampled_from(Integrity)),
    st.one_of(st.none(), st.sampled_from(Confidentiality)),
    labels,
)
def test_meet_is_conjunction(
    i1: Integrity | None,
    c1: Confidentiality | None,
    i2: Integrity | None,
    c2: Confidentiality | None,
    lab: Label,
) -> None:
    a, b = Requirement(i1, c1), Requirement(i2, c2)
    assert (not a.meet(b).failures(lab)) == (not a.failures(lab) and not b.failures(lab))
