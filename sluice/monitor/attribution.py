"""Heuristic attribution of model-emitted tool arguments to labelled context values.

Monitor mode cannot see inside the model, so it infers where an argument came from:

1. lineage: the model passed ``{"$ref": "<value id>"}`` (exact label, handled by the middleware)
2. containment: normalised argument is contained in a context value, or embeds one
3. n-gram overlap: character n-gram containment above a threshold

The argument's label is the join of every matched value's label. Text not explained by
any match is model-generated and gets the ``fallback`` label (the policy's ``model``
source). Integrity endorsement: if a *trusted* value contains the whole argument, the
attacker cannot have chosen it, so integrity is trusted (confidentiality is still joined).
See docs/monitor-limits.md: paraphrased exfiltration evades this by design.
"""

from __future__ import annotations

import json
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal

from sluice.labels.label import Integrity, Label, ValueId, join_all
from sluice.labels.value import LabeledValue

Method = Literal["ref", "exact", "contained", "embeds", "ngram"]


@dataclass(frozen=True)
class Match:
    value_id: ValueId
    method: Method
    score: float
    path: str = ""

    def describe(self, origin: str = "") -> str:
        where = f" at {self.path}" if self.path else ""
        src = f" ({origin})" if origin else ""
        return f"{self.method}{where} <- {self.value_id}{src} score={self.score:.2f}"


@dataclass(frozen=True)
class Attribution:
    label: Label
    matches: tuple[Match, ...]
    generated: bool  # some part of the argument is unexplained, model-generated text

    @property
    def value_ids(self) -> list[ValueId]:
        return list(dict.fromkeys(m.value_id for m in self.matches))


def normalise(text: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


def ngrams(text: str, n: int) -> set[str]:
    if len(text) < n:
        return {text} if text else set()
    return {text[i : i + n] for i in range(len(text) - n + 1)}


def as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(value)


class Attributor:
    def __init__(self, n: int = 5, threshold: float = 0.6, min_len: int = 4) -> None:
        if not 0 < threshold <= 1:
            raise ValueError("threshold must be in (0, 1]")
        self.n = n
        self.threshold = threshold
        self.min_len = min_len
        self._cache: dict[ValueId, tuple[str, set[str]]] = {}

    def _prep(self, lv: LabeledValue[Any]) -> tuple[str, set[str]]:
        hit = self._cache.get(lv.id)
        if hit is None:
            norm = normalise(as_text(lv.value))
            hit = (norm, ngrams(norm, self.n))
            self._cache[lv.id] = hit
        return hit

    def attribute(
        self, arg: Any, context: Sequence[LabeledValue[Any]], fallback: Label
    ) -> Attribution:
        leaves = list(_leaves(arg))
        results = [self._attribute_leaf(v, p, context, fallback) for p, v in leaves]
        if not results:  # empty list/dict: nothing flows
            return Attribution(Label.bottom(), (), False)
        label = join_all(r.label for r in results)
        matches = tuple(m for r in results for m in r.matches)
        return Attribution(label, matches, any(r.generated for r in results))

    def _attribute_leaf(
        self, value: Any, path: str, context: Sequence[LabeledValue[Any]], fallback: Label
    ) -> Attribution:
        if value is None or isinstance(value, bool):
            # Constants with one bit of information; treated as model-generated.
            return Attribution(fallback, (), True)
        arg = normalise(as_text(value))
        by_id = {lv.id: lv for lv in context}
        matches: list[Match] = []
        endorsed = False
        covered = False
        arg_grams = ngrams(arg, self.n)
        for lv in context:
            text, grams = self._prep(lv)
            if not text:
                continue
            if arg == text:
                matches.append(Match(lv.id, "exact", 1.0, path))
                covered = True
                endorsed |= lv.label.trusted
                continue
            if len(arg) < self.min_len:
                continue  # short strings match only exactly
            if arg in text:
                matches.append(Match(lv.id, "contained", 1.0, path))
                covered = True
                endorsed |= lv.label.trusted
            elif len(text) >= self.min_len and text in arg:
                matches.append(Match(lv.id, "embeds", len(text) / len(arg), path))
            elif arg_grams and grams:
                inter = len(arg_grams & grams)
                score = max(inter / len(arg_grams), inter / len(grams))
                if score >= self.threshold:
                    matches.append(Match(lv.id, "ngram", score, path))
        parts = [by_id[m.value_id].label.with_provenance(m.value_id) for m in matches]
        generated = not covered
        if generated:
            parts.append(fallback)
        label = join_all(parts)
        if endorsed and label.integrity is not Integrity.TRUSTED:
            label = Label(Integrity.TRUSTED, label.confidentiality, label.sources, label.provenance)
        return Attribution(label, tuple(matches), generated)


def _leaves(value: Any, path: str = "") -> list[tuple[str, Any]]:
    if isinstance(value, dict):
        return [leaf for k, v in value.items() for leaf in _leaves(v, f"{path}.{k}")]
    if isinstance(value, list | tuple):
        return [leaf for i, v in enumerate(value) for leaf in _leaves(v, f"{path}[{i}]")]
    return [(path, value)]
