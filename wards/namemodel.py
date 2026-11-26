"""Runtime side of the small name scorer trained by tools/train_name_model.py.

Character 2-4-gram naive Bayes (log-likelihood ratios in wards/data/name_model.json, ~150 KB). Trained by us
from the gazetteer, rule-generated spelling variants and the practice corpus' medical vocabulary. It is a
classical model, not pretrained, not generative. Used only as the lowest-priority detector layer, and only
when the same line also carries supporting context (age/sex, a phone, an ID, a relation marker).
"""
from __future__ import annotations

import functools
import json
from pathlib import Path

_PATH = Path(__file__).resolve().parent / "data" / "name_model.json"


@functools.lru_cache(maxsize=1)
def _model():
    try:
        return json.loads(_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


@functools.lru_cache(maxsize=100000)
def score(token: str) -> float:
    m = _model()
    if m is None:
        return -99.0
    t = "^" + token.lower() + "$"
    lo, hi = m["n"]
    gs = [t[i:i + n] for n in range(lo, hi + 1) for i in range(len(t) - n + 1)]
    llr, unseen = m["llr"], m["unseen"]
    return m["prior"] + sum(llr.get(g, unseen) for g in gs) / max(len(gs), 1) * 4


def is_name(token: str) -> bool:
    m = _model()
    return m is not None and len(token) >= 3 and score(token) > m["threshold"]
