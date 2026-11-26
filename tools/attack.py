#!/usr/bin/env python3
"""Approximate re-implementation of the published attack arena (docs/ATTACKS.md) for tuning.

  python3 tools/attack.py --dev kit/dev --output out        (also runs the attack on raw input)

A2/A3 record linkage, A4 profile aggregation, A5 targeted known-facts attack.
Each attack is run on our release and on the raw input; the ratio is what the arena scores.
"""
import argparse
import collections
import csv
import datetime as dt
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from score import load_unit_text  # noqa: E402
from wards import gazetteer as gz  # noqa: E402
from wards.textnorm import fold  # noqa: E402
from wards.translit import to_latin  # noqa: E402

FILTER_ORDER = ["phone", "email", "last4", "mphone", "district", "gender", "age", "byear", "tehsil", "village", "pin", "pin3"]


def load_registry(dev):
    rows = list(csv.DictReader(open(dev / "attacker" / "registry.csv", encoding="utf-8")))
    for r in rows:
        r["age"] = int(r["age"]) if r["age"] else None
        r["_tok"] = set(fold(r["name"]).split())
        r["_given"] = fold(r["name"]).split()[0] if r["name"] else ""
        r["_sur"] = fold(r["name"]).split()[-1] if r["name"] else ""
        r["_rel"] = set(fold(r["relative_name"]).split())
    return rows


def extract(text, reg_vocab):
    t = fold(to_latin(text)) + " " + fold(text)
    ev = collections.defaultdict(set)
    for m in re.finditer(r"(?<!\d)[6-9]\d{9}(?!\d)", re.sub(r"(?<=\d)[ \-](?=\d)", "", re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", " ", t))):
        ev["phone"].add(m.group(0))
    for m in re.finditer(r"[\w.]+@[\w.]+", t):
        ev["email"].add(m.group(0))
    for m in re.finditer(r"x{4}[ \-]?x{4}[ \-]?(\d{4})", t):
        ev["last4"].add(m.group(1))
    t_nouuid = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|psn-[0-9a-z]{6}|(?:enc|id)-[0-9a-z]{6}", " ", t)
    for m in re.finditer(r"(?<![\d\-])(\d{1,3})\s*-\s*(\d{1,3})\s*(?=(?:yrs?|y)?\s*/\s*[mf]\b|yrs?\b|वर्ष)", t_nouuid):
        lo, hi = int(m.group(1)), int(m.group(2))
        if 0 < hi - lo <= 20:
            ev["age"].add((lo, hi))
    for m in re.finditer(r"(?<![\d\-])(\d{1,3})\s*(?:yrs?|y)?\s*/\s*[mf]\b|\bage\s*:?\s*(\d{1,3})\b(?!\s*-)|(?<![\d\-])(\d{1,3})\s*(?:वर्ष)", t_nouuid):
        a = next(g for g in m.groups() if g)
        ev["age"].add((int(a), int(a)))
    for m in re.finditer(r"(\d{2,3})\+", t):
        ev["age"].add((int(m.group(1)), 120))
    for m in re.finditer(r"/\s*([mf])\b|\b(male|female)\b|(महिला|पुरुष)|\b([sdw])/o\b", t):
        g = m.group(1) or (m.group(2) or "")[:1] or ("f" if m.group(3) == "महिला" else "m" if m.group(3) else "") or ("m" if m.group(4) == "s" else "f")
        if g:
            ev["gender"].add(g.upper())
    for m in re.finditer(r"\b(19\d\d|20[0-2]\d)-\d\d-\d\d\b|\b\d\d/\d\d/(19\d\d)\b", t):
        y = m.group(1) or m.group(2)
        if y and int(y) < 2015:
            ev["byear"].add(int(y))
    for m in re.finditer(r"(?<![\d\-/.])([1-8]\d{5})(?![\d\-/.])", t_nouuid):
        ev["pin"].add(m.group(1))
    for m in re.finditer(r"(?<!\d)([1-8]\d{2})\*{3}", t):
        ev["pin3"].add(m.group(1))
    for key in ("district", "tehsil", "village"):
        for v in reg_vocab[key]:
            if v and re.search(r"(?<![a-z])" + re.escape(v) + r"(?![a-z])", t):
                ev[key].add(v)
    words = set(re.findall(r"[a-z]+", t))
    ev["tokens"] = words
    for m in re.finditer(r"\b(?:h\.?\s*no\.?|house|makan\s*no\.?)\s*(\d+)", t):
        ev["house"].add(m.group(1))
    ev["psn"] = set(re.findall(r"psn-[0-9a-z]{6}", t))
    ev["dates"] = set(re.findall(r"\d{4}-\d\d-\d\d|\d\d/\d\d/\d{4}|\d\d-\d\d-\d{4}", t))
    return ev


def attack(ev, reg):
    cand = reg
    for f in FILTER_ORDER:
        vals = ev.get(f)
        if not vals:
            continue
        def ok(r):
            if f == "phone":
                return r["phone"] in vals
            if f == "email":
                return r["email"] in vals
            if f == "last4":
                return r["aadhaar_last4"] in vals
            if f == "district":
                return fold(r["district"]) in vals
            if f == "tehsil":
                return fold(r["tehsil"]) in vals
            if f == "village":
                return fold(r["village"]) in vals
            if f == "gender":
                return r["gender"] in vals
            if f == "age":
                return r["age"] is not None and any(lo - 1 <= r["age"] <= hi + 2 for lo, hi in vals)
            if f == "byear":
                return r["age"] is not None and any(abs((2026 - y) - r["age"]) <= 2 for y in vals)
            if f == "pin":
                return r["pin"] in vals
            if f == "pin3":
                return r["pin"][:3] in vals
            return True
        nxt = [r for r in cand if ok(r)]
        if nxt:
            cand = nxt
    toks = ev.get("tokens", set())
    w = []
    for r in cand:
        x = 1.0
        if r["_tok"] and r["_tok"] <= toks:
            x *= 60
        elif r["_given"] in toks:
            x *= 8
        elif r["_sur"] in toks and r["_sur"] not in gz.GENERIC_NAME_TOKENS:
            x *= 3
        if r["_rel"] and r["_rel"] & toks - gz.GENERIC_NAME_TOKENS:
            x *= 8
        if r["house_no"] and r["house_no"] in ev.get("house", set()):
            x *= 2
        w.append(x)
    tot = sum(w)
    return {r["rid"]: x / tot for r, x in zip(cand, w)}


def run(dev, root, use_output, truth, reg, vocab):
    rep = json.loads((root / "report.json").read_text()) if use_output else None
    by_sha = {f["input_sha256"]: f for f in rep["files"]} if rep else {}
    records = []   # (true rid, ev)
    for rel, f in truth["files"].items():
        if use_output:
            e = by_sha.get(f["sha256"])
            if not e or not e.get("output"):
                continue
            path = root / e["output"]
        else:
            path = dev / "input" / rel
        for loc, un in f["units"].items():
            if loc.startswith("@") or not un.get("patient"):
                continue
            txt = load_unit_text(path, f["format"], loc)
            if txt is None:
                continue
            rid = truth["patients"][un["patient"]]["rid"]
            records.append((rid, extract(txt, vocab), un.get("patient"), rel))
    # A2/A3
    a3 = [attack(ev, reg).get(rid, 0.0) for rid, ev, _, _ in records]
    # A4: profiles via shared pseudonyms (release) or shared uhid (raw: truth patient as proxy for shared refs)
    groups = collections.defaultdict(list)
    for i, (rid, ev, pt, _) in enumerate(records):
        key = sorted(ev["psn"])[0] if ev["psn"] else (("raw", pt) if not use_output else ("solo", i))
        groups[key].append(i)
    reid = {}
    for key, idx in groups.items():
        pooled = collections.defaultdict(set)
        for i in idx:
            for k, v in records[i][1].items():
                pooled[k] |= v
        probs = attack(pooled, reg)
        for i in idx:
            rid = records[i][0]
            p = max(probs.get(rid, 0.0), attack(records[i][1], reg).get(rid, 0.0))
            reid[rid] = max(reid.get(rid, 0.0), p)
    a4 = sum(1 for p in reid.values() if p >= 0.5) / max(len(reid), 1)
    # A5: known facts
    facts = [json.loads(l) for l in open(dev / "attacker" / "known_facts.jsonl")]
    regby = {r["rid"]: r for r in reg}
    prof = {}
    for key, idx in groups.items():
        pooled = collections.defaultdict(set)
        for i in idx:
            for k, v in records[i][1].items():
                pooled[k] |= v
        prof[key] = (pooled, {records[i][0] for i in idx})
    succ = []
    for fct in facts:
        person = regby.get(fct["rid"])
        if not person:
            continue
        cands = []
        dates = set()
        for d in fct.get("visit_dates", []):
            y, m, dd = d.split("-")
            dates |= {d, f"{dd}/{m}/{y}", f"{dd}-{m}-{y}", f"{m}/{dd}/{y}"}
        cond = fold(fct.get("condition_hint", ""))
        for key, (pooled, rids) in prof.items():
            score = 0
            if pooled["dates"] & dates:
                score += 1
            if cond and cond[:12] in " ".join(pooled["tokens"]) or cond and all(w in pooled["tokens"] for w in re.findall(r"[a-z]{4,}", cond)[:3]):
                score += 8
            if score == 0:
                continue
            p = attack(pooled, [person] + [r for r in reg if r is not person][:0])
            # consistency: person must survive the filters
            filt = attack(pooled, reg)
            if fct["rid"] not in filt:
                continue
            cands.append((score * (1 + filt[fct["rid"]]), fct["rid"] in rids))
        if cands:
            tot = sum(s for s, _ in cands)
            succ.append(sum(s for s, ok in cands if ok) / tot)
        else:
            succ.append(0.0)
    a5 = sum(succ) / max(len(succ), 1)
    return sum(a3) / max(len(a3), 1), a4, a5


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev", default="kit/dev")
    ap.add_argument("--output", default="out")
    a = ap.parse_args()
    dev, out = Path(a.dev), Path(a.output)
    truth = json.loads((dev / "truth" / "truth.json").read_text(encoding="utf-8"))
    reg = load_registry(dev)
    vocab = {k: {fold(r[k]) for r in reg if r[k]} for k in ("district", "tehsil", "village")}
    raw = run(dev, out, False, truth, reg, vocab)
    rel = run(dev, out, True, truth, reg, vocab)
    names = ["A2/A3 record linkage", "A4 profile re-id", "A5 targeted"]
    risks = []
    for n, r0, r1 in zip(names, raw, rel):
        ratio = r1 / r0 if r0 else 0
        risks.append(min(ratio, 1))
        print(f"{n:22} raw {r0:.3f}  release {r1:.3f}  ratio {ratio:.3f}")
    print(f"mean risk (A2-A5 only) {sum(risks) / len(risks):.3f}")


if __name__ == "__main__":
    main()
