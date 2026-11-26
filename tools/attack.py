#!/usr/bin/env python3
"""LOCAL APPROXIMATION of the published attack arena (kit docs/ATTACKS.md + docs/SCORING.md).
It is NOT the official evaluator (that code is published only after the results).

  python3 tools/attack.py --dev kit/dev --output out [--output2 out_other_secret]

A1 direct exposure, A2/A3 record linkage, A4 profile aggregation, A5 targeted known-facts attack,
A6 pseudonym inversion, A7 cross-release linkability (needs --output2: same input, different secret).
A2-A5 are run on the release and on the raw input; the arena scores the ratio.
"""
import base64 as _b64
import hashlib as _hl
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

REF_YEAR = 2026   # replaced from truth["ref_date"] at run time
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
    # a bare year under a DOB field or anchor ("DOB: 1977", "dob": "1977", birthDate "1977", जन्म तिथि: 1977)
    for m in re.finditer(r"(?:\bd\.?o\.?b\b|birth\s*_?date|birthdate|date\s*of\s*birth|janm\s*tithi|जन्म\s*तिथि)[\"']?\s*[:=]?\s*[\"']?\s*(19\d\d|20[01]\d)(?![\d/\-.])", t):
        ev["byear"].add(int(m.group(1)))
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
                # age on the reference date is REF_YEAR - y, or one less if the birthday has not come yet
                return r["age"] is not None and any(REF_YEAR - y - 1 <= r["age"] <= REF_YEAR - y for y in vals)
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
    rep = json.loads((root / "report.json").read_text(encoding="utf-8")) if use_output else None
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
            if loc.startswith("row:") and f["format"] in ("csv", "tsv"):
                hdr = load_unit_text(path, f["format"], "@header") or ""
                d = "\t" if "\t" in hdr else ","
                txt = " | ".join(f"{h}: {v}" for h, v in zip(hdr.split(d), txt.split(d)))
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
    facts = [json.loads(l) for l in open(dev / "attacker" / "known_facts.jsonl", encoding="utf-8")]
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


def release_blob(root):
    parts = []
    for p in sorted(root.rglob("*")):
        if p.is_file() and "quarantine" not in p.parts:
            parts.append(p.name)
            try:
                parts.append(p.read_text(encoding="utf-8"))
            except UnicodeDecodeError:
                pass
    return "\n".join(parts)


def psn_by_patient(truth, root):
    rep = json.loads((root / "report.json").read_text(encoding="utf-8"))
    out2in = {}
    file_map = collections.defaultdict(list)
    for rel, f in truth["files"].items():
        file_map[f["sha256"]].append(rel)
    for e in rep["files"]:
        if e.get("output"):
            c = file_map.get(e["input_sha256"], [])
            same = [x for x in c if "sanitized/" + x == e["output"]]
            out2in[e["output"]] = same[0] if same else (c[0] if c else None)
    got = collections.defaultdict(collections.Counter)
    for line in (root / "records.jsonl").read_text(encoding="utf-8").splitlines():
        r = json.loads(line)
        rel = out2in.get(r["file"])
        if not rel or not r["patient"]:
            continue
        un = truth["files"][rel]["units"].get(r["loc"])
        if un and un.get("patient"):
            got[un["patient"]][r["patient"]] += 1
    return {pt: c.most_common(1)[0][0] for pt, c in got.items()}


def originals(truth):
    """patient -> list of original identifier strings (UHIDs, Aadhaar, phone, ABHA, Latin full name)."""
    pid2pt = {v["pid"]: k for k, v in truth["patients"].items()}
    orig = collections.defaultdict(set)
    for pt, v in truth["patients"].items():
        for ids in v["uhids"].values():
            orig[pt] |= set(ids)
    for f in truth["files"].values():
        for u in f["units"].values():
            for e in u["entities"]:
                pt = pid2pt.get(e.get("person"))
                if not pt or e.get("role") != "patient":
                    continue
                if e["type"] in ("AADHAAR", "PHONE", "ABHA_NUMBER") or (e["type"] == "PATIENT_NAME" and e.get("full") and e["script"] == "latin"):
                    orig[pt].add(e["surface"])
    return orig


def transforms(x):
    out = {x, x.lower(), x.upper(), re.sub(r"\D", "", x), x[::-1], x.lower()[::-1]}
    for v in list(out):
        if not v:
            continue
        b = v.encode("utf-8")
        for h in (_hl.md5, _hl.sha1, _hl.sha256, _hl.sha512):
            out.add(h(b).hexdigest())
        out.add(_b64.b64encode(b).decode().rstrip("="))
    return {t for t in out if t}


def a1_direct(truth, root, blob=None):
    blob = fold(release_blob(root) if blob is None else blob)
    digits = re.sub(r"(?<=\d)[\s\-./]+(?=\d)", "", blob)
    pid2pt = {v["pid"]: k for k, v in truth["patients"].items()}
    exposed, pts = set(), set(truth["patients"])
    for f in truth["files"].values():
        for u in f["units"].values():
            for e in u["entities"]:
                pt = pid2pt.get(e.get("person"))
                if not pt or not e.get("critical"):
                    continue
                if e.get("match") == "digits":
                    k = e.get("key") or re.sub(r"\D", "", e["surface"])
                    # allow a country-code / trunk prefix (+91 / 0) glued on once separators are removed
                    if re.search(r"(?<!\d)(?:91|0|091)?" + re.escape(k) + r"(?!\d)", digits):
                        exposed.add(pt)
                elif e.get("full") and len(e.get("tokens", [])) >= 2:
                    if re.search(r"(?<![\w])" + r"\s+".join(re.escape(t) for t in e["tokens"]) + r"(?![\w])", blob):
                        exposed.add(pt)
                elif e.get("match") != "name":
                    k = fold(e["surface"]).strip()
                    if k and k in blob:
                        exposed.add(pt)
    return len(exposed) / max(len(pts), 1)


def a6_inversion(truth, root):
    psn = psn_by_patient(truth, root)
    orig = originals(truth)
    inv = 0
    for pt, p in psn.items():
        code = p.split("-", 1)[-1].lower()
        full = p.lower()
        hit = False
        for o in orig.get(pt, ()):
            core = re.sub(r"\D", "", o)
            if len(core) >= 5 and core in re.sub(r"\D", "", p):
                hit = True
            for t in transforms(o):
                tl = t.lower()
                for cand in (full, code):
                    if len(cand) >= 6 and (cand == tl or (len(cand) >= 8 and tl.startswith(cand)) or tl.startswith(cand) and len(cand) >= 8):
                        hit = True
        inv += hit
    return inv / max(len(psn), 1), len(psn)


def a7_cross(truth, root, root2):
    p1, p2 = psn_by_patient(truth, root), psn_by_patient(truth, root2)
    common = [pt for pt in p1 if pt in p2]
    same_psn = sum(1 for pt in common if p1[pt] == p2[pt]) / max(len(common), 1)
    rep1 = json.loads((root / "report.json").read_text(encoding="utf-8"))
    rep2 = json.loads((root2 / "report.json").read_text(encoding="utf-8"))
    o1 = {e["input_sha256"]: e["output"] for e in rep1["files"] if e.get("output")}
    o2 = {e["input_sha256"]: e["output"] for e in rep2["files"] if e.get("output")}
    date_rx = re.compile(r"\d{4}-\d\d-\d\d|\d{1,2}[/.\-]\d{1,2}[/.\-]\d{2,4}")
    stable = total = 0
    for rel, f in truth["files"].items():
        a, b = o1.get(f["sha256"]), o2.get(f["sha256"])
        if not a or not b:
            continue
        for loc, un in f["units"].items():
            if loc.startswith("@") or not un.get("dates"):
                continue
            tin = load_unit_text(dev_root / "input" / rel, f["format"], loc) or ""
            t1 = load_unit_text(root / a, f["format"], loc) or ""
            t2 = load_unit_text(root2 / b, f["format"], loc) or ""
            raw_dates = set(date_rx.findall(tin))
            d1 = set(date_rx.findall(t1)) - raw_dates
            d2 = set(date_rx.findall(t2)) - raw_dates
            if not d1 and not d2:
                continue
            total += 1
            stable += bool(d1 & d2)
    same_dates = stable / max(total, 1)
    return max(same_psn, same_dates), same_psn, same_dates


def main():
    global dev_root
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev", default="kit/dev")
    ap.add_argument("--output", default="out")
    ap.add_argument("--output2", default="", help="second run of the same input with a DIFFERENT secret (for A7)")
    a = ap.parse_args()
    dev_root = Path(a.dev)
    dev, out = Path(a.dev), Path(a.output)
    truth = json.loads((dev / "truth" / "truth.json").read_text(encoding="utf-8"))
    global REF_YEAR
    REF_YEAR = int(str(truth.get("ref_date", "2026"))[:4])
    reg = load_registry(dev)
    vocab = {k: {fold(r[k]) for r in reg if r[k]} for k in ("district", "tehsil", "village")}
    raw = run(dev, out, False, truth, reg, vocab)
    rel = run(dev, out, True, truth, reg, vocab)
    print("LOCAL APPROXIMATION of the attack arena (not the official evaluator)")
    a1 = a1_direct(truth, out)
    print(f"A1 direct exposure      share of patients exposed {a1:.3f}  (raw {a1_direct_raw(truth, dev):.3f})")
    names = ["A2/A3 record linkage", "A4 profile re-id", "A5 targeted"]
    ratios = []
    for n, r0, r1 in zip(names, raw, rel):
        ratio = min(r1 / r0, 1) if r0 else 0
        ratios.append(ratio)
        print(f"{n:22}  raw {r0:.3f}  release {r1:.3f}  ratio {ratio:.3f}")
    a6, npsn = a6_inversion(truth, out)
    print(f"A6 pseudonym inversion  {a6:.3f}  ({npsn} pseudonymised patients checked)")
    comps = [(0.20, a1), (0.20, ratios[0]), (0.20, ratios[1]), (0.20, ratios[2]), (0.10, a6)]
    if a.output2:
        a7, sp, sd = a7_cross(truth, out, Path(a.output2))
        print(f"A7 cross-release        {a7:.3f}  (same pseudonym {sp:.3f}, same shifted dates {sd:.3f})")
        comps.append((0.10, a7))
    else:
        print("A7 cross-release        skipped (pass --output2 with a run under a different secret)")
    risk = sum(w * v for w, v in comps) / sum(w for w, _ in comps)
    print(f"combined risk {risk:.3f} -> resistance {1 - risk:.3f}  (SCORING.md weights; before the utility coupling)")


def a1_direct_raw(truth, dev):
    return a1_direct(truth, None, blob=release_blob(dev / "input"))


if __name__ == "__main__":
    main()
