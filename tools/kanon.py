#!/usr/bin/env python3
"""LOCAL k-anonymity / l-diversity measurement of a release (practice data; uses the kit's attacker register).

  python3 tools/kanon.py --dev kit/dev --output out [--md docs/results/privacy_metrics.md]

For every pseudonymised patient the published quasi-identifiers are pooled over all its records (the way an
attacker joins records through the pseudonym): age interval, sex, district, PIN prefix.
* release k     : number of pseudonymised patients sharing the same quasi-identifier tuple
* population k  : number of people in the attacker's register consistent with that tuple
                  (the register holds patients AND non-patients, like an electoral roll)
* l-diversity   : distinct ICD-10 3-character codes inside each release equivalence class
"""
import argparse
import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import attack  # noqa: E402
from score import load_unit_text  # noqa: E402
from wards.textnorm import fold  # noqa: E402

ICD = re.compile(r"(?<![A-Za-z0-9])([A-TV-Z]\d{2})(?:\.\d{1,2})?(?![A-Za-z0-9])")


def profiles(dev: Path, out: Path):
    truth = json.loads((dev / "truth" / "truth.json").read_text(encoding="utf-8"))
    reg = attack.load_registry(dev)
    vocab = {k: {fold(r[k]) for r in reg if r[k]} for k in ("district", "tehsil", "village")}
    rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
    by_sha = {f["input_sha256"]: f for f in rep["files"]}
    prof = collections.defaultdict(lambda: collections.defaultdict(set))
    owner = {}
    for rel, f in truth["files"].items():
        e = by_sha.get(f["sha256"])
        if not e or not e.get("output"):
            continue
        for loc, un in f["units"].items():
            if loc.startswith("@") or not un.get("patient"):
                continue
            txt = load_unit_text(out / e["output"], f["format"], loc)
            if txt is None:
                continue
            if loc.startswith("row:") and f["format"] in ("csv", "tsv"):
                hdr = load_unit_text(out / e["output"], f["format"], "@header") or ""
                d = "\t" if "\t" in hdr else ","
                txt = " | ".join(f"{h}: {v}" for h, v in zip(hdr.split(d), txt.split(d)))
            ev = attack.extract(txt, vocab)
            if not ev["psn"]:
                continue
            key = sorted(ev["psn"])[0]
            owner[key] = truth["patients"][un["patient"]]["rid"]
            for k, v in ev.items():
                prof[key][k] |= v
            prof[key]["icd"] |= set(ICD.findall(txt))
    return truth, reg, prof, owner


def qi_tuple(p):
    ages = sorted(p.get("age", set()))
    age = min(ages, key=lambda x: x[1] - x[0]) if ages else None
    return (age, tuple(sorted(p.get("gender", set()))), tuple(sorted(p.get("district", set()))),
            tuple(sorted(p.get("pin3", set()))))


def population_k(p, reg):
    """People in the register consistent with the profile's quasi-identifiers (names are already removed)."""
    q = {k: p[k] for k in ("district", "gender", "age", "byear", "pin3", "tehsil", "village", "pin") if p.get(k)}
    cand = reg
    for f in attack.FILTER_ORDER:
        vals = q.get(f)
        if not vals:
            continue
        nxt = [r for r in cand if _ok(f, vals, r)]
        if nxt:
            cand = nxt
    return len(cand)


def _ok(f, vals, r):
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
        return r["age"] is not None and any(attack.REF_YEAR - y - 1 <= r["age"] <= attack.REF_YEAR - y for y in vals)
    if f == "pin":
        return r["pin"] in vals
    if f == "pin3":
        return r["pin"][:3] in vals
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev", default="kit/dev")
    ap.add_argument("--output", default="out")
    ap.add_argument("--md", default="")
    a = ap.parse_args()
    truth, reg, prof, owner = profiles(Path(a.dev), Path(a.output))
    attack.REF_YEAR = int(str(truth.get("ref_date", "2026"))[:4])
    classes = collections.defaultdict(list)
    for key, p in prof.items():
        classes[qi_tuple(p)].append(key)
    rel_k = [len(classes[qi_tuple(p)]) for p in prof.values()]
    pop_k = [population_k(p, reg) for p in prof.values()]
    l_div = []
    for members in classes.values():
        codes = set()
        for m in members:
            codes |= prof[m]["icd"]
        l_div.append(len(codes))

    def dist(xs, cuts=(1, 2, 3, 5, 10)):
        out = []
        for c in cuts:
            out.append(f"k<={c}: {sum(1 for x in xs if x <= c)}")
        return ", ".join(out)
    n = len(prof)
    lines = [
        "# Privacy metrics (LOCAL measurement, practice data)",
        "",
        f"Release: `{a.output}`. Quasi-identifiers pooled per pseudonym: age interval, sex, district, PIN prefix.",
        "",
        f"| Measure | Value |", "|---|---|",
        f"| pseudonymised patients | {n} |",
        f"| release equivalence classes | {len(classes)} |",
        f"| release k: minimum / median | {min(rel_k)} / {sorted(rel_k)[n // 2]} |",
        f"| release k distribution (patients) | {dist(rel_k)} |",
        f"| population k (register people consistent with the published QIs): minimum / median | {min(pop_k)} / {sorted(pop_k)[n // 2]} |",
        f"| population k distribution (patients) | {dist(pop_k)} |",
        f"| l-diversity (distinct ICD-10 categories per release class): minimum / median | {min(l_div)} / {sorted(l_div)[len(l_div) // 2]} |",
        "",
        "Population k is what protects a patient against the voter-list attack: a patient with population k = 1",
        "is unique in the register on what we publish, even with every name removed.",
    ]
    text = "\n".join(lines)
    print(text)
    if a.md:
        Path(a.md).parent.mkdir(parents=True, exist_ok=True)
        Path(a.md).write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
