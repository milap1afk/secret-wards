#!/usr/bin/env python3
"""THE GATE: run after every fix, before committing.

  python3 tools/gate.py [--ref docs/results/gate_ref.json] [--accept]

1. tests/run_all.py must pass (NOT VERIFIED counts as a failure here).
2. Official checks on practice: 0 leaks, 0 canaries, 4855/4855 medical, linking precision 1.00, 0 false merges,
   0 raw copies, CONTRACT OK.
3. Every other dataset present (chaos/, blind/, blind2/): no official measure worse than the reference, and
   zero false merges.
4. Practice: contextual precision 1.000 (tools/score.py) and token retention not more than 0.002 below the
   reference (tools/retention.py); run time < 10 s and peak memory < 512 MB.
--accept stores the current numbers as the new reference (do this after a passing gate).
"""
import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from eval_all import official, run_pipeline  # noqa: E402

DATASETS = [("practice", ROOT / "kit" / "dev"), ("chaos", ROOT / "chaos"), ("blind", ROOT / "blind"),
            ("blind2", ROOT / "blind2")]


def num(frac: str):
    a, b = frac.split("/")
    return int(a), int(b)


def measure() -> dict:
    res = {}
    for name, dev in DATASETS:
        if not (dev / "truth" / "truth.json").exists():
            continue
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "o"
            rc, secs, peak = run_pipeline(dev / "input", out, "gate-secret")
            row = {"exit": rc, "seconds": round(secs, 2), "peak_mb": round(peak, 1)}
            if rc == 0:
                row.update(official(dev, out))
                if name == "practice":
                    t = subprocess.run([sys.executable, str(ROOT / "tools" / "score.py"), "--dev", str(dev), "--output", str(out)],
                                       capture_output=True, text=True, encoding="utf-8").stdout
                    m = re.search(r"contextual precision ([\d.]+)", t)
                    row["ctx_precision"] = float(m.group(1)) if m else -1
                    t = subprocess.run([sys.executable, str(ROOT / "tools" / "retention.py"), str(dev), str(out)],
                                       capture_output=True, text=True, encoding="utf-8").stdout
                    m = re.search(r"token retention ([\d.]+)", t)
                    row["retention"] = float(m.group(1)) if m else -1
            res[name] = row
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ref", default=str(ROOT / "docs" / "results" / "gate_ref.json"))
    ap.add_argument("--accept", action="store_true")
    a = ap.parse_args()
    fails = []
    r = subprocess.run([sys.executable, str(ROOT / "tests" / "run_all.py")], capture_output=True, text=True, encoding="utf-8")
    if r.returncode != 0:
        fails.append("tests/run_all.py: " + "; ".join(ln for ln in r.stdout.splitlines() if not ln.startswith("PASS")))
    cur = measure()
    ref = json.loads(Path(a.ref).read_text(encoding="utf-8")) if Path(a.ref).exists() else {}
    p = cur.get("practice", {})
    want = {"leaked": "0/3230", "canaries": "0/4", "medical_kept": "4855/4855", "link_P": "1.00",
            "false_merges": "0", "raw_copies": "0", "contract": "OK"}
    for k, v in want.items():
        if p.get(k) != v:
            fails.append(f"practice {k} = {p.get(k)} (need {v})")
    if p.get("ctx_precision", 0) < 1.0:
        fails.append(f"practice contextual precision {p.get('ctx_precision')}")
    if ref.get("practice", {}).get("retention") and p.get("retention", 0) < ref["practice"]["retention"] - 0.002:
        fails.append(f"retention {p.get('retention')} < ref {ref['practice']['retention']} - 0.002")
    if p.get("seconds", 99) >= 10 or p.get("peak_mb", 9999) >= 512:
        fails.append(f"practice time/memory {p.get('seconds')} s / {p.get('peak_mb')} MB")
    for name, row in cur.items():
        if row.get("false_merges") not in ("0", None):
            fails.append(f"{name}: {row.get('false_merges')} false merges")
        if row.get("contract") != "OK":
            fails.append(f"{name}: contract {row.get('contract')}")
        old = ref.get(name)
        if not old:
            continue
        for k in ("leaked", "canaries"):
            if num(row[k])[0] > num(old[k])[0]:
                fails.append(f"{name} {k}: {old[k]} -> {row[k]}")
        if num(row["medical_kept"])[0] < num(old["medical_kept"])[0]:
            fails.append(f"{name} medical: {old['medical_kept']} -> {row['medical_kept']}")
        for k in ("link_P", "link_R"):
            if float(row[k]) < float(old[k]):
                fails.append(f"{name} {k}: {old[k]} -> {row[k]}")
    for name, row in cur.items():
        print(name, {k: row.get(k) for k in ("leaked", "canaries", "medical_kept", "link_P", "link_R", "false_merges",
                                              "raw_copies", "contract", "ctx_precision", "retention", "seconds", "peak_mb")
                     if k in row})
    for f in fails:
        print("GATE FAIL:", f)
    print("GATE PASS" if not fails else f"GATE FAIL ({len(fails)})")
    if a.accept and not fails:
        Path(a.ref).write_text(json.dumps(cur, indent=1) + "\n", encoding="utf-8")
        print("reference updated")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
