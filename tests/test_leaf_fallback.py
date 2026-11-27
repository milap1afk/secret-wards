#!/usr/bin/env python3
"""A typed cell whose value does not fit its type (a name in a gender, insurance, age or relation column) is
never kept as is: it goes through the text detector. Clean vocabulary values are kept.
Run: python3 tests/test_leaf_fallback.py"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CSV = ("uhid,patient_name,relation,gender,insurance,age,tehsil,state\n"
       "WQ-3101,Sarla Negi,Husband - Bhupal Singh 9837200001,F (per Sarla),Self - Sarla Negi,about Sarla 61,"
       "Bhikiyasain (Bhupal Singh ke ghar),UK\n"
       "WQ-3102,Hema Bisht,mother,F,Star Health,58,Ranikhet,Uttarakhand\n")
GONE = ["Sarla", "Negi", "Bhupal", "9837200001"]
KEEP = [",mother,F,Star Health,", "Uttarakhand"]


def main():
    fails = []
    with tempfile.TemporaryDirectory() as td:
        inp, out = Path(td) / "in", Path(td) / "out"
        inp.mkdir()
        (inp / "r.csv").write_text(CSV, encoding="utf-8")
        r = subprocess.run([sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
                           env=dict(os.environ, RAKSHA_SECRET="fallback"), capture_output=True, text=True)
        t = (out / "sanitized" / "r.csv").read_text(encoding="utf-8") if r.returncode == 0 else ""
        if r.returncode:
            fails.append("non-zero exit")
        fails += [f"leaked {g}" for g in GONE if g in t]
        fails += [f"lost {k}" for k in KEEP if k not in t]
    for f in fails:
        print("FAIL", f)
    print(f"leaf fallback test: {len(fails)} failures")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
