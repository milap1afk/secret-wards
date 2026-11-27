#!/usr/bin/env python3
"""Other people named in a patient's note (village head, neighbour, contractor, grandson) are removed but do NOT
get the patient's pseudonym; the patient's own name does. Run: python3 tests/test_attribution.py"""
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NOTE = ("Pt: Mewalal Prajapati   Age/Sex: 70/M   IPD: 26/MED/007731\n"
        "History: Gaon ke Pradhan Ramnaresh Pal ji ne 108 call kiya. Neighbour Bhola ne blood diya.\n"
        "Works with contractor Lallan Thekedar. Report collected by grandson Sonu. Mewalal ko bukhar hai.\n")


def main():
    fails = []
    with tempfile.TemporaryDirectory() as td:
        inp, out = Path(td) / "in", Path(td) / "out"
        inp.mkdir()
        (inp / "n.txt").write_text(NOTE, encoding="utf-8")
        subprocess.run([sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
                       env=dict(os.environ, RAKSHA_SECRET="attr"), capture_output=True, text=True)
        t = (out / "sanitized" / "n.txt").read_text(encoding="utf-8")
        for x in ("Mewalal", "Prajapati", "Ramnaresh", "Bhola", "Lallan", "Sonu"):
            if x in t:
                fails.append(f"leaked {x}")
        psn = re.findall(r"PSN-[A-Z]{6}", t)
        if len(psn) != 2:     # "Pt:" and "Mewalal ko": the patient twice, nobody else
            fails.append(f"patient pseudonym used {len(psn)} times (want 2): {t!r}")
    for f in fails:
        print("FAIL", f)
    print(f"attribution test: {len(fails)} failures")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
