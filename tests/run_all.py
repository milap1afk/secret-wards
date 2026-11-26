#!/usr/bin/env python3
"""Run every test suite and print one line each. Exit 0 only if all PASS (NOT VERIFIED counts as not passed).
Run: python3 tests/run_all.py"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
# every tests/test_*.py, so a new suite can never be left out by accident
SUITES = sorted(p.stem for p in HERE.glob("test_*.py"))


def main():
    worst = 0
    for s in SUITES:
        r = subprocess.run([sys.executable, str(HERE / f"{s}.py")], capture_output=True, text=True, encoding="utf-8", errors="replace")
        last = (r.stdout.strip().splitlines() or [""])[-1]
        state = {0: "PASS", 2: "NOT VERIFIED"}.get(r.returncode, "FAIL")
        print(f"{state:13} {s:20} {last}")
        worst = max(worst, 1 if r.returncode not in (0, 2) else r.returncode)
    return worst


if __name__ == "__main__":
    sys.exit(main())
