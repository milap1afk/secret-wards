#!/usr/bin/env python3
"""Missing / empty RAKSHA_SECRET must fail closed: non-zero exit, nothing written, clear message.
Run: python3 tests/test_secret.py"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main():
    fails = []
    with tempfile.TemporaryDirectory() as td:
        inp = Path(td) / "in"
        inp.mkdir()
        (inp / "note.txt").write_text("Patient Name: Ramesh Yadav  Mob: 9876501234\n")
        for label, env in (("missing", {k: v for k, v in os.environ.items() if k != "RAKSHA_SECRET"}),
                           ("empty", dict(os.environ, RAKSHA_SECRET="")),
                           ("blank", dict(os.environ, RAKSHA_SECRET="   "))):
            out = Path(td) / ("out_" + label)
            r = subprocess.run([sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
                               env=env, capture_output=True, text=True)
            if r.returncode == 0:
                fails.append(f"{label}: exit code 0")
            if out.exists() and any(out.rglob("*")):
                fails.append(f"{label}: output was written")
            if "RAKSHA_SECRET" not in r.stderr:
                fails.append(f"{label}: no clear message")
            if "Ramesh" in r.stdout + r.stderr or "9876501234" in r.stdout + r.stderr:
                fails.append(f"{label}: PII in error output")
        # a supplied secret still works
        out = Path(td) / "out_ok"
        r = subprocess.run([sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
                           env=dict(os.environ, RAKSHA_SECRET="s3cret-value"), capture_output=True, text=True)
        if r.returncode != 0 or not (out / "report.json").exists():
            fails.append("with a secret: run failed")
        else:
            blob = "".join(p.read_text(encoding="utf-8", errors="replace") for p in out.rglob("*") if p.is_file())
            if "s3cret-value" in blob + r.stdout + r.stderr:
                fails.append("secret value written to output or logs")
    for f in fails:
        print("FAIL", f)
    print(f"secret test: {len(fails)} failures")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
