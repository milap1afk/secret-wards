#!/usr/bin/env python3
"""Evaluate the pipeline on one or more datasets and print/save a compact summary.

  python3 tools/eval_all.py --name practice --dev kit/dev [--name blind --dev blind] [--save docs/results/x.json]

A dataset dir must contain input/ and truth/truth.json (attacker/ is optional; without it the attack columns
are skipped). Leak / medical / linking numbers are parsed from the OFFICIAL kit/check_dev.py; the contract from
the OFFICIAL kit/validate_output.py; attack numbers are LOCAL (tools/attack.py). Nothing here prints PII.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KIT = Path(os.environ.get("SECRET_WARDS_KIT", ROOT / "kit"))


def run_pipeline(inp: Path, out: Path, secret: str):
    t0 = time.monotonic()
    code = ("import resource,subprocess,sys;"
            "r=subprocess.run(sys.argv[1:]);"
            "u=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss;"
            "print('PEAK', u/1048576 if sys.platform=='darwin' else u/1024, file=sys.stderr);"
            "sys.exit(r.returncode)")
    r = subprocess.run([sys.executable, "-c", code, sys.executable, str(ROOT / "main.py"), "--input", str(inp),
                        "--output", str(out)], env=dict(os.environ, RAKSHA_SECRET=secret), capture_output=True, text=True, encoding="utf-8", errors="replace")
    m = re.search(r"PEAK ([\d.]+)", r.stderr)
    return r.returncode, time.monotonic() - t0, float(m.group(1)) if m else -1.0


def official(dev: Path, out: Path) -> dict:
    res = {}
    r = subprocess.run([sys.executable, str(KIT / "validate_output.py"), "--input", str(dev / "input"), "--output", str(out)],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    res["contract"] = "OK" if "CONTRACT OK" in r.stdout else "PROBLEMS"
    r = subprocess.run([sys.executable, str(KIT / "check_dev.py"), "--output", str(out), "--truth",
                        str(dev / "truth" / "truth.json")], capture_output=True, text=True, encoding="utf-8", errors="replace")
    t = r.stdout
    m = re.search(r"PERSONAL DATA: (\d+) of (\d+) pieces", t)
    res["leaked"] = f"{m.group(1)}/{m.group(2)}" if m else "?"
    m = re.search(r"by language: latin ([\d.]+)%, deva ([\d.]+)%, hinglish ([\d.]+)%", t)
    res["leak_by_script"] = f"{m.group(1)}/{m.group(2)}/{m.group(3)}%" if m else "?"
    m = re.search(r"CANARIES: (\d+) of (\d+)", t)
    res["canaries"] = f"{m.group(1)}/{m.group(2)}" if m else "?"
    m = re.search(r"MEDICAL DATA KEPT: (\d+) of (\d+)", t)
    res["medical_kept"] = f"{m.group(1)}/{m.group(2)}" if m else "?"
    m = re.search(r"precision ([\d.]+), recall ([\d.]+), F0.5 ([\d.]+).*?: (\d+)\)", t)
    if m:
        res["link_P"], res["link_R"], res["link_F05"], res["false_merges"] = m.group(1), m.group(2), m.group(3), m.group(4)
    m = re.search(r"RAW COPIES: (\d+)", t)
    res["raw_copies"] = m.group(1) if m else "?"
    return res


def attacks(dev: Path, out: Path, out2: Path) -> dict:
    if not (dev / "attacker" / "registry.csv").exists():
        return {}
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "attack.py"), "--dev", str(dev), "--output", str(out),
                        "--output2", str(out2)], capture_output=True, text=True, encoding="utf-8", errors="replace")
    t = r.stdout
    res = {}
    for key, pat in (("A1", r"A1 direct exposure\s+share of patients exposed ([\d.]+)"),
                     ("A2A3", r"A2/A3 record linkage.*ratio ([\d.]+)"), ("A4", r"A4 profile re-id.*ratio ([\d.]+)"),
                     ("A5", r"A5 targeted.*ratio ([\d.]+)"), ("A6", r"A6 pseudonym inversion\s+([\d.]+)"),
                     ("A7", r"A7 cross-release\s+([\d.]+)"), ("risk", r"combined risk ([\d.]+)")):
        m = re.search(pat, t)
        res[key] = m.group(1) if m else "?"
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", action="append", required=True)
    ap.add_argument("--dev", action="append", required=True)
    ap.add_argument("--save", default="")
    a = ap.parse_args()
    rows = {}
    for name, dev in zip(a.name, a.dev):
        dev = Path(dev)
        with tempfile.TemporaryDirectory() as td:
            o1, o2 = Path(td) / "o1", Path(td) / "o2"
            rc, secs, peak = run_pipeline(dev / "input", o1, "eval-secret-1")
            row = {"exit": rc, "seconds": round(secs, 2), "peak_mb": round(peak, 1)}
            if rc == 0:
                row.update(official(dev, o1))
                if (dev / "attacker").exists():
                    run_pipeline(dev / "input", o2, "eval-secret-2")
                    row.update(attacks(dev, o1, o2))
            rows[name] = row
    print(json.dumps(rows, indent=1))
    if a.save:
        Path(a.save).parent.mkdir(parents=True, exist_ok=True)
        Path(a.save).write_text(json.dumps(rows, indent=1) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
