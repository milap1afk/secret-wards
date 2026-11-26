#!/usr/bin/env python3
"""Positive controls for the LOCAL attack approximations A1, A6, A7 (tools/attack.py):
each check must fire on a deliberately broken release, and stay at 0 on ours.
Needs the practice kit (kit/dev, or SECRET_WARDS_KIT). Exit 2 = NOT VERIFIED when it is missing.
Run: python3 tests/test_attack_checks.py"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT))
import attack  # noqa: E402

DEV = Path(os.environ.get("SECRET_WARDS_KIT", ROOT / "kit")) / "dev"


def run(secret, out):
    subprocess.run([sys.executable, str(ROOT / "main.py"), "--input", str(DEV / "input"), "--output", str(out)],
                   env=dict(os.environ, RAKSHA_SECRET=secret), check=True, capture_output=True)


def main():
    if not DEV.exists():
        print("NOT VERIFIED: practice kit not found (run tools/get_kit.py or set SECRET_WARDS_KIT)")
        return 2
    truth = json.loads((DEV / "truth" / "truth.json").read_text(encoding="utf-8"))
    attack.dev_root = DEV
    fails = []
    with tempfile.TemporaryDirectory() as td:
        o1, o2 = Path(td) / "o1", Path(td) / "o2"
        run("secret-a", o1)
        run("secret-b", o2)
        # our release
        if attack.a1_direct(truth, o1) != 0:
            fails.append("A1 > 0 on our release")
        if attack.a6_inversion(truth, o1)[0] != 0:
            fails.append("A6 > 0 on our release")
        if attack.a7_cross(truth, o1, o2)[0] != 0:
            fails.append("A7 > 0 on our release")
        # control 1: A1 must fire when a phone survives
        bad = Path(td) / "bad1"
        shutil.copytree(o1, bad)
        ph = next(e["surface"] for f in truth["files"].values() for u in f["units"].values() for e in u["entities"]
                  if e["type"] == "PHONE" and e.get("role") == "patient")
        (bad / "sanitized" / "leak.txt").write_text("call " + ph, encoding="utf-8")
        if attack.a1_direct(truth, bad) <= 0:
            fails.append("control: A1 did not detect a surviving phone")
        # control 2: A6 must fire when pseudonyms are an unkeyed hash of the UHID
        bad2 = Path(td) / "bad2"
        shutil.copytree(o1, bad2)
        psn = attack.psn_by_patient(truth, o1)
        lines = (bad2 / "records.jsonl").read_text(encoding="utf-8").splitlines()
        repl = {}
        for pt, p in psn.items():
            uhid = next(iter(next(iter(truth["patients"][pt]["uhids"].values()))))
            repl[p] = "PSN-" + hashlib.sha256(uhid.encode()).hexdigest()[:10]
        (bad2 / "records.jsonl").write_text("\n".join(
            json.dumps({**json.loads(l), "patient": repl.get(json.loads(l)["patient"], json.loads(l)["patient"])}) for l in lines) + "\n", encoding="utf-8")
        if attack.a6_inversion(truth, bad2)[0] <= 0.9:
            fails.append("control: A6 did not detect sha256(UHID) pseudonyms")
        # control 3: A7 must fire when the second release is identical (secret ignored)
        if attack.a7_cross(truth, o1, o1)[0] < 0.99:
            fails.append("control: A7 did not detect identical releases")
    for f in fails:
        print("FAIL", f)
    print(f"attack-check controls: {len(fails)} failures")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
