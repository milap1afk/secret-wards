#!/usr/bin/env python3
"""With dob_policy: suppress, no birth year may survive in any DOB field or DOB anchor (CSV, JSON, FHIR, text),
FHIR birthDate is removed (optional in R4) and the bundle stays valid. Run: python3 tests/test_dob_policy.py"""
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from fhir_check import check_bundle  # noqa: E402


def main():
    fails = []
    with tempfile.TemporaryDirectory() as td:
        inp, out = Path(td) / "in", Path(td) / "out"
        (inp / "fhir").mkdir(parents=True)
        (inp / "reg.csv").write_text("UHID,Name,DOB,Age\nKG-100200,Trilok Bundela,12/04/1977,48\n", encoding="utf-8")
        (inp / "p.json").write_text(json.dumps({"patients": [{"uhid": "KG-100201", "name": "Yamini Chandel",
                                                               "dob": "1991-06-30", "age": 35}]}), encoding="utf-8")
        (inp / "note.txt").write_text("Patient Name: Omveer Jadon\nDOB: 03/02/1968\nD.O.B. 1968\n", encoding="utf-8")
        (inp / "fhir" / "b.json").write_text(json.dumps({"resourceType": "Bundle", "type": "document", "entry": [
            {"fullUrl": "urn:uuid:11111111-1111-4111-8111-111111111111",
             "resource": {"resourceType": "Patient", "id": "11111111-1111-4111-8111-111111111111",
                          "name": [{"text": "Gangadin Parihar"}], "birthDate": "1959-08-14"}}]}), encoding="utf-8")
        r = subprocess.run([sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
                           env=dict(os.environ, RAKSHA_SECRET="dob-test"), capture_output=True, text=True, encoding="utf-8")
        if r.returncode:
            fails.append("non-zero exit")
        blob = "".join(p.read_text(encoding="utf-8") for p in (out / "sanitized").rglob("*") if p.is_file())
        for y in ("1977", "1991", "1968", "1959"):
            if y in blob:
                fails.append(f"birth year {y} survived")
        b = json.loads((out / "sanitized" / "fhir" / "b.json").read_text(encoding="utf-8"))
        if "birthDate" in b["entry"][0]["resource"]:
            fails.append("FHIR birthDate not removed")
        if check_bundle(b):
            fails.append(f"FHIR invalid: {check_bundle(b)}")
        bands = [(int(a), int(b)) for a, b in re.findall(r"\b(\d{1,2})-(\d{1,3})\b", blob)]
        if not any(lo <= 48 <= hi and hi - lo >= 4 for lo, hi in bands):
            fails.append("no age band containing the true age 48")
    for f in fails:
        print("FAIL", f)
    print(f"dob policy test: {len(fails)} failures")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
