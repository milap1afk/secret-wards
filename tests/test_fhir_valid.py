#!/usr/bin/env python3
"""Positive controls for the LOCAL FHIR validator (tools/fhir_check.py), plus a run on the practice
output when the kit is available. Exit codes: 0 pass, 1 fail, 2 practice part NOT VERIFIED (kit missing).
Run: python3 tests/test_fhir_valid.py"""
import copy
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from fhir_check import check_bundle  # noqa: E402

GOOD = {
    "resourceType": "Bundle", "id": "b1", "type": "document", "timestamp": "2026-02-12T11:00:00+05:30",
    "entry": [
        {"fullUrl": "urn:uuid:11111111-1111-4111-8111-111111111111",
         "resource": {"resourceType": "Patient", "id": "11111111-1111-4111-8111-111111111111", "gender": "female",
                      "birthDate": "1977", "text": {"status": "generated",
                                                    "div": '<div xmlns="http://www.w3.org/1999/xhtml">x</div>'}}},
        {"fullUrl": "urn:uuid:22222222-2222-4222-8222-222222222222",
         "resource": {"resourceType": "Encounter", "id": "22222222-2222-4222-8222-222222222222", "status": "finished",
                      "class": {"code": "IMP"}, "subject": {"reference": "urn:uuid:11111111-1111-4111-8111-111111111111"},
                      "period": {"start": "2026-02-04T18:15:00+05:30"}}},
        {"fullUrl": "urn:uuid:33333333-3333-4333-8333-333333333333",
         "resource": {"resourceType": "DocumentReference", "id": "33333333-3333-4333-8333-333333333333",
                      "status": "current", "content": [{"attachment": {"contentType": "text/plain", "data": "aGVsbG8="}}]}},
    ],
}


def mutate(f):
    b = copy.deepcopy(GOOD)
    f(b)
    return b


CONTROLS = {
    "broken reference": lambda b: b["entry"][1]["resource"]["subject"].__setitem__("reference", "Patient/missing"),
    "bad birthDate": lambda b: b["entry"][0]["resource"].__setitem__("birthDate", "12/04/1977"),
    "bad dateTime": lambda b: b["entry"][1]["resource"]["period"].__setitem__("start", "2026-02-04 18:15"),
    "bad instant": lambda b: b.__setitem__("timestamp", "2026-02-12"),
    "invalid id": lambda b: b["entry"][0]["resource"].__setitem__("id", "SNJ/26/064127"),
    "bad base64": lambda b: b["entry"][2]["resource"]["content"][0]["attachment"].__setitem__("data", "%%%not-b64%%%"),
    "gender value set": lambda b: b["entry"][0]["resource"].__setitem__("gender", "F"),
    "missing required": lambda b: b["entry"][1]["resource"].pop("status"),
    "lost xhtml namespace": lambda b: b["entry"][0]["resource"]["text"].__setitem__("div", "<div>x</div>"),
    "unknown resourceType": lambda b: b["entry"][2]["resource"].__setitem__("resourceType", "Foo"),
}


def main():
    fails = []
    if check_bundle(GOOD):
        fails.append(f"valid bundle flagged: {check_bundle(GOOD)}")
    for name, f in CONTROLS.items():
        if not check_bundle(mutate(f)):
            fails.append(f"control not detected: {name}")
    kit = Path(os.environ.get("SECRET_WARDS_KIT", ROOT / "kit"))
    status = 0
    if (kit / "dev" / "input").exists():
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out"
            subprocess.run([sys.executable, str(ROOT / "main.py"), "--input", str(kit / "dev" / "input"), "--output", str(out)],
                           env=dict(os.environ, RAKSHA_SECRET="fhir-check"), check=True, capture_output=True)
            r = subprocess.run([sys.executable, str(ROOT / "tools" / "fhir_check.py"), "--input", str(kit / "dev" / "input"),
                                "--output", str(out)], capture_output=True, text=True)
            print(r.stdout.strip())
            if r.returncode != 0:
                fails.append("practice output has FHIR issues not present in the input")
    else:
        print("NOT VERIFIED: practice part skipped (kit not found; run tools/get_kit.sh or set SECRET_WARDS_KIT)")
        status = 2
    for f in fails:
        print("FAIL", f)
    print(f"fhir validator: {len(CONTROLS)} controls, {len(fails)} failures")
    return 1 if fails else status


if __name__ == "__main__":
    sys.exit(main())
