#!/usr/bin/env python3
"""FHIR identifier-like ids and references: no identifier may survive, every reference must still resolve,
the remapping must be deterministic and keyed by the secret.  Run: python3 tests/test_fhir_ids.py
"""
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SECRET_IDS = ["064127", "0076928", "IPD-2026-00461", "9876501234"]

BUNDLE = {
    "resourceType": "Bundle", "id": "bundle-SNJ-26-064127", "type": "document",
    "entry": [
        {"fullUrl": "http://snj.example/fhir/Patient/SNJ-26-064127",
         "resource": {"resourceType": "Patient", "id": "SNJ-26-064127",
                      "identifier": [{"system": "https://snj.example/uhid", "value": "SNJ/26/064127"}],
                      "name": [{"text": "Mahesh Chauhan", "given": ["Mahesh"], "family": "Chauhan"}],
                      "telecom": [{"system": "phone", "value": "9876501234"}], "birthDate": "1977-04-12"}},
        {"fullUrl": "urn:uuid:8b5c7d1e-0000-4000-8000-000000000001",
         "resource": {"resourceType": "Encounter", "id": "8b5c7d1e-0000-4000-8000-000000000001",
                      "identifier": [{"system": "https://snj.example/ipd", "value": "IPD-2026-00461"}],
                      "subject": {"reference": "Patient/SNJ-26-064127", "display": "Mahesh Chauhan"},
                      "period": {"start": "2026-02-04T18:15:00+05:30", "end": "2026-02-12T11:00:00+05:30"}}},
        {"fullUrl": "http://snj.example/fhir/Observation/obs-JJH-0076928-1",
         "resource": {"resourceType": "Observation", "id": "obs-JJH-0076928-1", "status": "final",
                      "code": {"text": "Haemoglobin"},
                      "subject": {"reference": "http://snj.example/fhir/Patient/SNJ-26-064127"},
                      "encounter": {"reference": "urn:uuid:8b5c7d1e-0000-4000-8000-000000000001"},
                      "valueQuantity": {"value": 9.2, "unit": "g/dL"}}},
        {"fullUrl": "http://snj.example/fhir/Condition/cond-9876501234",
         "resource": {"resourceType": "Condition", "id": "cond-9876501234",
                      "subject": {"reference": "Patient/SNJ-26-064127"},
                      "code": {"text": "Typhoid fever"}}},
    ],
}
FHIR_ID = re.compile(r"^[A-Za-z0-9\-.]{1,64}$")


def run(secret, inp, out):
    r = subprocess.run([sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
                       env=dict(os.environ, RAKSHA_SECRET=secret), capture_output=True, text=True, encoding="utf-8", errors="replace")
    return r.returncode, json.loads((out / "sanitized" / "fhir" / "b.json").read_text(encoding="utf-8"))


def check(b):
    fails = []
    blob = json.dumps(b)
    for s in SECRET_IDS:
        if s in blob:
            fails.append(f"identifier survived: {s}")
    if "Mahesh" in blob or "Chauhan" in blob:
        fails.append("patient name survived")
    full = {e["fullUrl"] for e in b["entry"]}
    local = {f'{e["resource"]["resourceType"]}/{e["resource"]["id"]}' for e in b["entry"]}
    for e in b["entry"]:
        rid = e["resource"]["id"]
        if not FHIR_ID.match(rid):
            fails.append(f"invalid FHIR id {rid!r}")
        if not e["fullUrl"].startswith("urn:uuid:") and not e["fullUrl"].endswith("/" + rid):
            fails.append(f"fullUrl does not end with its id: {e['fullUrl']}")
        if e["fullUrl"].startswith("urn:uuid:") and e["fullUrl"] != "urn:uuid:" + rid:
            fails.append("urn:uuid fullUrl no longer matches id")

    def refs(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k == "reference" and isinstance(v, str):
                    yield v
                else:
                    yield from refs(v)
        elif isinstance(o, list):
            for v in o:
                yield from refs(v)
    for r in refs(b):
        if r not in full and r not in local:
            fails.append(f"unresolved reference {r}")
    if b["entry"][1]["resource"]["id"] != "8b5c7d1e-0000-4000-8000-000000000001":
        fails.append("plain UUID id was changed (it carries no identity)")
    return fails


def main():
    with tempfile.TemporaryDirectory() as td:
        inp = Path(td) / "in"
        (inp / "fhir").mkdir(parents=True)
        (inp / "fhir" / "b.json").write_text(json.dumps(BUNDLE, indent=2), encoding="utf-8")
        c1, b1 = run("secret-one", inp, Path(td) / "o1")
        c2, b1b = run("secret-one", inp, Path(td) / "o1b")
        c3, b2 = run("secret-two", inp, Path(td) / "o2")
        fails = check(b1)
        if c1 or c2 or c3:
            fails.append("non-zero exit")
        if b1 != b1b:
            fails.append("not deterministic with the same secret")
        if b1["entry"][0]["resource"]["id"] == b2["entry"][0]["resource"]["id"]:
            fails.append("remapped id did not change with a different secret")
        for f in fails:
            print("FAIL", f)
        print(f"fhir id test: {len(fails)} failures")
        return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
