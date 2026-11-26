#!/usr/bin/env python3
"""Round-5 end-to-end probes for structural hiding places: names in CSV headers, Devanagari file names,
Devanagari JSON keys, free-text metadata values, base64 inside plain notes, XML attributes, FHIR extensions,
contact lists. Nothing planted may survive anywhere; medical values must. Run: python3 tests/test_probe_e2e2.py"""
import base64
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLANTED = ["Kalpana", "9876512345", "सुरेश यादव", "9812300022", "Gurpreet", "Lalita", "9812312312", "सुनीता", "9876500011",
           "Hemant Joshi", "9898123450", "Ishwari", "Tenzin Norbu", "9612300456", "Mridula", "Wangkhem"]
KEEP = ["Hb 10.2 g/dL", "Tab Metformin 500 mg 1-0-1", "BP 130/84", "Typhoid fever (A01.0)"]


def build(d: Path):
    (d / "lab").mkdir(parents=True)
    (d / "lab" / "vitals.csv").write_text("time,Kalpana_9876512345 BP,pulse\n06:00,130/84,88\n", encoding="utf-8")
    (d / "lab" / "रिपोर्ट_सुनीता_9876500011.txt").write_text("Hb 10.2 g/dL\n", encoding="utf-8")
    (d / "contacts.json").write_text(json.dumps({"सुरेश यादव": {"फ़ोन": "9812300022"},
                                                 "_meta": {"exported_for": "Patient Gurpreet Kaur, OPD 4"},
                                                 "contacts": [{"type": "relative", "value": "Hemant Joshi"},
                                                              {"type": "phone", "value": "9898123450"}]},
                                                ensure_ascii=False), encoding="utf-8")
    b64 = base64.b64encode("Report of Lalita Devi, mob 9812312312".encode()).decode()
    (d / "note.txt").write_text(f"Tab Metformin 500 mg 1-0-1. BP 130/84.\nattachment: {b64}\n", encoding="utf-8")
    (d / "cda.xml").write_text('<?xml version="1.0"?><doc><patient name="Ishwari Bhandari" phone="9612300400"/>'
                               '<dx>Typhoid fever (A01.0)</dx></doc>', encoding="utf-8")
    (d / "fhir").mkdir()
    (d / "fhir" / "b.json").write_text(json.dumps({"resourceType": "Bundle", "type": "document", "entry": [
        {"fullUrl": "urn:uuid:11111111-1111-4111-8111-111111111111",
         "resource": {"resourceType": "Patient", "id": "11111111-1111-4111-8111-111111111111",
                      "name": [{"text": "Mridula Wangkhem"}],
                      "extension": [{"url": "https://x.example/fhir/StructureDefinition/fathers-name",
                                     "valueString": "Tenzin Norbu"}],
                      "telecom": [{"system": "phone", "value": "9612300456"}]}}]}), encoding="utf-8")


def main():
    with tempfile.TemporaryDirectory() as td:
        inp, out = Path(td) / "in", Path(td) / "out"
        build(inp)
        r = subprocess.run([sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
                           env=dict(os.environ, RAKSHA_SECRET="probe-e2e2"), capture_output=True, text=True, encoding="utf-8")
        fails = ["non-zero exit"] if r.returncode else []
        blob = r.stdout + r.stderr
        for p in sorted(out.rglob("*")):
            blob += p.name + "\n"
            if p.is_file():
                t = p.read_text(encoding="utf-8", errors="replace")
                blob += t
                for tok in t.split():                     # decode base64 the way the scorer does
                    try:
                        blob += base64.b64decode(tok + "=" * (-len(tok) % 4), validate=True).decode("utf-8")
                    except Exception:
                        pass
        for x in PLANTED:
            if x in blob:
                fails.append(f"leaked: {x}")
        for k in KEEP:
            if k not in blob:
                fails.append(f"medical value lost: {k}")
        rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
        q = [f.get("reason") for f in rep["files"] if f["status"] != "sanitized"]
        if q:
            fails.append(f"quarantined: {q}")
    for f in fails:
        print("FAIL", f)
    print(f"probe e2e round 5: {len(PLANTED)} planted, {len(KEEP)} kept, {len(fails)} failures")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
