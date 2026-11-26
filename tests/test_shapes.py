#!/usr/bin/env python3
"""End-to-end test on file shapes the practice data does not contain.

Builds a small synthetic input tree in a temp dir, runs the pipeline and checks that
nothing is quarantined, no planted name or phone survives, and different people never
share a pseudonym. Run: python3 tests/test_shapes.py
"""
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NAMES = ["Kanhaiyalal Ojha", "Hiralal Rajak", "Vaidehi Mallah", "Rudransh Gaharwar", "Bhagirath Tomar", "Chandrakala Sengar", "Trilok Bundela", "Yamini Chandel", "Mangru Ram",
         "Omveer Jadon", "Fakira Sisodia", "Gangadin Parihar", "Nankau", "Pancham"]
PHONES = ["9811100022", "9800012345", "234567890123", "9876501234", "9876501299", "9812345670", "9812345671", "9811122233", "9800011122", "9800011199"]


def build(d: Path) -> None:
    (d / "a").mkdir(parents=True)
    (d / "b").mkdir()
    json.dump([{"mrn": "KGMU/2026/004512", "full_name": "Bhagirath Tomar", "mobile_no": "9876501234", "dob": "1961-03-04"},
               {"mrn": "KGMU/2026/004513", "full_name": "Chandrakala Sengar", "mobile_no": "9876501299", "dob": "1970-11-23"}],
              open(d / "a/top_level_list.json", "w", encoding="utf-8"), indent=2)
    (d / "a/semicolon.csv").write_text("Patient No;Patient Full Name;Contact;Village;Age\n"
                                       "KG-000451;Trilok Bundela;9812345670;Lakhanpur;63\n"
                                       "KG-000452;Yamini Chandel;9812345671;Sarai Mir;29\n", encoding="utf-8")
    (d / "a/pipe.psv").write_text("id|name|phone\n1|Mangru Ram|9811122233\n", encoding="utf-8")
    json.dump({"data": {"records": {"items": [{"patient": {"name": "Omveer Jadon", "uhid": "KG-000453"},
                                               "note": "Omveer ji ka sugar high"}]}}}, open(d / "b/deep.json", "w", encoding="utf-8"))
    (d / "b/latin1.txt").write_bytes("Patient: Fakira Sisodia, Temp 101.2°F – stable. Mob 9800011122".encode("cp1252"))
    (d / "b/utf16.txt").write_bytes("Name: Gangadin Parihar Ph 9800011199".encode("utf-16-le"))
    (d / "b/hinglish.txt").write_text("Raat ko Nankau ki tabiyat kharab hui. Uske bete Pancham ne bataya.\n", encoding="utf-8")
    (d / "b/cda.xml").write_text('<?xml version="1.0"?>\n<ClinicalDocument xmlns="urn:hl7-org:v3"><recordTarget><patientRole>'
                                 '<id root="2.16.356.aadhaar" extension="234567890123"/><telecom value="tel:+91-9800012345"/>'
                                 '<patient><name><given>Rudransh</given><family>Gaharwar</family></name></patient></patientRole>'
                                 '</recordTarget><component><text>Rudransh ji admitted with dengue</text></component></ClinicalDocument>', encoding="utf-8")
    (d / "a/preamble.csv").write_text("Lab export - Collection Centre\nCourier booked by Kanhaiyalal Ojha, ph 9811100022\n\n"
                                      "sample,patient_name,uhid,test,result\nS1,Hiralal Rajak,KG-000901,Hb,9.1\n"
                                      "S2,Vaidehi Mallah,KG-000902,Hb,11.4\n", encoding="utf-8")
    (d / "b/bomb.xml").write_text('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">]><a>&lol;</a>', encoding="utf-8")


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        inp, out = Path(td) / "in", Path(td) / "out"
        build(inp)
        env = dict(os.environ, RAKSHA_SECRET="shape-test")
        r = subprocess.run([sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
                           env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
        fails = []
        if r.returncode != 0:
            fails.append(f"exit code {r.returncode}")
        rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
        q = [f for f in rep["files"] if f["status"] != "sanitized"]
        if len(q) != 1 or q[0].get("reason") != "xml_dtd_not_allowed":
            fails.append(f"expected exactly the DTD bomb quarantined, got {[x.get('reason') for x in q]}")
        blob = "".join(p.read_text(encoding="utf-8") for p in (out / "sanitized").rglob("*") if p.is_file())
        blob += (out / "report.json").read_text(encoding="utf-8") + (out / "records.jsonl").read_text(encoding="utf-8") + r.stdout + r.stderr
        for n in NAMES:
            for tok in n.split():
                if len(tok) > 3 and re.search(r"\b" + tok + r"\b", blob):
                    fails.append(f"name leaked: {tok}")
        for ph in PHONES:
            if ph in blob:
                fails.append(f"phone leaked: {ph}")
        recs = [json.loads(l) for l in (out / "records.jsonl").read_text(encoding="utf-8").splitlines()]
        pre = {x["loc"]: x["patient"] for x in recs if x["file"].endswith("preamble.csv")}
        if sorted(pre) != ["row:0", "row:1"] or pre.get("row:0") == pre.get("row:1"):
            fails.append(f"preamble CSV rows wrong: {sorted(pre)}")
        tl = [x["patient"] for x in recs if x["file"].endswith("top_level_list.json")]
        if len(tl) != 2 or tl[0] == tl[1]:
            fails.append(f"top-level list records wrong: {tl}")
        for f in fails:
            print("FAIL", f)
        print(f"shape test: {len(fails)} failures")
        return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
