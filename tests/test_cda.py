#!/usr/bin/env python3
"""CDA/XML: next-of-kin and guardian persons are not clinicians, TS timestamps are shifted with the time kept,
birthTime is suppressed, id extensions / addr / telecom removed, clinical text kept. Run: python3 tests/test_cda.py"""
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CDA = """<?xml version="1.0" encoding="UTF-8"?>
<ClinicalDocument xmlns="urn:hl7-org:v3"><effectiveTime value="20260301091500+0530"/>
<recordTarget><patientRole><id root="2.16.356.1" extension="MRN77310"/>
<addr><streetAddressLine>H 4, Mohalla Kaziwara</streetAddressLine><postalCode>244001</postalCode></addr>
<telecom value="tel:+91-9837500001"/><telecom value="mailto:rehana.k@example.in"/>
<patient><name><given>Rehana</given><family>Khatoon</family></name><birthTime value="19700101"/>
<guardian><guardianPerson><name><given>Iqbal</given><family>Ahmad</family></name></guardianPerson></guardian>
</patient></patientRole></recordTarget>
<participant typeCode="IND"><associatedEntity classCode="NOK"><associatedPerson><name>Zarina Begum</name></associatedPerson></associatedEntity></participant>
<component><structuredBody><component><section><text>Known HTN. BP 150/94. Tab Telmisartan 40 mg OD.</text></section></component></structuredBody></component>
</ClinicalDocument>
"""
GONE = ["MRN77310", "77310", "Kaziwara", "244001", "9837500001", "rehana.k", "Rehana", "Khatoon", "19700101", "Iqbal", "Ahmad",
        "Zarina", "20260301"]
KEEP = ["BP 150/94", "Tab Telmisartan 40 mg OD"]


def main():
    fails = []
    with tempfile.TemporaryDirectory() as td:
        inp, out = Path(td) / "in", Path(td) / "out"
        inp.mkdir()
        (inp / "c.xml").write_text(CDA, encoding="utf-8")
        r = subprocess.run([sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
                           env=dict(os.environ, RAKSHA_SECRET="cda"), capture_output=True, text=True)
        t = (out / "sanitized" / "c.xml").read_text(encoding="utf-8") if r.returncode == 0 else ""
        fails += [f"leaked {g}" for g in GONE if g in t]
        fails += [f"lost {k}" for k in KEEP if k not in t]
        if not re.search(r'effectiveTime value="\d{8}091500\+0530"', t):
            fails.append("effectiveTime not shifted with its time kept")
    for f in fails:
        print("FAIL", f)
    print(f"cda test: {len(fails)} failures")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
