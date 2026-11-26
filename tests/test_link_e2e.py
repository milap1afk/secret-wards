#!/usr/bin/env python3
"""End-to-end linking traps: twins sharing DOB and phone, father and son of one name on one phone, mother and
daughter sharing phone and e-mail, a reformatted UHID, a note whose DOB label follows the name.
Every registration row must keep its own pseudonym; notes link only when exactly one person fits.
Run: python3 tests/test_link_e2e.py"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REG = """uhid,patient_name,dob,gender,phone,village,email
HX-20001,Ankit Dubey,2012-08-09,M,9450700001,Gosainganj,
HX-20002,Ankur Dubey,2012-08-09,M,9450700001,Gosainganj,
HX-20003,Naresh Bajpai,1959-01-21,M,9450700003,Malihabad,
HX-20004,Naresh Bajpai,1987-11-02,M,9450700003,Malihabad,
HX-20005,Shabnam Khatoon,1976-06-06,F,9450700005,Kakori,khatoon.home@example.in
HX-20006,Nazia Khatoon,2001-03-15,F,9450700005,Kakori,khatoon.home@example.in
HX-20007,Mohammad Salim,1981-10-10,M,9450700007,Itaunja,
"""
NOTES = {  # file -> registration row it must link to (None = must stay unlinked from every row)
    "a.txt": ("UHID: HX/20007\nName: Mohd. Salim\nDx: Pulmonary TB (A15.0)\n", 6),
    "b.txt": ("Patient: Ankur Dubey, DOB 09/08/2012, mob 9450700001\nDx: Asthma (J45.9)\n", 1),
    "c.txt": ("Name: Naresh Bajpai, mob 9450700003\nDx: Hypertension (I10)\n", None),
    "d.txt": ("Name: Nazia Khatoon, email khatoon.home@example.in\nDx: Anaemia (D64.9)\n", 5),
}


def main():
    fails = []
    with tempfile.TemporaryDirectory() as td:
        inp, out = Path(td) / "in", Path(td) / "out"
        inp.mkdir()
        (inp / "reg.csv").write_text(REG, encoding="utf-8")
        for f, (body, _) in NOTES.items():
            (inp / f).write_text(body, encoding="utf-8")
        r = subprocess.run([sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
                           env=dict(os.environ, RAKSHA_SECRET="link-e2e"), capture_output=True, text=True)
        if r.returncode:
            print("FAIL non-zero exit")
            return 1
        m = {}
        for ln in (out / "records.jsonl").read_text(encoding="utf-8").splitlines():
            x = json.loads(ln)
            m[(x["file"].split("/")[-1], x["loc"])] = x["patient"]
        rows = [m.get(("reg.csv", f"row:{i}")) for i in range(7)]
        if None in rows or len(set(rows)) != 7:
            fails.append(f"registration rows merged or unlinked: {len(set(rows))} pseudonyms for 7 people")
        for f, (_, want) in NOTES.items():
            p = m.get((f, "doc"))
            hit = [i for i, v in enumerate(rows) if v == p and p]
            if want is None and hit:
                fails.append(f"{f}: guessed a link to row {hit}")
            if want is not None and hit != [want]:
                fails.append(f"{f}: linked to {hit}, expected [{want}]")
    for f in fails:
        print("FAIL", f)
    print(f"link e2e: {len(NOTES)} notes, 7 registrations, {len(fails)} failures")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
