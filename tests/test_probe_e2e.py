#!/usr/bin/env python3
"""End-to-end mini dataset built from the adversarial probes: nothing planted may survive anywhere in the
release (content, file names, JSON keys, CSV headers, report, records, stdout/stderr) and the medical text
must survive. Run: python3 tests/test_probe_e2e.py"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLANTED = ["Thangjam", "Ibomcha", "Sebastian Kurian", "Abhilash", "Gurtej", "Sandhu", "Selvi", "Shanmugam", "Lalrinpuii",
           "Zoramthanga", "Pachuau", "Kunjumon", "Varkey", "Chinnaswamy", "Mangayarkarasi", "Bhupendranath", "Qazipura",
           "Itaunja", "Mahona", "9845012345", "9443012345", "9876543210", "2026/000123", "H-554321", "PMJ9K2L7Q",
           "UPX1234567", "selvi.k@yahoo.co.in", "श्यामलाल", "लालरिनपुई", "ज़ोरमथंगा", "226203"]
KEEP = ["Thyronorm 50 mcg OD", "Ecosprin AV 75/10", "11.2 g/dl", "Guillain-Barre syndrome", "Dr. Lakshmi Narayanan",
        "H/o DM x 5 yrs", "C/O fever", "1-0-1", "BP 150/100"]


def build(d: Path):
    (d / "notes").mkdir(parents=True)
    (d / "notes" / "ward_note.txt").write_text(
        "Name & Age: Thangjam Ibomcha, 61\nPatient's name - Sebastian Kurian; age 44\nInformed son Mr. Abhilash Nambiar.\n"
        "Relative (husband): Gurtej Singh Sandhu\nConsulted Dr. Lakshmi Narayanan; patient Selvi informed.\n"
        "F/o Chinnaswamy, H/o Mangayarkarasi. H/o DM x 5 yrs. C/O fever x 3 days.\n"
        "Smt. Mangaleshwari Devi w/o Sh. Bhupendranath r/o Qazipura\n"
        "Address: H.No. 12/4, Mohalla Qazipura, PO Itaunja, PS Mahona, Distt Lucknow 226203\n"
        "MR# 2026/000123; Hosp. No. H-554321; PMJAY ID PMJ9K2L7Q; Voter ID: UPX1234567\n"
        "K/C/O Hypothyroidism on Thyronorm 50 mcg OD. Tab. Ecosprin AV 75/10 HS 1-0-1. Hb 11.2 g/dl. BP 150/100 mmHg.\n"
        "Diagnosis: Guillain-Barre syndrome\n", encoding="utf-8")
    (d / "notes" / "report_for_Thangjam_Ibomcha_9845012345.txt").write_text("Seen. Stable.\n", encoding="utf-8")
    (d / "reg.csv").write_text("Beneficiary,Insured person,Emergency contact\nZoramthanga Pachuau,Kunjumon Varkey,9876543210\n",
                               encoding="utf-8")
    (d / "contacts.json").write_text(json.dumps({"Shanmugam Pillai": {"phone": "9443012345"},
                                                 "email": "selvi.k@yahoo.co.in"}), encoding="utf-8")
    (d / "notes" / "hindi.txt").write_text("रोगी: लालरिनपुई, उम्र ४७ वर्ष। अभिभावक: ज़ोरमथंगा\nमरीज़ श्यामलाल को बुखार है\n", encoding="utf-8")


def main():
    with tempfile.TemporaryDirectory() as td:
        inp, out = Path(td) / "in", Path(td) / "out"
        build(inp)
        r = subprocess.run([sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
                           env=dict(os.environ, RAKSHA_SECRET="probe-e2e"), capture_output=True, text=True, encoding="utf-8")
        fails = []
        if r.returncode:
            fails.append("non-zero exit")
        blob = r.stdout + r.stderr
        for p in sorted(out.rglob("*")):
            blob += p.name + "\n"
            if p.is_file():
                blob += p.read_text(encoding="utf-8", errors="replace")
        for x in PLANTED:
            if x in blob:
                fails.append(f"leaked: {x}")
        notes = (out / "sanitized" / "notes" / "ward_note.txt").read_text(encoding="utf-8")
        for k in KEEP:
            if k not in notes:
                fails.append(f"medical text lost: {k}")
    for f in fails:
        print("FAIL", f)
    print(f"probe e2e: {len(PLANTED)} planted values, {len(KEEP)} kept values, {len(fails)} failures")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
