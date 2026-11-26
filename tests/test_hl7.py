#!/usr/bin/env python3
"""HL7 v2 messages are recognised by their MSH header whatever the file extension (.hl7, .txt, no extension),
person fields are typed by their standard positions, timestamps are shifted with the time of day kept, and the
segment structure survives. Run: python3 tests/test_hl7.py"""
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MSG = ("MSH|^~\\&|HIS|HOSP|LAB|HOSP|202604010815||ADT^A01|M1|P|2.5\r"
       "PID|1||MRN55120^^^HOSP||Rawat^Bhagirathi^^^Smt||19610903|F|||7 Rajpur Road^^Dehradun^UK^248001||9412000777\r"
       "NK1|1|Rawat^Devendra|SON|^^Dehradun|9412000888\r"
       "OBX|1|NM|GLU^Glucose||182|mg/dL|||||F\r")
PLANTED = ["Bhagirathi", "Rawat", "Devendra", "MRN55120", "55120", "19610903", "Rajpur Road", "248001", "9412000777", "9412000888"]


def main():
    fails = []
    with tempfile.TemporaryDirectory() as td:
        inp, out = Path(td) / "in", Path(td) / "out"
        inp.mkdir()
        (inp / "a.hl7").write_text(MSG, encoding="utf-8")
        (inp / "b.txt").write_text(MSG.replace("\r", "\n"), encoding="utf-8")
        r = subprocess.run([sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
                           env=dict(os.environ, RAKSHA_SECRET="hl7-test"), capture_output=True, text=True)
        if r.returncode:
            fails.append("non-zero exit")
        else:
            rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
            if any(f["status"] != "sanitized" for f in rep["files"]):
                fails.append("an HL7 file was quarantined")
            for name, sep in (("a.hl7", "\r"), ("b.txt", "\n")):
                t = (out / "sanitized" / name).read_bytes().decode("utf-8")   # keep CR separators as written
                for x in PLANTED:
                    if x in t:
                        fails.append(f"{name}: leaked {x}")
                segs = [s for s in t.split(sep) if s]
                if [s[:3] for s in segs] != ["MSH", "PID", "NK1", "OBX"]:
                    fails.append(f"{name}: segment structure changed")
                if "|182|mg/dL|" not in t:
                    fails.append(f"{name}: lab value lost")
                m = re.match(r"MSH\|\^~\\&\|HIS\|HOSP\|LAB\|HOSP\|(\d{8})0815\|", t)
                if not m or m.group(1) == "20260401":
                    fails.append(f"{name}: message timestamp not shifted with its time kept")
            pats = {json.loads(ln)["patient"] for ln in (out / "records.jsonl").read_text().splitlines()}
            if len(pats) != 1:
                fails.append(f"the same patient got {len(pats)} pseudonyms")
    for f in fails:
        print("FAIL", f)
    print(f"hl7 test: {len(fails)} failures")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
