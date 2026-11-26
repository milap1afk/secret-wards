#!/usr/bin/env python3
"""Schema-preservation and FHIR-validity check: input vs sanitised output.

  python3 tools/structure.py --input kit/dev/input --output out
"""
import argparse
import csv
import io
import json
import re
import sys
from pathlib import Path

FHIR_DATE = re.compile(r"^\d{4}(-\d{2}(-\d{2})?)?$")
FHIR_DT = re.compile(r"^\d{4}(-\d{2}(-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+\-]\d{2}:\d{2})?)?)?)?$")
DATE_KEYS = {"birthDate", "recordedDate", "date", "issued"}
DT_KEYS = {"effectiveDateTime", "start", "end", "timestamp", "lastUpdated", "authoredOn", "onsetDateTime"}


def read_text(p):
    raw = p.read_bytes()
    for enc in ("utf-8-sig", "utf-16", "cp1252"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            pass
    return None


def paths(o, pre=""):
    out = {}
    if isinstance(o, dict):
        for k, v in o.items():
            out.update(paths(v, f"{pre}/{k}"))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            out.update(paths(v, f"{pre}/[]"))
    else:
        out[pre] = type(o).__name__
    return out


def fhir_problems(b):
    probs = []
    if b.get("resourceType") != "Bundle":
        return probs
    full = {e.get("fullUrl") for e in b.get("entry", [])}
    def walk(o, key=""):
        if isinstance(o, dict):
            for k, v in o.items():
                if k == "reference" and isinstance(v, str) and v.startswith("urn:uuid:") and v not in full:
                    probs.append(f"unresolved reference {v[:20]}")
                if k in DATE_KEYS and isinstance(v, str) and not FHIR_DT.match(v):
                    probs.append(f"bad date {k}={v[:25]}")
                if k in DT_KEYS and isinstance(v, str) and not FHIR_DT.match(v):
                    probs.append(f"bad dateTime {k}={v[:25]}")
                if k == "div" and isinstance(v, str) and 'xmlns="http://www.w3.org/1999/xhtml"' not in v:
                    probs.append("narrative div lost xhtml namespace")
                if k == "data" and isinstance(v, str):
                    import base64
                    try:
                        base64.b64decode(v, validate=True)
                    except Exception:
                        probs.append("invalid base64 attachment")
                walk(v, k)
        elif isinstance(o, list):
            for v in o:
                walk(v, key)
    walk(b)
    for e in b.get("entry", []):
        r = e.get("resource", {})
        if not r.get("resourceType") or not r.get("id"):
            probs.append("resource without type/id")
    return probs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="kit/dev/input")
    ap.add_argument("--output", default="out")
    a = ap.parse_args()
    inp, out = Path(a.input), Path(a.output)
    rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
    import hashlib
    sha_out = {f["input_sha256"]: f["output"] for f in rep["files"] if f.get("output")}
    issues = 0
    for p in sorted(inp.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(inp).as_posix()
        o = sha_out.get(hashlib.sha256(p.read_bytes()).hexdigest())
        if not o:
            continue
        q = out / o
        if not (out / ("sanitized/" + rel)).exists() and q.exists():
            pass
        tin, tout = read_text(p), q.read_text(encoding="utf-8")
        ext = p.suffix.lower()
        msgs = []
        if ext == ".json":
            ji, jo = json.loads(tin), json.loads(tout)
            pi, po = paths(ji), paths(jo)
            missing = set(pi) - set(po)
            extra = set(po) - set(pi)
            changed = [k for k in pi if k in po and pi[k] != po[k]]
            if missing:
                msgs.append(f"{len(missing)} key paths missing e.g. {sorted(missing)[:2]}")
            if extra:
                msgs.append(f"{len(extra)} new key paths e.g. {sorted(extra)[:2]}")
            if changed:
                msgs.append(f"type changes: {[(k, pi[k], po[k]) for k in changed[:4]]}")
            msgs += fhir_problems(jo)
        elif ext in (".csv", ".tsv"):
            d = "\t" if (ext == ".tsv" or tin.split("\n")[0].count("\t") > tin.split("\n")[0].count(",")) else ","
            ri = list(csv.reader(io.StringIO(tin, newline=""), delimiter=d))
            ro = list(csv.reader(io.StringIO(tout, newline=""), delimiter=d))
            if len(ri) != len(ro):
                msgs.append(f"row count {len(ri)} -> {len(ro)}")
            if ri and ro and ri[0] != ro[0]:
                msgs.append(f"header changed: {[x for x, y in zip(ri[0], ro[0]) if x != y][:4]}")
            shape = sum(1 for x, y in zip(ri, ro) if len(x) != len(y))
            if shape:
                msgs.append(f"{shape} rows changed shape")
        else:
            li, lo = tin.count("\n"), tout.count("\n")
            if li != lo:
                msgs.append(f"line count {li} -> {lo}")
        if msgs:
            issues += 1
            print(f"{rel}:")
            for m in msgs:
                print("   ", m)
    print(f"files with structural differences: {issues}")


if __name__ == "__main__":
    main()
