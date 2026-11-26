#!/usr/bin/env python3
"""DEV-ONLY FHIR R4 check with the fhir.resources library (6.x = R4, needs pydantic<2). Never imported by
main.py or wards/. Parses every sanitised FHIR Bundle (and, for comparison, every input Bundle) as a full R4
model, then checks that every reference resolves inside the Bundle.

  .venv/bin/pip install "fhir.resources==6.5.0" "pydantic<2"
  .venv/bin/python tools/fhir_validate_lib.py --input kit/dev/input --output out
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

try:
    from fhir.resources.bundle import Bundle
except ImportError:
    print('NOT VERIFIED: fhir.resources not installed (pip install "fhir.resources==6.5.0" "pydantic<2")')
    sys.exit(2)


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


def check(d):
    errs = []
    try:
        Bundle.parse_obj(d)
    except Exception as exc:  # pydantic ValidationError: report the paths, never the values
        lines = [ln for ln in str(exc).splitlines() if ln and not ln.startswith("  ")]
        errs += [f"R4 model: {ln}" for ln in lines[:6]] or ["R4 model: invalid"]
    full = {e.get("fullUrl") for e in d.get("entry", [])}
    local = {f'{e.get("resource", {}).get("resourceType")}/{e.get("resource", {}).get("id")}' for e in d.get("entry", [])}
    for r in refs(d):
        if not (r.startswith("#") or r in full or r in local):
            errs.append("unresolved reference")
    return errs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="kit/dev/input")
    ap.add_argument("--output", default="out")
    a = ap.parse_args()
    inp, out = Path(a.input), Path(a.output)
    base = {}
    for p in sorted(inp.rglob("*.json")):
        try:
            d = json.loads(p.read_text(encoding="utf-8-sig"))
        except (ValueError, UnicodeDecodeError, RecursionError):
            continue
        if isinstance(d, dict) and d.get("resourceType") == "Bundle":
            base[hashlib.sha256(p.read_bytes()).hexdigest()] = check(d)
    print(f"input bundles: {len(base)}, invalid as R4: {sum(1 for v in base.values() if v)}")
    rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
    n = bad = 0
    for f in rep["files"]:
        if f["input_sha256"] not in base or not f.get("output"):
            continue
        n += 1
        d = json.loads((out / f["output"]).read_text(encoding="utf-8"))
        new = [e for e in check(d) if e not in base[f["input_sha256"]]]
        if new:
            bad += 1
            print(f"{f['output']}: {new[:4]}")
    print(f"output bundles: {n}, with R4/reference problems not present in the input: {bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
