#!/usr/bin/env python3
"""LOCAL structural FHIR R4 check (an approximation; the official validator raksha_eval/scoring/fhir.py is
not published). Covers the items SCORING.md lists for FHIR validity: resource types, ids, required elements,
value sets, date/dateTime/instant syntax, base64 attachments, references resolvable inside the Bundle.

  python3 tools/fhir_check.py --input kit/dev/input --output out
The validator is first run on the INPUT bundles: it must report 0 issues there to be trusted.
"""
import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
from pathlib import Path

ID = re.compile(r"^[A-Za-z0-9\-.]{1,64}$")
DATE = re.compile(r"^\d{4}(-(0[1-9]|1[0-2])(-(0[1-9]|[12]\d|3[01]))?)?$")
DATETIME = re.compile(r"^\d{4}(-(0[1-9]|1[0-2])(-(0[1-9]|[12]\d|3[01])(T([01]\d|2[0-3]):[0-5]\d:([0-5]\d|60)(\.\d+)?(Z|[+\-]((0\d|1[0-3]):[0-5]\d|14:00)))?)?)?$")
INSTANT = re.compile(r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:([0-5]\d|60)(\.\d+)?(Z|[+\-]((0\d|1[0-3]):[0-5]\d|14:00))$")
URN_UUID = re.compile(r"^urn:uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

KNOWN_TYPES = {"Bundle", "Composition", "Patient", "Practitioner", "PractitionerRole", "Organization", "Encounter",
               "Condition", "Observation", "MedicationRequest", "MedicationStatement", "Procedure", "DocumentReference",
               "DiagnosticReport", "AllergyIntolerance", "Immunization", "Location", "RelatedPerson", "CarePlan",
               "ServiceRequest", "Specimen", "Coverage", "Claim", "Medication", "Binary", "Provenance"}
REQUIRED = {
    "Bundle": ["type"], "Composition": ["status", "type", "date", "author", "title"], "Encounter": ["status", "class"],
    "Observation": ["status", "code"], "Condition": ["subject"], "MedicationRequest": ["status", "intent", "subject"],
    "Procedure": ["status", "subject"], "DocumentReference": ["status", "content"], "DiagnosticReport": ["status", "code"],
    "AllergyIntolerance": ["patient"], "Immunization": ["status", "vaccineCode", "patient"],
}
VALUESETS = {
    ("Bundle", "type"): {"document", "message", "transaction", "transaction-response", "batch", "batch-response",
                         "history", "searchset", "collection"},
    ("Patient", "gender"): {"male", "female", "other", "unknown"},
    ("Composition", "status"): {"preliminary", "final", "amended", "entered-in-error"},
    ("Encounter", "status"): {"planned", "arrived", "triaged", "in-progress", "onleave", "finished", "cancelled",
                              "entered-in-error", "unknown"},
    ("Observation", "status"): {"registered", "preliminary", "final", "amended", "corrected", "cancelled",
                                "entered-in-error", "unknown"},
    ("MedicationRequest", "status"): {"active", "on-hold", "cancelled", "completed", "entered-in-error", "stopped",
                                      "draft", "unknown"},
    ("MedicationRequest", "intent"): {"proposal", "plan", "order", "original-order", "reflex-order", "filler-order",
                                      "instance-order", "option"},
    ("DocumentReference", "status"): {"current", "superseded", "entered-in-error"},
}
DATE_FIELDS = {"birthDate"}
INSTANT_FIELDS = {"lastUpdated", "timestamp", "issued"}
DATETIME_FIELDS = {"date", "recordedDate", "effectiveDateTime", "start", "end", "authoredOn", "onsetDateTime",
                   "abatementDateTime", "performedDateTime", "occurrenceDateTime", "created"}


def check_bundle(b) -> list:
    issues = []
    if not isinstance(b, dict) or b.get("resourceType") != "Bundle":
        return ["not a Bundle"]
    if "id" in b and not ID.match(str(b["id"])):
        issues.append(f"Bundle.id invalid: {str(b['id'])[:30]}")
    full, local = set(), set()
    for i, e in enumerate(b.get("entry", [])):
        r = e.get("resource")
        if not isinstance(r, dict):
            issues.append(f"entry[{i}] without resource")
            continue
        rt, rid = r.get("resourceType"), r.get("id")
        if rt not in KNOWN_TYPES:
            issues.append(f"entry[{i}] unknown resourceType {rt}")
        if not isinstance(rid, str) or not ID.match(rid):
            issues.append(f"{rt} id invalid: {str(rid)[:30]}")
        fu = e.get("fullUrl")
        if fu:
            full.add(fu)
            if fu.startswith("urn:uuid:") and not URN_UUID.match(fu):
                issues.append(f"fullUrl is not a valid urn:uuid: {fu[:40]}")
            if fu.startswith("urn:uuid:") and isinstance(rid, str) and fu != "urn:uuid:" + rid and URN_UUID.match("urn:uuid:" + rid):
                issues.append(f"fullUrl/id mismatch in entry[{i}]")
        if rt and rid:
            local.add(f"{rt}/{rid}")
        for f in REQUIRED.get(rt, []):
            if f == "subject" and rt == "MedicationRequest":
                pass
            if f not in r and not (f == "medication" and any(k.startswith("medication") for k in r)):
                issues.append(f"{rt} missing required {f}")
        for (vrt, field), allowed in VALUESETS.items():
            if vrt == rt and field in r and r[field] not in allowed:
                issues.append(f"{rt}.{field} not in value set: {r[field]}")
    for (vrt, field), allowed in VALUESETS.items():
        if vrt == "Bundle" and field in b and b[field] not in allowed:
            issues.append(f"Bundle.{field} not in value set: {b[field]}")

    def walk(o, path):
        if isinstance(o, dict):
            for k, v in o.items():
                p = path + "/" + k
                if isinstance(v, str):
                    if k in DATE_FIELDS and not DATE.match(v):
                        issues.append(f"bad date {p}={v[:25]}")
                    elif k in INSTANT_FIELDS and not INSTANT.match(v):
                        issues.append(f"bad instant {p}={v[:25]}")
                    elif k in DATETIME_FIELDS and not DATETIME.match(v):
                        issues.append(f"bad dateTime {p}={v[:25]}")
                    elif k == "data" and "attachment" in path.lower() or k == "data" and "content" in path:
                        try:
                            base64.b64decode(v, validate=True)
                        except (binascii.Error, ValueError):
                            issues.append(f"invalid base64 at {p}")
                    elif k == "reference":
                        if not (v.startswith("#") or v in full or v in local):
                            issues.append(f"unresolved reference {v[:40]}")
                    elif k == "div" and 'xmlns="http://www.w3.org/1999/xhtml"' not in v:
                        issues.append(f"narrative div without xhtml namespace at {p}")
                walk(v, p)
        elif isinstance(o, list):
            for v in o:
                walk(v, path + "/[]")
    walk(b, "")
    return issues


def bundles(root: Path, report=None):
    if report is None:
        for p in sorted(root.rglob("*.json")):
            try:
                d = json.loads(p.read_text(encoding="utf-8-sig"))
            except (ValueError, UnicodeDecodeError, RecursionError):
                continue
            if isinstance(d, dict) and d.get("resourceType") == "Bundle":
                yield hashlib.sha256(p.read_bytes()).hexdigest(), p.relative_to(root).as_posix(), d
    else:
        for f in report["files"]:
            if f.get("output") and f["output"].endswith(".json"):
                d = json.loads((root / f["output"]).read_text(encoding="utf-8"))
                if isinstance(d, dict) and d.get("resourceType") == "Bundle":
                    yield f["input_sha256"], f["output"], d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="kit/dev/input")
    ap.add_argument("--output", default="out")
    a = ap.parse_args()
    inp, out = Path(a.input), Path(a.output)
    in_issues = {}
    n_in = 0
    for sha, rel, b in bundles(inp):
        n_in += 1
        in_issues[sha] = check_bundle(b)
    bad_in = {k: v for k, v in in_issues.items() if v}
    print(f"input bundles: {n_in}, with issues: {len(bad_in)}  (validator sanity: should be 0)")
    for sha, v in list(bad_in.items())[:3]:
        print("   ", v[:3])
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    n_out = 0
    new_issues = 0
    for sha, rel, b in bundles(out, report):
        n_out += 1
        iss = [x for x in check_bundle(b) if x not in in_issues.get(sha, [])]
        if iss:
            new_issues += 1
            print(f"{rel}: {iss[:4]}")
    print(f"output bundles: {n_out}, with issues not present in the input: {new_issues}")
    return 1 if new_issues or n_out < n_in else 0


if __name__ == "__main__":
    sys.exit(main())
