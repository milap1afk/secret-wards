#!/usr/bin/env python3
"""Live demo: sanitise one SYNTHETIC note typed on the command line and explain every decision.

  python3 tools/demo.py "Patient Name: Asha Rajput 48/F, W/o Kamal. C/O fever x 3 days. Dr. Ramesh Srivastava. Mob 9876543210"

Prints the note before and after, then one line per span: what it was, which detector layer found it, and
whether it was removed, generalised or protected. Nothing is written to disk. If RAKSHA_SECRET is not set, a
random key is used for this process only (it is never printed).
"""
import os
import secrets
import sys
from pathlib import Path

if not os.environ.get("RAKSHA_SECRET", "").strip():
    os.environ["RAKSHA_SECRET"] = secrets.token_hex(16)    # in-memory demo key, never shown
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wards.pipeline import Pipeline, Unit  # noqa: E402

LAYER = {
    "label": "label (Name:, नाम:, Attendant:)", "relation": "relation marker (S/o, W/o, C/O <name>)",
    "honorific": "honorific (sahab, ji, didi)", "prefix": "prefix (Shri, Smt.)", "verb": "role verb (called by, witnessed by)",
    "role": "role in brackets ((attendant)", "chat": "chat sender", "phone-adj": "name next to a phone",
    "lexicon": "dataset lexicon", "lexicon-token": "dataset lexicon", "lexicon-deva": "dataset lexicon (Devanagari)",
    "gazetteer": "name gazetteer", "gazetteer-caps": "name gazetteer", "gazetteer-deva": "name gazetteer (Devanagari)",
    "suffix": "name + Devi/Kumar/Bano/Singh", "possessive": "Hinglish possessive (X ka BP)", "kinship": "Hinglish kinship (bete X ne)",
    "deva-role": "Devanagari role ((पड़ोसी)", "deva-phone": "Devanagari name before मो.", "model": "trained name scorer",
    "sweep": "record sweep (name seen elsewhere in the record)",
}
PROTECT = {"doctor": "doctor", "org": "hospital / lab name", "ward": "clinical ward/bed", "eponym": "disease eponym",
           "asha": "ASHA worker", "uuid": "UUID", "hex": "hash", "url": "URL", "ifsc": "bank branch code (IFSC)"}


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    note = " ".join(sys.argv[1:])
    pl = Pipeline(Path("."), Path("."))          # no files are read or written
    u = Unit("demo", "doc", "doc", text=note)
    from wards.privacy import shift_days
    u.shift = shift_days("demo#" + note)         # the pipeline gives every record its own keyed shift
    t2, spans = pl._detect(note)
    after = pl._render_free(note, u, set())
    print("BEFORE:", note)
    print("AFTER: ", after)
    print()
    print(f"{'span':34} {'kind':13} {'action':12} layer")
    for s in spans:
        seg = t2[s.start:s.end]
        if s.kind == "PROTECT":
            action, layer = "kept", "protected: " + PROTECT.get(s.value, s.value)
        elif s.kind in ("DATE", "DOB"):
            action, layer = "shifted" if s.kind == "DATE" else "suppressed", "date parser"
        elif s.kind == "AGE":
            action, layer = "banded", "age parser"
        elif s.kind in ("NAME", "NAME_MODEL"):
            action, layer = "removed", LAYER.get(s.meta.get("src", ""), s.meta.get("src", "name rule"))
        elif s.kind == "SOFT":
            action, layer = "generalised", "soft identifier: " + s.value
        elif s.kind == "PIN":
            action, layer = "generalised", "PIN in address context"
        else:
            action, layer = "removed", "identifier pattern"
        print(f"{seg[:34]:34} {s.kind:13} {action:12} {layer}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
