#!/usr/bin/env python3
"""Build a BLIND holdout variant of the Secret Wards practice set (kit/dev).

    python3 tools/blind_variant.py --dev kit/dev --out blind

Reads only the organisers' practice data (input/, truth/truth.json, attacker/) and
writes blind/input/, blind/truth/truth.json and blind/attacker/.  Standard library only,
fully deterministic (fixed SEED, no clock, no set iteration order dependence).

The goal is a stand-in for the "unseen-format" hidden round: same patients and the same
traps, but names, labels, identifier/date/phone formats, column names and file layouts
that never occur in the practice files.  Every change is mirrored in the answer key, so
the official kit/check_dev.py can score a system against blind/truth/truth.json.

Variations (see VARIATIONS in main() and the report printed at the end)
-----------------------------------------------------------------------
1. Global, consistent renaming of every patient, relative, doctor and old-canary name
   token in BOTH scripts (Latin + Devanagari), including spelling variants (Rina/Reena ->
   Rimjhim/Rimjim), names inside file names, JSON keys, export metadata, \\uXXXX escapes
   and base64 payloads (decoded, renamed, re-encoded).  New names come largely from
   regions the practice data never uses (Northeast, South, East, Kashmir, Punjab).
   Generic tokens (Devi, Kumar, Singh, Kaur, Bano, Khatoon, Mohd./Mohammad, ji, sahab)
   and kinship words (Bhaiya, Mama, Papa, Chachu) are left alone.  The attacker registry
   is renamed with the same function, so re-identification still works.
2. UHID format change for one hospital: JJH-0076900 -> JJCH0076900 (content, file names,
   truth "patients"); the digit core (scoring key) is unchanged.
3. New column headers / JSON keys (English synonyms, transliterated Hindi, Devanagari,
   a key containing "/" so its JSON pointer needs "~1" escaping).
4. New labels and relation markers in notes (English, Hinglish, Devanagari).
5. New identifier types inserted as PII entities (VOTER_ID, DRIVING_LICENCE, PASSPORT,
   RATION_CARD, BANK_ACCOUNT, UPI_ID, VEHICLE_REG, EMPLOYEE_ID), incl. FHIR identifiers.
6. New phone formats (0091-, spaced pairs, dots, brackets, Devanagari digits) and date
   formats (3rd March 2026, 2026.03.03, 03-Mar-26, Hindi month names, d.m.yyyy).  Truth
   date values are unchanged; DOB surfaces and "exclude" strings are updated.
7. New file layouts (see conventions below), incl. an extension that lies.
8. Three new canary identities (CANARY-4..6) in new contexts; the four practice canaries
   are renamed as well.

Unit-locator conventions for the new layouts (following SPEC.md as closely as possible)
--------------------------------------------------------------------------------------
* JSON Lines (.jsonl): ``row:N`` = 0-based index of the non-empty line (every line is one
  record; line 0 here is the export-metadata object).  Metadata / key-channel PII in that
  first line stays in the file-level unit ``@file``.  Paths inside a record (preserve /
  dates / fields "path") and "generalizable" entries are JSON pointers relative to the
  line's object (e.g. ``/patient/age_sex``).
* Top-level JSON array: RFC 6901 pointer ``/N``.
* Records nested deeper: full RFC 6901 pointer, e.g. ``/export/batches/1/payload/visits/0``;
  generalizable uses ``[]`` for every array level.
* JSON keys containing "/" are escaped in pointers as ``~1`` (RFC 6901).
* CSV with preamble lines: ``row:N`` counts DATA rows only (0-based), i.e. preamble lines
  and the header line are excluded.  PII in the preamble belongs to unit ``@header``.
* Pipe-delimited text (.txt, delimiter "|") and TSV disguised as .xls: ``row:N`` as CSV.
* Fixed-width text table (.txt): ``row:N`` = 0-based data line after the header line and
  the dashed ruler line; preserve paths keep ``col:<header>``.
* key:value notes and JSON stored under a .txt extension: ``doc``.
* expect: every new layout a robust system should parse is "sanitize"; the TSV hiding
  behind a binary-office extension (.xls) is "either" (quarantine is acceptable).
"""
from __future__ import annotations

import argparse
import base64
import binascii
import csv
import datetime as dt
import hashlib
import io
import json
import random
import re
import shutil
import sys
import unicodedata
from pathlib import Path

SEED = "secret-wards-blind-v1"

# ---------------------------------------------------------------------------------------
# 1. Name tables: (old Latin variants, new Latin variants, new Devanagari)
# ---------------------------------------------------------------------------------------
NAME_GROUPS = [
    # female given names
    (("anita", "aneeta"), ("Bhagyashree", "Bhagyashri"), "भाग्यश्री"),
    (("asha",), ("Mrinalini",), "मृणालिनी"),
    (("ayesha",), ("Nusrat",), "नुसरत"),
    (("farida",), ("Lalnunmawii",), "लालनुनमावी"),
    (("fatima", "fatma"), ("Mehrunnisa", "Mehrunisa"), "मेहरुन्निसा"),
    (("geeta", "gita"), ("Sreelakshmi", "Srilakshmi"), "श्रीलक्ष्मी"),
    (("kamla", "kamala"), ("Ponnamma", "Ponamma"), "पोन्नम्मा"),
    (("kavita", "kavitha"), ("Hemlata", "Hemalatha"), "हेमलता"),
    (("mary",), ("Teresa",), "टेरेसा"),
    (("neha",), ("Dipanwita",), "दीपान्विता"),
    (("nasreen",), ("Gulnaz",), "गुलनाज़"),
    (("parvati", "parvathi"), ("Bhanumati", "Bhanumathi"), "भानुमती"),
    (("reena", "rina"), ("Rimjhim", "Rimjim"), "रिमझिम"),
    (("rukhsana",), ("Shagufta",), "शगुफ़्ता"),
    (("salma",), ("Tabassum",), "तबस्सुम"),
    (("sarita",), ("Sushmita",), "सुष्मिता"),
    (("saroj",), ("Tulika",), "तूलिका"),
    (("shabana",), ("Yasmeen",), "यास्मीन"),
    (("shanti", "shanthi"), ("Pramila", "Premila"), "प्रमिला"),
    (("sunita", "suneeta"), ("Lalita", "Laleeta"), "ललिता"),
    (("usha",), ("Ibemhal",), "इबेमहल"),
    (("zainab", "zenab"), ("Ruqaiya", "Rukaiya"), "रुक़ैया"),
    (("harpreet",), ("Navneet",), "नवनीत"),
    (("manpreet",), ("Gurleen",), "गुरलीन"),
    (("jaspreet",), ("Paramvir",), "परमवीर"),
    (("sukhwinder", "sukhvinder"), ("Rajwinder", "Rajvinder"), "राजविंदर"),
    # male given names
    (("ajay",), ("Thangboi",), "थांगबोई"),
    (("akram",), ("Tanveer",), "तनवीर"),
    (("anil",), ("Biswajit",), "बिस्वजीत"),
    (("anthony",), ("Sebastian",), "सेबेस्टियन"),
    (("arjun",), ("Hrishikesh",), "हृषिकेश"),
    (("ashok",), ("Venkatesh",), "वेंकटेश"),
    (("aslam",), ("Shoaib",), "शोएब"),
    (("brijesh", "brajesh"), ("Debashish", "Debasish"), "देबाशीष"),
    (("deepak",), ("Raghunath",), "रघुनाथ"),
    (("dinesh",), ("Gopinath",), "गोपीनाथ"),
    (("harish", "hareesh"), ("Srikanth", "Sreekanth"), "श्रीकांत"),
    (("irfan", "irfaan"), ("Shahbaz", "Shahbaaz"), "शाहबाज़"),
    (("jagdish",), ("Nityanand",), "नित्यानंद"),
    (("javed",), ("Junaid",), "जुनैद"),
    (("kamal",), ("Tenzing",), "तेनज़िंग"),
    (("kishan",), ("Lakshmikant",), "लक्ष्मीकांत"),
    (("kuldeep",), ("Harmanjot",), "हरमनजोत"),
    (("mahesh",), ("Pradyumna",), "प्रद्युम्न"),
    (("manoj",), ("Satyabrata",), "सत्यब्रत"),
    (("mohan",), ("Balwant",), "बलवंत"),
    (("mukesh",), ("Anirban",), "अनिर्बान"),
    (("naresh",), ("Chiranjeevi",), "चिरंजीवी"),
    (("naseem",), ("Sohail",), "सोहेल"),
    (("prakash",), ("Ganesan",), "गणेशन"),
    (("rahul",), ("Abhijit",), "अभिजीत"),
    (("rajan",), ("Murugan",), "मुरुगन"),
    (("raju",), ("Bablu",), "बबलू"),
    (("ramesh",), ("Dhananjay",), "धनंजय"),
    (("ravi",), ("Partha",), "पार्थ"),
    (("salim",), ("Tariq",), "तारिक़"),
    (("shahid",), ("Mujtaba",), "मुज्तबा"),
    (("shyam", "shyaam"), ("Mrityunjay", "Mrityunjoy"), "मृत्युंजय"),
    (("sunil", "suneel"), ("Devendra", "Debendra"), "देवेंद्र"),
    (("suresh",), ("Lalduhawma",), "लालदुहावमा"),
    (("umesh",), ("Bipul",), "बिपुल"),
    (("vijay", "vijai"), ("Ranjit", "Ranjeet"), "रंजीत"),
    (("vikas", "vikash"), ("Pranab", "Pranav"), "प्रणब"),
    (("yusuf",), ("Haroon",), "हारून"),
    (("zubair",), ("Ehsaan",), "एहसान"),
    # surnames
    (("ansari",), ("Lone",), "लोन"),
    (("baig",), ("Wani",), "वानी"),
    (("chaudhary", "chaudhari", "choudhary"), ("Bordoloi", "Bordolai", "Bordoloy"), "बोरदोलोई"),
    (("chauhan", "chouhan"), ("Hembram", "Hembrom"), "हेम्ब्रम"),
    (("gupta",), ("Sangma",), "संगमा"),
    (("qureshi", "kureshi"), ("Bhat", "Butt"), "भट"),
    (("lodhi",), ("Murmu",), "मुर्मू"),
    (("malik",), ("Andrabi",), "अंद्राबी"),
    (("masih",), ("Fernandes",), "फ़र्नांडिस"),
    (("mishra",), ("Panigrahi",), "पाणिग्रही"),
    (("nishad",), ("Soren",), "सोरेन"),
    (("pandey", "pande", "pandeya"), ("Kalita", "Kalitha", "Kaleeta"), "कलिता"),
    (("paswan",), ("Majhi",), "माझी"),
    (("patel",), ("Gaikwad",), "गायकवाड़"),
    (("rajput",), ("Lyngdoh",), "लिंगदोह"),
    (("sharma", "sarma"), ("Baruah", "Barua"), "बरुआ"),
    (("shaikh",), ("Peerzada",), "पीरज़ादा"),
    (("siddiqui", "siddiqi"), ("Kirmani", "Kermani"), "किरमानी"),
    (("thakur",), ("Pillai",), "पिल्लई"),
    (("tiwari", "tiwary"), ("Reddy", "Reddi"), "रेड्डी"),
    (("verma",), ("Gowda",), "गौड़ा"),
    (("yadav",), ("Lepcha",), "लेप्चा"),
    # the four practice canaries (a system may have memorised them)
    (("zorawar",), ("Thupstan",), "थुपस्तान"),
    (("qadri",), ("Namgail",), "नामग्याल"),
    (("ilavenil",), ("Pavizham",), "पविழम"),
    (("bhattacharya",), ("Chakladar",), "चकलादार"),
    (("kaveri",), ("Ahalya",), "अहल्या"),
    (("nambiar",), ("Kuruvilla",), "कुरुविला"),
    (("tsering",), ("Yangchen",), "यांगचेन"),
    (("wangmo",), ("Dolkar",), "दोलकर"),
    # doctors (renamed so a memorised doctor allow-list does not help; doctor-vs-relative
    # trap stays intact because Ramesh -> Dhananjay everywhere)
    (("vandana",), ("Sharmila",), "शर्मिला"),
    (("kulshrestha",), ("Bhattathiri",), "भट्टथिरी"),
    (("srivastava",), ("Phukan",), "फुकन"),
    (("harjeet",), ("Gurbir",), "गुरबीर"),
    (("bedi",), ("Sodhi",), "सोढ़ी"),
    (("imtiaz",), ("Mushtaq",), "मुश्ताक़"),
    (("ahmed",), ("Zaidi",), "ज़ैदी"),
    (("kavya",), ("Revathi",), "रेवती"),
    (("menon",), ("Varghese",), "वर्गीज़"),
    (("sameer",), ("Shahnawaz",), "शाहनवाज़"),
    (("rizvi",), ("Naqvi",), "नक़वी"),
]
# Old Devanagari token -> canonical old Latin token (first of its group)
DEVA_OLD = {
    "अंसारी": "ansari", "अकरम": "akram", "अजय": "ajay", "अनिल": "anil", "अनीता": "anita",
    "आशा": "asha", "इरफ़ान": "irfan", "कमल": "kamal", "कमला": "kamla", "कविता": "kavita",
    "क़ुरैशी": "qureshi", "किशन": "kishan", "गीता": "geeta", "चौधरी": "chaudhary",
    "चौहान": "chauhan", "जगदीश": "jagdish", "ज़ुबैर": "zubair", "ठाकुर": "thakur",
    "तिवारी": "tiwari", "नरेश": "naresh", "निषाद": "nishad", "पटेल": "patel", "पांडे": "pandey",
    "पार्वती": "parvati", "फ़ातिमा": "fatima", "बृजेश": "brijesh", "मनोज": "manoj",
    "मलिक": "malik", "महेश": "mahesh", "मिश्रा": "mishra", "मुकेश": "mukesh", "यादव": "yadav",
    "यूसुफ": "yusuf", "रमेश": "ramesh", "रवि": "ravi", "राजपूत": "rajput", "राहुल": "rahul",
    "रीना": "reena", "रुख़साना": "rukhsana", "लोधी": "lodhi", "विजय": "vijay", "शर्मा": "sharma",
    "शाहिद": "shahid", "शेख़": "shaikh", "श्याम": "shyam", "सरिता": "sarita", "सलमा": "salma",
    "सिद्दीक़ी": "siddiqui", "सुखविंदर": "sukhwinder", "सुनीता": "sunita", "सुनील": "sunil",
    "हरीश": "harish",
}

LAT_MAP: dict = {}     # old lower -> new (proper case)
DEVA_NEW: dict = {}    # canonical old lower -> new deva
for olds, news, deva in NAME_GROUPS:
    for i, o in enumerate(olds):
        LAT_MAP[o] = news[min(i, len(news) - 1)]
    DEVA_NEW[olds[0]] = deva

_PRECOMP = {"क़": "क़", "ख़": "ख़", "ग़": "ग़", "ज़": "ज़", "ड़": "ड़",
            "ढ़": "ढ़", "फ़": "फ़", "य़": "य़"}


def _deva_forms(s: str):
    forms = {s, unicodedata.normalize("NFD", s), unicodedata.normalize("NFC", s)}
    base = unicodedata.normalize("NFD", s)
    pre = base
    for k, v in _PRECOMP.items():
        pre = pre.replace(unicodedata.normalize("NFD", k), v)
    forms.add(pre)
    return forms


DEVA_MAP: dict = {}
for old, canon in DEVA_OLD.items():
    for f in _deva_forms(old):
        DEVA_MAP[f] = DEVA_NEW[canon]

_LAT_RE = re.compile(r"(?<![A-Za-z])(" + "|".join(sorted(LAT_MAP, key=len, reverse=True)) + r")(?![A-Za-z])",
                     re.IGNORECASE)
_DEVA_RE = re.compile(r"(?<![ऀ-ॿ])(" + "|".join(sorted(DEVA_MAP, key=len, reverse=True))
                      + r")(?![ऀ-ॿ])")
_JJH_RE = re.compile(r"JJH-(\d{7})")


def _case_like(src: str, new: str) -> str:
    if src.isupper() and len(src) > 1:
        return new.upper()
    if src.islower():
        return new.lower()
    return new


def _lat_sub(m):
    src = m.group(0)
    if src.lower() == "asha" and m.string[m.end():m.end() + 8].lower().startswith(" worker"):
        return src  # "ASHA worker" is the community health worker, not a name (trap)
    return _case_like(src, LAT_MAP[src.lower()])


def T(s):
    """Global, deterministic rename used for files, file names, truth and registry."""
    if not isinstance(s, str) or not s:
        return s
    s = _JJH_RE.sub(r"JJCH\1", s)
    s = _LAT_RE.sub(_lat_sub, s)
    s = _DEVA_RE.sub(lambda m: DEVA_MAP[m.group(0)], s)
    return s


def T_token(t: str) -> str:
    if t in LAT_MAP:
        return LAT_MAP[t].lower()
    if t in DEVA_MAP:
        return DEVA_MAP[t]
    return t


_B64_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_UESC_RE = re.compile(r"(?:\\u[0-9a-fA-F]{4})+")


def _try_b64(tok: str):
    try:
        raw = base64.b64decode(tok + "=" * (-len(tok) % 4), validate=True)
        txt = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if not txt or any(ord(c) < 32 and c not in "\r\n\t" for c in txt):
        return None
    return txt


def T_text(text: str) -> str:
    """T() on a whole file: protects/rewrites base64 payloads and \\uXXXX escape runs."""
    out, pos = [], 0
    spans = []
    for m in _B64_RE.finditer(text):
        dec = _try_b64(m.group(0))
        if dec is not None:
            spans.append((m.start(), m.end(), "b64", dec))
    for m in _UESC_RE.finditer(text):
        if not any(a <= m.start() < b for a, b, _, _ in spans):
            spans.append((m.start(), m.end(), "u", None))
    spans.sort()
    for a, b, kind, dec in spans:
        out.append(T(text[pos:a]))
        seg = text[a:b]
        if kind == "b64":
            new = T(dec)
            out.append(seg if new == dec else base64.b64encode(new.encode("utf-8")).decode("ascii"))
        else:
            dec_u = json.loads('"' + seg + '"')
            new = T(dec_u)
            out.append(seg if new == dec_u else "".join("\\u%04x" % ord(c) for c in new))
        pos = b
    out.append(T(text[pos:]))
    return "".join(out)


# ---------------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------------
def norm(s: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", s).casefold().split())


def with_b64(text: str) -> str:
    extra = []
    for m in re.finditer(r"[A-Za-z0-9+/]{24,}={0,2}", text):
        tok = m.group(0)
        try:
            extra.append(base64.b64decode(tok + "=" * (-len(tok) % 4)).decode("utf-8", errors="ignore"))
        except (binascii.Error, ValueError):
            pass
    return text + "\n" + "\n".join(extra) if extra else text


def rng_for(*parts) -> random.Random:
    h = hashlib.sha256(("|".join([SEED] + [str(p) for p in parts])).encode()).hexdigest()
    return random.Random(int(h[:16], 16))


def ptr_escape(k: str) -> str:
    return k.replace("~", "~0").replace("/", "~1")


def ptr_map(p, kmap):
    """Rename segments of a JSON pointer (or 'col:' path) with a key map."""
    if not isinstance(p, str) or not p.startswith("/"):
        return p
    segs = p.split("/")[1:]
    out = []
    for s in segs:
        raw = s.replace("~1", "/").replace("~0", "~")
        out.append(ptr_escape(kmap.get(raw, raw)))
    return "/" + "/".join(out)


def rename_keys(obj, kmap):
    if isinstance(obj, dict):
        return {kmap.get(k, k): rename_keys(v, kmap) for k, v in obj.items()}
    if isinstance(obj, list):
        return [rename_keys(v, kmap) for v in obj]
    return obj


def json_style(text: str):
    s = text.lstrip("﻿")
    indent = None
    m = re.match(r"[\[{]\n( +)\S", s)
    if m:
        indent = len(m.group(1))
    compact = indent is None and not re.search(r'[,:] ', s[:400])
    has_esc = bool(_UESC_RE.search(s))
    return {"indent": indent, "compact": compact, "ascii": has_esc, "nl": s.endswith("\n")}


def json_dump(obj, style) -> str:
    seps = (",", ":") if style["compact"] else ((",", ": ") if style["indent"] else (", ", ": "))
    s = json.dumps(obj, indent=style["indent"], ensure_ascii=style["ascii"], separators=seps)
    return s + ("\n" if style["nl"] else "")


def new_unit(loc):
    return {"loc": loc, "patient": None, "cid": None, "link": "none", "tags": [], "entities": [],
            "preserve": [], "dates": [], "fields": [], "exclude": []}


MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September",
          "October", "November", "December"]
HI_MONTHS = ["जनवरी", "फ़रवरी", "मार्च", "अप्रैल", "मई", "जून", "जुलाई", "अगस्त", "सितंबर", "अक्टूबर",
             "नवंबर", "दिसंबर"]
DEVA_DIGITS = str.maketrans("0123456789", "०१२३४५६७८९")


def ordinal(n: int) -> str:
    if 10 <= n % 100 <= 20:
        suf = "th"
    else:
        suf = {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suf}"


DATE_STYLES = {
    "ordinal": lambda d: f"{ordinal(d.day)} {MONTHS[d.month - 1]} {d.year}",
    "dotted_ymd": lambda d: f"{d.year}.{d.month:02d}.{d.day:02d}",
    "dd-mon-yy": lambda d: f"{d.day:02d}-{MONTHS[d.month - 1][:3]}-{d.year % 100:02d}",
    "dd-mon-yyyy": lambda d: f"{d.day:02d}-{MONTHS[d.month - 1][:3]}-{d.year}",
    "hindi": lambda d: f"{d.day} {HI_MONTHS[d.month - 1]} {d.year}",
    "hindi_deva_digits": lambda d: f"{d.day} {HI_MONTHS[d.month - 1]} {d.year}".translate(DEVA_DIGITS),
    "d.m.yyyy": lambda d: f"{d.day}.{d.month}.{d.year}",
}

PHONE_STYLES = {
    "0091-dash": lambda p: f"0091-{p[:5]}-{p[5:]}",
    "0091-space": lambda p: f"0091 {p[:5]} {p[5:]}",
    "pairs": lambda p: " ".join(p[i:i + 2] for i in range(0, 10, 2)),
    "dots": lambda p: f"{p[:3]}.{p[3:6]}.{p[6:]}",
    "bracket": lambda p: f"(+91) {p[:3]}-{p[3:6]}-{p[6:]}",
    "deva": lambda p: f"{p[:5]}-{p[5:]}".translate(DEVA_DIGITS),
    "zero-prefix": lambda p: f"(0) {p[:4]} {p[4:7]} {p[7:]}",
}

_DATE_RE = re.compile(r"^(\d{1,2})[/\-.](\d{1,2})[/\-.](\d{4})$|^(\d{4})-(\d{2})-(\d{2})$")


def parse_date(s: str, hint: str):
    m = _DATE_RE.match(s.strip())
    if not m:
        return None
    try:
        if m.group(4):
            return dt.date(int(m.group(4)), int(m.group(5)), int(m.group(6)))
        a, b, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
        return dt.date(y, b, a) if hint != "mdy" else dt.date(y, a, b)
    except ValueError:
        return None


# ---------------------------------------------------------------------------------------
# the dataset container
# ---------------------------------------------------------------------------------------
class DS:
    def __init__(self, dev: Path):
        self.dev = dev
        self.truth = json.loads((dev / "truth" / "truth.json").read_text(encoding="utf-8"))
        self.files = {}      # current rel path -> dict(text|bytes, enc, meta)
        self.cur = {}        # original rel -> current rel
        self.changed = set()  # original rels whose bytes changed
        self.log = []        # (variation, file) pairs for the report

    def note(self, what, orig):
        self.log.append((what, orig))

    def f(self, orig):
        return self.files[self.cur[orig]]

    def rename(self, orig, new_rel):
        old = self.cur[orig]
        rec = self.files.pop(old)
        rec["meta"]["path"] = new_rel
        self.files[new_rel] = rec
        self.cur[orig] = new_rel


def decode(raw: bytes, meta):
    enc, fmt = meta["encoding"], meta["format"]
    if fmt in ("pdf", "binary"):
        return raw.decode("latin-1"), "latin-1"
    if enc == "utf-16":
        return raw.decode("utf-16"), "utf-16"
    if enc == "cp1252":
        return raw.decode("cp1252"), "cp1252"
    if enc == "utf-8-sig":
        return raw.decode("utf-8-sig"), "utf-8-sig"
    return raw.decode("utf-8", errors="surrogateescape"), "utf-8"


def encode(text: str, enc: str) -> bytes:
    if enc == "utf-8":
        return text.encode("utf-8", errors="surrogateescape")
    return text.encode(enc)


def T_unit(u):
    for e in u["entities"]:
        old = e["surface"]
        e["surface"] = T(old)
        if e.get("tokens"):
            e["tokens"] = [T_token(t) for t in e["tokens"]]
        if e.get("match") == "text" and e["surface"] != old and isinstance(e.get("key"), str):
            e["key"] = norm(e["surface"])
    for p in u.get("preserve") or []:
        p["text"] = T(p["text"])
    for d in u.get("dates") or []:
        if d.get("anchor"):
            d["anchor"] = T(d["anchor"])
    u["exclude"] = [T(x) for x in u.get("exclude") or []]


# ---------------------------------------------------------------------------------------
# per-file variation helpers
# ---------------------------------------------------------------------------------------
def csv_header_rename(ds, orig, newheads, preamble_lines=0):
    rec = ds.f(orig)
    lines = rec["text"].split("\n")
    delim = rec["meta"]["delimiter"]
    hdr = lines[preamble_lines].rstrip("\r")
    old = hdr.split(delim)
    assert len(old) == len(newheads), (orig, old)
    kmap = dict(zip(old, newheads))
    lines[preamble_lines] = delim.join(newheads) + ("\r" if lines[preamble_lines].endswith("\r") else "")
    rec["text"] = "\n".join(lines)
    _col_paths(rec["meta"], kmap)
    ds.note("V1 header synonyms", orig)
    return kmap


def _col_paths(meta, kmap):
    def mp(p):
        if isinstance(p, str) and p.startswith("col:") and p[4:] in kmap:
            return "col:" + kmap[p[4:]]
        return p
    meta["generalizable"] = [mp(g) for g in meta.get("generalizable") or []]
    for u in meta["units"].values():
        for k in ("preserve", "dates", "fields"):
            for x in u.get(k) or []:
                if "path" in x:
                    x["path"] = mp(x["path"])


def json_rekey(ds, orig, kmap, label="V1 JSON key synonyms"):
    rec = ds.f(orig)
    style = json_style(rec["text"])
    obj = json.loads(rec["text"])
    obj = rename_keys(obj, kmap)
    rec["text"] = json_dump(obj, style)
    meta = rec["meta"]
    meta["generalizable"] = [ptr_map(g, kmap) for g in meta.get("generalizable") or []]
    newunits = {}
    for loc, u in meta["units"].items():
        nl = ptr_map(loc, kmap)
        u["loc"] = nl
        for k in ("preserve", "dates", "fields"):
            for x in u.get(k) or []:
                if x.get("path"):
                    x["path"] = ptr_map(x["path"], kmap)
        newunits[nl] = u
    meta["units"] = newunits
    ds.note(label, orig)


def relabel(ds, orig, pairs, label="V2 note labels / relation markers", regex=False):
    rec = ds.f(orig)
    t = rec["text"]
    for a, b in pairs:
        t = re.sub(a, b, t) if regex else t.replace(a, b)
    rec["text"] = t
    for u in rec["meta"]["units"].values():
        for d in u.get("dates") or []:
            if d.get("anchor"):
                an = d["anchor"]
                for a, b in pairs:
                    an = re.sub(a, b, an) if regex else an.replace(a, b)
                d["anchor"] = an
    ds.note(label, orig)


def _line_scopes(rec, preamble=0):
    """For CSV/TSV with one physical line per row: unit loc -> line index."""
    lines = rec["text"].split("\n")
    nrows = len([ln for ln in lines[preamble + 1:] if ln.strip()])
    rows = [k for k in rec["meta"]["units"] if k.startswith("row:")]
    if rows and nrows != max(int(k[4:]) for k in rows) + 1:
        return None
    return {f"row:{i}": preamble + 1 + i for i in range(nrows)}


def reformat_phones(ds, orig, style_names, per_row=False):
    rec = ds.f(orig)
    meta = rec["meta"]
    scopes = _line_scopes(rec) if per_row else None
    lines = rec["text"].split("\n") if per_row else None
    n = 0
    for i, (loc, u) in enumerate(sorted(meta["units"].items())):
        for e in u["entities"]:
            if e["type"] != "PHONE" or e.get("canary") or e["channel"] != "content":
                continue
            digits = re.sub(r"\D", "", e["surface"])[-10:]
            if len(digits) != 10:
                continue
            style = style_names[(i + n) % len(style_names)]
            new = PHONE_STYLES[style](digits)
            old = e["surface"]
            if per_row:
                li = scopes.get(loc) if scopes else None
                if li is None or old not in lines[li]:
                    continue
                lines[li] = lines[li].replace(old, new)
            else:
                if old not in rec["text"]:
                    continue
                rec["text"] = rec["text"].replace(old, new)
                # same surface elsewhere in this file (other units) gets the same new form
                for u2 in meta["units"].values():
                    for e2 in u2["entities"]:
                        if e2 is not e and e2["surface"] == old and e2["channel"] == "content":
                            e2["surface"] = new
            e["surface"] = new
            n += 1
    if per_row:
        rec["text"] = "\n".join(lines)
    if n:
        ds.note("V5 phone formats", orig)
    return n


def reformat_dates(ds, orig, style_names, per_row=False, only_dob=False):
    rec = ds.f(orig)
    meta = rec["meta"]
    hint = meta.get("date_hint") or "dmy"
    scopes = _line_scopes(rec) if per_row else None
    lines = rec["text"].split("\n") if per_row else None
    n = 0
    for i, (loc, u) in enumerate(sorted(meta["units"].items())):
        truths = {d["true"] for d in u.get("dates") or []}
        dobs = {e["key"] for e in u["entities"] if e["type"] == "DOB"}
        valid = dobs if only_dob else (truths | dobs)
        cands = [x for x in u.get("exclude") or []] + [e["surface"] for e in u["entities"] if e["type"] == "DOB"]
        mapping = {}
        for s in cands:
            d = parse_date(s, hint)
            if d is None or d.isoformat() not in valid or s in mapping:
                continue
            style = style_names[(i + len(mapping)) % len(style_names)]
            mapping[s] = DATE_STYLES[style](d)
        if not mapping:
            continue
        for old in sorted(mapping, key=len, reverse=True):
            new = mapping[old]
            if per_row:
                li = scopes.get(loc) if scopes else None
                if li is None or old not in lines[li]:
                    continue
                lines[li] = lines[li].replace(old, new)
            else:
                if old not in rec["text"]:
                    continue
                rec["text"] = rec["text"].replace(old, new)
            n += 1
            u["exclude"] = [new if x == old else x for x in u.get("exclude") or []]
            for e in u["entities"]:
                if e["type"] == "DOB" and e["surface"] == old:
                    e["surface"] = new
            if not per_row:  # other units of this file containing the same literal
                for u2 in meta["units"].values():
                    if u2 is u:
                        continue
                    u2["exclude"] = [new if x == old else x for x in u2.get("exclude") or []]
                    for e in u2["entities"]:
                        if e["type"] == "DOB" and e["surface"] == old:
                            e["surface"] = new
    if per_row:
        rec["text"] = "\n".join(lines)
    if n:
        ds.note("V5 date formats", orig)
    return n


# ----- new identifier types --------------------------------------------------------------
def _letters(r, k):
    return "".join(r.choice("ABCDEFGHJKLMNPRSTUVWXYZ") for _ in range(k))


def _digits(r, k):
    return "".join(r.choice("0123456789") for _ in range(k))


def make_id(kind, person, first_name="pt"):
    r = rng_for("id", kind, person)
    if kind == "VOTER_ID":
        return _letters(r, 3) + _digits(r, 7)
    if kind == "DRIVING_LICENCE":
        return f"UP{r.randint(11, 85)} {r.randint(2005, 2022)}{_digits(r, 7)}"
    if kind == "PASSPORT":
        return _letters(r, 1) + str(r.randint(1, 9)) + _digits(r, 6)
    if kind == "RATION_CARD":
        return f"UP{r.randint(11, 75)}-RC-{_digits(r, 8)}"
    if kind == "BANK_ACCOUNT":
        return str(r.randint(1, 9)) + _digits(r, 10 + r.randint(0, 4))
    if kind == "IFSC":
        return r.choice(["SBIN", "PUNB", "BARB", "UBIN", "CNRB"]) + "0" + _digits(r, 6)
    if kind == "UPI_ID":
        return f"{first_name.lower()}.{_digits(r, 3)}@{r.choice(['okaxis', 'ybl', 'oksbi', 'paytm', 'ibl'])}"
    if kind == "VEHICLE_REG":
        return f"UP{r.randint(11, 85)} {_letters(r, 2)} {_digits(r, 4)}"
    if kind == "EMPLOYEE_ID":
        return f"{r.choice(['UPSRTC', 'NTPC', 'BHEL', 'UPPCL'])}/EMP/{_digits(r, 5)}"
    raise KeyError(kind)


def id_entity(kind, surface, person, script="latin", channel="content", role="patient"):
    digits_kind = kind in ("BANK_ACCOUNT",)
    key = re.sub(r"\D", "", surface) if digits_kind else norm(surface)
    return {"type": kind, "surface": surface, "person": person, "role": role, "script": script,
            "channel": channel, "match": "digits" if digits_kind else "text", "key": key,
            "critical": True, "new_type": True}


def unit_person(ds, u):
    pt = u.get("patient")
    if pt and pt in ds.truth["patients"]:
        return ds.truth["patients"][pt]["pid"]
    for e in u["entities"]:
        if e.get("role") == "patient" and str(e.get("person", "")).startswith("P"):
            return e["person"]
    return None


def first_name_of(u):
    for script in ("latin", "hinglish"):
        for e in u["entities"]:
            if e["type"] == "PATIENT_NAME" and e.get("tokens") and e["script"] == script \
                    and e["tokens"][0].isascii():
                return e["tokens"][0]
    return "patient"


def insert_text_ids(ds, orig, after_regex, lines_tpl, kinds, loc="doc"):
    """Insert lines (template uses {KIND} placeholders) after the first match of after_regex."""
    rec = ds.f(orig)
    u = rec["meta"]["units"][loc]
    person = unit_person(ds, u)
    vals = {k: make_id(k, person, first_name_of(u)) for k in kinds}
    if "BANK_ACCOUNT" in kinds:
        vals["IFSC"] = make_id("IFSC", person)
    block = "\n".join(l.format(**vals) for l in lines_tpl)
    t = rec["text"]
    m = re.search(after_regex, t, re.M)
    assert m, (orig, after_regex)
    eol = t.find("\n", m.end())
    eol = len(t) if eol < 0 else eol
    rec["text"] = t[:eol] + "\n" + block + t[eol:]
    script = "deva" if re.search(r"[ऀ-ॿ]", block) and False else "latin"
    for k in kinds:
        u["entities"].append(id_entity(k, vals[k], person, script=script))
    ds.note("V4 new ID types (" + ", ".join(kinds) + ")", orig)
    return vals


# ---------------------------------------------------------------------------------------
# layout converters
# ---------------------------------------------------------------------------------------
def read_csv_rows(text, delim):
    return list(csv.reader(io.StringIO(text), delimiter=delim))


def write_rows(rows, delim, lineterm="\n"):
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=delim, lineterminator=lineterm, quoting=csv.QUOTE_MINIMAL)
    w.writerows(rows)
    return buf.getvalue()


def to_fixed_width(rows):
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    out = []
    for j, r in enumerate(rows):
        out.append("  ".join(c.ljust(widths[i]) for i, c in enumerate(r)).rstrip())
        if j == 0:
            out.append("  ".join("-" * w for w in widths))
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="Build the blind holdout variant of kit/dev.")
    ap.add_argument("--dev", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    dev, out = Path(a.dev), Path(a.out)
    ds = DS(dev)
    truth = ds.truth

    # ---- load + global rename --------------------------------------------------------
    orig_raw = {}
    for rel, meta in sorted(truth["files"].items()):
        raw = (dev / "input" / rel).read_bytes()
        orig_raw[rel] = raw
        text, enc = decode(raw, meta)
        new_text = T_text(text) if meta["format"] not in ("pdf", "binary") else T(text)
        for u in meta["units"].values():
            T_unit(u)
        new_rel = T(rel)
        meta["path"] = new_rel
        ds.files[new_rel] = {"text": new_text, "enc": enc, "meta": meta}
        ds.cur[rel] = new_rel
    for pt, p in truth["patients"].items():
        p["uhids"] = {h: [T(x) for x in v] for h, v in p["uhids"].items()}
    ds.note("V3 new name set (Latin+Devanagari, all files)", "*")
    ds.note("V2b UHID format JJH-nnnnnnn -> JJCHnnnnnnn", "*")

    # ======================================================================================
    # V1: headers / JSON keys
    # ======================================================================================
    csv_header_rename(ds, "registration/sanjeevani_registration.csv", [
        "Panjikaran Kramank", "Rogi ka Naam", "Ling", "Aayu (Varsh)", "Janam Tithi", "Rishta",
        "Abhibhavak ka Naam", "Poora Pata", "Mauza/Basti", "Tehsil", "Janpad", "Dak Pin",
        "Sampark Sutra", "UIDAI Sankhya", "Swasthya Khata (ABHA)", "Darj Tithi"])
    csv_header_rename(ds, "registration/sanjeevani_registration (1).csv", [
        "MR Number", "Full Name of Patient", "Sex", "Years", "Birth Date", "Rel.", "Kin Name",
        "Residence", "Hamlet", "Block", "Dist.", "Postal Code", "Cell", "UID", "Health ID",
        "Enrolled On"])
    csv_header_rename(ds, "registration/jeevanjyoti_patients.tsv", [
        "पंजीयन सं.", "रोगी", "लिंग", "उम्र", "जन्म तिथि", "संरक्षक", "निवास", "ग्राम/मजरा",
        "तहसील", "ज़िला", "पिन", "दूरभाष", "आधार", "दर्ज दिनांक"])
    csv_header_rename(ds, "registration/arogya_legacy_export.csv", [
        "MRNo", "Surname", "GivenName", "Gender", "BirthDt (MM/DD/YYYY)", "NextOfKin", "Addr1",
        "Town", "Dist", "PostCode", "ContactNo", "E-mail", "AdmitDt (MM/DD/YYYY)", "Remarks"])
    csv_header_rename(ds, "lab/city_results.csv", [
        "barcode", "naam", "umr/ling", "mrd_no", "referring_dr", "parameter", "observed_value",
        "units", "bio_ref_interval", "sample_dt", "report_dt"])
    json_rekey(ds, "registration/dhh_patients.json", {
        "patients": "labharthi", "name": "naam", "first": "pratham", "last": "upnaam",
        "local": "नाम_हिंदी", "gender": "ling", "dob": "janm_tithi", "age": "umr",
        "guardian": "abhibhavak", "relation": "rishta", "contact": "sampark", "mobile": "doorbhash",
        "email": "e_dak", "address": "pata", "line": "gali_mohalla", "village": "gaon",
        "district": "janpad", "pin": "dak_suchak", "ids": "pehchan", "aadhar_no": "uid_sankhya",
        "abha": "swasthya_khata", "registered_on": "darj_dinank", "uhid": "cr_no"})
    json_rekey(ds, "opd/jeevanjyoti_opd_2026_08.json", {
        "patient": "rogi_vivaran", "name": "poora_naam", "mobile": "sampark_no",
        "age_sex": "umar_ling", "patient_ref": "mrd_sankhya", "source_path": "nirgat_path"})
    json_rekey(ds, "opd/sanjeevani_opd_2026_05.json", {
        "patient": "रोगी", "name": "नाम", "mobile": "मोबाइल", "age_sex": "आयु/लिंग",
        "patient_ref": "पंजीयन_संख्या"}, label="V1 Devanagari JSON keys (one with '/')")

    # ======================================================================================
    # V2: labels / relation markers in notes
    # ======================================================================================
    LABEL_SETS = [
        [("Patient Name:", "Name of Pt. :"), ("\nW/o ", "\nWife of "), ("\nS/o ", "\nSon of "),
         ("\nD/o ", "\nDaughter of "), ("Mobile:", "Contact No. :"), ("Attendant:", "Bystander:"),
         ("Mob.", "Ph."), ("DOB:", "Born on"), ("Address:", "Residing at:")],
        [("Patient Name:", "Mareez ka naam -"), ("\nW/o ", "\nPatni "), ("\nS/o ", "\nPutra "),
         ("\nD/o ", "\nPutri "), ("Mobile:", "Sampark:"), ("Attendant:", "Saath mein aaye:"),
         ("Mob.", "Phone no."), ("Address:", "Pata:"), ("DOB:", "Janm tithi:")],
        [("Patient Name:", "रोगी का नाम / Patient:"), ("\nW/o ", "\nपत्नी "), ("\nS/o ", "\nपुत्र "),
         ("\nD/o ", "\nपुत्री "), ("Mobile:", "मोबाइल:"), ("Attendant:", "परिचारक:"),
         ("Address:", "पता:"), ("DOB:", "जन्म तिथि:"), ("Mob.", "मो.")],
        [("Patient Name:", "PT NAME >>"), ("\nW/o ", "\nw/o. "), ("\nS/o ", "\ns.o. "),
         ("\nD/o ", "\nd.o. "), ("Mobile:", "Cell#"), ("Attendant:", "Guardian/Escort -"),
         ("Mob.", "Cell"), ("Address:", "Addr -"), ("DOB:", "D.O.B. -"),
         ("Date of Admission:", "DOA :"), ("Date of Discharge:", "DOD :")],
    ]
    ds_files = sorted(r for r in truth_paths(ds) if r.startswith("discharge/") and "note_" not in r
                      and r != "discharge/sanjeevani_ds_IPD-2026-00454.txt")
    for i, r in enumerate(ds_files):
        if i % 5 == 4:
            continue  # leave some files with the practice labels
        relabel(ds, r, LABEL_SETS[i % 4])
    NURSE_SETS = [
        [("Attendant (S/o ", "Gharwale (beta "), ("Attendant (W/o ", "Gharwale (pati "),
         ("Attendant (D/o ", "Gharwale (pita "), ("informed about diet", "ko diet samjhayi")],
        [("Attendant (S/o ", "परिजन (पुत्र "), ("Attendant (W/o ", "परिजन (पति "),
         ("Attendant (D/o ", "परिजन (पिता "), ("informed about diet", "ko diet bata di")],
        [("Attendant (S/o ", "Relative (son of "), ("Attendant (W/o ", "Relative (husband: "),
         ("Attendant (D/o ", "Relative (father: ")],
    ]
    for i, r in enumerate(sorted(x for x in truth_paths(ds) if x.startswith("notes/nursing_"))):
        relabel(ds, r, NURSE_SETS[i % 3])
    relabel(ds, "discharge/note_0004.txt", [(r"(\w+), W/o (\w+),", r"\1 (\2 ki patni),")], regex=True)
    relabel(ds, "discharge/note_0015.txt", [(r"(\w+), W/o (\w+),", r"\1, wife of \2,")], regex=True)
    RX_HI = [
        [("नाम:", "रोगी का नाम –"), ("आयु:", "उम्र -"), ("ग्राम:", "मौज़ा/गाँव:"), ("तारीख:", "दिनांक:")],
        [("नाम:", "मरीज़:"), ("आयु:", "उम्र:"), ("ग्राम:", "गाँव -"), ("तारीख:", "दि.")],
    ]
    RX_EN = [
        [("Name:", "Pt:"), ("Age:", "Umr:"), ("Reg No:", "CR No.:"), ("Mob:", "Ph:")],
        [("Name:", "Mareez:"), ("Age:", "Age/Sex -"), ("Reg No:", "OPD Regn #"), ("Mob:", "Contact -")],
        [("Name:", "Naam -"), ("Reg No:", "MRD:"), ("Mob:", "M:")],
    ]
    rx = sorted(x for x in truth_paths(ds) if x.startswith("prescriptions/"))
    for i, r in enumerate(rx):
        if i % 3 == 2:
            continue
        txt = ds.f(r)["text"]
        if "नाम:" in txt:
            relabel(ds, r, RX_HI[i % 2])
        else:
            relabel(ds, r, RX_EN[i % 3])
    relabel(ds, "registration/jeevanjyoti_patients.tsv",
            [("\tD/o ", "\tपुत्री "), ("\tS/o ", "\tसुपुत्र "), ("\tW/o ", "\tधर्मपत्नी ")],
            label="V2 Devanagari relation markers in cells")

    # ======================================================================================
    # V4: new identifier types
    # ======================================================================================
    insert_text_ids(ds, "discharge/Discharge_Summary_Fatima_Bano_SNJ-26-064508.txt", r"^(Contact No\. :|Mobile:|Sampark:|मोबाइल:|Cell#).*$",
                    ["Voter ID (EPIC): {VOTER_ID}",
                     "Refund to Bank A/c No. {BANK_ACCOUNT}, IFSC {IFSC}"], ["VOTER_ID", "BANK_ACCOUNT"])
    insert_text_ids(ds, "discharge/jeevanjyoti_ds_IP-26-00130.txt", r"^(Contact No\. :|Mobile:|Sampark:|मोबाइल:|Cell#).*$",
                    ["DL No.: {DRIVING_LICENCE}   (RTA case, vehicle {VEHICLE_REG})"],
                    ["DRIVING_LICENCE", "VEHICLE_REG"])
    insert_text_ids(ds, "discharge/Discharge_Summary_Usha_Tiwari_SNJ-26-064365.txt", r"^ABHA No:.*$",
                    ["Passport No: {PASSPORT} (NRI relative visiting)"], ["PASSPORT"])
    insert_text_ids(ds, "discharge/sanjeevani_ds_IPD-2026-00459.txt", r"^ABHA No:.*$",
                    ["Employer: State transport, Emp. Code {EMPLOYEE_ID} (ESIC cashless)"], ["EMPLOYEE_ID"])
    insert_text_ids(ds, "prescriptions/rx_arogya_00056.txt", r"^.*(ग्राम|गाँव|मौज़ा).*$",
                    ["राशन कार्ड सं.: {RATION_CARD}", "मतदाता पहचान पत्र: {VOTER_ID}"],
                    ["RATION_CARD", "VOTER_ID"])
    insert_text_ids(ds, "lab/whatsapp_forward_0003.txt", r"^Koi problem.*$",
                    ["Payment GPay kar dena: {UPI_ID}"], ["UPI_ID"])
    insert_text_ids(ds, "discharge/jeevanjyoti_ds_IP-26-00134.txt", r"^(Contact No\. :|Mobile:|Sampark:|मोबाइल:|Cell#).*$",
                    ["Aadhaar-seeded A/c: {BANK_ACCOUNT} / {IFSC}; UPI {UPI_ID}"], ["BANK_ACCOUNT", "UPI_ID"])
    # CSV: billing columns
    orig = "billing/jeevanjyoti_claims.csv"
    rec = ds.f(orig)
    rows = read_csv_rows(rec["text"], ",")
    rows[0] = ["invoice_no", "cr_no", "beneficiary", "pmjay_card", "payer_pan_no", "policy", "pkg",
               "surgery", "doa", "dod", "amount_inr", "claim_status", "bank_ac_no", "ifsc", "upi_vpa"]
    kmap = {"bill_no": "invoice_no", "uhid": "cr_no", "patient_name": "beneficiary", "pmjay_id": "pmjay_card",
            "payer_pan": "payer_pan_no", "policy_no": "policy", "package_code": "pkg", "procedure": "surgery",
            "admission_date": "doa", "discharge_date": "dod", "status": "claim_status"}
    _col_paths(rec["meta"], kmap)
    for i, row in enumerate(rows[1:]):
        if not row:
            continue
        u = rec["meta"]["units"][f"row:{i}"]
        person = unit_person(ds, u)
        acc, ifsc, upi = (make_id("BANK_ACCOUNT", person), make_id("IFSC", person),
                          make_id("UPI_ID", person, first_name_of(u)))
        row += [acc, ifsc, upi]
        u["entities"] += [id_entity("BANK_ACCOUNT", acc, person), id_entity("UPI_ID", upi, person)]
    rec["text"] = write_rows(rows, ",")
    ds.note("V1 header synonyms + V4 bank account / UPI columns", orig)
    # JSON: EPIC + DL inside OPD visits (renamed keys file)
    orig = "opd/jeevanjyoti_opd_2026_08.json"
    rec = ds.f(orig)
    style = json_style(rec["text"])
    obj = json.loads(rec["text"])
    for i, v in enumerate(obj["visits"]):
        u = rec["meta"]["units"].get(f"/visits/{i}")
        if not u or not isinstance(v.get("rogi_vivaran"), dict):
            continue
        person = unit_person(ds, u)
        kind = ["VOTER_ID", "DRIVING_LICENCE", "RATION_CARD"][i % 3]
        val = make_id(kind, person)
        v["rogi_vivaran"][{"VOTER_ID": "epic_no", "DRIVING_LICENCE": "dl_no", "RATION_CARD": "ration_card"}[kind]] = val
        u["entities"].append(id_entity(kind, val, person))
    rec["text"] = json_dump(obj, style)
    ds.note("V4 EPIC / DL / ration card keys in JSON", orig)
    # FHIR identifiers
    for orig, kinds in (("fhir/bundle_7dfbd411.json", ["VOTER_ID", "PASSPORT"]),
                        ("fhir/bundle_877f67e7.json", ["DRIVING_LICENCE"])):
        rec = ds.f(orig)
        style = json_style(rec["text"])
        obj = json.loads(rec["text"])
        u = rec["meta"]["units"]["doc"]
        person = unit_person(ds, u)
        systems = {"VOTER_ID": "https://eci.gov.in/epic", "PASSPORT": "https://passportindia.gov.in",
                   "DRIVING_LICENCE": "https://parivahan.gov.in/dl"}
        for ent in obj["entry"]:
            res = ent.get("resource", {})
            if res.get("resourceType") == "Patient":
                for k in kinds:
                    val = make_id(k, person)
                    res.setdefault("identifier", []).append({"system": systems[k], "value": val})
                    u["entities"].append(id_entity(k, val, person))
                break
        rec["text"] = json_dump(obj, style)
        ds.note("V4 FHIR Patient.identifier with new systems", orig)

    # ======================================================================================
    # V5: phone + date formats
    # ======================================================================================
    reformat_phones(ds, "registration/sanjeevani_registration.csv", ["0091-dash", "dots", "zero-prefix"], per_row=True)
    reformat_phones(ds, "registration/jeevanjyoti_patients.tsv", ["deva", "pairs"], per_row=True)
    reformat_dates(ds, "registration/jeevanjyoti_patients.tsv", ["hindi", "dd-mon-yyyy", "hindi_deva_digits"],
                   per_row=True, only_dob=True)
    reformat_dates(ds, "registration/sanjeevani_registration.csv", ["ordinal", "dotted_ymd"], per_row=True)
    for i, r in enumerate(ds_files):
        reformat_phones(ds, r, [["0091-space", "bracket"], ["dots", "pairs"], ["deva", "0091-dash"]][i % 3])
        if r.startswith("discharge/arogya") or "UHID-" in r or "Shahid" in r or "Parvati" in r:
            continue  # month-first hospital: leave as is
        reformat_dates(ds, r, [["ordinal"], ["dotted_ymd"], ["dd-mon-yy"], ["hindi"]][i % 4])
    for r in sorted(x for x in truth_paths(ds) if x.startswith("lab/whatsapp_forward_")):
        reformat_phones(ds, r, ["pairs", "0091-space", "dots"])
    reformat_phones(ds, "opd/jeevanjyoti_opd_2026_02.json", ["bracket", "0091-dash"])
    reformat_dates(ds, "opd/sanjeevani_opd_2026_11.json", ["ordinal", "dd-mon-yyyy"])
    reformat_dates(ds, "opd/jeevanjyoti_opd_2026_06.json", ["hindi", "dotted_ymd"])
    for r in [x for x in rx if "sanjeevani" in x][:6]:
        reformat_dates(ds, r, ["d.m.yyyy"])

    # ======================================================================================
    # V6: layouts
    # ======================================================================================
    # (a) JSON Lines + key-channel canary in the meta line
    orig = "opd/jeevanjyoti_opd_2026_10.json"
    rec = ds.f(orig)
    obj = json.loads(rec["text"])
    meta_line = {"_export_meta": obj.get("_export_meta", {})}
    can6 = ("Pemba Dorjee Sherpa", "+977 984-1052736", "9779841052736")
    meta_line["_export_meta"]["escalation_contacts"] = {can6[0]: can6[1]}
    lines = [json.dumps(meta_line, ensure_ascii=False)] + [json.dumps(v, ensure_ascii=False) for v in obj["visits"]]
    rec["text"] = "\n".join(lines) + "\n"
    m = rec["meta"]
    m["format"] = "jsonl"
    m["generalizable"] = [g.replace("/visits/[]", "", 1) for g in m.get("generalizable") or []]
    nu = {}
    for loc, u in m["units"].items():
        if loc.startswith("/visits/"):
            nl = f"row:{int(loc.split('/')[2]) + 1}"
            u["loc"] = nl
            nu[nl] = u
        else:
            nu[loc] = u
    if "@file" not in nu:
        nu["@file"] = new_unit("@file")
    nu["@file"]["entities"] += [
        {"type": "CANARY", "surface": can6[0], "person": "CANARY-6", "role": "patient", "script": "latin",
         "channel": "key", "match": "name", "tokens": ["pemba", "dorjee", "sherpa"], "full": True,
         "critical": True, "canary": True},
        {"type": "PHONE", "surface": can6[1], "person": "CANARY-6", "role": "patient", "script": "latin",
         "channel": "metadata", "match": "digits", "key": can6[2], "critical": True, "canary": True}]
    m["units"] = dict(sorted(nu.items(), key=lambda kv: (kv[0][0] != "@", len(kv[0]), kv[0])))
    ds.rename(orig, ds.cur[orig][:-5] + ".jsonl")
    ds.note("V6 JSON Lines (row:N) + V7 canary as JSON key", orig)

    # (b) top-level JSON array
    orig = "lab/bulk_lab_export.json"
    rec = ds.f(orig)
    obj = json.loads(rec["text"])
    rec["text"] = json.dumps(obj["results"], ensure_ascii=False, indent=1) + "\n"
    m = rec["meta"]
    m["units"] = {("/" + loc.split("/")[2] if loc.startswith("/results/") else loc): u for loc, u in m["units"].items()}
    for loc, u in m["units"].items():
        u["loc"] = loc
    m["generalizable"] = [g.replace("/results/[]", "/[]", 1) for g in m.get("generalizable") or []]
    ds.note("V6 top-level JSON array (/N)", orig)

    # (c) deeper nesting
    orig = "opd/sanjeevani_opd_2026_09.json"
    rec = ds.f(orig)
    style = json_style(rec["text"])
    obj = json.loads(rec["text"])
    visits = obj.pop("visits")
    k = (len(visits) + 1) // 2
    newobj = {"export": {"meta": obj.pop("_export_meta", {}), **obj,
                         "batches": [{"batch_no": 1, "counter": "OPD-A", "payload": {"visits": visits[:k]}},
                                     {"batch_no": 2, "counter": "OPD-B", "payload": {"visits": visits[k:]}}]}}
    rec["text"] = json_dump(newobj, style)
    m = rec["meta"]
    nu = {}
    for loc, u in m["units"].items():
        if loc.startswith("/visits/"):
            i = int(loc.split("/")[2])
            b, j = (0, i) if i < k else (1, i - k)
            nl = f"/export/batches/{b}/payload/visits/{j}"
            u["loc"] = nl
            nu[nl] = u
        else:
            nu[loc] = u
    m["units"] = nu
    m["generalizable"] = [g.replace("/visits/[]", "/export/batches/[]/payload/visits/[]", 1)
                          for g in m.get("generalizable") or []]
    ds.note("V6 records nested deeper (/export/batches/b/payload/visits/j)", orig)

    # (d) CSV with preamble + canary in the preamble
    orig = "lab/pathkind_results.csv"
    rec = ds.f(orig)
    can4 = ("Lalthansangi Ralte", "0091 70051 38264", "7005138264")
    pre = ["Pathkind Labs - Collection Centre Hazratganj",
           f"Home-collection courier booked by {can4[0]}, ph {can4[1]}",
           "Report run: 21-11-2026 09:14 (LIS v4.2)", ""]
    rec["text"] = "\n".join(pre) + "\n" + rec["text"]
    rec["meta"]["preamble_lines"] = len(pre)
    hu = rec["meta"]["units"].setdefault("@header", new_unit("@header"))
    hu["entities"] += [
        {"type": "CANARY", "surface": can4[0], "person": "CANARY-4", "role": "patient", "script": "latin",
         "channel": "header", "match": "name", "tokens": ["lalthansangi", "ralte"], "full": True,
         "critical": True, "canary": True},
        {"type": "PHONE", "surface": can4[1], "person": "CANARY-4", "role": "patient", "script": "latin",
         "channel": "header", "match": "digits", "key": can4[2], "critical": True, "canary": True}]
    rec["meta"]["units"] = dict(sorted(rec["meta"]["units"].items(),
                                       key=lambda kv: (kv[0][0] != "@", int(kv[0][4:]) if kv[0].startswith("row:") else 0)))
    ds.note("V6 CSV with preamble lines + V7 canary in preamble (@header)", orig)

    # (e) pipe-delimited .txt
    orig = "billing/arogya_claims.csv"
    rec = ds.f(orig)
    rows = read_csv_rows(rec["text"], ",")
    rec["text"] = write_rows([r for r in rows if r], "|")
    rec["meta"]["delimiter"] = "|"
    ds.rename(orig, ds.cur[orig][:-4] + ".txt")
    ds.note("V6 pipe-delimited table with .txt extension", orig)

    # (f) fixed-width table
    orig = "lab/sanjeevani_results.csv"
    rec = ds.f(orig)
    rows = [r for r in read_csv_rows(rec["text"], ",") if r]
    rec["text"] = to_fixed_width(rows)
    rec["meta"]["format"] = "fixed_width"
    rec["meta"]["delimiter"] = None
    ds.rename(orig, ds.cur[orig][:-4] + ".txt")
    ds.note("V6 fixed-width text table", orig)

    # (g) TSV hiding behind .xls (either)
    orig = "billing/sanjeevani_claims.csv"
    rec = ds.f(orig)
    rows = [r for r in read_csv_rows(rec["text"], ",") if r]
    rec["text"] = write_rows(rows, "\t", "\r\n")
    rec["meta"].update({"format": "tsv", "delimiter": "\t", "expect": "either"})
    ds.rename(orig, ds.cur[orig][:-4] + ".xls")
    ds.note("V6 extension mismatch: TSV text saved as .xls (expect either)", orig)

    # (h) JSON content under .txt
    orig = "lab/report_00055.json"
    ds.rename(orig, ds.cur[orig][:-5] + ".txt")
    ds.note("V6 extension mismatch: JSON report saved as .txt (expect sanitize)", orig)

    # (i) key:value note (+ ID + canary-free); labels rewritten, anchors updated
    orig = "discharge/sanjeevani_ds_IPD-2026-00454.txt"
    kv = [(r"^Patient Name: (.*?)\s{2,}Age/Sex: (.*)$", r"patient.name      :: \1\npatient.age_sex   :: \2"),
          (r"^UHID: (.*?)\s{2,}IPD No: (.*)$", r"patient.uhid      :: \1\nadmission.ipd_no  :: \2"),
          (r"^W/o (.*)$", r"patient.spouse    :: \1"),
          (r"^Address: (.*)$", r"patient.address   :: \1"),
          (r"^Mobile: (.*)$", r"patient.mobile    :: \1"),
          (r"^ABHA No: (.*)$", r"patient.abha      :: \1"),
          (r"^Consultant: (.*)$", r"care.consultant   :: \1"),
          (r"^Ward/Bed: (.*)$", r"care.ward_bed     :: \1"),
          (r"^Date of Admission: (.*)$", r"admission.date    :: \1"),
          (r"^Date of Discharge: (.*)$", r"discharge.date    :: \1"),
          (r"^Attendant: (.*?), Mob\. (.*)$", r"attendant.name    :: \1\nattendant.mobile  :: \2")]
    rec = ds.f(orig)
    t = rec["text"]
    for a, b in kv:
        t = re.sub(a, b, t, flags=re.M)
    rec["text"] = t
    for u in rec["meta"]["units"].values():
        for d in u.get("dates") or []:
            d["anchor"] = {"Date of Admission:": "admission.date    ::",
                           "Date of Discharge:": "discharge.date    ::"}.get(d.get("anchor"), d.get("anchor"))
    rec["meta"]["format"] = "text"
    ds.note("V6 key :: value note layout", orig)

    # ======================================================================================
    # V7: Devanagari canary in a Hindi prescription
    # ======================================================================================
    orig = "prescriptions/rx_arogya_00030.txt"
    rec = ds.f(orig)
    can5 = ("थोकचोम इबोम्चा", "९४३६० २१७७५", "9436021775")
    rec["text"] = rec["text"].replace("\nRx\n", f"\nदवा लेने आए: {can5[0]} (पड़ोसी), मो. {can5[1]}\nRx\n", 1)
    assert can5[0] in rec["text"]
    u = rec["meta"]["units"]["doc"]
    u["entities"] += [
        {"type": "CANARY", "surface": can5[0], "person": "CANARY-5", "role": "patient", "script": "deva",
         "channel": "content", "match": "name", "tokens": ["थोकचोम", "इबोम्चा"], "full": True,
         "critical": True, "canary": True},
        {"type": "PHONE", "surface": can5[1], "person": "CANARY-5", "role": "patient", "script": "deva",
         "channel": "content", "match": "digits", "key": can5[2], "critical": True, "canary": True}]
    ds.note("V7 Devanagari canary (neighbour collecting medicine, Devanagari digits)", orig)
    truth["canaries"] = sorted(set(truth.get("canaries", [])) | {"CANARY-4", "CANARY-5", "CANARY-6"})

    # ======================================================================================
    # write everything + verify
    # ======================================================================================
    if out.exists():
        shutil.rmtree(out)
    (out / "input").mkdir(parents=True)
    new_files = {}
    for orig in sorted(ds.cur):
        cur = ds.cur[orig]
        rec = ds.files[cur]
        meta = rec["meta"]
        data = encode(rec["text"], rec["enc"])
        if meta["format"] == "pdf":
            data = fix_pdf_lengths(data)
        p = out / "input" / cur
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        meta["sha256"] = hashlib.sha256(data).hexdigest()
        meta["size"] = len(data)
        meta["path"] = cur
        if data != orig_raw[orig] or cur != orig:
            ds.changed.add(orig)
        new_files[cur] = meta
    truth["files"] = new_files
    truth["seed"] = SEED
    truth["variant_of"] = "dev-seed-1 (kit/dev), transformed by tools/blind_variant.py"
    (out / "truth").mkdir(parents=True)
    (out / "truth" / "truth.json").write_text(json.dumps(truth, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")

    # attacker side
    (out / "attacker").mkdir(parents=True)
    reg_text = (dev / "attacker" / "registry.csv").read_text(encoding="utf-8")
    rows = read_csv_rows(reg_text, ",")
    rows = [rows[0]] + [[T(c) for c in r] for r in rows[1:]]
    (out / "attacker" / "registry.csv").write_text(write_rows(rows, ","), encoding="utf-8")
    kf = (dev / "attacker" / "known_facts.jsonl").read_text(encoding="utf-8")
    (out / "attacker" / "known_facts.jsonl").write_text(T_text(kf), encoding="utf-8")
    if (dev / "attacker" / "README.md").exists():
        shutil.copy(dev / "attacker" / "README.md", out / "attacker" / "README.md")

    ok = verify(dev, out, ds, orig_raw, rows)
    summarize(ds, truth)
    return 0 if ok else 1


def truth_paths(ds):
    return list(ds.cur.keys())


def fix_pdf_lengths(data: bytes) -> bytes:
    """Recompute /Length of each stream after renaming text inside it."""
    def rep(m):
        body = m.group(2)
        return m.group(1) + str(len(body)).encode() + b" >> stream\n" + body + b"\nendstream"
    return re.sub(rb"(<< /Length )\d+ >> stream\n(.*?)\nendstream", rep, data, flags=re.S)


# ---------------------------------------------------------------------------------------
# verification
# ---------------------------------------------------------------------------------------
def _decoded(p: Path, meta):
    raw = p.read_bytes()
    if meta["format"] in ("pdf", "binary"):
        return raw.decode("latin-1")
    enc = meta["encoding"]
    try:
        return raw.decode({"utf-16": "utf-16", "cp1252": "cp1252", "utf-8-sig": "utf-8-sig"}.get(enc, "utf-8"))
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="replace")


def verify(dev, out, ds, orig_raw, reg_rows) -> bool:
    ok = True
    problems = []
    orig_truth = json.loads((dev / "truth" / "truth.json").read_text(encoding="utf-8"))
    rev = {v: k for k, v in ds.cur.items()}
    all_words_new = set()
    for rel, meta in ds.truth["files"].items():
        orel = rev[rel]
        ometa = orig_truth["files"][orel]
        p = out / "input" / rel
        txt = norm(with_b64(_decoded(p, meta)))
        otxt = norm(with_b64(_decoded(dev / "input" / orel, ometa)))
        all_words_new.update(re.findall(r"[a-z]+", txt))
        if hashlib.sha256(p.read_bytes()).hexdigest() != meta["sha256"]:
            problems.append(f"sha mismatch {rel}")
        # entity / probe presence must be at least as good as in the practice copy
        for loc, u in meta["units"].items():
            ou = ometa["units"].get(_orig_loc(loc, ometa, rel, orel))
            for k, e in enumerate(u["entities"]):
                hay = norm(rel) if e["channel"] == "filename" else txt
                found = norm(e["surface"]) in hay
                if found:
                    continue
                if ou and k < len(ou["entities"]):
                    oe = ou["entities"][k]
                    ohay = norm(orel) if oe["channel"] == "filename" else otxt
                    if norm(oe["surface"]) not in ohay:
                        continue  # was not literally findable in practice either (e.g. \\u escapes)
                problems.append(f"entity not found {rel} {loc} {e['type']} {e['surface']!r}")
            for k, pv in enumerate(u.get("preserve") or []):
                if norm(pv["text"]) in txt:
                    continue
                if ou and k < len(ou.get("preserve") or []) and norm(ou["preserve"][k]["text"]) not in otxt:
                    continue
                problems.append(f"probe lost {rel} {loc} {pv['text']!r}")
        # parse checks
        if meta["expect"] == "sanitize":
            s = p.read_bytes().decode("utf-8-sig" if meta["encoding"] == "utf-8-sig" else
                                      ("utf-16" if meta["encoding"] == "utf-16" else
                                       ("cp1252" if meta["encoding"] == "cp1252" else "utf-8")))
            if meta["format"] in ("json", "fhir"):
                try:
                    obj = json.loads(s)
                except ValueError as ex:
                    problems.append(f"json parse {rel}: {ex}")
                    obj = None
                if obj is not None:
                    for loc in meta["units"]:
                        if loc.startswith("/") and not _resolve(obj, loc):
                            problems.append(f"pointer does not resolve {rel} {loc}")
            if meta["format"] == "jsonl":
                lines = [ln for ln in s.split("\n") if ln.strip()]
                for ln in lines:
                    json.loads(ln)
                for loc in meta["units"]:
                    if loc.startswith("row:") and int(loc[4:]) >= len(lines):
                        problems.append(f"jsonl row missing {rel} {loc}")
            if meta["format"] in ("csv", "tsv") and meta.get("delimiter"):
                body = s.split("\n", meta.get("preamble_lines", 0))[-1] if meta.get("preamble_lines") else s
                rows = [r for r in csv.reader(io.StringIO(body), delimiter=meta["delimiter"]) if r]
                nrow = len(rows) - 1
                for loc in meta["units"]:
                    if loc.startswith("row:") and int(loc[4:]) >= nrow:
                        problems.append(f"csv row missing {rel} {loc} (rows={nrow})")
                hdr = rows[0] if rows else []
                for loc, u in meta["units"].items():
                    for kk in ("preserve", "dates", "fields"):
                        for x in u.get(kk) or []:
                            pth = x.get("path")
                            if isinstance(pth, str) and pth.startswith("col:") and pth[4:] not in hdr:
                                problems.append(f"col path not in header {rel} {pth}")
    # new names must not collide with practice vocabulary
    practice_words = set()
    for orel in orig_truth["files"]:
        try:
            practice_words.update(re.findall(r"[a-z]+", norm(orig_raw[orel].decode("utf-8", errors="ignore"))))
        except Exception:
            pass
    reg_old = (dev / "attacker" / "registry.csv").read_text(encoding="utf-8")
    practice_words.update(re.findall(r"[a-z]+", norm(reg_old)))
    for olds, news, _ in NAME_GROUPS:
        for n in news:
            if n.lower() in practice_words:
                problems.append(f"new name token already in practice data: {n}")
    for c in ("lalthansangi", "ralte", "pemba", "dorjee", "sherpa"):
        if c in practice_words or c in norm(T(reg_old)):
            problems.append(f"canary token collides: {c}")
    if problems:
        ok = False
        print("VERIFY: %d problem(s)" % len(problems), file=sys.stderr)
        for pr in problems[:60]:
            print("  -", pr, file=sys.stderr)
    else:
        print("VERIFY: all entity surfaces, preserve probes, pointers, rows and hashes consistent")
    return ok


def _orig_loc(loc, ometa, rel, orel):
    if loc in ometa["units"]:
        return loc
    m = re.match(r"^row:(\d+)$", loc)
    if m and rel.endswith(".jsonl"):
        return f"/visits/{int(m.group(1)) - 1}"
    m = re.match(r"^/export/batches/(\d+)/payload/visits/(\d+)$", loc)
    if m:
        nb0 = sum(1 for k in ometa["units"] if k.startswith("/visits/"))
        k = (nb0 + 1) // 2
        return f"/visits/{int(m.group(2)) + (k if m.group(1) == '1' else 0)}"
    m = re.match(r"^/(\d+)$", loc)
    if m:
        return f"/results/{m.group(1)}"
    for k in ometa["units"]:  # renamed container keys
        if k.split("/")[-1] == loc.split("/")[-1] and len(k.split("/")) == len(loc.split("/")):
            return k
    return None


def _resolve(obj, ptr):
    cur = obj
    for seg in ptr.split("/")[1:]:
        seg = seg.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, list):
            if not seg.isdigit() or int(seg) >= len(cur):
                return False
            cur = cur[int(seg)]
        elif isinstance(cur, dict):
            if seg not in cur:
                return False
            cur = cur[seg]
        else:
            return False
    return True


def summarize(ds, truth):
    files = truth["files"]
    ents = [e for f in files.values() for u in f["units"].values() for e in u["entities"]]
    from collections import Counter
    print(f"files: {len(files)}  changed: {len(ds.changed)}  unchanged: {len(files) - len(ds.changed)}")
    print(f"entities: {len(ents)}  canary identities: {len(truth['canaries'])}  "
          f"(CANARY-typed entities: {sum(1 for e in ents if e['type'] == 'CANARY')})")
    print("expect:", dict(Counter(f["expect"] for f in files.values())))
    print("formats:", dict(Counter(f["format"] for f in files.values())))
    print("new ID entities:", dict(Counter(e["type"] for e in ents if e.get("new_type"))))
    print("scripts:", dict(Counter(e["script"] for e in ents)))
    by = {}
    for what, orig in ds.log:
        by.setdefault(what, []).append(orig)
    for what in sorted(by):
        fl = by[what]
        print(f"  {what}: {len(fl)} file(s): " + ", ".join(fl[:6]) + (" ..." if len(fl) > 6 else ""))


if __name__ == "__main__":
    raise SystemExit(main())
