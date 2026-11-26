#!/usr/bin/env python3
"""Second blind holdout: a re-written copy of the official practice set.

    python3 tools/blind_variant2.py --dev kit/dev --out blind2

Reads the organisers' practice data (input/, truth/truth.json, attacker/) and writes
an independent stand-in for the "unseen-format" hidden round:

  blind2/input/          transformed input tree (same traps, same file types)
  blind2/truth/truth.json  answer key re-derived for the transformed files
  blind2/attacker/       registry.csv + known_facts.jsonl transformed consistently

What changes (see VARIATIONS in the final report / --explain):
  * a new name pool in Latin AND Devanagari (South Indian, North-Eastern, Sikh,
    Christian, Muslim names; one single-name person; one initials-style person;
    initials / surname-first / ALL-CAPS / lower-case renderings in some files);
  * new identifier formats (MR# 2026/064127, H-0076900, ASS/UH/010565, ...);
  * new date formats (20260219, 19-II-2026, 19 फ़रवरी 2026, the 3rd of March 2026,
    24-Sep-2026, 2026.05.20) per file;
  * new phone / Aadhaar / ABHA renderings per file (incl. Devanagari digits);
  * new field labels, column names and JSON keys (English, transliterated Hindi,
    Devanagari), relation markers, honorific prefixes, age forms, address markers;
  * 13 canary identities (4 renamed + 9 new) in 13 different hiding places.

The answer key is kept valid for kit/check_dev.py: every entity surface, preserve
probe, sha256, path and unit locator is recomputed from the transformed files, and the
script verifies that every surface/probe that was findable in the original file is
findable (with check_dev.py semantics) in the transformed one.

Standard library only, deterministic (no randomness is used beyond the fixed SEED tag).
"""
from __future__ import annotations

import argparse
import base64
import binascii
import copy
import csv
import fnmatch
import hashlib
import io
import json
import re
import shutil
import sys
import unicodedata
from pathlib import Path

SEED = "blind2-20261127"  # recorded in truth.json; all choices below are fixed tables

# ---------------------------------------------------------------------------------
# 1. Name pool.  old Latin variants | new Latin variants | new Devanagari | old Devanagari
#    Spelling variants of one old name map to spelling variants of one new name, so
#    "same person = same name" and transliteration noise both survive.
# ---------------------------------------------------------------------------------
POOL = [
    # female given names
    ("anita aneeta", "Thenmozhi Thenmoli", "थेनमोझी", "अनीता"),
    ("asha", "Lalrinpuii", "ललरिनपुई", "आशा"),
    ("geeta gita", "Bhagyalakshmi Bhagyalaxmi", "भाग्यलक्ष्मी", "गीता"),
    ("kamala kamla", "Sanatombi Sanathombi", "सनातोम्बी", "कमला"),
    ("kavita kavitha", "Sreekutty Srikutty", "श्रीकुट्टी", "कविता"),
    ("neha", "Vanlalruati", "वनलालरुआती", ""),
    ("parvati parvathi", "Ponnammal Ponammal", "पोन्नम्मल", "पार्वती"),
    ("reena rina", "Akhono Akono", "अखोनो", "रीना"),
    ("sarita", "Junmoni", "जुनमोनी", "सरिता"),
    ("saroj", "Kalyanikutty", "कल्याणीकुट्टी", ""),
    ("shanti shanthi", "Chinnathai Chinnathayi", "चिन्नाथाई", ""),
    ("sunita suneeta", "Ibemhal Ibemal", "इबेमहल", "सुनीता"),
    ("usha", "Vasanthakumari", "वसंतकुमारी", ""),
    ("kiran", "Mamoni", "मामोनी", ""),
    ("lakshmi", "Kunjumol", "कुंजुमोल", ""),
    ("manju", "Lalnunsangi", "ललनुनसांगी", ""),
    ("meera", "Bidyabati", "बिद्याबती", ""),
    ("pooja", "Tamilselvi", "तमिलसेल्वी", ""),
    ("pushpa", "Achamma", "अचम्मा", ""),
    ("radha", "Kezhavino", "केझाविनो", ""),
    ("rekha", "Maheswari", "महेश्वरी", ""),
    ("savitri", "Chellammal", "चेल्लम्मल", ""),
    ("sita", "Bornali", "बोर्नाली", ""),
    ("suman", "Thoibi", "थोइबी", ""),
    ("urmila", "Kamakshi", "कामाक्षी", ""),
    # male given names
    ("ajay", "Arumugam", "अरुमुगम", "अजय"),
    ("anil", "Senthilnathan", "सेंथिलनाथन", "अनिल"),
    ("arjun", "Lalthanzuala", "ललथनज़ुआला", ""),
    ("ashok", "Bhaskaran", "भास्करन", ""),
    ("brijesh brajesh", "Venkataramanan Venkatramanan", "वेंकटरमणन", "बृजेश"),
    ("deepak", "Zoramthanga", "ज़ोरमथांगा", ""),
    ("dinesh", "Hiranya", "हिरण्य", ""),
    ("harish hareesh", "Thiyagarajan Thyagarajan", "थियागराजन", "हरीश"),
    ("jagdish", "Pradyut", "प्रद्युत", "जगदीश"),
    ("kamal", "Imtiwapang", "इम्तीवापांग", "कमल"),
    ("kishan", "Tomba", "तोम्बा", "किशन"),
    ("mahesh", "Subramaniam", "सुब्रमण्यम", "महेश"),
    ("manoj", "Ratheesh", "रतीश", "मनोज"),
    ("mohan", "Lalhmingliana", "ललह्मिंगलियाना", ""),
    ("mukesh", "Jayakrishnan", "जयकृष्णन", "मुकेश"),
    ("naresh", "Bhupen", "भूपेन", "नरेश"),
    ("prakash", "Muthuswamy", "मुथुस्वामी", ""),
    ("rahul", "Kevichusa", "केविचुसा", "राहुल"),
    ("rajan", "Dhrubajyoti", "ध्रुबज्योति", ""),
    ("raju", "Appukuttan", "अप्पुकुट्टन", ""),
    ("ramesh", "Ilango", "इलांगो", "रमेश"),
    ("shyam shyaam", "Murugan Murugen", "मुरुगन", "श्याम"),
    ("sunil suneel", "Sanjeeb Sanjib", "संजीब", "सुनील"),
    ("suresh", "Manikandan", "मणिकंडन", ""),
    ("umesh", "Ibobi", "इबोबी", ""),
    ("vijay vijai", "Karthikeyan Karthikeyen", "कार्तिकेयन", "विजय"),
    ("vikas vikash", "Thangaraj Thangaraju", "थंगराज", ""),
    ("amit", "Biswajit", "बिस्वजीत", ""),
    ("gopal", "Kuttappan", "कुट्टप्पन", ""),
    ("rajesh", "Lalremruata", "ललरेमरुआता", ""),
    ("rakesh", "Nandagopal", "नंदगोपाल", ""),
    ("ravi", "Sivasankaran", "शिवशंकरन", "रवि"),
    ("sanjay", "Rongsen", "रोंगसेन", ""),
    ("santosh", "Debojit", "देबोजीत", ""),
    # Muslim names
    ("akram", "Kunhabdulla", "कुन्हब्दुल्ला", "अकरम"),
    ("aslam", "Moideen", "मोइदीन", ""),
    ("irfan irfaan", "Basheer Bashir", "बशीर", "इरफ़ान"),
    ("javed", "Rafeeq", "रफ़ीक़", ""),
    ("naseem", "Ummer", "उम्मर", ""),
    ("salim", "Kunjali", "कुंजाली", ""),
    ("shahid", "Muneer", "मुनीर", "शाहिद"),
    ("yusuf", "Sulaiman", "सुलैमान", "यूसुफ"),
    ("zubair", "Abubacker", "अबूबकर", "ज़ुबैर"),
    ("arif", "Shoukath", "शौकत", ""),
    ("faizan", "Riyas", "रियास", ""),
    ("imran", "Nowshad", "नौशाद", ""),
    ("rahim", "Kabeer", "कबीर", ""),
    ("ayesha", "Saabira", "साबिरा", ""),
    ("farida", "Jameela", "जमीला", ""),
    ("fatima fatma", "Haseena Hasina", "हसीना", "फ़ातिमा"),
    ("nasreen", "Mehrunnisa", "मेहरुन्निसा", ""),
    ("rukhsana", "Thasleem", "तस्लीम", "रुख़साना"),
    ("salma", "Raihanath", "रैहानत", "सलमा"),
    ("shabana", "Suhara", "सुहरा", ""),
    ("zainab zenab", "Nafeesa Nafisa", "नफ़ीसा", ""),
    # Sikh names
    ("harpreet", "Navroop", "नवरूप", ""),
    ("jaspreet", "Arshdeep", "अर्शदीप", ""),
    ("kuldeep", "Tejinder", "तेजिंदर", ""),
    ("manpreet", "Simranjeet", "सिमरनजीत", ""),
    ("sukhwinder sukhvinder", "Gurnam Gurnaam", "गुरनाम", "सुखविंदर"),
    ("balwinder", "Harbhajan", "हरभजन", ""),
    ("gurpreet", "Jasleen", "जसलीन", ""),
    # Christian names
    ("anthony", "Varghese", "वर्गीज़", ""),
    ("mary", "Mariamma", "मरियम्मा", ""),
    ("grace", "Ancy", "एन्सी", ""),
    ("joseph", "Chacko", "चाको", ""),
    ("peter", "Lalrosanga", "ललरोसांगा", ""),
    # surnames
    ("chauhan chouhan", "Hmar Hmaar", "ह्मार", "चौहान"),
    ("chaudhary chaudhari choudhary", "Bordoloi Bordoloy Bordolai", "बोरदोलोई", "चौधरी"),
    ("gupta", "Nongrum", "नोंगरुम", ""),
    ("lodhi", "Konyak", "कोन्याक", "लोधी"),
    ("mishra", "Iyengar", "अयंगर", "मिश्रा"),
    ("nishad", "Kharkongor", "खारकोंगोर", "निषाद"),
    ("pandey pande pandeya", "Ramaswamy Ramaswami Ramasamy", "रामास्वामी", "पांडे"),
    ("paswan", "Hazarika", "हज़ारिका", ""),
    ("patel", "Pillai", "पिल्लई", "पटेल"),
    ("rajput", "Kikon", "किकोन", "राजपूत"),
    ("sharma sarma", "Namboodiri Namboothiri", "नम्बूदिरी", "शर्मा"),
    ("thakur", "Lyngdoh", "लिंगदोह", "ठाकुर"),
    ("tiwari tiwary", "Chettiar Chettiyar", "चेट्टियार", "तिवारी"),
    ("verma", "Pachuau", "पचुआउ", ""),
    ("yadav", "Gounder Goundar", "गौंडर", "यादव"),
    ("joshi", "Ralte", "राल्टे", ""),
    ("kushwaha", "Sangma", "संगमा", ""),
    ("maurya", "Jamir", "जमीर", ""),
    ("prajapati", "Naidu", "नायडू", ""),
    ("rawat", "Reddy", "रेड्डी", ""),
    ("ansari", "Thangal", "थंगल", "अंसारी"),
    ("baig", "Koya", "कोया", ""),
    ("malik", "Manjeri", "मंजेरी", "मलिक"),
    ("qureshi kureshi", "Rowther Ravuther", "रावुथर", "क़ुरैशी"),
    ("shaikh", "Marakkar", "मरक्कर", "शेख़"),
    ("siddiqui siddiqi", "Labbai Labbay", "लब्बई", "सिद्दीक़ी"),
    ("khan", "Kunnath", "कुन्नत", ""),
    ("hussain", "Kakkattil", "कक्कट्टिल", ""),
    ("masih", "Kurian", "कुरियन", ""),
]
MUSLIM_FEMALE_NEW = {"saabira", "jameela", "haseena", "hasina", "mehrunnisa", "thasleem",
                     "raihanath", "suhara", "nafeesa", "nafisa"}
# Generic name parts / honorifics: not identifying on their own, left unchanged.
GENERIC = {"bano", "kaur", "singh", "ji", "kumar", "kumari", "mohammad", "mohammed", "mohd",
           "md", "devi", "behenji", "didi", "sahab", "babu", "bhai", "bhaiya", "amma",
           "khatoon", "khatun", "mama", "papa", "chachu"}

# Person-level renderings (global): one single-name person, one initials-style person.
OVERRIDES = [
    # (old given variants, old surname variants, {separator: latin output}, old deva, new deva)
    ("anita aneeta", "sharma sarma", {" ": "Thenmozhi", "_": "Thenmozhi", ".": "thenmozhi"},
     ["अनीता शर्मा"], "थेनमोझी"),
    ("rukhsana", "siddiqui siddiqi", {" ": "M. K. Thasleem", "_": "MK_Thasleem", ".": "mk.thasleem"},
     ["रुख़साना सिद्दीक़ी"], "एम. के. तस्लीम"),
]

# Text that must never be treated as a name.
PROTECT = [re.compile(r"ASHA(?= workers?)")]

# ---------------------------------------------------------------------------------
# 2. Canaries.  CANARY-0..3 replace the practice canaries in their original hiding
#    places; CANARY-4..12 are new, each in a different hiding place.
# ---------------------------------------------------------------------------------
CANARY_NEW = {
    "CANARY-0": ("Kezhasielie Rutsa", "6235501947"),           # free-text visitor log (orig.)
    "CANARY-1": ("Ponnambalavanan Iyalisai", "7093318265"),     # nested helpdesk JSON (orig.)
    "CANARY-2": ("Lhingneikim Touthang", "8127740396"),        # base64 consent form (orig.)
    "CANARY-3": ("Elamkulam Nirmalakumari", "9447160382"),     # ambulance CSV remarks (orig.)
    "CANARY-4": ("Tsungmerenla Imchen", "9612073548"),         # nursing-note free text
    "CANARY-5": ("Thangminlen Kipgen", "7005928163"),          # file name
    "CANARY-6": ("Vadivambal Thirunavukkarasu", "9443217095"), # JSON key
    "CANARY-7": ("Lalhmangaihsangi Chhangte", "8731946205"),   # CSV header
    "CANARY-8": ("Rongsentemjen Longkumer", "6009184372"),     # OPD export metadata
    "CANARY-9": ("Yumnam Thoinu Leishangthem", "7629305814"),  # base64 inside a FHIR bundle
    "CANARY-10": ("थौनाओजम बिनोदिनी", "9862047135"),           # Devanagari note, Devanagari digits
    "CANARY-11": ("Phulmoni Hasdak Kisku", "9431765028"),      # multi-line cell, cp1252 CSV
    "CANARY-12": ("Gurnihal Dhindsa", "9814620357"),           # FHIR narrative (text.div)
}

DEVA_DIGITS = str.maketrans("0123456789", "०१२३४५६७८९")
LAT = r"A-Za-z"
DEV = "ऀ-ॿ‌‍"


def norm(s: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", s).casefold().split())


def case_like(src: str, new: str) -> str:
    letters = [c for c in src if c.isalpha()]
    if letters and all(c.isupper() for c in letters) and len(letters) > 1:
        return new.upper()
    if letters and all(c.islower() for c in letters):
        return new.lower()
    return new


def deva_forms(s: str):
    """Both the decomposed (NFC) and the precomposed nukta spelling of a Devanagari word."""
    out = {s, unicodedata.normalize("NFC", s), unicodedata.normalize("NFD", s)}
    pre = {"क़": "क़", "ख़": "ख़", "ग़": "ग़",
           "ज़": "ज़", "ड़": "ड़", "ढ़": "ढ़",
           "फ़": "फ़", "य़": "य़"}
    for x in list(out):
        y = x
        for a, b in pre.items():
            y = y.replace(a, b)
        out.add(y)
    return out


class NameMap:
    def __init__(self):
        self.lat, self.dev = {}, {}
        new_seen = set()
        for old, new, ndev, odev in POOL:
            olds, news = old.split(), new.split()
            for i, o in enumerate(olds):
                assert o not in self.lat, o
                self.lat[o] = news[min(i, len(news) - 1)]
            for n in news:
                assert n.lower() not in new_seen and n.lower() not in GENERIC, n
                new_seen.add(n.lower())
            for o in odev.split():
                for f in deva_forms(o):
                    self.dev[f] = ndev
        self.new_latin = new_seen
        alt = "|".join(sorted(self.lat, key=len, reverse=True))
        self.lat_re = re.compile(rf"(?<![{LAT}])({alt})(?![{LAT}])", re.I)
        dalt = "|".join(sorted((re.escape(k) for k in self.dev), key=len, reverse=True))
        self.dev_re = re.compile(rf"(?<![{DEV}])({dalt})(?![{DEV}])")
        # overrides
        self.ovr = []
        for giv, sur, outs, odevs, ndev in OVERRIDES:
            rx = re.compile(rf"(?<![{LAT}])((?:{'|'.join(giv.split())}))([ _.])((?:{'|'.join(sur.split())}))(?![{LAT}])", re.I)
            self.ovr.append((rx, outs))
            for od in odevs:
                for f in deva_forms(od):
                    self.ovr.append((re.compile(rf"(?<![{DEV}]){re.escape(f)}(?![{DEV}])"), ndev))

    def __call__(self, s: str) -> str:
        for rx, out in self.ovr:
            if isinstance(out, dict):
                s = rx.sub(lambda m: case_like(m.group(0), out[m.group(2)]), s)
            else:
                s = rx.sub(out, s)
        s = self.lat_re.sub(lambda m: case_like(m.group(1), self.lat[m.group(1).lower()]), s)
        s = self.dev_re.sub(lambda m: self.dev[m.group(1)], s)
        return s

    def token(self, t: str) -> str:
        if re.fullmatch(rf"[{LAT}]+", t):
            return self.lat.get(t.lower(), t).lower()
        return self.dev.get(t, t)


NAMES = NameMap()

# ---------------------------------------------------------------------------------
# 3. Identifier formats (global, so cross-file links survive). Digit cores are kept.
# ---------------------------------------------------------------------------------
ID_RULES = [
    (r"SNJ/26/(\d{6})", "MR# 2026/{0}"),
    (r"SNJ-26-(\d{6})", "MR2026-{0}"),
    (r"JJH-(\d{7})", "H-{0}"),
    (r"UHID-(\d{6})", "ASS/UH/{0}"),
    (r"DHH2026-(\d{6})", "HDI:2026:{0}"),
    (r"DHH-IPD-(\d{5})", "HDI-IP-{0}"),
    (r"IPD-2026-(\d{5})", "SIPD/2026/{0}"),
    (r"IP[/-]26[/-](\d{5})", "JIP.26.{0}"),
    (r"ADM(\d{6})", "IPA-{0}"),
    (r"PMJAY-UP-(\d{10})", "PMJ/UP/K{0}"),
    (r"POL/(\d\d)/(\d{8})", "MDI-TPA/{0}/{1}"),
]
_ID_RE = re.compile("|".join(f"(?P<r{i}>(?<![A-Za-z0-9]){p}(?!\\d))" for i, (p, _) in enumerate(ID_RULES)), re.I)
_ID_SUB = [re.compile(p, re.I) for p, _ in ID_RULES]


def map_ids(s: str) -> str:
    def rep(m):
        i = int(m.lastgroup[1:])
        txt = m.group(0)
        g = _ID_SUB[i].fullmatch(txt).groups()
        out = ID_RULES[i][1].format(*g)
        return out.lower() if txt == txt.lower() else out
    return _ID_RE.sub(rep, s)


def filename_safe(s: str) -> str:
    return s.replace("/", "-").replace("#", "").replace(":", "-")


def map_global(s: str) -> str:
    """Name pool + canaries + identifier formats: applied everywhere (incl. registry)."""
    s, masks = mask(s)
    for old, new in CANARY_SUBST:
        s = s.replace(old, new)
    s = NAMES(s)
    s = map_ids(s)
    return unmask(s, masks)


def mask(s):
    masks = []
    for rx in PROTECT:
        def rep(m):
            masks.append(m.group(0))
            return f"{len(masks) - 1}"
        s = rx.sub(rep, s)
    return s, masks


def unmask(s, masks):
    return re.sub("(\\d+)", lambda m: masks[int(m.group(1))], s)


CANARY_SUBST = []  # filled from truth: (old surface, new surface)

# ---------------------------------------------------------------------------------
# 4. Phone / Aadhaar / ABHA renderings and date formats (per file)
# ---------------------------------------------------------------------------------
PHONE_STYLES = {
    "p00": lambda d: f"0091 {d[:5]} {d[5:]}",
    "paren": lambda d: f"(+91) {d[:3]}-{d[3:6]}-{d[6:]}",
    "dot": lambda d: f"{d[:5]}.{d[5:]}",
    "zero": lambda d: f"0{d[:3]}-{d[3:6]}-{d[6:]}",
    "sp334": lambda d: f"{d[:3]} {d[3:6]} {d[6:]}",
    "deva": lambda d: d.translate(DEVA_DIGITS),
    "plus": lambda d: f"+91{d}",
}
AADHAAR_STYLES = {
    "dash4": lambda d: f"{d[:4]}-{d[4:8]}-{d[8:]}",
    "sp4": lambda d: f"{d[:4]} {d[4:8]} {d[8:]}",
    "plain": lambda d: d,
}
ABHA_STYLES = {"space": lambda d: f"{d[:2]} {d[2:6]} {d[6:10]} {d[10:]}",
               "plain": lambda d: d}
MASK_STYLES = {"dash": lambda last4: f"xxxx-xxxx-{last4}", "stars": lambda last4: f"********{last4}"}

ROMAN = ["I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X", "XI", "XII"]
MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
MONTH = ["January", "February", "March", "April", "May", "June", "July", "August",
         "September", "October", "November", "December"]
HINDI_MONTH = ["जनवरी", "फ़रवरी", "मार्च", "अप्रैल", "मई", "जून", "जुलाई", "अगस्त",
               "सितंबर", "अक्टूबर", "नवंबर", "दिसंबर"]


def ordinal(n: int) -> str:
    suf = "th" if 10 <= n % 100 <= 20 else {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suf}"


DATE_STYLES = {
    "compact": lambda y, m, d: f"{y:04d}{m:02d}{d:02d}",
    "roman": lambda y, m, d: f"{d:02d}-{ROMAN[m - 1]}-{y}",
    "hindi": lambda y, m, d: f"{d} {HINDI_MONTH[m - 1]} {y}",
    "ordinal": lambda y, m, d: f"the {ordinal(d)} of {MONTH[m - 1]} {y}",
    "mon": lambda y, m, d: f"{d:02d}-{MON[m - 1]}-{y}",
    "dotted": lambda y, m, d: f"{y:04d}.{m:02d}.{d:02d}",
}
DATE_HINT = {"compact": "ymd", "dotted": "ymd", "roman": "dmy", "hindi": "dmy", "ordinal": "dmy", "mon": "dmy"}
_ISO = re.compile(r"(?<![\d/.:-])(\d{4})-(\d{2})-(\d{2})(?![\dT:-])")
_DMY = re.compile(r"(?<![\d/.:-])(\d{1,2})([/.-])(\d{1,2})\2(\d{4})(?![\d/.-])")


def convert_dates(s: str, style: str, order: str) -> str:
    f = DATE_STYLES[style]

    def ok(y, m, d):
        return 1 <= m <= 12 and 1 <= d <= 31 and 1900 <= y <= 2100

    def iso(m):
        y, mo, d = int(m[1]), int(m[2]), int(m[3])
        return f(y, mo, d) if ok(y, mo, d) else m[0]

    def dmy(m):
        a, b, y = int(m[1]), int(m[3]), int(m[4])
        d, mo = (b, a) if order == "mdy" else (a, b)
        return f(y, mo, d) if ok(y, mo, d) else m[0]
    return _DMY.sub(dmy, _ISO.sub(iso, s))


# ---------------------------------------------------------------------------------
# 5. Per-file profiles
# ---------------------------------------------------------------------------------
def R(pat, rep, flags=re.M):
    return (re.compile(pat, flags), rep)


def honorific(name: str, sex: str, age: int) -> str:
    if age < 14:
        return "Master " if sex == "M" else "Baby "
    first = name.split()[0].lower() if name.split() else ""
    if sex == "F":
        return "Mst. " if first in MUSLIM_FEMALE_NEW else "Smt. "
    return "Sh. "


def _ds_arg(m):
    return f"Inpatient: {m['n']}, a {m['a']}-year-old {'male' if m['s'] == 'M' else 'female'}"


def _rx_jjh(m):
    return f"pt name: {honorific(m['n'], m['s'], int(m['a']))}{m['n']} ({m['s']}/{m['a']})   Hosp. No. "


def _rx_snj(m):
    return f"Name/Age/Sex: {honorific(m['n'], m['s'], int(m['a']))}{m['n']}/{m['a']}/{m['s']}   "


DS_HEAD = r"Patient Name: (?P<n>.+?) {2,}Age/Sex: (?P<a>\d+) Yrs/(?P<s>[MF])"
RX_HEAD = r"Name: (?P<n>.+?) {2,}Age: (?P<a>\d+)/(?P<s>[MF]) {2,}Reg No: "
RX_HI = r"नाम: (?P<n>.+?) {2,}आयु: (?P<a>\d+) वर्ष"

PROFILES = [
    # --- registration -------------------------------------------------------------
    ("registration/sanjeevani_registration*.csv", dict(
        phone="p00", aadhaar="dash4", abha="space", mask="stars", dates="compact",
        header={"UHID": "MR No.", "Patient Name": "Beneficiary", "Gender": "Sex", "Age": "Umr (yrs)",
                "DOB": "Janm Tithi", "Relation": "Rishta", "Relative Name": "Abhibhavak",
                "Address": "Residence", "Village/Mohalla": "Gram/Majra", "Tehsil": "Tahsil",
                "District": "Zila", "PIN": "Postal Code", "Mobile": "Contact#", "Aadhaar No": "UID",
                "ABHA No": "Health ID", "Reg Date": "Enrolled On (YYYYMMDD)"},
        regex=[R(r"\bTehsil ", "PS "), R(r"\bDistt\. ", "Zila "), R(r"\bMohalla ", "Tola "),
               R(r"\bWard (\d+)", r"Gali No. \1")],
        cells="snj_reg")),
    ("registration/jeevanjyoti_patients.tsv", dict(
        phone="zero", aadhaar="plain", dates="hindi",
        header={"Reg No": "पंजीकरण सं.", "Naam": "रोगी का नाम", "Ling": "लिंग", "Umar": "आयु",
                "Janm Tithi": "जन्म तिथि", "Pita/Pati ka Naam": "अभिभावक", "Pata": "पता",
                "Gaon": "ग्राम/मजरा", "Tehsil": "तहसील", "Jila": "जनपद", "Pin Code": "पिन",
                "Mobile No": "दूरभाष", "Aadhar": "आधार सं.", "Registration Date": "पंजीकरण तिथि"},
        regex=[R(r"मकान नं\. ", "म.नं. "), R(r"तहसील ", "थाना "), R(r"जिला ", "जनपद "),
               R(r"मोहल्ला ", "टोला "), R(r"\bMakan No\. ", "Mkn. No. "), R(r"\bTehsil ", "Block "),
               R(r"\bDistt\. ", "Dist. "), R(r"\bMohalla ", "Purwa ")],
        cells="jjh_reg")),
    ("registration/arogya_legacy_export.csv", dict(
        phone="paren", dates="mon",
        header={"PatientID": "Hosp No", "LastName": "Surname", "FirstName": "Given Name(s)",
                "Sex": "M/F", "DOB (MM/DD/YYYY)": "Birth Date (DD-Mon-YYYY)", "Guardian": "Next of Kin",
                "Street": "Addr Line 1", "City": "Town/Village", "District": "Dist", "Zip": "Postcode",
                "Phone": "Tel", "Email": "E-mail", "Registered (MM/DD/YYYY)": "Regd On (DD-Mon-YYYY)",
                "Notes": "Remarks"},
        regex=[R(r"\bMohalla ", "Nagla "), R(r"^S/O ", "SON OF "), R(r"^W/O ", "WIFE OF "),
               R(r"^D/O ", "DAUGHTER OF ")],
        cells="arg_reg")),
    ("registration/dhh_patients.json", dict(
        dates="compact",
        keys={"patients": "beneficiaries", "first": "given", "last": "family",
              "local": "hindi_naam", "guardian": "next_of_kin", "contact": "reach", "mobile": "cell_no",
              "address": "residence", "village": "gram", "pin": "pincode"})),
    # --- OPD ------------------------------------------------------------------------
    ("opd/sanjeevani_opd_2026_0[159].json", dict(
        phone="sp334",
        keys={"patient": "beneficiary", "name": "full_name", "age_sex": "age_gender", "mobile": "contact_no"},
        regex=[R(r"^(\d{1,3})/([MF])$", r"\2/\1")])),
    ("opd/sanjeevani_opd_2026_[01][026].json", dict(dates="hindi", keys={"visits": "encounters"})),
    ("opd/sanjeevani_opd_2026_07.json", dict(phone="plus", hook="canary_meta")),
    ("opd/jeevanjyoti_opd_2026_0[678].json", dict(
        dates="hindi", phone="deva",
        keys={"patient": "rogi", "name": "naam", "age_sex": "umr_ling", "mobile": "sampark"},
        hook="jjh_opd")),
    ("opd/jeevanjyoti_opd_2026_09.json", dict(
        dates="ordinal", keys={"patient": "rogi", "name": "naam", "age_sex": "umr_ling", "mobile": "sampark"},
        hook="jjh_opd")),
    ("opd/jeevanjyoti_opd_2026_1[01].json", dict(
        dates="ordinal", phone="dot",
        keys={"patient": "rogi", "name": "naam", "age_sex": "umr_ling", "mobile": "sampark"},
        hook="jjh_opd")),
    ("opd/arogya_opd_2026_*.json", dict(dates="roman")),
    ("opd/arogya_opd_2026_0[569].json", dict(keys={"patient_ref": "hosp_no"})),
    ("opd/dhhardoi_opd_*.json", dict(dates="compact", phone="paren", keys={"address_note": "pata_note"},
                                     regex=[R(r"\bMohalla ", "Majra ")])),
    # --- discharge ------------------------------------------------------------------
    ("discharge/sanjeevani_ds_*.txt", dict(
        phone="dot", dates="roman",
        regex=[R(DS_HEAD, r"Name/Age/Sex: \g<n> / \g<a> / \g<s>"), R(r"^UHID: ", "MRD No.: "),
               R(r"IPD No: ", "Adm. No.: "), R(r"^S/o ", "son of "), R(r"^W/o ", "wife of "),
               R(r"^D/o ", "daughter of "), R(r"^Address: ", "r/o "), R(r"\bTehsil ", "PS "),
               R(r"\bDistt\. ", "Dist. "), R(r"\bMohalla ", "Tola "), R(r"\bGram ", "Vill. & PO "),
               R(r"\bHouse (\d+)", r"Ghar No. \1"), R(r"\bMakan No\. ", "Mkn. No. "),
               R(r"^Mobile: ", "Contact#: "), R(r"^DOB: ", "D.O.B.: "), R(r"^Attendant: ", "Emergency contact: ")])),
    ("discharge/jeevanjyoti_ds_*.txt", dict(
        phone="zero", dates="hindi",
        regex=[R(DS_HEAD, r"Rogi ka naam: \g<n>        Umr/Ling: \g<a>Y/\g<s>"), R(r"^UHID: ", "Hosp. No.: "),
               R(r"^S/o (.+)$", r"Abhibhavak: \1 (pita)"), R(r"^W/o (.+)$", r"Abhibhavak: \1 (pati)"),
               R(r"^D/o (.+)$", r"Abhibhavak: \1 (pita)"), R(r"^Address: ", "Pata: "),
               R(r"\bTehsil ", "Block "), R(r"\bDistt\. ", "Zila "), R(r"\bGram ", "Gram Panchayat "),
               R(r"\bMohalla ", "Purwa "), R(r"^Mobile: ", "Mob. No.: "), R(r"^DOB: ", "Janm tithi: "),
               R(r"^Attendant: ", "Saath mein: ")])),
    ("discharge/Discharge_Summary_*.txt", dict(
        phone="p00", dates="ordinal",
        regex=[R(DS_HEAD, r"Patient \g<n> (\g<s>/\g<a>)"), R(r"^Address: ", "Resident of: "),
               R(r"\bVill\. ", "Gram Panchayat "), R(r"\bTehsil ", "Thana "), R(r"\bDistt\. ", "Janpad ")],
        hook="h_of")),
    ("discharge/arogya_ds_*.txt", dict(
        phone="paren", dates="mon",
        regex=[R(DS_HEAD, _ds_arg), R(r"^S/o (.+)$", r"Next of kin: \1 (father)"),
               R(r"^W/o (.+)$", r"Next of kin: \1 (husband)"), R(r"^Address: ", "r/o: "),
               R(r"\bGram ", "Majra "), R(r"\bMohalla ", "Nagla "),
               # address wards only: "Ward 3 (Surgery)" on the ward/bed line is clinical, never a lane (Gali)
               R(r"\bWard (\d+)(?!\s*\()", r"Gali No. \1"),
               R(r"^ABHA No: ", "Health ID: ")])),
    ("discharge/dhhardoi_ds_*.txt", dict(
        dates="hindi",
        regex=[R(r"मरीज़ का नाम: ", "रोगी का नाम: "), R(r"आयु: (\d+) वर्ष / महिला", r"उम्र: \1 साल / स्त्री"),
               R(r"आयु: (\d+) वर्ष / पुरुष", r"उम्र: \1 साल / पुरुष"), R(r"पिता का नाम: ", "अभिभावक: "),
               R(r"पता: ", "निवास: "), R(r"तहसील ", "थाना "), R(r"जिला ", "जनपद "), R(r"मोहल्ला ", "टोला "),
               R(r"मोबाइल: ", "दूरभाष: "), R(r"^Attendant: ", "Emergency contact: ")])),
    ("discharge/note_0004.txt", dict(regex=[R(r"^Visit: (\d+) ([A-Z][a-z]+)$",
                                              lambda m: f"Visit: the {ordinal(int(m[1]))} of {m[2]}")])),
    # --- notes ----------------------------------------------------------------------
    ("notes/nursing_ip-26-*.txt", dict(dates="hindi", regex=[R(r"Attendant \(([SWD])/o ", r"Abhibhavak (\1/o ")])),
    ("notes/nursing_ipd-2026-*.txt", dict(regex=[R(r"Attendant \(", "Emergency contact (")])),
    ("notes/nursing_ipd-2026-00459.txt", dict(hook="canary_note")),
    # --- prescriptions --------------------------------------------------------------
    ("prescriptions/rx_jeevanjyoti_*.txt", dict(
        regex=[R(RX_HEAD, _rx_jjh), R(r"^Mob: ", "Cell: "), R(r"^Date: ", "Dt.: "),
               R(RX_HI, r"रोगी का नाम: \g<n>   umr \g<a> saal"), R(r"^ग्राम: ", "गाँव: ")])),
    ("prescriptions/rx_jeevanjyoti_*[13579].txt", dict(dates="ordinal", phone="sp334")),
    ("prescriptions/rx_sanjeevani_*.txt", dict(
        phone="sp334", regex=[R(RX_HEAD, _rx_snj), R(r"^Mob: ", "Ph. No.: ")])),
    ("prescriptions/rx_sanjeevani_*[02468].txt", dict(dates="roman")),
    ("prescriptions/rx_arogya_*.txt", dict(
        regex=[R(RX_HI, r"रोगी: \g<n>   उम्र \g<a> साल"), R(r"^ग्राम: ", "मौजा: "), R(r"^तारीख: ", "दिनांक: "),
               R(RX_HEAD, _rx_jjh)])),
    ("prescriptions/rx_arogya_00030.txt", dict(hook="canary_deva")),
    ("prescriptions/rx_dhhardoi_*.txt", dict(
        phone="deva", regex=[R(RX_HI, r"मरीज़: \g<n> (\g<a> वर्ष)"), R(r"^ग्राम: ", "ग्राम पंचायत: ")])),
    # --- lab --------------------------------------------------------------------------
    ("lab/whatsapp_forward_*.txt", dict(regex=[R(r"(\d{1,3}) Y / ([MF])", r"\1Y/\2")])),
    ("lab/whatsapp_forward_*[13579].txt", dict(phone="deva")),
    ("lab/city_results.csv", dict(
        dates="dotted",
        header={"patient_name": "pt name", "age_sex": "Age/Sex", "uhid": "Hosp No", "ref_doctor": "Referred by",
                "collected_on": "Collected (YYYY.MM.DD)", "reported_on": "Reported (YYYY.MM.DD)"},
        regex=[R(r"^(\d{1,3})/([MF])$", r"\1Y/\2")])),
    ("lab/lifeline_results.csv", dict(header={"patient_name": "naam", "age_sex": "umr/ling", "uhid": "mrn"},
                                      cells="lower_names")),
    ("lab/pathkind_results.csv", dict(header={"patient_name": "PATIENT (SURNAME, GIVEN)", "age_sex": "SEX/AGE"},
                                      regex=[R(r"^(\d{1,3})/([MF])$", r"\2/\1")], cells="surname_first_upper")),
    ("lab/report_000[0-9][13579].json", dict(keys={"patient": "subject", "phone": "contact_no",
                                                   "hospital_uhid": "mrd_no", "age": "age_yrs"}, phone="zero")),
    ("lab/report_00005.json", dict(hook="canary_filename")),
    ("lab/bulk_lab_export.json", dict(dates="compact", keys={"patient_name": "pt_nm", "uhid": "hosp_no"})),
    # --- billing ----------------------------------------------------------------------
    ("billing/sanjeevani_claims.csv", dict(
        dates="mon", header={"patient_name": "insured_person", "uhid": "mr_no", "pmjay_id": "ab_pmjay_id",
                             "payer_pan": "pan", "policy_no": "tpa_card_no", "admission_date": "doa",
                             "discharge_date": "dod"})),
    ("billing/arogya_claims.csv", dict(dates="compact", header={"patient_name": "Patient (Last, First)"},
                                       cells="surname_first")),
    ("billing/jeevanjyoti_claims.csv", dict(header={"patient_name": "BENEFICIARY NAME", "uhid": "HOSP. NO."},
                                            cells="upper_names")),
    # --- misc / fhir ------------------------------------------------------------------
    ("misc/patient_index.json", dict(hook="canary_key")),
    ("misc/ward_vitals_sheet.csv", dict(hook="canary_header")),
    ("fhir/bundle_fb4908ad.json", dict(hook="canary_b64")),
    ("fhir/bundle_2b7ec3cf.json", dict(hook="canary_div")),
    ("misc/hl7_cda_discharge.xml", dict(aadhaar="sp4")),
]


def profile_for(rel: str) -> dict:
    prof = {"regex": [], "header": {}, "keys": {}, "hooks": []}
    for pat, p in PROFILES:
        if fnmatch.fnmatchcase(rel, pat):
            for k, v in p.items():
                if k == "regex":
                    prof["regex"] = prof["regex"] + v
                elif k in ("header", "keys"):
                    prof[k] = {**prof[k], **v}
                elif k == "hook":
                    prof["hooks"].append(v)
                else:
                    prof[k] = v
    return prof


# ---------------------------------------------------------------------------------
# 6. The per-file string transform
# ---------------------------------------------------------------------------------
_B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


def b64_text(tok: str):
    try:
        raw = base64.b64decode(tok + "=" * (-len(tok) % 4), validate=True)
        txt = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if not txt or sum(c.isprintable() or c in "\n\r\t" for c in txt) < 0.95 * len(txt):
        return None
    if not re.search(r"[A-Za-zऀ-ॿ]{3}", txt):
        return None
    return txt


class Ctx:
    def __init__(self, rel, finfo, truth_units, registry):
        self.rel = rel
        self.f = finfo
        self.p = profile_for(rel)
        self.order = "mdy" if finfo.get("date_hint") == "mdy" else "dmy"
        self.edits = {}       # new loc -> [(before, after)]
        self.add_ents = {}    # new loc -> [entity dicts]
        self.drop_ents = {}   # new loc -> [surfaces to drop]
        self.registry = registry
        self.units = truth_units
        self.surface_map = {}
        self.ent_index = {}
        self._build_surface_map()

    def _build_surface_map(self):
        p = self.p
        for u in self.units.values():
            for e in u["entities"]:
                if e.get("canary") or e["channel"] == "filename":
                    continue
                s, t, key = e["surface"], e["type"], e.get("key", "")
                new = None
                if t == "PHONE" and p.get("phone") and len(key) == 10:
                    new = PHONE_STYLES[p["phone"]](key)
                elif t == "AADHAAR" and p.get("aadhaar") and len(key) == 12:
                    new = AADHAAR_STYLES[p["aadhaar"]](key)
                elif t == "ABHA_NUMBER" and p.get("abha") and len(key) == 14:
                    new = ABHA_STYLES[p["abha"]](key)
                elif t == "AADHAAR_MASKED" and p.get("mask"):
                    new = MASK_STYLES[p["mask"]](s[-4:])
                if new and new != s:
                    self.surface_map[s] = new
        if self.surface_map:
            alt = "|".join(re.escape(k) for k in sorted(self.surface_map, key=len, reverse=True))
            self.surface_re = re.compile(rf"(?<![\d०-९])({alt})(?![\d०-९])")

    # one string -> transformed string (also used for every truth string of this file)
    def F(self, s: str) -> str:
        if not s:
            return s
        b64 = []

        def hold(m):
            txt = b64_text(m.group(0))
            if txt is None:
                return m.group(0)
            new = self.F_plain(txt)
            b64.append(base64.b64encode(new.encode("utf-8")).decode("ascii") if new != txt else m.group(0))
            return f"{len(b64) - 1}"
        s = _B64.sub(hold, s)
        s = self.F_plain(s)
        return re.sub("(\\d+)", lambda m: b64[int(m.group(1))], s)

    def F_plain(self, s: str) -> str:
        if self.surface_map:
            s = self.surface_re.sub(lambda m: self.surface_map[m.group(1)], s)
        s = map_global(s)
        for rx, rep in self.p["regex"]:
            s = rx.sub(rep, s)
        if self.p.get("dates"):
            s = convert_dates(s, self.p["dates"], self.order)
        return s

    def edit(self, loc, before, after):
        if before != after:
            self.edits.setdefault(loc, []).append((before, after))


def F_filename(s: str) -> str:
    return filename_safe(map_global(s)) if s else s


def rename_path(rel: str) -> str:
    d, _, base = rel.rpartition("/")
    nb = F_filename(base)
    return f"{d}/{nb}" if d else nb


# ---------------------------------------------------------------------------------
# 7. File handlers
# ---------------------------------------------------------------------------------
def rename_seg(path: str, keys: dict) -> str:
    if not path or not keys:
        return path
    if path.startswith("/"):
        return "/".join(keys.get(seg, seg) for seg in path.split("/"))
    return path


def json_dump_like(obj, original: str):
    for sep in (None, (",", ":")):
        for ind in (2, 1, 4, None):
            for ea in (False, True):
                kw = dict(indent=ind, ensure_ascii=ea)
                if sep:
                    kw["separators"] = sep
                try:
                    d = json.dumps(obj, **kw)
                except (RecursionError, ValueError):
                    return None
                if d == original or d + "\n" == original:
                    return kw, original.endswith("\n") and not d.endswith("\n")
    return None


def walk_json(o, ctx, keys):
    if isinstance(o, dict):
        return {keys.get(k2, k2): walk_json(v, ctx, keys) for k2, v in
                ((ctx.F(k), v) for k, v in o.items())}
    if isinstance(o, list):
        return [walk_json(v, ctx, keys) for v in o]
    if isinstance(o, str):
        return ctx.F(o)
    return o


def reg_row(ctx, loc):
    u = ctx.units.get(loc)
    if not u or not u.get("patient"):
        return None
    return ctx.registry.get(TRUTH["patients"][u["patient"]]["rid"])


def handle_json(ctx, text):
    try:
        obj = json.loads(text)
    except (ValueError, RecursionError):
        return None
    fmt = json_dump_like(obj, text)
    if fmt is None:
        return None
    kw, nl = fmt
    keys = ctx.p["keys"]
    new = walk_json(obj, ctx, keys)
    for h in ctx.p["hooks"]:
        HOOKS[h](ctx, new)
    out = json.dumps(new, **kw)
    return out + ("\n" if nl else "")


def handle_csv(ctx, text, delim):
    lt = "\r\n" if "\r\n" in text else "\n"
    rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delim))
    if not rows:
        return None
    header = rows[0]
    new_rows = [[ctx.F(c) for c in r] for r in rows]
    ctx.p["header_orig"] = header
    new_rows[0] = [ctx.p["header"].get(h, nh) for h, nh in zip(header, new_rows[0])]
    cells = ctx.p.get("cells")
    if cells:
        CELL_FNS[cells](ctx, header, rows, new_rows)
    for h in ctx.p["hooks"]:
        HOOKS[h](ctx, new_rows)
    buf = io.StringIO(newline="")
    w = csv.writer(buf, delimiter=delim, lineterminator=lt, quoting=csv.QUOTE_MINIMAL)
    w.writerows(new_rows)
    out = buf.getvalue()
    if not text.endswith(("\n", "\r")):
        out = out[: -len(lt)]
    return out


def handle_text(ctx, text):
    out = ctx.F(text)
    for h in ctx.p["hooks"]:
        out = HOOKS[h](ctx, out)
    return out


# ----- cell-level renderings (CSV) ---------------------------------------------------
def _col(header, name):
    return header.index(name) if name in header else None


def cells_snj_reg(ctx, header, rows, new_rows):
    ci, cr, crel, ca, cp = (_col(header, x) for x in ("Patient Name", "Relation", "Relative Name", "Address", "PIN"))
    relmap = {"S/o": "Pita", "W/o": "Pati", "D/o": "Pita"}
    for i, r in enumerate(new_rows[1:]):
        loc = f"row:{i}"
        if len(r) <= max(ci, cr, crel, ca, cp):
            continue
        rel_raw = r[cr]
        r[cr] = relmap.get(rel_raw, rel_raw)
        if r[cp] and r[ca] and r[cp] not in r[ca]:
            r[ca] = f"{r[ca]}, PIN {r[cp]}"
        # initials rendering for every 5th row with a father (S/o, D/o) and a 2-token name
        name, relname = r[ci], r[crel]
        toks = name.split()
        if i % 5 == 0 and rel_raw in ("S/o", "D/o") and len(toks) == 2 and relname.split():
            new = f"{relname.split()[0][0].upper()}. {toks[1][0].upper()}. {toks[0]}"
            ctx.edit(loc, name, new)
            r[ci] = new


def cells_jjh_reg(ctx, header, rows, new_rows):
    ci, cr = _col(header, "Naam"), _col(header, "Pita/Pati ka Naam")
    dv = {"S/o ": "पुत्र ", "W/o ": "पत्नी ", "D/o ": "पुत्री "}
    for i, r in enumerate(new_rows[1:]):
        loc = f"row:{i}"
        if len(r) <= max(ci, cr):
            continue
        if re.search(r"[ऀ-ॿ]", r[cr]):
            for a, b in dv.items():
                if r[cr].startswith(a):
                    r[cr] = b + r[cr][len(a):]
        else:
            r[cr] = re.sub(r"^([SWD])/o ", lambda m: m[1].lower() + "/o ", r[cr])
        name = r[ci]
        toks = name.split()
        if i % 3 == 1 and len(toks) == 2 and re.fullmatch(r"[A-Za-z ]+", name):
            new = f"{toks[1]}, {toks[0]}"
            ctx.edit(loc, name, new)
            r[ci] = new


def cells_arg_reg(ctx, header, rows, new_rows):
    cl, cf, cn = _col(header, "LastName"), _col(header, "FirstName"), _col(header, "Notes")
    for i, r in enumerate(new_rows[1:]):
        loc = f"row:{i}"
        # the single-name person has no surname in a split-name export
        if len(r) > cf and r[cf] == "Thenmozhi" and r[cl]:
            ctx.drop_ents.setdefault(loc, []).append(r[cl])
            r[cl] = ""
    # CANARY-11: a multi-line remark in the legacy cp1252 export (row 1)
    name, ph = CANARY_NEW["CANARY-11"]
    r = new_rows[2]
    extra = f"Brought by neighbour {name}\nphone {ph[:5]} {ph[5:]} - not a relative."
    r[cn] = (r[cn] + "\n" + extra) if r[cn] else extra
    add_canary(ctx, "row:1", "CANARY-11", name, f"{ph[:5]} {ph[5:]}", "content")


def _name_col_fn(fn):
    def run(ctx, header, rows, new_rows):
        c = _col(header, "patient_name")
        for i, r in enumerate(new_rows[1:]):
            if c is None or len(r) <= c:
                continue
            new = fn(r[c])
            ctx.edit(f"row:{i}", r[c], new)
            r[c] = new
    return run


def _surname_first(n):
    t = n.split()
    return f"{t[-1]}, {' '.join(t[:-1])}" if len(t) >= 2 else n


CELL_FNS = {
    "snj_reg": cells_snj_reg,
    "jjh_reg": cells_jjh_reg,
    "arg_reg": cells_arg_reg,
    "lower_names": _name_col_fn(str.lower),
    "upper_names": _name_col_fn(str.upper),
    "surname_first": _name_col_fn(_surname_first),
    "surname_first_upper": _name_col_fn(lambda n: _surname_first(n).upper()),
}


# ----- hooks (insertions, structural edits) ------------------------------------------
def add_canary(ctx, loc, cid, name, phone_surface, channel, unit_new=True):
    script = "deva" if re.search(r"[ऀ-ॿ]", name) else "latin"
    toks = [t.lower() if script == "latin" else t for t in re.findall(rf"[{LAT}]+|[ऀ-ॿ]+", name)]
    digits = CANARY_NEW[cid][1]
    ents = [
        {"type": "CANARY", "surface": name, "person": cid, "role": "patient", "script": script,
         "channel": channel, "match": "name", "tokens": toks, "full": True, "critical": True, "canary": True},
        {"type": "PHONE", "surface": phone_surface, "person": cid, "role": "patient",
         "script": "deva" if re.search("[०-९]", phone_surface) else "latin", "channel": channel,
         "match": "digits", "key": digits, "critical": True, "canary": True},
    ]
    ctx.add_ents.setdefault(loc, []).extend(ents)


def hook_canary_meta(ctx, obj):
    name, ph = CANARY_NEW["CANARY-8"]
    meta = obj["_export_meta"]
    meta["exported_by"] = name
    meta["exporter_contact"] = f"{ph[:5]} {ph[5:]}"
    add_canary(ctx, "@file", "CANARY-8", name, f"{ph[:5]} {ph[5:]}", "metadata")


def hook_jjh_opd(ctx, obj):
    cont = "encounters" if "encounters" in obj else "visits"
    for i, v in enumerate(obj.get(cont, [])):
        loc = f"/{cont}/{i}"
        rg = v.get("rogi")
        if not isinstance(rg, dict):
            continue
        m = re.match(r"(\d{1,3})/([MF])$", rg.get("umr_ling", ""))
        if not m:
            continue
        age, sex = int(m[1]), m[2]
        rg["naam"] = honorific(rg.get("naam", ""), sex, age) + rg.get("naam", "")
        if isinstance(v.get("notes"), str):
            v["notes"] = v["notes"] + f" Umr {age} saal."
        # attendant line: F/o for a child, H/o for a married woman (relative from the registry)
        reg = reg_row(ctx, rename_loc_back(ctx, loc))
        if reg and isinstance(v.get("notes"), str) and reg["relative_name"]:
            relname = map_global(reg["relative_name"])
            if age < 14 and reg["relation"] in ("S/o", "D/o"):
                v["notes"] += f" Attendant: {relname} (F/o pt)."
            elif reg["relation"] == "W/o":
                v["notes"] += f" Attendant: {relname} (H/o pt)."
            else:
                continue
            ctx.add_ents.setdefault(loc, []).append(relative_entity(ctx, loc, relname))


def relative_entity(ctx, loc, relname):
    u = ctx.units[rename_loc_back(ctx, loc)]
    pid = TRUTH["patients"][u["patient"]]["pid"]
    toks = [t.lower() for t in relname.split() if t.lower() not in GENERIC]
    return {"type": "RELATIVE_NAME", "surface": relname, "person": pid, "role": "relative", "script": "latin",
            "channel": "content", "match": "name", "tokens": toks, "full": True, "critical": False}


def rename_loc_back(ctx, newloc):
    inv = {v: k for k, v in ctx.p["keys"].items()}
    return rename_seg(newloc, inv)


def hook_h_of(ctx, text):
    if re.search(r"^W/o ", text, re.M):
        text = re.sub(r"^Attendant: ([^,\n]+), Mob\.", r"Attendant: \1 (H/o patient), Mob.", text, flags=re.M)
    return text


def hook_canary_note(ctx, text):
    name, ph = CANARY_NEW["CANARY-4"]
    surf = f"{ph[:5]} {ph[5:]}"
    text = text.rstrip("\n") + f"\n20:15 - Visitor {name} (neighbour) asked about bed no.; mob {surf}.\n"
    add_canary(ctx, "doc", "CANARY-4", name, surf, "content")
    return text


def hook_canary_deva(ctx, text):
    name, ph = CANARY_NEW["CANARY-10"]
    surf = ph.translate(DEVA_DIGITS)
    text = text.rstrip("\n") + f"\nसूचना: मरीज़ के साथ पड़ोसन {name} आई थीं, मो. {surf}\n"
    add_canary(ctx, "doc", "CANARY-10", name, surf, "content")
    return text


def hook_canary_key(ctx, obj):
    name, ph = CANARY_NEW["CANARY-6"]
    key = f"{name} ({ph})"
    obj["by_name"] = {key: "callback pending", **obj["by_name"]}
    add_canary(ctx, "@file", "CANARY-6", name, ph, "key")


def hook_canary_header(ctx, rows):
    name, ph = CANARY_NEW["CANARY-7"]
    rows[0].append(f"relief nurse {name} {ph}")
    for r in rows[1:]:
        r.append("")
    add_canary(ctx, "@header", "CANARY-7", name, ph, "header")


def _fhir_entries(obj, rtype):
    for e in obj.get("entry", []):
        r = e.get("resource", {})
        if r.get("resourceType") == rtype:
            yield r


def hook_canary_b64(ctx, obj):
    name, ph = CANARY_NEW["CANARY-9"]
    done = False
    for r in _fhir_entries(obj, "DocumentReference"):
        for c in r.get("content", []):
            att = c.get("attachment", {})
            if "data" in att and not done:
                txt = base64.b64decode(att["data"]).decode("utf-8")
                txt += f" Courier handed over to {name}, mobile {ph}."
                att["data"] = base64.b64encode(txt.encode("utf-8")).decode("ascii")
                done = True
    assert done, "no attachment in FHIR bundle"
    add_canary(ctx, "doc", "CANARY-9", name, ph, "base64")


def hook_canary_div(ctx, obj):
    name, ph = CANARY_NEW["CANARY-12"]
    surf = f"+91 {ph[:5]} {ph[5:]}"
    for r in _fhir_entries(obj, "Patient"):
        div = r["text"]["div"]
        r["text"]["div"] = div.replace("</div>", f"; emergency contact {name} {surf}</div>")
        break
    add_canary(ctx, "doc", "CANARY-12", name, surf, "content")


def hook_canary_filename(ctx, data):
    return data  # rename handled in main(); unit added there


HOOKS = {
    "canary_meta": hook_canary_meta, "jjh_opd": hook_jjh_opd, "h_of": hook_h_of,
    "canary_note": hook_canary_note, "canary_deva": hook_canary_deva, "canary_key": hook_canary_key,
    "canary_header": hook_canary_header, "canary_b64": hook_canary_b64, "canary_div": hook_canary_div,
    "canary_filename": hook_canary_filename,
}


# ---------------------------------------------------------------------------------
# 8. Binary-ish files
# ---------------------------------------------------------------------------------
def handle_pdf(ctx, raw: bytes) -> bytes:
    """Rewrite text in uncompressed content streams; adjust /Length by the byte delta."""
    def fix(m):
        body = m.group(2)
        new = map_global(body)
        n = int(m.group(1)) + len(new.encode("latin-1")) - len(body.encode("latin-1"))
        return f"/Length {n} >> stream\n{new}\nendstream"
    s = raw.decode("latin-1")
    out = re.sub(r"/Length (\d+) >> stream\n(.*?)\nendstream", fix, s, flags=re.S)
    return out.encode("latin-1")


def handle_jpg(ctx, raw: bytes) -> bytes:
    """Rewrite text inside JPEG APPn segments (EXIF description) and fix the segment length."""
    out, i = bytearray(raw[:2]), 2
    while i + 4 <= len(raw) and raw[i] == 0xFF and 0xE0 <= raw[i + 1] <= 0xEF:
        n = int.from_bytes(raw[i + 2:i + 4], "big")
        seg = raw[i + 4:i + 2 + n]
        m = re.search(rb"[ -~]{6,}", seg[6:])
        if m:
            txt = m.group(0).decode("ascii")
            new = map_global(txt).encode("ascii")
            seg = seg[:6 + m.start()] + new + seg[6 + m.end():]
        out += raw[i:i + 2] + (len(seg) + 2).to_bytes(2, "big") + seg
        i += 2 + n
    out += raw[i:]
    return bytes(out)


# ---------------------------------------------------------------------------------
# 9. Truth rebuild + verification
# ---------------------------------------------------------------------------------
def checker_text(data: bytes) -> str:
    """Exactly what check_dev.py sees (UTF-8 + decoded base64)."""
    t = data.decode("utf-8", errors="replace")
    extra = []
    for m in _B64.finditer(t):
        tok = m.group(0)
        try:
            extra.append(base64.b64decode(tok + "=" * (-len(tok) % 4)).decode("utf-8", errors="ignore"))
        except (binascii.Error, ValueError):
            pass
    return norm(t + "\n" + "\n".join(extra) if extra else t)


def decoded_text(data: bytes, enc: str) -> str:
    """What an encoding-aware reader sees (used to compare before/after)."""
    try:
        t = data.decode(enc or "utf-8")
    except (UnicodeDecodeError, LookupError):
        t = data.decode("utf-8", errors="replace")
    extra = []
    for m in _B64.finditer(t):
        x = b64_text(m.group(0))
        if x:
            extra.append(x)
    return norm(t + "\n" + "\n".join(extra))


def new_tokens(e, new_surface):
    words = {w.casefold() for w in re.findall(rf"[{LAT}]+|[ऀ-ॿ‌‍]+", new_surface)}
    out = []
    for t in e.get("tokens", []):
        nt = NAMES.token(t)
        nt = nt.lower() if re.fullmatch(rf"[{LAT}]+", nt) else nt
        if nt.casefold() in words and nt not in out:
            out.append(nt)
    return out


def rebuild_units(ctx, new_rel_is_renamed):
    keys = ctx.p["keys"]
    hdr = ctx.p["header"]
    units = {}
    for loc, u in ctx.units.items():
        nloc = rename_seg(loc, keys)
        nu = copy.deepcopy(u)
        nu["loc"] = nloc
        ents = []
        for e in nu["entities"]:
            if e["channel"] == "filename":
                ns = F_filename(e["surface"])
            else:
                ns = ctx.F(e["surface"])
            for before, after in ctx.edits.get(nloc, []):
                if ns == before:
                    ns = after
            if ns in ctx.drop_ents.get(nloc, []) or e["surface"] in ctx.drop_ents.get(nloc, []):
                e["_drop"] = True
            if e["match"] == "name":
                e["tokens"] = new_tokens(e, ns) if e.get("type") != "CANARY" else \
                    [t.lower() for t in re.findall(rf"[{LAT}]+|[ऀ-ॿ]+", ns)]
            elif e["match"] == "text":
                e["key"] = " ".join(ns.casefold().split())
            elif e["match"] in ("digits", "digits_exact") and e.get("canary"):
                e["key"] = re.sub(r"\D", "", ns.translate(str.maketrans("०१२३४५६७८९", "0123456789")))
            e["surface"] = ns
            ents.append(e)
        ctx.ent_index[nloc] = ents
        nu["entities"] = [e for e in ents if not e.get("_drop")]
        for pv in nu["preserve"]:
            pv["text"] = ctx.F(pv["text"])
            if "path" in pv:
                pv["path"] = rename_path_field(pv["path"], keys, hdr)
        for d in nu["dates"]:
            if ctx.p.get("dates"):
                d["hint"] = DATE_HINT[ctx.p["dates"]]
            if "path" in d:
                d["path"] = rename_path_field(d["path"], keys, hdr)
            if "anchor" in d and d["anchor"]:
                d["anchor"] = ctx.F(d["anchor"])
        for fl in nu["fields"]:
            if "path" in fl:
                fl["path"] = rename_path_field(fl["path"], keys, hdr)
        nu["exclude"] = [ctx.F(x) for x in nu["exclude"]]
        units[nloc] = nu
    for loc, ents in ctx.add_ents.items():
        if loc not in units:
            units[loc] = {"loc": loc, "patient": None, "cid": None, "link": "none", "tags": [],
                          "entities": [], "preserve": [], "dates": [], "fields": [], "exclude": []}
        units[loc]["entities"].extend(ents)
    return units


def rename_path_field(p, keys, hdr):
    if p is None:
        return p
    if p.startswith("col:"):
        return "col:" + hdr.get(p[4:], p[4:])
    return rename_seg(p, keys)


# ---------------------------------------------------------------------------------
# 10. main
# ---------------------------------------------------------------------------------
TRUTH = {}


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the second blind holdout set.")
    ap.add_argument("--dev", required=True, help="kit/dev folder (input/, truth/, attacker/)")
    ap.add_argument("--out", required=True, help="output folder, e.g. blind2")
    a = ap.parse_args()
    dev, out = Path(a.dev), Path(a.out)
    truth = json.loads((dev / "truth" / "truth.json").read_text(encoding="utf-8"))
    TRUTH.update(truth)
    reg_rows = list(csv.DictReader(io.StringIO((dev / "attacker" / "registry.csv").read_text(encoding="utf-8"))))
    registry = {r["rid"]: r for r in reg_rows}

    # canary substitutions from the practice truth
    for f in truth["files"].values():
        for u in f["units"].values():
            for e in u["entities"]:
                if e.get("canary"):
                    cid = e["person"]
                    nname, nph = CANARY_NEW[cid]
                    if e["type"] == "CANARY":
                        CANARY_SUBST.append((e["surface"], nname))
                    else:
                        old = e["surface"]
                        new = nph if old.isdigit() else f"{nph[:5]}-{nph[5:]}"
                        CANARY_SUBST.append((old, new))
    CANARY_SUBST.sort(key=lambda x: -len(x[0]))

    # sanity: canary phones must be new
    all_digits = set()
    for p in (dev / "input").rglob("*"):
        if p.is_file():
            all_digits |= set(re.findall(rb"\d{10}", p.read_bytes()))
    for cid, (_, ph) in CANARY_NEW.items():
        assert ph.encode() not in all_digits, f"{cid} phone collides"

    for sub in ("input", "truth", "attacker"):
        shutil.rmtree(out / sub, ignore_errors=True)
    (out / "truth").mkdir(parents=True)
    (out / "attacker").mkdir(parents=True)

    new_files = {}
    problems = []
    stats = {"files": 0, "changed": 0, "renamed": 0}
    for rel, f in truth["files"].items():
        src = dev / "input" / rel
        raw = src.read_bytes()
        ctx = Ctx(rel, f, f["units"], registry)
        enc = f.get("encoding") or "utf-8"
        nrel = rename_path(rel)
        data = None
        if rel == "lab/report_00005.json":
            name, ph = CANARY_NEW["CANARY-5"]
            nrel = f"lab/report_00005_shared_by_{name.replace(' ', '_')}_{ph}.json"
            add_canary(ctx, "@filename", "CANARY-5", name.replace(" ", "_"), ph, "filename")
        if not raw:
            data = raw
        elif f["format"] == "pdf":
            data = handle_pdf(ctx, raw)
        elif f["format"] == "binary":
            data = handle_jpg(ctx, raw)
        else:
            try:
                text = raw.decode(enc)
                strict = True
            except UnicodeDecodeError:
                text = raw.decode("utf-8", errors="surrogateescape")
                strict = False
            res = None
            if strict and f["format"] in ("json", "fhir"):
                res = handle_json(ctx, text)
            elif strict and f["format"] in ("csv", "tsv") and not text.lstrip("﻿").startswith(("{", "[")):
                res = handle_csv(ctx, text, f.get("delimiter") or ",")
            if res is None:
                res = handle_text(ctx, text)
            data = res.encode(enc, errors="surrogateescape") if strict else res.encode("utf-8", errors="surrogateescape")
        dst = out / "input" / nrel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(data)
        stats["files"] += 1
        stats["changed"] += data != raw
        stats["renamed"] += nrel != rel

        nf = copy.deepcopy({k: v for k, v in f.items() if k != "units"})
        nf["path"] = nrel
        nf["sha256"] = hashlib.sha256(data).hexdigest()
        nf["size"] = len(data)
        if ctx.p.get("dates"):
            nf["date_hint"] = DATE_HINT[ctx.p["dates"]]
        nf["generalizable"] = [rename_path_field(g, ctx.p["keys"], ctx.p["header"]) for g in f.get("generalizable", [])]
        nf["units"] = rebuild_units(ctx, nrel != rel)
        new_files[nrel] = nf

        # verification: everything findable before must be findable after
        before_c, after_c = decoded_text(raw, enc), decoded_text(data, enc)
        before_n, after_n = norm(rel), norm(nrel)
        for loc, u in f["units"].items():
            nloc = rename_seg(loc, ctx.p["keys"])
            nu = nf["units"][nloc]
            nents = dict(enumerate(ctx.ent_index[nloc]))
            for i, e in enumerate(u["entities"]):
                hay_b, hay_a = (before_n, after_n) if e["channel"] == "filename" else (before_c, after_c)
                if norm(e["surface"]) not in hay_b:
                    continue
                ne = nents[i]
                if ne.get("_drop"):
                    continue
                if norm(ne["surface"]) not in hay_a:
                    problems.append((nrel, nloc, e["type"], f"{e['surface']} -> {ne['surface']}"))
                elif e["type"] != "CANARY" and not e.get("canary") and e["match"] == "name" and \
                        norm(e["surface"]) == norm(ne["surface"]) and e.get("tokens"):
                    problems.append((nrel, nloc, "name unchanged", e["surface"]))
            for pv, npv in zip(u["preserve"], nu["preserve"]):
                if norm(pv["text"]) in before_c and norm(npv["text"]) not in after_c:
                    problems.append((nrel, nloc, "preserve", f"{pv['text']} -> {npv['text']}"))
        for loc, ents in ctx.add_ents.items():
            for e in ents:
                hay = after_n if e["channel"] == "filename" else after_c
                if norm(e["surface"]) not in hay:
                    problems.append((nrel, loc, "added entity missing", e["surface"]))

    # truth top level
    nt = {k: copy.deepcopy(v) for k, v in truth.items() if k != "files"}
    nt["seed"] = SEED
    nt["generator_version"] = f"{truth.get('generator_version')}+blind_variant2"
    nt["files"] = new_files
    for p in nt["patients"].values():
        p["uhids"] = {h: [map_ids(x) for x in ids] for h, ids in p["uhids"].items()}
    nt["canaries"] = sorted(CANARY_NEW, key=lambda c: int(c.split("-")[1]))
    req = amb = 0
    for f in new_files.values():
        for u in f["units"].values():
            req += u.get("link") == "required"
            amb += u.get("link") == "ambiguous"
    nt.setdefault("linkability", {})
    nt["linkability"]["required_units"] = req
    nt["linkability"]["ambiguous_units"] = amb
    (out / "truth" / "truth.json").write_text(json.dumps(nt, ensure_ascii=False, indent=1), encoding="utf-8")

    # attacker side: registry names through the same global map; facts carry no names
    buf = io.StringIO(newline="")
    w = csv.DictWriter(buf, fieldnames=list(reg_rows[0].keys()), lineterminator="\n")
    w.writeheader()
    for r in reg_rows:
        r = dict(r)
        for k in ("name", "relative_name", "email"):
            r[k] = map_global(r[k])
        w.writerow(r)
    (out / "attacker" / "registry.csv").write_text(buf.getvalue(), encoding="utf-8")
    shutil.copyfile(dev / "attacker" / "known_facts.jsonl", out / "attacker" / "known_facts.jsonl")
    if (dev / "attacker" / "README.md").exists():
        shutil.copyfile(dev / "attacker" / "README.md", out / "attacker" / "README.md")

    # leftover old-pool tokens anywhere in the new input (should be none)
    leftovers = {}
    for p in (out / "input").rglob("*"):
        if p.is_file():
            t = p.read_bytes().decode("utf-8", errors="ignore") + "\n" + p.name
            try:
                t += "\n" + p.read_bytes().decode("utf-16")
            except UnicodeDecodeError:
                pass
            t, _ = mask(t)
            for m in NAMES.lat_re.finditer(t):
                leftovers.setdefault(m.group(1).lower(), set()).add(str(p.relative_to(out / "input")))
            for m in NAMES.dev_re.finditer(t):
                leftovers.setdefault(m.group(1), set()).add(str(p.relative_to(out / "input")))

    ents = sum(len(u["entities"]) for f in new_files.values() for u in f["units"].values())
    print(f"files {stats['files']}, changed {stats['changed']}, renamed {stats['renamed']}, entities {ents}")
    print(f"canaries {len(nt['canaries'])}")
    for k, v in sorted(leftovers.items()):
        print(f"  leftover old-pool token {k!r} in {sorted(v)[:3]}")
    for pr in problems:
        print("  PROBLEM", *pr)
    print("verification:", "OK" if not problems else f"{len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
