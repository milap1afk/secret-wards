"""Rare-condition generalisation (the Re-identification Trap).

A diagnosis or procedure that only a handful of patients share is a near-unique fingerprint
("97-year-old with a rare procedure"). Codes seen in fewer than `rare_k` patients are
generalised to their ICD-10 chapter; common diagnoses stay exactly as written.
"""
from __future__ import annotations

import re

ICD_RE = re.compile(r"(?<![A-Za-z0-9])([A-TV-Z])(\d{2})(?:\.(\d{1,2}))?(?![A-Za-z0-9])")

_CHAPTERS = [
    ("A00", "B99", "Certain infectious and parasitic diseases"), ("C00", "D49", "Neoplasms"),
    ("D50", "D89", "Diseases of the blood and immune mechanism"), ("E00", "E89", "Endocrine, nutritional and metabolic diseases"),
    ("F01", "F99", "Mental and behavioural disorders"), ("G00", "G99", "Diseases of the nervous system"),
    ("H00", "H59", "Diseases of the eye and adnexa"), ("H60", "H95", "Diseases of the ear and mastoid process"),
    ("I00", "I99", "Diseases of the circulatory system"), ("J00", "J99", "Diseases of the respiratory system"),
    ("K00", "K95", "Diseases of the digestive system"), ("L00", "L99", "Diseases of the skin and subcutaneous tissue"),
    ("M00", "M99", "Diseases of the musculoskeletal system"), ("N00", "N99", "Diseases of the genitourinary system"),
    ("O00", "O9A", "Pregnancy, childbirth and the puerperium"), ("P00", "P96", "Perinatal conditions"),
    ("Q00", "Q99", "Congenital malformations"), ("R00", "R99", "Symptoms and abnormal findings"),
    ("S00", "T88", "Injury and poisoning"), ("V00", "Y99", "External causes"), ("Z00", "Z99", "Factors influencing health status"),
]


def chapter(code: str) -> tuple:
    c = code[:3].upper()
    for lo, hi, name in _CHAPTERS:
        if lo <= c <= hi:
            return f"{lo}-{hi}", name
    return "", "Other condition"


def find_rare(units, rare_k: int) -> dict:
    """Return {surface text -> replacement} for diagnoses seen in fewer than rare_k patients."""
    holders: dict = {}      # 3-char code -> set of patient keys
    displays: dict = {}     # 3-char code -> set of display strings
    for u in units:
        who = u.cluster if u.cluster is not None else ("unit", u.file, u.loc)
        texts = [u.text] if u.text else []
        texts += [str(lf.value) for lf in u.leaves if isinstance(lf.value, str)]
        joined = "\n".join(texts)
        for m in ICD_RE.finditer(joined):
            code3 = m.group(1) + m.group(2)
            holders.setdefault(code3, set()).add(who)
            # display text written just before "(CODE)" in discharge notes
            pre = joined[max(0, m.start() - 80):m.start()]
            dm = re.search(r"(?:Diagnosis\s*:|;)\s*([^;:\n()]{4,70}?)\s*\($", pre)
            if dm:
                displays.setdefault(code3, set()).add(dm.group(1).strip())
        # JSON {"code": "...", "display": "..."} pairs
        by_parent: dict = {}
        for lf in u.leaves:
            if isinstance(lf.value, str) and lf.key in ("code", "display", "text") and len(lf.path) >= 1:
                by_parent.setdefault(tuple(lf.path[:-1]), {})[lf.key] = lf.value
        for d in by_parent.values():
            c = d.get("code", "")
            m = ICD_RE.fullmatch(c.strip()) if c else None
            if m and d.get("display"):
                displays.setdefault(m.group(1) + m.group(2), set()).add(d["display"].strip())
    out = {}
    for code3, who in holders.items():
        if len(who) >= rare_k:
            continue
        rng, name = chapter(code3)
        for disp in displays.get(code3, ()):
            if len(disp) >= 4:
                out[disp] = name
        out["__code__" + code3] = rng
    return out


def apply(text: str, rare: dict) -> str:
    if not rare or not text:
        return text
    for disp in sorted((k for k in rare if not k.startswith("__code__")), key=len, reverse=True):
        if disp in text:
            text = text.replace(disp, rare[disp])

    def code_sub(m):
        key = "__code__" + m.group(1) + m.group(2)
        return rare.get(key, m.group(0))
    return ICD_RE.sub(code_sub, text)
