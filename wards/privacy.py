"""Privacy layer: keyed pseudonyms, per-patient date shifting, age banding, generalisation.

Every secret-dependent value is an HMAC-SHA256 keyed with RAKSHA_SECRET, so:
  * the same secret gives byte-identical output (determinism),
  * a different secret gives different pseudonyms and shifts (no cross-release linkage),
  * pseudonyms cannot be inverted by hashing a dictionary of original IDs.
The secret is read once from the environment and never written anywhere.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import os
import re

from .policy import POLICY

_SECRET = os.environ.get("RAKSHA_SECRET", "").encode("utf-8")
_ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ"  # letters only: a pseudonym must never look like a PIN, age or phone


class MissingSecret(RuntimeError):
    pass


def _mac(*parts: str) -> bytes:
    if not _SECRET.strip():
        raise MissingSecret("RAKSHA_SECRET is empty")
    msg = "\x1f".join(parts).encode("utf-8")
    return hmac.new(_SECRET, msg, hashlib.sha256).digest()


def _code(digest: bytes, n: int) -> str:
    v = int.from_bytes(digest[:8], "big")
    out = []
    for _ in range(n):
        v, r = divmod(v, len(_ALPHABET))
        out.append(_ALPHABET[r])
    return "".join(out)


def pseudonym(cluster_key: str) -> str:
    return "PSN-" + _code(_mac("psn", cluster_key), 6)


def surrogate_id(kind: str, value: str) -> str:
    """Stable surrogate for an identifier we must remove but whose joins are useful (e.g. IPD no)."""
    return f"{kind}-" + _code(_mac("sid", kind, value), 6)


def fhir_id(old: str) -> str:
    """Deterministic, secret-keyed replacement for a FHIR logical id (valid id chars, <= 64)."""
    return "r" + _code(_mac("fhir-id", old), 13).lower()


def shift_days(key: str) -> int:
    m = int(POLICY["date_shift_max_days"])
    lo = int(POLICY.get("date_shift_min_days", 7))
    v = int.from_bytes(_mac("shift", key)[:4], "big")
    span = m - lo + 1
    mag = lo + v % span
    return mag if (v >> 20) & 1 else -mag


# ---------------------------------------------------------------- ages
def age_band(age: int, width: int = 0) -> str:
    w = int(width or POLICY["age_band_years"])
    top = int(POLICY["age_top_code"])
    if age >= top:
        return f"{top}+"
    lo = (age // w) * w
    return f"{lo}-{lo + w - 1}"


def band_int_lo(age: int) -> int:
    w = int(POLICY["age_band_years"])
    top = int(POLICY["age_top_code"])
    if age >= top:
        return top
    return (age // w) * w


# ---------------------------------------------------------------- dates
MONTH_NAMES = ["January", "February", "March", "April", "May", "June", "July", "August", "September",
               "October", "November", "December"]
_MON_IDX = {m.lower(): i + 1 for i, m in enumerate(MONTH_NAMES)}
for _m, _i in list(_MON_IDX.items()):
    _MON_IDX[_m[:3]] = _i
_MON_IDX["sept"] = 9
HINDI_MONTHS = ["जनवरी", "फ़रवरी", "मार्च", "अप्रैल", "मई", "जून", "जुलाई", "अगस्त", "सितंबर", "अक्टूबर", "नवंबर", "दिसंबर"]
_HINDI_ALT = {"फरवरी": 2, "सितम्बर": 9, "अक्तूबर": 10, "नवम्बर": 11, "दिसम्बर": 12, "अप्रेल": 4}
for _i, _m in enumerate(HINDI_MONTHS):
    _MON_IDX[_m] = _i + 1
_MON_IDX.update(_HINDI_ALT)


def _mk(y: int, m: int, d: int):
    try:
        return dt.date(y, m, d)
    except ValueError:
        return None


def parse_num_date(s: str, order: str):
    """Parse '12/04/1977', '04-20-1979', '30/05/26', '19.02.2026'. Returns (date, info) or None."""
    m = re.match(r"^\s*(\d{1,2})([/.\-])(\d{1,2})\2(\d{4}|\d{2})\s*$", s)
    if not m:
        return None
    a, sep, b, y = int(m.group(1)), m.group(2), int(m.group(3)), m.group(4)
    year = int(y) if len(y) == 4 else 2000 + int(y)
    if len(y) == 2 and year > 2030:
        year -= 100
    if order == "mdy":
        d = _mk(year, a, b)
        if d is None:
            d = _mk(year, b, a)
            order = "dmy"
    else:
        d = _mk(year, b, a)
        if d is None:
            d = _mk(year, a, b)
            order = "mdy"
    if d is None:
        return None
    return d, {"style": "num", "sep": sep, "order": order, "y2": len(y) == 2,
               "pad": len(m.group(1)) == 2 and len(m.group(3)) == 2}


def format_num_date(d: dt.date, info: dict) -> str:
    sep = info["sep"]
    y = f"{d.year % 100:02d}" if info["y2"] else f"{d.year:04d}"
    if info["pad"]:
        a, b = f"{d.day:02d}", f"{d.month:02d}"
    else:
        a, b = str(d.day), str(d.month)
    if info["order"] == "mdy":
        a, b = b, a
    return f"{a}{sep}{b}{sep}{y}"


def parse_iso(s: str):
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})(.*)$", s.strip())
    if not m:
        return None
    d = _mk(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    if d is None:
        return None
    return d, {"style": "iso", "tail": m.group(4)}


def parse_text_date(s: str, ref_year: int):
    m = re.match(r"^\s*(\d{1,2})\s+([\u0900-\u097F]+)\s+(\d{4})\s*$", s)    # 12 अप्रैल 1977
    if m and m.group(2) in _MON_IDX:
        d = _mk(int(m.group(3)), _MON_IDX[m.group(2)], int(m.group(1)))
        return (d, {"style": "hindi"}) if d else None
    m = re.match(r"(?i)^\s*(\d{1,2})(st|nd|rd|th)?\s+([a-z]+)\.?(,?)(?:\s+(\d{4}))?\s*$", s)
    if m:
        mon = _MON_IDX.get(m.group(3).lower()[:4].rstrip(".")) or _MON_IDX.get(m.group(3).lower()[:3])
        if not mon:
            return None
        year = int(m.group(5)) if m.group(5) else ref_year
        d = _mk(year, mon, int(m.group(1)))
        if d is None:
            return None
        return d, {"style": "text", "suffix": m.group(2) or "", "has_year": bool(m.group(5)),
                   "abbr": len(m.group(3)) <= 4, "comma": m.group(4)}
    m = re.match(r"(?i)^\s*([a-z]+)\.?\s+(\d{1,2})(st|nd|rd|th)?,?\s+(\d{4})\s*$", s)
    if m:
        mon = _MON_IDX.get(m.group(1).lower()[:4]) or _MON_IDX.get(m.group(1).lower()[:3])
        if not mon:
            return None
        d = _mk(int(m.group(4)), mon, int(m.group(2)))
        if d is None:
            return None
        return d, {"style": "text2", "abbr": len(m.group(1)) <= 4}
    return None


def format_date(d: dt.date, info: dict) -> str:
    st = info["style"]
    if st == "num":
        return format_num_date(d, info)
    if st == "compact":
        return f"{d.year:04d}{d.month:02d}{d.day:02d}"
    if st == "hindi":
        return f"{d.day} {HINDI_MONTHS[d.month - 1]} {d.year}"
    if st == "mon":
        mon = MONTH_NAMES[d.month - 1][:3] if info["abbr"] else MONTH_NAMES[d.month - 1]
        mon = mon.upper() if info["upper"] else mon
        y = f"{d.year % 100:02d}" if info["y2"] else str(d.year)
        day = f"{d.day:02d}" if info["pad"] else str(d.day)
        return f"{day}{info['s1']}{mon}{info['s2']}{y}"
    if st == "ymd":
        return f"{d.year:04d}{info['sep']}{d.month:02d}{info['sep']}{d.day:02d}"
    if st == "iso":
        return f"{d.year:04d}-{d.month:02d}-{d.day:02d}" + info.get("tail", "")
    mon = MONTH_NAMES[d.month - 1]
    if info.get("abbr"):
        mon = mon[:3]
    if st == "text":
        out = f"{d.day}{info.get('suffix', '')} {mon}"
        if info.get("has_year"):
            out += f"{info.get('comma', '')} {d.year}"
        return out
    return f"{mon} {d.day}, {d.year}"


def parse_mon_date(s: str):
    m = re.match(r"(?i)^\s*(\d{1,2})([\-/ ])([a-z]+)\.?([\-/ ,]+)(\d{4}|\d{2})\s*$", s)
    if not m:
        return None
    mon = _MON_IDX.get(m.group(3).lower()[:4]) or _MON_IDX.get(m.group(3).lower()[:3])
    if not mon:
        return None
    y = int(m.group(5)) if len(m.group(5)) == 4 else 2000 + int(m.group(5))
    if len(m.group(5)) == 2 and y > 2030:
        y -= 100
    d = _mk(y, mon, int(m.group(1)))
    if d is None:
        return None
    return d, {"style": "mon", "s1": m.group(2), "s2": m.group(4), "abbr": len(m.group(3)) <= 4,
               "upper": m.group(3).isupper(), "y2": len(m.group(5)) == 2, "pad": len(m.group(1)) == 2}


def parse_ymd(s: str):
    m = re.match(r"^\s*(\d{4})([/.])(\d{1,2})\2(\d{1,2})\s*$", s)
    if not m:
        return None
    d = _mk(int(m.group(1)), int(m.group(3)), int(m.group(4)))
    return (d, {"style": "ymd", "sep": m.group(2)}) if d else None


def parse_compact(s: str):
    m = re.match(r"^\s*((?:19|20)\d{2})(\d{2})(\d{2})\s*$", s)
    if not m:
        return None
    d = _mk(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return (d, {"style": "compact"}) if d else None


def parse_any_date(s: str, order: str, ref_year: int = 2026):
    s2 = s.strip()
    r = parse_compact(s2)
    if r:
        return r
    for fn in (parse_mon_date, parse_ymd):
        r = fn(s2)
        if r:
            return r
    r = parse_iso(s2)
    if r:
        return r
    r = parse_num_date(s2, order)
    if r:
        return r
    return parse_text_date(s2, ref_year)


def shift_date_string(s: str, days: int, order: str, ref_year: int = 2026):
    r = parse_any_date(s, order, ref_year)
    if not r:
        return None
    d, info = r
    try:
        nd = d + dt.timedelta(days=days)
    except OverflowError:
        return None
    return format_date(nd, info)


# ---------------------------------------------------------------- locations
def pin_prefix(pin: str) -> str:
    if POLICY.get("pin_policy") == "drop":
        return "******"
    digits = re.sub(r"\D", "", pin)
    if len(digits) >= 3:
        return digits[:3] + "***"
    return "***"
