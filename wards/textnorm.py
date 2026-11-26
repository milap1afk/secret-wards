"""Text normalisation helpers.

`fold()` returns a string of the SAME LENGTH as its input, so detector offsets found on
the folded copy map 1:1 back onto the original text. It folds the tricks the scorer
also folds: Indic digits, Cyrillic/Greek homoglyphs, Latin diacritics, case.
"""
from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from urllib.parse import unquote

# --- same-length character folding ---------------------------------------------------
_INDIC_DIGIT_BASES = (0x0966, 0x09E6, 0x0A66, 0x0AE6, 0x0B66, 0x0BE6, 0x0C66, 0x0CE6, 0x0D66, 0xFF10)
_HOMOGLYPHS = {
    # Cyrillic
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C",
    "Т": "T", "У": "Y", "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S", "Ԁ": "D", "Ԛ": "Q", "Ԝ": "W",
    "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p", "с": "c",
    "т": "t", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w",
    "һ": "h", "ӏ": "l", "ԍ": "g",
    # Greek
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N",
    "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X", "α": "a", "ε": "e", "ι": "i", "κ": "k",
    "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
}
ZERO_WIDTH = "​‌‍⁠﻿­"
_ZW_RE = re.compile("[" + ZERO_WIDTH + "]")

_fold_cache: dict = {}


def _fold_char(ch: str) -> str:
    r = _fold_cache.get(ch)
    if r is not None:
        return r
    o = ord(ch)
    out = ch
    if o < 128:
        out = ch.lower()
    else:
        for base in _INDIC_DIGIT_BASES:
            if base <= o <= base + 9:
                out = str(o - base)
                break
        else:
            if ch in _HOMOGLYPHS:
                out = _HOMOGLYPHS[ch].lower()
            elif ch in ZERO_WIDTH:
                out = " "
            elif "À" <= ch <= "ɏ" or "Ḁ" <= ch <= "ỿ":
                d = unicodedata.normalize("NFD", ch)
                base_ch = d[0] if d and d[0].isascii() else ch
                out = base_ch.lower()
            else:
                low = ch.lower()
                out = low if len(low) == 1 else ch
    _fold_cache[ch] = out
    return out


def fold(text: str) -> str:
    """Same-length normalised copy: lower-case ASCII, digits ASCII, homoglyphs folded."""
    return "".join(_fold_char(c) for c in text)


def strip_zero_width(text: str) -> str:
    return _ZW_RE.sub("", text)


def ascii_digits(text: str) -> str:
    out = []
    for c in text:
        o = ord(c)
        for base in _INDIC_DIGIT_BASES:
            if base <= o <= base + 9:
                c = str(o - base)
                break
        out.append(c)
    return "".join(out)


def digits_only(text: str) -> str:
    return re.sub(r"\D", "", ascii_digits(text))


# --- hidden payload decoding -----------------------------------------------------------
_U_ESC = re.compile(r"\\u([0-9a-fA-F]{4})")
_PCT = re.compile(r"%[0-9A-Fa-f]{2}")
_ENTITY = re.compile(r"&(#\d+|#x[0-9a-fA-F]+|[a-zA-Z]{2,8});")
B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
HEX_RE = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){10,}(?![0-9a-fA-F])")


def decode_escapes(text: str) -> str:
    """Decode literal \\uXXXX, HTML entities and %-encoding so detectors see the payload."""
    if "\\u" in text:
        text = _U_ESC.sub(lambda m: chr(int(m.group(1), 16)), text)
    if "&" in text and _ENTITY.search(text):
        text = html.unescape(text)
    if "%" in text and len(_PCT.findall(text)) >= 2:
        try:
            text = unquote(text, errors="strict")
        except Exception:  # noqa: BLE001
            pass
    return text


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    good = sum(1 for c in s if c.isprintable() or c in "\n\r\t")
    return good / len(s)


def try_b64(token: str) -> str | None:
    """Return decoded text if token is base64 of mostly-printable UTF-8, else None."""
    t = token.strip()
    if len(t) < 16 or len(t) % 4 not in (0, 2, 3):
        return None
    if t.isdigit() or t.isalpha() and (t.islower() or t.isupper()):
        return None
    pad = "=" * (-len(t) % 4)
    try:
        raw = base64.b64decode(t + pad, validate=True)
        s = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if _printable_ratio(s) < 0.95 or not re.search(r"[A-Za-zऀ-ॿ]{3}", s):
        return None
    return s


def try_hex(token: str) -> str | None:
    try:
        s = bytes.fromhex(token).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    if _printable_ratio(s) < 0.95 or not re.search(r"[A-Za-zऀ-ॿ]{3}", s):
        return None
    return s


def encode_b64_like(original: str, new_text: str) -> str:
    return base64.b64encode(new_text.encode("utf-8")).decode("ascii")


DEVA_RE = re.compile(r"[ऀ-ॿ]")


def has_deva(text: str) -> bool:
    return bool(DEVA_RE.search(text))
