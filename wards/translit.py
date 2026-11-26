"""Devanagari -> Latin transliteration and phonetic name keys.

Hand-written (no external dependency) so behaviour is deterministic and explainable.
`name_key()` maps "Mohammad", "Mohd", "Md.", "मोहम्मद" and "Muhammad" to comparable keys,
"Reena"/"Rina"/"रीना" to one key, "Hareesh"/"Harish"/"हरीश" to one key.
"""
from __future__ import annotations

import functools
import re
import unicodedata

_CONS = {
    "क": "k", "ख": "kh", "ग": "g", "घ": "gh", "ङ": "n", "च": "ch", "छ": "chh", "ज": "j",
    "झ": "jh", "ञ": "n", "ट": "t", "ठ": "th", "ड": "d", "ढ": "dh", "ण": "n", "त": "t",
    "थ": "th", "द": "d", "ध": "dh", "न": "n", "प": "p", "फ": "ph", "ब": "b", "भ": "bh",
    "म": "m", "य": "y", "र": "r", "ल": "l", "व": "v", "श": "sh", "ष": "sh", "स": "s",
    "ह": "h", "ळ": "l", "क़": "q", "ख़": "kh", "ग़": "gh", "ज़": "z", "ड़": "r", "ढ़": "rh",
    "फ़": "f", "य़": "y", "ऱ": "r", "ऩ": "n",
}
_NUKTA_MAP = {"क": "q", "ख": "kh", "ग": "gh", "ज": "z", "ड": "r", "ढ": "rh", "फ": "f"}
_VOWELS = {
    "अ": "a", "आ": "aa", "इ": "i", "ई": "ee", "उ": "u", "ऊ": "oo", "ऋ": "ri", "ए": "e",
    "ऐ": "ai", "ओ": "o", "औ": "au", "ऑ": "o", "ऍ": "e",
}
_MATRAS = {
    "ा": "aa", "ि": "i", "ी": "ee", "ु": "u", "ू": "oo", "ृ": "ri", "े": "e", "ै": "ai",
    "ो": "o", "ौ": "au", "ॉ": "o", "ॅ": "e",
}
_VIRAMA = "्"
_NUKTA = "़"
_ANUSVARA = "ं"
_CHANDRA = "ँ"
_VISARGA = "ः"


def deva_to_latin(text: str) -> str:
    """Simple ITRANS-like transliteration with word-final schwa deletion."""
    text = unicodedata.normalize("NFC", text)
    out = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if ch in _CONS or (ch in _NUKTA_MAP and nxt == _NUKTA):
            if nxt == _NUKTA and ch in _NUKTA_MAP:
                base = _NUKTA_MAP[ch]
                i += 1
                nxt = text[i + 1] if i + 1 < n else ""
            else:
                base = _CONS[ch]
            out.append(base)
            if nxt == _VIRAMA:
                i += 2
                continue
            if nxt in _MATRAS:
                out.append(_MATRAS[nxt])
                i += 2
                continue
            # inherent vowel; drop it at word end (schwa deletion)
            after = nxt
            if after and ("ऀ" <= after <= "ॿ") and after not in (" ",):
                if after in (_ANUSVARA, _CHANDRA, _VISARGA):
                    out.append("a")
                else:
                    out.append("a")
            i += 1
            continue
        if ch in _VOWELS:
            out.append(_VOWELS[ch])
        elif ch in _MATRAS:
            out.append(_MATRAS[ch])
        elif ch in (_ANUSVARA, _CHANDRA):
            out.append("n")
        elif ch == _VISARGA:
            out.append("h")
        elif ch in (_VIRAMA, _NUKTA):
            pass
        elif "०" <= ch <= "९":
            out.append(str(ord(ch) - 0x0966))
        elif ch in ("।", "॥"):
            out.append(".")
        else:
            out.append(ch)
        i += 1
    s = "".join(out)
    # schwa deletion inside common name shapes: "kamala" (from कमला: k-a-m-l-aa) handled by key
    return s


_LATIN_RULES = [
    (r"^(mohd|md|mohmd|mohamad|mohammed|mohammad|muhammad|muhammed|mohamed|mohammd)$", "mhmd"),
    (r"ph", "f"), (r"w", "v"), (r"z", "j"), (r"q", "k"), (r"x", "ks"), (r"ck", "k"),
    (r"c(?!h)", "k"), (r"ee", "i"), (r"oo", "u"), (r"ou", "u"), (r"ai", "e"), (r"ei", "e"),
    (r"au", "o"), (r"y$", "i"), (r"([bcdfghjklmnpqrstvwxz])h", r"\1"), (r"sh", "s"),
]


_MOHD = re.compile(r"^(mohd|md|mohmd|mohamad|mohammed|mohammad|muhammad|muhammed|mohamed|mohammd|mohummad)$")


def latin_simplify(token: str) -> str:
    t = re.sub(r"[^a-z]", "", token.lower())
    if _MOHD.match(t):
        return "mhmd"
    for pat, rep in _LATIN_RULES[1:]:
        t = re.sub(pat, rep, t)
    return t


@functools.lru_cache(maxsize=200000)
def name_key(token: str) -> str:
    """Consonant skeleton of a single name token (script independent)."""
    if not token:
        return ""
    if re.search(r"[ऀ-ॿ]", token):
        token = deva_to_latin(token)
    t = latin_simplify(token)
    if t == "mhmd":
        return "mhmd"
    if not t:
        return ""
    head, rest = t[0], t[1:]
    rest = re.sub(r"[aeiouy]", "", rest)
    s = head + rest
    s = re.sub(r"(.)\1+", r"\1", s)
    return s


@functools.lru_cache(maxsize=200000)
def vowel_key(token: str) -> str:
    """Less lossy key: simplified spelling with vowel runs collapsed (for tie-breaking)."""
    if re.search(r"[ऀ-ॿ]", token):
        token = deva_to_latin(token)
    t = latin_simplify(token)
    t = re.sub(r"a+$", "", t) if len(t) > 3 else t
    t = re.sub(r"([aeiou])\1+", r"\1", t)
    return re.sub(r"(.)\1+", r"\1", t)


def to_latin(text: str) -> str:
    return deva_to_latin(text) if re.search(r"[ऀ-ॿ]", text) else text
