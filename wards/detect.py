"""Context-aware PII detection for free text (English, Hindi/Devanagari, Hinglish).

Detection runs on a same-length folded copy of the text (see textnorm.fold) so homoglyphs,
Indic digits and diacritics cannot hide identifiers. Every finding is a Span over the
ORIGINAL text. Overlaps are resolved by priority, then by length.

Layers (all deterministic):
  1. protected spans: doctors ("Dr. Ramesh ..."), organisations ("... Hospital"),
     clinical wards ("Ward 4 (Medicine)"), complaint / history markers (C/O fever, K/C/O, H/O);
  2. identifier patterns: Aadhaar, masked Aadhaar, ABHA number/address, PAN, phones,
     e-mail, insurance IDs, hospital IDs (UHID / IPD / MRN shapes);
  3. labelled values: "Patient Name:", "नाम:", "Attendant:", "Mob.", "UHID:", "Address:" ...;
  4. relation markers: S/o, D/o, W/o, C/O <name>, पुत्र/पत्नी ...;
  5. honorific context: "<name> sahab/ji/didi/bhaiya", "Shri/Smt <name>";
  6. role/verb context: "called by <name>", "witnessed by", "<name> (attendant", chat senders;
  7. address parts: house numbers, mohalla/ward, landmarks, village markers, PIN codes;
  8. known-person lexicon (harvested from structured columns of the whole dataset);
  9. gazetteer names (Latin exact, Devanagari through phonetic keys);
 10. dates and ages (not PII by themselves; transformed later by the privacy layer).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import gazetteer as gz
from .textnorm import fold
from .translit import name_key

# ------------------------------------------------------------------ span model
PRIORITY = {
    "PROTECT": 100, "EMAIL": 90, "ABHA_ADDR": 90, "ABHA": 85, "AADHAAR": 84, "AADHAAR_MASKED": 83,
    "PAN": 82, "INSURANCE": 82, "GOVID": 81, "UPI": 90, "PHONE": 80, "LONGNUM": 77, "PHONE_MASKED": 79, "MRN": 78, "DOB": 75, "DATE": 70,
    "NAME": 60, "HOUSE": 55, "LOCALITY": 55, "LANDMARK": 55, "VILLAGE": 54, "PIN": 53, "ADDRESS": 52,
    "AGE": 40,
}


@dataclass
class Span:
    start: int
    end: int
    kind: str
    role: str = ""            # for NAME: patient / relative / other
    value: str = ""           # normalised value (digits for numbers, text for names)
    meta: dict = field(default_factory=dict)

    @property
    def length(self) -> int:
        return self.end - self.start


def resolve(spans: list) -> list:
    """Greedy non-overlapping selection by priority then length."""
    ordered = sorted(spans, key=lambda s: (-PRIORITY.get(s.kind, 0), -s.length, s.start))
    taken: list = []
    occupied = []
    for s in ordered:
        if s.end <= s.start:
            continue
        clash = False
        for a, b in occupied:
            if s.start < b and a < s.end:
                clash = True
                break
        if not clash:
            taken.append(s)
            occupied.append((s.start, s.end))
    return sorted(taken, key=lambda s: s.start)


# ------------------------------------------------------------------ token helpers
LAT_TOKEN = r"[A-Za-z][A-Za-z'’]*\.?"
DEV_TOKEN = r"[\u0900-\u0963\u0970-\u097F]+"
TOKEN_RE = re.compile(r"[A-Za-z\u00C0-\u024F][A-Za-z\u00C0-\u024F'’]*\.?|[\u0900-\u0963\u0970-\u097F]+")

HINDI_STOP = set("""
को है हैं से में की का के ने दिन बुखार नाम आयु वर्ष ग्राम तारीख पर्चा ओपीडी और मरीज़ मरीज पता मकान नं तहसील जिला
पिन मोबाइल महिला पुरुष पास पीछे सामने मंदिर मस्जिद गुरुद्वारे गुरुद्वारा भवन पंचायत स्कूल टंकी पानी बाज़ार बाजार
कॉलोनी नगर बस्ती चौक मोहल्ला मुहल्ला वार्ड गली सड़क रोड मार्ग कोतवाली काली माता हनुमान शिव जामा प्राथमिक विद्यालय दवा दवाई गोली दर्द पेट सिर खांसी
उल्टी दस्त कमजोरी सांस रोज़ रोज सुबह शाम रात दोपहर खाना बाद पहले साथ लिए लिया दिया गया गई हुआ हुई था थी थे
कर करें करना रहा रही रहे जांच रिपोर्ट अस्पताल डॉक्टर डॉ नर्स वार्ड बिस्तर भर्ती छुट्टी निदान इलाज सलाह समीक्षा
उपचार हफ्ते सप्ताह महीने महीना साल एक दो तीन चार पांच छह सात आठ नौ दस बार भी नहीं हाँ जी श्री श्रीमती कुमारी
पुत्र पुत्री पत्नी पति सुपुत्र बेटा बेटी लिंग उम्र जन्म तिथि पिता पति का रजिस्ट्रेशन पंजीकरण संख्या नंबर फ़ोन फोन
""".split())


def is_name_token(tok: str) -> bool:
    """Could this token be part of a person name?"""
    t = tok.strip(".'’")
    if not t:
        return False
    if re.match(r"^[\u0900-\u097F]+$", t):
        return t not in HINDI_STOP and len(t) >= 2
    if not re.match(r"^[A-Za-z\u00C0-\u024F'’]+$", t):
        return False
    low = t.lower()
    if low in gz.NON_NAME_WORDS or low in gz.ORG_WORDS or low in gz.DISTRICTS:
        return False
    if t[0].isupper():
        return True
    return False


def is_initial(tok: str) -> bool:
    return bool(re.match(r"^[A-Z]\.?$", tok))


# ------------------------------------------------------------------ identifier patterns
SEP = r"[\s\-./]?"
RE_EMAIL = re.compile(r"[a-z0-9][a-z0-9._%+\-]*@[a-z0-9\-]+(?:\.[a-z0-9\-]+)+")
RE_ABHA_ADDR = re.compile(r"\b[a-z0-9][a-z0-9._]{2,}@(?:abdm|sbx|ndhm|abha)\b")
RE_ABHA = re.compile(r"(?<![\d])\d{2}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}(?![\d])|(?<![\d])\d{14}(?![\d])")
RE_AADHAAR = re.compile(r"(?<![\d.])[2-9]\d{3}([\s\-.]?)\d{4}\1\d{4}(?![\d])")
RE_AADHAAR_MASKED = re.compile(r"(?<![a-z0-9])(?:[x*]{4}[\s\-.]?){2}\d{4}(?!\d)|(?<![a-z0-9])[x*]{8}\d{4}(?!\d)")
RE_PAN = re.compile(r"(?<![a-z0-9])[a-z]{5}\d{4}[a-z](?![a-z0-9])")
RE_PHONE = re.compile(
    r"(?<![\d+])(?:\(?(?:\+|00)?91\)?[ .\-]?|\(0\)[ ]?|0)?[6-9](?:[ .\-]?\d){9}(?![\d])"
)
# other Indian identifiers (shapes, not labels, so they are found in any context)
RE_UPI = re.compile(r"(?<![a-z0-9._%+\-])[a-z0-9][a-z0-9._\-]{1,}@[a-z]{2,}(?![a-z0-9.@])")
RE_DL = re.compile(r"(?<![a-z0-9])[a-z]{2}[ \-]?\d{2}[ \-]?(?:19|20)\d{2}[ \-]?\d{7}(?![a-z0-9])")
RE_VEHICLE = re.compile(r"(?<![a-z0-9])[a-z]{2}[ \-]?\d{1,2}[ \-]?[a-z]{1,3}[ \-]?\d{4}(?![a-z0-9])")
RE_PASSPORT = re.compile(r"(?<![a-z0-9])[a-z][1-9]\d{6}(?![a-z0-9])")
RE_EPIC = re.compile(r"(?<![a-z0-9])[a-z]{3}\d{7}(?![a-z0-9])")
RE_IFSC = re.compile(r"(?<![a-z0-9])[a-z]{4}0[a-z0-9]{6}(?![a-z0-9])")
RE_LONGNUM = re.compile(r"(?<![\d.])\d{9,18}(?![\d.])")
RE_PHONE_MASKED = re.compile(r"(?<![a-z0-9])[6-9]\d[x*]{6}\d{2}(?![a-z0-9])|(?<![a-z0-9])[6-9]\d{1,3}[x*]{4,7}\d{1,4}(?![a-z0-9])")
RE_INSURANCE = re.compile(
    r"(?<![a-z0-9])(?:pmjay|abpmjay|ab-pmjay|ayushman|pol|policy|ins|claim|cghs|esic)[\-/ ]?(?:[a-z]{2}[\-/])?\d[\d\-/]{5,}\d(?![\d])"
)
# hospital identifiers: PREFIX[sep]digits[sep digits]; prefix 1-6 letters
RE_MRN = re.compile(
    r"(?<![a-z0-9])(?:[a-z]{1,6}[\-/ ]?)?(?:\d{2,4}[\-/])?\d{4,8}(?:[\-/]\d{2,8})?(?![a-z0-9])"
)
RE_MRN_ALNUM = re.compile(r"(?<![a-z0-9])[a-z]{2,6}[\-/]?\d{2,4}[\-/]\d{3,8}(?![a-z0-9])|(?<![a-z0-9])[a-z]{2,6}\d{5,8}(?![a-z0-9])|(?<![a-z0-9])[a-z]{2,6}[\-/]\d{4,8}(?![a-z0-9])|(?<![a-z0-9])[a-z]{2,5}\d{4}[\-/]\d{4,8}(?![a-z0-9])|(?<![a-z0-9])[a-z]{2,5}[\-/][a-z]{2,4}[\-/]\d{4,8}(?![a-z0-9])")
# prefixes that are NOT personal identifiers (visit / bill / sample / trip / ticket / lab codes)
NON_ID_PREFIXES = {
    "opd", "bl", "bill", "s", "amb", "hd", "loinc", "icd", "sg", "mg", "se", "sn", "pkg", "lot", "batch",
    "ref", "inv", "rx", "trip", "page", "v", "ver", "tkt", "ticket", "req", "order", "ord", "sample", "smp",
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "sept", "oct", "nov", "dec", "january",
    "february", "march", "april", "june", "july", "august", "september", "october", "november", "december",
    "year", "yr", "dated", "date", "dt", "time", "since", "till", "upto",
}

LABEL_SEP = r"\s*(?:[:\-–=]|\bis\b)?\s*"
# labels whose value is an identifier
ID_LABELS = re.compile(
    r"(?i)\b(uhid|u\.h\.i\.d|mrn|m\.r\.n|cr\s*no|reg(?:istration)?\.?\s*(?:no|number|id)|patient\s*id|pt\.?\s*id|hospital\s*(?:no|id)|"
    r"ipd\s*(?:no|number)|ip\s*no|adm(?:ission)?\.?\s*(?:no|number)|opd\s*reg\s*no|file\s*no|card\s*no|"
    r"health\s*id|abha\s*(?:no|number|id)?|aadhaa?r\s*(?:no|number)?|uid|ipd|uhid)\b\.?(?:\s*(?:no|num|number)\b\.?)?\s*#?\s*[:\-–=]?\s*"
)
NAME_LABELS = re.compile(
    r"(?i)(?<![a-z])(patient'?s?\s*name|name\s*of\s*(?:the\s*)?patient|pt\.?\s*name|pt|patient|naam|name|full\s*name|"
    r"attendant(?:'s)?\s*(?:name)?|relative(?:'s)?\s*(?:name)?|guardian(?:'s)?\s*(?:name)?|informant|caller|"
    r"next\s*of\s*kin|nok|father(?:'s)?\s*name|husband(?:'s)?\s*name|mother(?:'s)?\s*name|spouse|"
    r"contact\s*person|witness|raised\s*by|reported\s*by\s*(?!dr)|brought\s*by|escort)\s*[:\-–=]\s*"
    r"|(नाम|मरीज़?\s*का\s*नाम|रोगी\s*का\s*नाम|पिता\s*का\s*नाम|पति\s*का\s*नाम|परिजन)\s*[:\-–]\s*"
)
REL_LABEL_WORDS = re.compile(r"(?i)attendant|relative|guardian|informant|caller|kin|nok|father|husband|mother|spouse|contact|witness|raised|reported|brought|escort|पिता|पति|परिजन")
PHONE_LABELS = re.compile(r"(?i)\b(mob(?:ile)?|ph(?:one)?|tel|contact|cell|whats\s*app|call\s*back|callback|मोबाइल|फ़ोन|फोन)\b\.?\s*(?:no\.?|number)?\s*[:\-–=]?\s*")
ADDR_LABELS = re.compile(r"(?i)(?<![a-z])(address|addr|add|residence|r/o|resident\s+of|पता|निवास)\s*[:\-–.]\s*")
VILLAGE_MARKERS = re.compile(r"(?i)(?<![a-z])(vill(?:age)?\.?|gram|gaon|ग्राम|गांव|गाँव|मौजा|mauza)\s*[:\-–.]?\s*")
DOB_LABELS = re.compile(r"(?i)(?<![a-z])(dob|d\.\s*o\.\s*b\.?|date\s*of\s*birth|birth\s*date|born\s*on|janm\s*tithi|जन्म\s*तिथि)\s*[:\-–=]?\s*")

RELATION_RE = re.compile(
    r"(?<![A-Za-z])(S\s*/\s*[Oo]|D\s*/\s*[Oo]|W\s*/\s*[Oo]|C\s*/\s*[Oo]|H\s*/\s*[Oo]|Son\s+of|Daughter\s+of|Wife\s+of|Husband\s+of|"
    r"Care\s+of)\b\.?\s*:?\s*|(पुत्र|पुत्री|पत्नी|पति|सुपुत्र|सुपुत्री)\s*(?:श्री\s*)?:?\s*"
)
VERB_CTX = re.compile(
    r"(?i)\b(called\s+by|raised\s+by|witnessed\s+by|brought\s+by|accompanied\s+by|informed\s+by|signed\s+by|"
    r"collected\s+by|received\s+from|consent\s+(?:given|signed)\s+by|report\s+of|on\s+behalf\s+of|"
    r"attendant|relative|husband|wife|son|daughter|father|mother|brother|sister)\s+(?:is\s+|named\s+|mr\.?\s+|mrs\.?\s+)?"
)
ROLE_AFTER = re.compile(r"(?i)^\s*\((attendant|relative|husband|wife|son|daughter|father|mother|brother|sister|guardian|visitor|caller|patient)")
CHAT_SENDER = re.compile(r"^\[[^\]]{4,40}\]\s*([^:\n]{2,40}):", re.M)

# ------------------------------------------------------------------ protected contexts
RE_URL = re.compile(r"(?i)\bhttps?://[^\s\"'<>]+|\bwww\.[^\s\"'<>]+")
STANDARD_HOSTS = ("w3.org", "hl7.org", "loinc.org", "snomed.info", "unitsofmeasure.org", "who.int", "fhir.org",
                  "abdm.gov.in", "ndhm.gov.in", "nrces.in", "example.org", "example.com", ".example")
RE_UUID = re.compile(r"(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f])")
RE_HEX = re.compile(r"(?<![0-9a-z])[0-9a-f]{16,}(?![0-9a-z])")
DOCTOR_RE = re.compile(
    r"(?<![A-Za-z])(?:Dr|DR|dr|Doctor|Prof)\.?\s*(?:(?:[A-Z]\.\s*){1,3})?[A-Z][A-Za-z]+(?:\s+(?:[A-Z]\.\s*)?[A-Z][A-Za-z]+){0,3}"
    r"|(?:डॉ|डा|डॉक्टर)\.?\s*[\u0900-\u097F]+(?:\s+[\u0900-\u097F]+){0,2}"
)
ORG_RE = re.compile(
    r"(?:[A-Z][A-Za-z]+\s+){0,4}(?:Hospital|Clinic|Pathology|Diagnostics|Diagnostic|Laboratory|Labs?|Sadan|Centre|Center|"
    r"Nursing\s+Home|Medical\s+College|Trust|PHC|CHC)\b(?:\s*,?\s*[A-Z][a-z]+)?"
    r"|(?:District|Community|Primary)\s+(?:Hospital|Health\s+Centre)\s+[A-Z][a-z]+"
)
CLINICAL_WARD = re.compile(r"(?i)\bward\s*(?:no\.?\s*)?\d{1,2}\s*\((?:[a-z ]+)\)|\bward\s*/\s*bed\b|\bward\s*\d{1,2}\s*/\s*bed\s*\d+|\bbed\s*(?:no\.?\s*)?\d+")
COMPLAINT_RE = re.compile(r"(?i)\b(?:k\s*/\s*c\s*/\s*o|h\s*/\s*o|c\s*/\s*o)\b\s*:?\s*(?=[a-z(]|no\b|known)|\bk/c/o\b")
EPONYM_RE = re.compile(r"(?i)\b[A-Z][a-z]+(?:'s|’s|s)?\s+(?:disease|syndrome|palsy|sarcoma|lymphoma|anomaly|phenomenon|ulcer|test|sign|fracture)\b")

# ------------------------------------------------------------------ address parts
HOUSE_RE = re.compile(
    r"(?i)(?<![a-z])(?:h\.?\s*no\.?|house\s*(?:no\.?)?|makan\s*(?:no\.?|number)?|flat\s*(?:no\.?)?|plot\s*(?:no\.?)?|door\s*no\.?|"
    r"qtr\.?\s*no\.?|quarter\s*no\.?|मकान\s*(?:नं\.?|नंबर|संख्या)?|म\.\s*नं\.?|घर\s*(?:नं\.?|नंबर)?)\s*[:\-]?\s*\d+[a-z]?(?:\s*[/-]\s*\d+[a-z]?)?"
)
LOCALITY_RE = re.compile(
    r"(?:(?i:mohalla|mohallah|muhalla|mohala|mohalla:|locality|colony|sector|ward\s*no\.?|ward)\s*[:\-]?\s*(?:\d{1,3}\b|(?:[A-Z][a-z]+\s*){1,3}))"
    r"|(?:मोहल्ला|मुहल्ला|वार्ड)\s*(?:नं\.?\s*)?(?:\d{1,3}|[\u0900-\u097F]+(?:\s+[\u0900-\u097F]+){0,2})"
)
LANDMARK_RE = re.compile(
    r"(?:(?i:near|opp\.?|opposite|behind|beside|next\s+to|in\s+front\s+of|close\s+to|nr\.?)\s+(?:the\s+)?(?:[A-Z][a-z]+\.?\s*){1,4})"
    r"|(?:[\u0900-\u097F]+\s+){1,3}(?:के|की)\s+(?:पास|पीछे|सामने|बगल\s+में|नज़दीक|निकट)"
)
PIN_RE = re.compile(r"(?<![\d])[1-8]\d{2}\s?\d{3}(?![\d])")
PIN_LABEL = re.compile(r"(?i)(?:pin(?:\s*code)?|zip|postal\s*code|pincode|पिन(?:\s*कोड)?)\s*[:\-]?\s*$")

# ------------------------------------------------------------------ dates & ages
MONTHS = {m: i + 1 for i, m in enumerate(
    ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"])}
MONTH_ABBR = {k[:3]: v for k, v in MONTHS.items()}
MONTH_ABBR["sept"] = 9
_MON = r"(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sept?(?:ember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
RE_ISO = re.compile(r"(?<![\d])(\d{4})-(\d{2})-(\d{2})(T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+\-]\d{2}:?\d{2})?)?(?![\d])")
RE_NUMDATE = re.compile(r"(?<![\d/.\-])(\d{1,2})([/.\-])(\d{1,2})\2(\d{4}|\d{2})(?![\d])")
RE_TEXTDATE = re.compile(r"(?i)(?<![a-z\d])(\d{1,2})(?:st|nd|rd|th)?\s+(" + _MON + r")\.?,?(?:\s+(\d{4}))?(?![a-z])")
RE_MONDATE = re.compile(r"(?i)(?<![a-z\d])(\d{1,2})[\-/ ](" + _MON + r")[\-/ ,]+(\d{4}|\d{2})(?![\d])")
RE_YMD = re.compile(r"(?<![\d])(\d{4})[/.](\d{1,2})[/.](\d{1,2})(?![\d])")
RE_HINDIDATE = re.compile(r"(?<![\d])(\d{1,2})\s+(जनवरी|फ़रवरी|फरवरी|मार्च|अप्रैल|अप्रेल|मई|जून|जुलाई|अगस्त|सितंबर|सितम्बर|अक्टूबर|अक्तूबर|नवंबर|नवम्बर|दिसंबर|दिसम्बर)\s+(\d{4})(?![\d])")
RE_TEXTDATE2 = re.compile(r"(?i)(?<![a-z\d])(" + _MON + r")\.?\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+(\d{4})(?![\d])")
RE_AGE = re.compile(
    r"(?i)(?<![\d\-/.x])(?<!x )(\d{1,3})\s*(?:yrs?|years?|y)\.?(?=\s*/\s*(?:[mf]\b|male|female)|\s*,?\s*(?:male|female|m\b|f\b|old\b))"
    r"|(?<![\d\-/.:])(\d{1,3})\s*/\s*(?=[mf]\b|male\b|female\b)"
    r"|(?<![\d])(\d{1,3})\s*(?=वर्ष|साल)"
    r"|(?i:\b(?:age|aged)\b\s*[:\-]?\s*)(\d{1,3})(?![\d/.\-])"
    r"|(?:आयु|उम्र)\s*[:\-]?\s*(\d{1,3})"
)


HONORIFIC_RE = re.compile(r"(?<![\w\u0900-\u097F])(" + "|".join(sorted((re.escape(h) for h in gz.HONORIFIC_SUFFIX), key=len, reverse=True)) + r")(?![\w\u0900-\u097F])", re.I)


@dataclass
class Lexicon:
    """Known PII harvested from structured fields of the whole dataset."""
    name_phrases: dict = field(default_factory=dict)   # folded phrase -> role
    name_tokens: dict = field(default_factory=dict)     # folded token -> count of persons
    name_keys: set = field(default_factory=set)         # phonetic keys of known name tokens (len>=3)
    id_cores: set = field(default_factory=set)          # digit cores of known hospital IDs
    id_strings: set = field(default_factory=set)        # folded alnum IDs
    phones: set = field(default_factory=set)            # 10-digit
    villages: set = field(default_factory=set)          # folded village names
    localities: set = field(default_factory=set)
    phrase_re: object = None
    token_re: object = None
    village_re: object = None

    def compile(self) -> None:
        phrases = sorted((p for p in self.name_phrases if len(p) >= 4), key=len, reverse=True)
        if phrases:
            self.phrase_re = re.compile(r"(?<![\w\u0900-\u097F])(?:" + "|".join(re.escape(p) for p in phrases) + r")(?![\w\u0900-\u097F])")
        toks = sorted((t for t in self.name_tokens if len(t) >= 3 and t not in gz.GENERIC_NAME_TOKENS), key=len, reverse=True)
        if toks:
            self.token_re = re.compile(r"(?<![\w\u0900-\u097F])(?:" + "|".join(re.escape(t) for t in toks) + r")(?![\w\u0900-\u097F])")
        vills = sorted((v for v in self.villages | self.localities if len(v) >= 4), key=len, reverse=True)
        if vills:
            self.village_re = re.compile(r"(?<![\w\u0900-\u097F])(?:" + "|".join(re.escape(v) for v in vills) + r")(?![\w\u0900-\u097F])")


EMPTY_LEX = Lexicon()


# ------------------------------------------------------------------ the detector
def _name_run(text: str, pos: int, max_tokens: int = 4, allow_lower: bool = False) -> tuple:
    """Extend a person-name span starting at pos over name-like tokens. Returns (start, end, tokens)."""
    i = pos
    n = len(text)
    toks = []
    start = None
    end = pos
    while len(toks) < max_tokens:
        m = re.compile(r"[ \t]*").match(text, i)
        j = m.end()
        tm = TOKEN_RE.match(text, j)
        if not tm:
            break
        tok = tm.group(0)
        bare = tok.rstrip(".")
        low = bare.lower()
        ok = False
        if is_initial(tok) or low in ("md", "mohd", "mohd.", "km", "smt", "shri", "sri"):
            ok = True
        elif is_name_token(bare):
            ok = True
        elif allow_lower and re.match(r"^[a-z]{3,}$", bare) and low not in gz.NON_NAME_WORDS and low not in gz.HONORIFIC_SUFFIX:
            ok = True
        elif bare.isupper() and len(bare) >= 3 and low not in gz.NON_NAME_WORDS and low not in gz.ORG_WORDS:
            ok = True
        if not ok:
            break
        if low in gz.HONORIFIC_SUFFIX and toks:
            break
        if start is None:
            start = tm.start()
        toks.append(bare)
        end = tm.end() if not tok.endswith(".") or is_initial(tok) or low in ("md", "mohd") else tm.end() - 1
        i = tm.end()
        if i < n and text[i] in ",;:()[]|\n0123456789":
            break
    if start is None:
        return pos, pos, []
    # trim trailing initials-only
    return start, end, toks


class Detector:
    def __init__(self, lexicon: Lexicon | None = None):
        self.lex = lexicon or EMPTY_LEX

    # -------------------------------------------------------------- main entry
    def detect(self, text: str, *, field_kind: str = "", address_ctx: bool = False) -> list:
        if not text or not text.strip():
            return []
        f = fold(text)
        spans: list = []
        self._protect(text, f, spans)
        self._identifiers(text, f, spans)
        self._labels(text, f, spans)
        self._relations(text, f, spans)
        self._honorifics(text, f, spans)
        self._verbs(text, f, spans)
        addr = address_ctx or bool(ADDR_LABELS.search(text)) or bool(re.search(r"(?i)\btehsil\b|\bdistt?\b|तहसील|जिला", text))
        self._address(text, f, spans, addr)
        self._lexicon(text, f, spans)
        self._gazetteer(text, f, spans)
        self._dates_ages(text, f, spans)
        return resolve(spans)

    # -------------------------------------------------------------- layers
    def _protect(self, t, f, spans):
        for m in RE_URL.finditer(t):
            url = m.group(0)
            host = re.match(r"(?i)(?:https?://|urn:)?([^/\s]+)", url).group(1).lower()
            path = url[len(re.match(r"(?i)(?:https?://)?[^/\s]*", url).group(0)):]
            if any(host.endswith(h) for h in STANDARD_HOSTS) or not (re.search(r"\d{5,}", path) or re.search(r"[A-Z][a-z]+[_ ][A-Z][a-z]+", path)):
                spans.append(Span(m.start(), m.end(), "PROTECT", value="url"))
        for m in RE_UUID.finditer(f):
            spans.append(Span(m.start(), m.end(), "PROTECT", value="uuid"))
        for m in RE_HEX.finditer(f):
            if re.search(r"[a-f]", m.group(0)) and re.search(r"\d", m.group(0)):
                spans.append(Span(m.start(), m.end(), "PROTECT", value="hex"))
        for m in DOCTOR_RE.finditer(t):
            spans.append(Span(m.start(), m.end(), "PROTECT", value="doctor"))
        for m in ORG_RE.finditer(t):
            spans.append(Span(m.start(), m.end(), "PROTECT", value="org"))
        for m in CLINICAL_WARD.finditer(t):
            spans.append(Span(m.start(), m.end(), "PROTECT", value="ward"))
        for m in EPONYM_RE.finditer(t):
            spans.append(Span(m.start(), m.end(), "PROTECT", value="eponym"))
        for m in re.finditer(r"(?i:\basha\s+(?:worker|karyakarta|sahyogini|kendra)\b)|\bASHA\b(?![ \t]+[A-Z][A-Za-z]+)", t):
            spans.append(Span(m.start(), m.end(), "PROTECT", value="asha"))

    def _identifiers(self, t, f, spans):
        for m in RE_IFSC.finditer(f):        # a bank BRANCH code, not a person: keep it, never use it to link.
            # Only next to an IFSC label: the shape alone also matches hospital IDs such as JJCH0077305.
            if re.search(r"ifsc\W{0,4}$", f[max(0, m.start() - 12):m.start()]):
                spans.append(Span(m.start(), m.end(), "PROTECT", value="ifsc"))
        for m in RE_UPI.finditer(f):
            dom = m.group(0).split("@", 1)[1]
            if dom not in ("abdm", "sbx", "ndhm", "abha"):
                spans.append(Span(m.start(), m.end(), "UPI", value=m.group(0)))
        for rx in (RE_DL, RE_VEHICLE, RE_PASSPORT, RE_EPIC):
            for m in rx.finditer(f):
                spans.append(Span(m.start(), m.end(), "GOVID", value=m.group(0).upper()))
        for m in RE_LONGNUM.finditer(f):     # 9+ digit runs are never doses, vitals, labs, dates or ages
            spans.append(Span(m.start(), m.end(), "LONGNUM", value=m.group(0)))
        for rx, kind in ((RE_EMAIL, "EMAIL"), (RE_ABHA_ADDR, "ABHA_ADDR")):
            for m in rx.finditer(f):
                spans.append(Span(m.start(), m.end(), kind, value=m.group(0)))
        for m in RE_ABHA.finditer(f):
            spans.append(Span(m.start(), m.end(), "ABHA", value=re.sub(r"\D", "", m.group(0))))
        for m in RE_AADHAAR.finditer(f):
            d = re.sub(r"\D", "", m.group(0))
            spans.append(Span(m.start(), m.end(), "AADHAAR", value=d))
        for m in RE_AADHAAR_MASKED.finditer(f):
            spans.append(Span(m.start(), m.end(), "AADHAAR_MASKED", value=re.sub(r"\D", "", m.group(0))))
        for m in RE_PAN.finditer(f):
            spans.append(Span(m.start(), m.end(), "PAN", value=m.group(0).upper()))
        for m in RE_INSURANCE.finditer(f):
            spans.append(Span(m.start(), m.end(), "INSURANCE", value=m.group(0).upper()))
        for m in RE_PHONE.finditer(f):
            d = re.sub(r"\D", "", m.group(0))[-10:]
            spans.append(Span(m.start(), m.end(), "PHONE", value=d))
        for m in RE_PHONE_MASKED.finditer(f):
            spans.append(Span(m.start(), m.end(), "PHONE_MASKED", value=m.group(0)))
        for m in RE_MRN_ALNUM.finditer(f):
            s = m.group(0)
            prefix = re.match(r"[a-z]+", s).group(0)
            if prefix in NON_ID_PREFIXES:
                continue
            if re.match(r"^[a-z]\d{2}(\.\d+)?$", s):  # ICD code
                continue
            spans.append(Span(m.start(), m.end(), "MRN", value=_id_core(s)))
        # labelled ids: "UHID: 064127", "Reg No 12345"
        for m in ID_LABELS.finditer(t):
            vm = re.compile(r"[A-Za-z]{0,6}[\-/ ]?[\dA-Za-z][\w\-/]{3,24}").match(f, m.end())
            if vm and re.search(r"\d{3,}", vm.group(0)):
                val = vm.group(0).rstrip("-/ ")
                spans.append(Span(vm.start(), vm.start() + len(val), "MRN", value=_id_core(val)))
        # known id digit cores anywhere (e.g. "Anita_Sharma_010565" in a path)
        if self.lex.id_cores:
            for m in re.finditer(r"\d{5,}", f):
                core = m.group(0)
                if core in self.lex.id_cores or core.lstrip("0") in self.lex.id_cores:
                    spans.append(Span(m.start(), m.end(), "MRN", value=core))
        if self.lex.phones:
            for m in re.finditer(r"\d{10}", f):
                if m.group(0) in self.lex.phones:
                    spans.append(Span(m.start(), m.end(), "PHONE", value=m.group(0)))

    def _labels(self, t, f, spans):
        for m in NAME_LABELS.finditer(t):
            label = m.group(0)
            if re.search(r"(?i)\bpatient\s*[:\-–=]\s*$", label) is None and re.match(r"(?i)patient\b", label) and not re.search(r"(?i)name", label):
                continue
            s, e, toks = _name_run(t, m.end(), allow_lower=False)
            if not toks:
                continue
            role = "relative" if REL_LABEL_WORDS.search(label) else "patient"
            if role == "patient" and re.match(r"(?i)\s*(?:witness|raised|reported|brought|escort|caller|informant)", label):
                role = "other"
            spans.append(Span(s, e, "NAME", role=role, value=" ".join(toks), meta={"src": "label"}))
        for m in PHONE_LABELS.finditer(t):
            vm = re.compile(r"[+\d][\d\s\-]{7,16}\d").match(f, m.end())
            if vm:
                d = re.sub(r"\D", "", vm.group(0))
                if 8 <= len(d) <= 13:
                    spans.append(Span(vm.start(), vm.end(), "PHONE", value=d[-10:]))
        for m in DOB_LABELS.finditer(t):
            dm = _match_date_at(t, f, m.end())
            if dm:
                spans.append(Span(dm[0], dm[1], "DOB", value=dm[2], meta=dm[3]))
                continue
            ym = re.compile(r"(?:19|20)\d\d(?![\d/.\-])").match(f, m.end())   # year-only DOB: "D.O.B. 1968"
            if ym:
                spans.append(Span(ym.start(), ym.end(), "DOB", value=ym.group(0), meta={"fmt": "year"}))
        for m in VILLAGE_MARKERS.finditer(t):
            s, e, toks = _name_run(t, m.end(), max_tokens=3)
            if toks:
                spans.append(Span(s, e, "VILLAGE", value=" ".join(toks)))

    def _relations(self, t, f, spans):
        for m in RELATION_RE.finditer(t):
            marker = (m.group(1) or m.group(2) or "").replace(" ", "").lower()
            after = t[m.end():m.end() + 40]
            if marker in ("h/o",):
                continue
            if marker in ("c/o", "careof"):
                # "C/O fever" is a complaint; "C/O Ramesh" is care-of a relative.
                tm = TOKEN_RE.match(after)
                if not tm:
                    continue
                first = tm.group(0).rstrip(".")
                if first.lower() in gz.NON_NAME_WORDS or not (first[0].isupper() or re.match(r"[\u0900-\u097F]", first)):
                    continue
                pre = t[max(0, m.start() - 3):m.start()].lower()
                if pre.endswith("k/") or pre.endswith("k /"):
                    continue
            s, e, toks = _name_run(t, m.end(), allow_lower=False)
            if not toks:
                continue
            spans.append(Span(s, e, "NAME", role="relative", value=" ".join(toks), meta={"src": "relation"}))

    def _honorifics(self, t, f, spans):
        # suffix honorific: "<Name> sahab", "<Name> ji", "<नाम> जी"
        for m in HONORIFIC_RE.finditer(t):
            hon = m.group(1).lower()
            # walk back over up to 3 name tokens
            left = t[:m.start()]
            toks = list(re.finditer(r"([A-Za-z\u00C0-\u024F][A-Za-z\u00C0-\u024F'’]*\.?|[\u0900-\u0963\u0970-\u097F]+)\s*$", left))
            seq = []
            pos = m.start()
            cur = left
            for _ in range(3):
                mm = re.search(r"([A-Za-z\u00C0-\u024F][A-Za-z\u00C0-\u024F'’]*\.?|[\u0900-\u0963\u0970-\u097F]+)[ \t]*$", cur)
                if not mm:
                    break
                tok = mm.group(1).rstrip(".")
                if not (is_name_token(tok) or tok.lower() in ("md", "mohd")):
                    break
                if tok.lower() in gz.DOCTOR_PREFIX:
                    seq = []
                    break
                seq.insert(0, (mm.start(1), mm.start(1) + len(tok)))
                cur = cur[:mm.start(1)]
                if re.search(r"(?i)\b(?:dr|doctor)\.?\s*$", cur):
                    seq = []
                    break
            if seq:
                if hon in ("beta", "beti", "baba", "uncle", "aunty") and len(seq) == 1 and not gz.is_known_name_token(t[seq[0][0]:seq[0][1]]):
                    continue
                s, e = seq[0][0], seq[-1][1]
                spans.append(Span(s, e, "NAME", role="", value=t[s:e], meta={"src": "honorific"}))
        # prefix honorific: "Shri Ram Prasad", "Smt. Kamla"
        for m in re.finditer(r"(?i)(?<![a-z])(shri|sri|shree|smt|shrimati|srimati|kumari|km|mr|mrs|ms|janab|late|श्रीमती|श्री|कुमारी|स्व)\.?\s+", t):
            s, e, toks = _name_run(t, m.end())
            if toks:
                spans.append(Span(s, e, "NAME", value=" ".join(toks), meta={"src": "prefix"}))

    def _verbs(self, t, f, spans):
        for m in VERB_CTX.finditer(t):
            s, e, toks = _name_run(t, m.end())
            if toks and not re.match(r"(?i)\s*dr\b", t[m.end():m.end() + 4]):
                w = m.group(1).lower()
                role = "relative" if w in ("attendant", "relative", "husband", "wife", "son", "daughter", "father", "mother", "brother", "sister") else "other"
                if w == "report of":
                    role = "patient"
                spans.append(Span(s, e, "NAME", role=role, value=" ".join(toks), meta={"src": "verb"}))
        # Hinglish possessive at clause start: "Hasina ka BP", "Ramesh ki tabiyat"
        for m in re.finditer(r"(?:^|(?<=[.\n:;\-–]\s)|(?<=^\s))((?:[A-Z][a-z]+\.?\s+){0,2}[A-Z][a-z]+)\s+(?:ka|ki|ke|ko|ne|se)\s", t, flags=re.M):
            words = m.group(1).split()
            if all(is_name_token(w.rstrip(".")) or w.lower().rstrip(".") in ("md", "mohd") for w in words):
                if not re.search(r"(?i)\b(?:dr|doctor)\.?\s*$", t[max(0, m.start(1) - 5):m.start(1)]):
                    spans.append(Span(m.start(1), m.end(1), "NAME", value=m.group(1), meta={"src": "possessive"}))
        # possessive anywhere before a clinical/state noun: "Nankau ki tabiyat", "Sunita ka sugar"
        for m in re.finditer(r"(?<![A-Za-z])((?:[A-Z][a-z]+\s+){0,1}[A-Z][a-z]{2,})\s+(?:ka|ki|ke)\s+(?i:tabiyat|tabiyet|tabeeyat|haalat|halat|bp|sugar|bukhar|pet|sar|report|dawai|dawa|ilaj|ilaaj|operation|condition|khana|neend|pulse|temp)\b", t):
            words = m.group(1).split()
            if all(is_name_token(w) for w in words) and words[0][0].isupper():
                if not re.search(r"(?i)\b(?:dr|doctor)\.?\s*$", t[max(0, m.start(1) - 5):m.start(1)]):
                    spans.append(Span(m.start(1), m.end(1), "NAME", value=m.group(1), meta={"src": "possessive"}))
        # Hinglish kinship: "bete Pancham ne", "pati Ramesh ko", "unki beti Sunita"
        for m in re.finditer(r"(?i)\b(?:beta|bete|beti|bitiya|pati|patni|bahu|bhai|bhaiya|behen|bahen|bhabhi|maa|pita|papa|chacha|chachi|mama|mami|nana|nani|dada|dadi|devar|jeth|saas|sasur|damad)\s+(?=[A-Z])", t):
            s0, e0, toks = _name_run(t, m.end(), max_tokens=3)
            if toks:
                spans.append(Span(s0, e0, "NAME", role="relative", value=" ".join(toks), meta={"src": "kinship"}))
        # Devanagari: "<नाम> (पड़ोसी)", "<नाम> (पुत्र)" and "<नाम>, मो. 98..." (name right before a phone label)
        for m in re.finditer(r"((?:[\u0900-\u0963\u0970-\u097F]+\s+){0,2}[\u0900-\u0963\u0970-\u097F]+)\s*\(\s*(?:पड़ोसी|पड़ोसन|परिजन|रिश्तेदार|पुत्र|पुत्री|पत्नी|पति|भाई|बहन|बेटा|बेटी|माँ|माता|पिता|ससुर|सास|देवर|जेठ|चाचा|मामा|परिचारक|मित्र|दोस्त)", t):
            words = m.group(1).split()
            words = [w for w in words if w not in HINDI_STOP]
            if words:
                st = m.start(1) + m.group(1).find(words[0])
                spans.append(Span(st, m.end(1), "NAME", role="relative", value=" ".join(words), meta={"src": "deva-role"}))
        for m in re.finditer(r"((?:[\u0900-\u0963\u0970-\u097F]+\s+){0,2}[\u0900-\u0963\u0970-\u097F]+)\s*[,:]?\s*(?:मो\.|मोबाइल|फ़ोन|फोन)\s*[:\-]?\s*[\d\u0966-\u096F+(]", t):
            words = [w for w in m.group(1).split() if w not in HINDI_STOP]
            if words:
                st = m.start(1) + m.group(1).find(words[0])
                spans.append(Span(st, m.end(1), "NAME", role="other", value=" ".join(words), meta={"src": "deva-phone"}))
        # "<Name> (attendant, bed 12)"
        for m in re.finditer(r"\(\s*(?:attendant|relative|husband|wife|son|daughter|father|mother|guardian|visitor|caller)", t, flags=re.I):
            left = t[:m.start()].rstrip()
            mm = re.search(r"((?:[A-Z][a-z]+\.?\s+){0,3}[A-Z][a-z]+)$", left)
            if mm and all(is_name_token(x) for x in mm.group(1).split()):
                spans.append(Span(mm.start(1), mm.end(1), "NAME", role="relative", value=mm.group(1), meta={"src": "role"}))
        # chat sender "[30/05/26, 9:32 pm] Kamal Bhaiya:"
        for m in CHAT_SENDER.finditer(t):
            name = m.group(1).strip()
            if re.search(r"\d{6,}", name):
                continue
            spans.append(Span(m.start(1), m.start(1) + len(name), "NAME", role="relative", value=name, meta={"src": "chat"}))
        # "<Name> <phone>" or "<Name>, Mob. <phone>"
        for m in RE_PHONE.finditer(fold(t)):
            left = t[:m.start()]
            mm = re.search(r"((?:[A-Z][a-z]+\s+){0,2}[A-Z][a-z]+)\s*(?:,|-|:)?\s*(?:\(?(?:mob(?:ile)?|ph(?:one)?|m)\.?\)?\s*(?:no\.?)?\s*[:\-]?\s*)?$", left)
            if mm:
                toks = mm.group(1).split()
                toks_ok = [x for x in toks if is_name_token(x)]
                if toks_ok and len(toks_ok) == len(toks) and (len(toks) >= 2 or gz.is_known_name_token(toks[0])):
                    if not re.search(r"(?i)\b(?:dr|doctor)\.?\s*$", left[:mm.start(1)]):
                        spans.append(Span(mm.start(1), mm.end(1), "NAME", role="other", value=mm.group(1), meta={"src": "phone-adj"}))

    def _address(self, t, f, spans, addr_ctx):
        for m in HOUSE_RE.finditer(t):
            spans.append(Span(m.start(), m.end(), "HOUSE", value=m.group(0)))
        for m in LOCALITY_RE.finditer(t):
            s = m.group(0)
            if re.match(r"(?i)ward", s):
                tail = t[m.end():m.end() + 6]
                if not addr_ctx or re.match(r"\s*[\(/]", tail):
                    continue
            spans.append(Span(m.start(), m.end(), "LOCALITY", value=s.strip()))
        for m in LANDMARK_RE.finditer(t):
            if not addr_ctx and not re.search(r"(?i)mandir|masjid|school|tanki|bhawan|gurudwara|church|chowk|temple|पास|पीछे|सामने", m.group(0)):
                continue
            spans.append(Span(m.start(), m.end(), "LANDMARK", value=m.group(0).strip()))
        for m in PIN_RE.finditer(f):
            before = t[max(0, m.start() - 20):m.start()]
            if addr_ctx and (re.search(r"[-–,]\s*$", before) or PIN_LABEL.search(before)) or PIN_LABEL.search(before):
                spans.append(Span(m.start(), m.end(), "PIN", value=re.sub(r"\D", "", m.group(0))))

    def _lexicon(self, t, f, spans):
        lx = self.lex
        if lx.phrase_re is not None:
            for m in lx.phrase_re.finditer(f):
                spans.append(Span(m.start(), m.end(), "NAME", role=lx.name_phrases.get(m.group(0), ""), value=t[m.start():m.end()], meta={"src": "lexicon"}))
        if lx.village_re is not None:
            for m in lx.village_re.finditer(f):
                spans.append(Span(m.start(), m.end(), "VILLAGE", value=t[m.start():m.end()]))
        if lx.token_re is not None:
            for m in lx.token_re.finditer(f):
                tok = t[m.start():m.end()]
                if tok.isupper() and len(tok) <= 4:
                    continue
                if not (tok[:1].isupper() or re.match(r"[\u0900-\u097F]", tok) or tok.isupper()):
                    continue
                spans.append(Span(m.start(), m.end(), "NAME", value=tok, meta={"src": "lexicon-token"}))
        if lx.name_keys:
            for m in re.finditer(DEV_TOKEN, t):
                tok = m.group(0)
                if tok in HINDI_STOP or len(tok) < 2:
                    continue
                k = name_key(tok)
                if len(k) >= 3 and k in lx.name_keys:
                    spans.append(Span(m.start(), m.end(), "NAME", value=tok, meta={"src": "lexicon-deva"}))

    def _gazetteer(self, t, f, spans):
        for m in re.finditer(r"(?<![A-Za-z])[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2}", t):
            words = m.group(0).split()
            # find a gazetteer given name and grow to following surname-ish tokens
            for i, w in enumerate(words):
                if gz.is_given_name(w) and w.lower() not in gz.NON_NAME_WORDS:
                    start = m.start() + len(" ".join(words[:i])) + (1 if i else 0)
                    toks = [w]
                    for w2 in words[i + 1:]:
                        if is_name_token(w2):
                            toks.append(w2)
                        else:
                            break
                    pre = t[max(0, start - 5):start]
                    if re.search(r"(?i)\b(?:dr|doctor)\.?\s*$", pre):
                        break
                    end = start + len(" ".join(toks))
                    spans.append(Span(start, end, "NAME", value=" ".join(toks), meta={"src": "gazetteer"}))
                    break
        # "<Capitalised> Devi/Kumar/Bano/Singh...": generic name suffix marks a person
        for m in re.finditer(r"(?<![A-Za-z])((?:[A-Z][a-z]+\s+){1,2})(Devi|Kumari|Kumar|Bano|Begum|Khatoon|Bibi|Singh|Kaur|Prasad|Lal|Nath)(?![a-z])", t):
            words = m.group(1).split()
            if all(is_name_token(w) for w in words):
                pre = t[max(0, m.start() - 5):m.start()]
                if not re.search(r"(?i)\b(?:dr|doctor)\.?\s*$", pre):
                    spans.append(Span(m.start(), m.end(), "NAME", value=m.group(0), meta={"src": "suffix"}))
        # surname-first full names in caps etc. "PATEL ASHOK" / "MAHESH CHAUHAN"
        for m in re.finditer(r"(?<![A-Za-z])[A-Z]{3,}(?:\s+[A-Z]{3,}){1,2}(?![A-Za-z])", t):
            words = m.group(0).split()
            if any(gz.is_known_name_token(w) for w in words) and not any(w.lower() in gz.NON_NAME_WORDS for w in words):
                spans.append(Span(m.start(), m.end(), "NAME", value=m.group(0), meta={"src": "gazetteer-caps"}))
        # Devanagari: two adjacent tokens where one is a gazetteer name
        for m in re.finditer(DEV_TOKEN + r"(?:\s+" + DEV_TOKEN + r")?", t):
            words = m.group(0).split()
            if any(w in HINDI_STOP for w in words):
                words2 = [w for w in words if w not in HINDI_STOP]
                if len(words2) != 1:
                    continue
            keys = [name_key(w) for w in words]
            hits = [k for k in keys if len(k) >= 3 and (k in gz.GIVEN_KEYS or k in gz.SURNAME_KEYS)]
            if hits and len(words) == 2 and not any(w in HINDI_STOP for w in words):
                spans.append(Span(m.start(), m.end(), "NAME", value=m.group(0), meta={"src": "gazetteer-deva"}))

    def _dates_ages(self, t, f, spans):
        for m in RE_ISO.finditer(f):
            spans.append(Span(m.start(), m.end(), "DATE", value=m.group(0), meta={"fmt": "iso"}))
        for m in RE_NUMDATE.finditer(f):
            spans.append(Span(m.start(), m.end(), "DATE", value=m.group(0), meta={"fmt": "num"}))
        for m in RE_TEXTDATE.finditer(f):
            spans.append(Span(m.start(), m.end(), "DATE", value=m.group(0), meta={"fmt": "text"}))
        for m in RE_HINDIDATE.finditer(f):
            spans.append(Span(m.start(), m.end(), "DATE", value=m.group(0), meta={"fmt": "hindi"}))
        for m in RE_MONDATE.finditer(f):
            spans.append(Span(m.start(), m.end(), "DATE", value=m.group(0), meta={"fmt": "mon"}))
        for m in RE_YMD.finditer(f):
            spans.append(Span(m.start(), m.end(), "DATE", value=m.group(0), meta={"fmt": "ymd"}))
        for m in RE_TEXTDATE2.finditer(f):
            spans.append(Span(m.start(), m.end(), "DATE", value=m.group(0), meta={"fmt": "text2"}))
        for m in RE_AGE.finditer(f):
            for g in range(1, 6):
                if m.group(g):
                    a = int(m.group(g))
                    if 0 <= a <= 120:
                        spans.append(Span(m.start(g), m.end(g), "AGE", value=str(a)))
                    break


def _id_core(s: str) -> str:
    """Digit core of an identifier: the longest digit run (leading zeros kept)."""
    runs = re.findall(r"\d+", s)
    if not runs:
        return s.lower()
    return "".join(runs) if len(runs) > 1 and all(len(r) >= 2 for r in runs) else max(runs, key=len)


def _match_date_at(t: str, f: str, pos: int):
    for rx, fmt in ((RE_ISO, "iso"), (RE_NUMDATE, "num"), (RE_HINDIDATE, "hindi"), (RE_MONDATE, "mon"), (RE_YMD, "ymd"), (RE_TEXTDATE, "text")):
        m = rx.match(f, pos)
        if m:
            return (m.start(), m.end(), m.group(0), {"fmt": fmt})
    return None
