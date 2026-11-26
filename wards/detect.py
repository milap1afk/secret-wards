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
    "AGE": 40, "NAME_MODEL": 30, "SOFT": 62,
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
    """Greedy non-overlapping selection by priority then length, O(n log n): accepted intervals are kept
    sorted and disjoint, so each candidate only needs its two neighbours checked."""
    import bisect
    ordered = sorted(spans, key=lambda s: (-(s.meta.get("prio") or PRIORITY.get(s.kind, 0)), -s.length, s.start))
    starts: list = []
    ends: list = []
    taken: list = []
    for s in ordered:
        if s.end <= s.start:
            continue
        i = bisect.bisect_right(starts, s.start)
        if i > 0 and ends[i - 1] > s.start:
            continue
        if i < len(starts) and starts[i] < s.end:
            continue
        starts.insert(i, s.start)
        ends.insert(i, s.end)
        taken.append(s)
    return sorted(taken, key=lambda s: s.start)


# ------------------------------------------------------------------ token helpers
LAT_TOKEN = r"[A-Za-z][A-Za-z'’]*\.?"
DEV_TOKEN = r"[\u0900-\u0963\u0970-\u097F]+"
TOKEN_RE = re.compile(r"[A-Za-z\u00C0-\u024F][A-Za-z\u00C0-\u024F'’]*(?:-[A-Z][A-Za-z\u00C0-\u024F'’]*)*\.?|[\u0900-\u0963\u0970-\u097F]+")

# words that sit before a phone number without being a name: contact labels and document words
DEVA_CONTACT_WORDS = set("""
संपर्क नंबर नम्बर नं मो मो. मोबाइल फोन फ़ोन दूरभाष हेल्पलाइन कॉल करें पर व्हाट्सएप वॉट्सऐप एम्बुलेंस शिकायत आपातकालीन
टोल फ्री सूचना रिपोर्ट पर्ची पर्चा जांच जाँच बिल रसीद सारांश डिस्चार्ज फाइल फ़ाइल
""".split())
HINDI_STOP = set("""
को है हैं से में की का के ने दिन बुखार नाम आयु वर्ष ग्राम तारीख पर्चा ओपीडी और मरीज़ मरीज पता मकान नं तहसील जिला
पिन मोबाइल महिला पुरुष पास पीछे सामने मंदिर मस्जिद गुरुद्वारे गुरुद्वारा भवन पंचायत स्कूल टंकी पानी बाज़ार बाजार
कॉलोनी नगर बस्ती चौक मोहल्ला मुहल्ला वार्ड गली सड़क रोड मार्ग कोतवाली काली माता हनुमान शिव जामा प्राथमिक विद्यालय दवा दवाई गोली दर्द पेट सिर खांसी
उल्टी दस्त कमजोरी सांस रोज़ रोज सुबह शाम रात दोपहर खाना बाद पहले साथ लिए लिया दिया गया गई हुआ हुई था थी थे
कर करें करना रहा रही रहे आई आया आए आये गई गया गए बोला बोली बताया बताई कहा जांच रिपोर्ट अस्पताल डॉक्टर डॉ नर्स वार्ड बिस्तर भर्ती छुट्टी निदान इलाज सलाह समीक्षा
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
    if not re.match(r"^[A-Za-z\u00C0-\u024F'’]+(?:-[A-Z][A-Za-z\u00C0-\u024F'’]*)*$", t):
        return False
    low = t.lower()
    if "-" in t and any(p.lower() in gz.NON_NAME_WORDS for p in t.split("-")):
        return False
    if low in gz.NON_NAME_WORDS or low in gz.ORG_WORDS or low in gz.DISTRICTS:
        return False
    if t[0].isupper():
        return True
    return False


def is_initial(tok: str) -> bool:
    return bool(re.match(r"^[A-Z]\.?$", tok))


# ------------------------------------------------------------------ identifier patterns
SEP = r"[\s\-./]?"
RE_EMAIL = re.compile(r"(?<![a-z0-9._%+\-])[a-z0-9][a-z0-9._%+\-]{0,63}@[a-z0-9\-]{1,63}(?:\.[a-z0-9\-]{1,63}){1,8}")
RE_EMAIL_OBF = re.compile(r"(?<![a-z0-9._])[a-z0-9][a-z0-9._%+\-]{0,63}\s*[\[(]\s*at\s*[\])]\s*[a-z0-9\-]{1,63}(?:\s*(?:[\[(]\s*dot\s*[\])]|\.)\s*[a-z0-9\-]{1,63}){1,4}")
RE_ABHA_ADDR = re.compile(r"(?<![a-z0-9._])[a-z0-9][a-z0-9._]{2,63}@(?:abdm|sbx|ndhm|abha)\b")
RE_ABHA = re.compile(r"(?<![\d])\d{2}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}(?![\d])|(?<![\d])\d{14}(?![\d])")
RE_VID = re.compile(r"(?<![\d.])\d{4}([\s\-.]?)\d{4}\1\d{4}\1\d{4}(?![\d])")
RE_AADHAAR = re.compile(r"(?<![\d.])[2-9]\d{3}([\s\-.]?)\d{4}\1\d{4}(?![\d])")
RE_AADHAAR_MASKED = re.compile(r"(?<![a-z0-9])(?:[x*]{4}[\s\-.]?){2}\d{4}(?!\d)|(?<![a-z0-9])[x*]{8}\d{4}(?!\d)")
RE_PAN = re.compile(r"(?<![a-z0-9])[a-z]{5}\d{4}[a-z](?![a-z0-9])")
RE_PHONE = re.compile(
    r"(?<![\d+])(?:\(?(?:\+|00)?91\)?[ .\-]?|\(0\)[ ]?|0)?\(?[6-9](?:(?:[ .\-]|\)[ ]?|[ ]?\()?\d){9}(?![\d])"
)
# other Indian identifiers (shapes, not labels, so they are found in any context)
RE_UPI = re.compile(r"(?<![a-z0-9._%+\-])[a-z0-9][a-z0-9._\-]{1,63}@[a-z]{2,32}(?![a-z0-9.@])")
RE_DL = re.compile(r"(?<![a-z0-9])[a-z]{2}[ \-]?\d{2}[ \-]?(?:19|20)\d{2}[ \-]?\d{7}(?![a-z0-9])")
RE_VEHICLE = re.compile(r"(?<![a-z0-9])[a-z]{2}[ \-]?\d{1,2}[ \-]?[a-z]{1,3}[ \-]?\d{4}(?![a-z0-9])")
RE_PASSPORT = re.compile(r"(?<![a-z0-9])[a-z][1-9]\d{6}(?![a-z0-9])")
RE_EPIC = re.compile(r"(?<![a-z0-9])[a-z]{3}\d{7}(?![a-z0-9])")
RE_IFSC = re.compile(r"(?<![a-z0-9])[a-z]{4}0[a-z0-9]{6}(?![a-z0-9])")
RE_LONGNUM = re.compile(r"(?<![\d.])\d{9,18}(?![\d.])")
RE_LANDLINE = re.compile(r"(?<![\d+])(?:\+91[ \-]?|0)\d{2,4}[ \-]\d{6,8}(?!\d)")
RE_PHONE_INTL = re.compile(r"(?<![\d+])\+(?!91)\d{1,3}[ \-.]?\(?\d{1,4}\)?(?:[ \-.]?\d){6,10}(?!\d)")
RE_PHONE_MASKED = re.compile(r"(?<![a-z0-9])[6-9]\d[x*]{6}\d{2}(?![a-z0-9])|(?<![a-z0-9])[6-9]\d{1,3}[x*]{4,7}\d{1,4}(?![a-z0-9])")
RE_INSURANCE = re.compile(
    r"(?<![a-z0-9])(?:pmjay|abpmjay|ab-pmjay|ayushman|pol|policy|ins|claim|cghs|esic)[\-/ ]?(?:[a-z]{2}[\-/])?\d[\d\-/]{5,}\d(?![\d])"
)
# hospital identifiers: PREFIX[sep]digits[sep digits]; prefix 1-6 letters
RE_MRN = re.compile(
    r"(?<![a-z0-9])(?:[a-z]{1,6}[\-/ ]?)?(?:\d{2,4}[\-/])?\d{4,8}(?:[\-/]\d{2,8})?(?![a-z0-9])"
)
RE_MRN_ALNUM = re.compile(r"(?<![a-z0-9])[a-z]{2,6}[\-/.:]?\d{2,4}[\-/.:]\d{3,8}(?![a-z0-9])|(?<![a-z0-9])[a-z]{2,6}\d{5,8}(?![a-z0-9])|(?<![a-z0-9])[a-z]{2,6}[\-/]\d{4,8}(?![a-z0-9])|(?<![a-z0-9])[a-z]{2,5}\d{4}[\-/]\d{4,8}(?![a-z0-9])|(?<![a-z0-9])[a-z]{2,5}[\-/][a-z]{2,4}[\-/]\d{4,8}(?![a-z0-9])")
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
DOB_LABELS = re.compile(r"(?i)(?<![a-z])(dob|d\.\s*o\.\s*b\.?|date\s*of\s*birth|birth\s*date|born\s*on|janm\s*tithi|जन्म\s*(?:तिथि|दिनांक|तारीख)?)(?:\s*[/&]\s*age)?\s*[:\-–=]?\s*")

RELATION_RE = re.compile(
    r"(?<![A-Za-z])(S\s*/\s*[Oo]|D\s*/\s*[Oo]|W\s*/\s*[Oo]|C\s*/\s*[Oo]|H\s*/\s*[Oo]|F\s*/\s*[Oo]|M\s*/\s*[Oo]|B\s*/\s*[Oo]|Son\s+of|Daughter\s+of|Wife\s+of|Husband\s+of|Father\s+of|Mother\s+of|"
    r"Care\s+of)\b\.?\s*:?\s*|(पुत्र|पुत्री|पत्नी|पति|सुपुत्र|सुपुत्री)\s*(?:श्री\s*)?:?\s*"
)
VERB_CTX = re.compile(
    r"(?i)\b(called\s+by|raised\s+by|witnessed\s+by|brought\s+by|accompanied\s+by|informed\s+by|signed\s+by|"
    r"collected\s+by|received\s+from|consent\s+(?:given|signed)\s+by|report\s+of|on\s+behalf\s+of|"
    r"attendant|relative|husband|wife|son|daughter|father|mother|brother|sister)\s+(?:is\s+|named\s+|mr\.?\s+|mrs\.?\s+)?"
)
GENERIC_LABEL = re.compile(r"(?:^|(?<=[\n;,.|]))\s*([A-Za-z][A-Za-z'’ &/()]{1,30}?|[\u0900-\u097F][\u0900-\u097F ]{0,20}?)(?:\s*(?:no\.?\s*)?#?\d{1,2})?\s*(?:[:=]|\s[-–]\s|[-–](?=\s))\s*", re.M)
NAME_WORD = re.compile(r"(?<![a-z])(name|naam|nam|नाम)(?![a-z])")
PATIENT_ROLE_WORD = re.compile(r"(?<![a-z])(patient|pt|beneficiary|insured|member|client|rogi|mareez|mariz|रोगी|मरीज़|मरीज|applicant|claimant|subscriber|holder|proband)(?![a-z])")
REL_ROLE_WORD = re.compile(r"(?<![a-z])(attendant|relative|guardian|abhibhavak|अभिभावक|परिजन|parijan|kin|nok|husband|wife|father|mother|son|daughter|spouse|parent|nominee|emergency|contact person|escort|bystander|pati|patni|pita|mata)(?![a-z])")
ROLE_WORD = re.compile(PATIENT_ROLE_WORD.pattern + "|" + REL_ROLE_WORD.pattern + r"|(?<![a-z])(contacts?|informants?|callers?|witness(?:es)?|donors?|recipients?|visitors?|referred by patient)(?![a-z])")
CLINICAL_LABEL = re.compile(r"(?<![a-z])(diagnosis|advice|adv|rx|complaint|complaints|c/o|history|h/o|k/c/o|ward|bed|consultant|doctor|dr|surgeon|department|dept|test|result|investigation|impression|plan|procedure|medication|medicine|drug|dose|frequency|vitals|bp|pulse|temp|spo2|weight|height|bmi|remarks?|notes?|course|treatment|status|hospital|unit|specimen|sample|lab|room|date|time|age|sex|gender|address|village|district|tehsil|state|pin|mobile|phone|email|uhid|mrn|id|no|number)(?![a-z])")
ROLE_NOUN = re.compile(r"(?<![A-Za-z])(?i:patient|pt\.?|mareez|mariz|rogi|beneficiary|visitor|neighbou?r|caretaker|attendant|escort|bystander)\s+(?=[A-Z\u0900-\u097F])"
                       r"|(?:मरीज़|मरीज|रोगी|पड़ोसी|पड़ोसन|परिजन|रिश्तेदार|परिचारक|मित्र|सहेली|दोस्त)\s+(?=[\u0900-\u097F])")
# "(Tsering Dolma, 41F)", "(Ramesh, 58 M)": a name sharing brackets with age and sex
NAME_AGE_BRACKET = re.compile(r"\(\s*((?:[A-Z][a-z'\-]+\.?\s+){0,3}[A-Z][a-z'\-]+)\s*,\s*\d{1,3}\s*(?:y|yrs?|years?)?\s*/?\s*[MF]\b")
# "spouse (Meenakshi)", "son (Rakesh Kumar)": a relation word with the name in brackets
REL_BRACKET_NAME = re.compile(r"(?i:\b(?:spouse|wife|husband|son|daughter|father|mother|brother|sister|guardian|nephew|niece|uncle|aunt|"
                              r"son-in-law|daughter-in-law|bhai|behen|beta|beti|pati|patni))\s*\(\s*((?:[A-Z][a-z'\-]+\s+){0,2}[A-Z][a-z'\-]+)\s*\)")
AGE_SEX_BRACKET = re.compile(r"\(\s*(?:[MF]\s*/\s*\d{1,3}|\d{1,3}\s*(?:Y|Yrs?|years?)?\s*/\s*[MF])\s*\)")
SUBJ_VERB = re.compile(r"(?:^|(?<=[.;!\n]\s)|(?<=^\s))([A-Z][a-z]{2,})\s+(?:called|phoned|rang|came|visited|paid|signed|informed|counselled|enquired|requested|refused|consented|agreed|left|brought)\b", re.M)
OBJ_VERB = re.compile(r"(?i:\b(?:told|informed|called|phoned|counselled|counseled|asked|briefed|advised|explained\s+to))\s+(?=[A-Z])")
GENERIC_ID_LABEL = re.compile(r"(?i)(?<![a-z])((?:[a-z][a-z.]{0,12}\s){0,2}[a-z][a-z.]{0,12})\s*(?:no\.?|number|num|id|#|code|card|policy|ref\.?|reference|account|a/c)(?![a-z])\s*[:#\-–=]?\s*")
NON_ID_LABEL = re.compile(r"(?i)(?<![a-z])(opd|visit|bill|invoice|receipt|sample|lab|test|batch|lot|package|pkg|loinc|icd|snomed|trip|ticket|order|bed|ward|room|unit|page|ref\.?\s*range|phone|mobile|mob|contact|cell|tel|pin|zip|postal|house|h|gali|plot|flat|serial|sr|s|sl)$")
PLACE_MARKER_ANY = re.compile(r"(?<![A-Za-z])(?:Gram\s+Panchayat|Panchayat|Thana|Native\s+of|[Rr]\s*/\s*[Oo]|ग्राम\s+पंचायत|थाना|निवासी)\s*[:\-]?\s*(?=[A-Z\u0900-\u097F])")
PLACE_MARKER_ADDR = re.compile(r"(?<![A-Za-z\u0900-\u097F])(?:P\.?\s?O\.?|Post|P\.?\s?S\.?|Block|Tola|Purwa|Nagla|Majra|डाकघर|पोस्ट|पो\.|ब्लॉक|टोला|पुरवा|नगला|मजरा)\s*[:\-]?\s*(?=[A-Z\u0900-\u097F])")
HINDI_FUNC = {"के", "की", "का", "को", "में", "से", "है", "हैं", "पर", "और", "ने", "था", "थी", "जिला", "तहसील", "पिन"}
GALI_RE = re.compile(r"(?i)(?<![a-z])gali\s*(?:no\.?|number)?\s*\d{1,4}|गली\s*(?:नं\.?|नंबर)?\s*\d{1,4}")
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
    r"(?:[A-Z][A-Za-z'’]+\s+){0,4}(?:Hospitals?|Clinic|Pathology|Diagnostics|Diagnostic|Laboratory|Labs?|Sadan|Centre|Center|"
    r"University|Institute|Sansthan|Medical\s+University|"
    r"Nursing\s+Home|Medical\s+College|Trust|PHC|CHC)\b(?:\s*,?\s*[A-Z][a-z]+)?"
    r"|(?:District|Community|Primary)\s+(?:Hospital|Health\s+Centre)\s+[A-Z][a-z]+"
)
CLINICAL_WARD = re.compile(r"(?i)\bward\s*(?:no\.?\s*)?\d{1,2}\s*\((?:[a-z ]+)\)|\bward\s*/\s*bed\b|\bward\s*\d{1,2}\s*/\s*bed\s*\d+|\bbed\s*(?:no\.?\s*)?\d+")
COMPLAINT_RE = re.compile(r"(?i)\b(?:k\s*/\s*c\s*/\s*o|h\s*/\s*o|c\s*/\s*o)\b\s*:?\s*(?=[a-z(]|no\b|known)|\bk/c/o\b")
EPONYM_RE = re.compile(r"(?i)\b(?-i:(?:[A-Z][a-z]+[\s\-]+){0,2})[A-Z][a-z]+(?:'s|’s|s)?\s+(?:disease|syndrome|palsy|sarcoma|lymphoma|anomaly|"
                       r"phenomenon|ulcer|test|sign|fracture|nodule|node|reflex|manoeuvre|maneuver|triad|tumou?r|cyst|"
                       r"hernia|gland|duct|operation|procedure|classification|criteria|score|scale|spots|cells|bodies)\b")
# a brand or generic drug written straight before its dose ("Syndopa 110 mg", "Telma 40 mg"): medicine, not a name
DRUG_DOSE = re.compile(r"\b[A-Z][A-Za-z]+(?:[\-\s][A-Z0-9][A-Za-z0-9]*)?\s+\d+(?:\.\d+)?(?:\s*/\s*\d+(?:\.\d+)?)?\s*"
                       r"(?:mg|mcg|µg|ug|gm|g|ml|mL|IU|iu|units?|U)\b(?!\s*/\s*(?:dL|L|kg|min|hr)\b)")
# the word for "name" in other Indian scripts, then the value in that script (up to 4 words)
_OS = {"\u0980-\u09FF": "নাম", "\u0A00-\u0A7F": "ਨਾਮ|ਨਾਂ", "\u0A80-\u0AFF": "નામ", "\u0B00-\u0B7F": "ନାମ",
       "\u0B80-\u0BFF": "பெயர்", "\u0C00-\u0C7F": "పేరు", "\u0C80-\u0CFF": "ಹೆಸರು", "\u0D00-\u0D7F": "പേര്"}
OTHER_SCRIPT_NAME = re.compile("|".join(
    rf"(?:{w})[{r}]*\s*[:\-–]\s*((?:[{r}]+[ \t]+){{0,3}}[{r}]+)" for r, w in _OS.items()))
# salutations: "Dear Mr. Harish", "प्रिय सीमा", "आदरणीय श्री ..."
SALUTATION = re.compile(r"(?:\bDear|प्रिय|आदरणीय)\s+")
SALUTATION_NOT_NAME = re.compile(r"(?i)(?:sir|madam|ma'?am|doctor|dr|team|colleague|all|patient|parents?|customer|member|friends?|"
                                 r"महोदय|महोदया|सर|डॉक्टर|डॉ|साहब|मित्रों|साथियों)\b")

# ------------------------------------------------------------------ address parts
HOUSE_RE = re.compile(
    r"(?i)(?<![a-z])(?:h\.?\s*no\.?|house\s*(?:no\.?)?|makan\s*(?:no\.?|number)?|flat\s*(?:no\.?)?|plot\s*(?:no\.?)?|door\s*no\.?|"
    r"qtr\.?\s*no\.?|quarter\s*no\.?|मकान\s*(?:नं\.?|नंबर|संख्या)?|म\.\s*नं\.?|घर\s*(?:नं\.?|नंबर)?)\s*[:\-]?\s*\d+[a-z]?(?:\s*[/-]\s*\d+[a-z]?)?"
)
LOCALITY_RE = re.compile(
    r"(?:(?i:mohalla|mohallah|muhalla|mohala|mohalla:|locality|colony|sector|ward\s*no\.?|ward)\s*[:\-]?\s*(?:\d{1,3}\b|(?:[A-Z][a-z]+\s*){1,3}))"
    r"|(?:मोहल्ला|मुहल्ला|वार्ड)\s*(?:नं\.?\s*)?(?:\d{1,3}|[\u0900-\u097F]+(?:\s+[\u0900-\u097F]+){0,2})"
)
# "<Shastri> Nagar", "<Sunshine> Apartments": a sub-district locality named by its suffix (used in address context)
LOCALITY_SUFFIX_RE = re.compile(r"\b(?:[A-Z][a-z]+\s+){1,3}(?:Nagar|Colony|Vihar|Enclave|Puram|Bagh|Ganj|Pura|Apartments?|"
                                r"Residency|Society|Heights|Towers?|Complex|Basti|Layout|Extension|Kunj|Niwas|Sadan|Market|"
                                r"Lines|Town|Chowk|Mohalla|Tola|Khera|Patti)\b")
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
RE_TEXTDATE = re.compile(r"(?i)(?<![a-z\d])(\d{1,2})(?:st|nd|rd|th)?\s+(?:of\s+)?(" + _MON + r")\.?,?(?:\s+(\d{4}))?(?![a-z])")
RE_ROMANDATE = re.compile(r"(?<![\w])(\d{1,2})[./\- ](XII|XI|X|IX|VIII|VII|VI|V|IV|III|II|I)[./\- ](\d{4}|\d{2})(?![\w])")
RE_MONDATE = re.compile(r"(?i)(?<![a-z\d])(\d{1,2})[\-/ ](" + _MON + r")[\-/ ,]+(\d{4}|\d{2})(?![\d])")
RE_YMD = re.compile(r"(?<![\d])(\d{4})[/.](\d{1,2})[/.](\d{1,2})(?![\d])")
RE_HINDIDATE = re.compile(r"(?<![\d])(\d{1,2})\s+(जनवरी|फ़रवरी|फरवरी|मार्च|अप्रैल|अप्रेल|मई|जून|जुलाई|अगस्त|सितंबर|सितम्बर|अक्टूबर|अक्तूबर|नवंबर|नवम्बर|दिसंबर|दिसम्बर)\s+(\d{4})(?![\d])")
RE_COMPACT = re.compile(r"(?<![\d])((?:19|20)\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(?![\d])")
RE_TEXTDATE2 = re.compile(r"(?i)(?<![a-z\d])(" + _MON + r")\.?\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+(\d{4})(?![\d])")
RE_AGE = re.compile(
    r"(?i)(?<![\d\-/.x])(?<!x )(\d{1,3})\s*(?:yrs?|years?|y)\.?(?=\s*/\s*(?:[mf]\b|male|female)|\s*,?\s*(?:male|female|m\b|f\b|old\b))"
    r"|(?<![\d\-/.:])(\d{1,3})\s*/\s*(?=[mf]\b|male\b|female\b)"
    r"|(?<![\d])(\d{1,3})\s*(?=वर्ष|साल)"
    r"|(?i:\b(?:age|aged)\b\s*[:\-]?\s*(?:about|approx\.?|approximately|around|nearly|~)?\s*)(\d{1,3})(?![\d/.\-])"
    r"|(?:आयु|उम्र)\s*[:\-]?\s*(\d{1,3})"
    r"|(?i:\b(?:umr|umar|aayu|ayu)\b\s*[:\-]?\s*)(\d{1,3})(?!\d)"
    r"|(?<![\d\-/.])(\d{1,3})(?=[\s\-]*(?i:years?|yrs?)[\s\-]+(?i:old)\b)"
    r"|(?<![\d\-/.])(\d{1,3})(?=\s*(?i:y/o|yo)\b)"
    r"|(?<=[MF]/)(\d{1,3})(?=\s*\))"
    r"|(?<=\()(\d{1,3})(?=\s*(?i:yrs?|years?|y)\s*\))"
)


HONORIFIC_RE = re.compile(r"(?<![\w\u0900-\u097F])(" + "|".join(sorted((re.escape(h) for h in gz.HONORIFIC_SUFFIX), key=len, reverse=True)) + r")(?![\w\u0900-\u097F])", re.I)


SOFT_OCC_LABEL = re.compile(r"(?i)(?<![a-z])(?:occupation|profession|pesha|vyavsay|kaam|naukri|व्यवसाय|पेशा)\s*[:\-–]\s*")
SOFT_OCC_PHRASE = re.compile(r"(?i)\b(?:works as an?|working as an?|by profession an?|is an?|was an?)\s+((?:retired\s+)?(?:school\s+)?"
                             r"(?:teacher|farmer|kisan|driver|tailor|carpenter|mason|labou?rer|mazdoor|shopkeeper|clerk|"
                             r"constable|soldier|army jawan|nurse|electrician|plumber|weaver|potter|barber|rickshaw puller|"
                             r"vendor|priest|maulvi|granthi|student|engineer|lawyer|accountant|peon|guard|chowkidar))\b")
SOFT_EMPLOYER = re.compile(r"(?i)\b(?:works at|working at|works in|employed (?:at|with|by)|employee of|employer\s*[:\-]|"
                           r"naukri karta hai|kaam karta hai|kaam karti hai)\s+(?:the\s+)?(?=[A-Z])")
SOFT_SCHOOL = re.compile(r"(?:[A-Z][a-z]+\s+){1,4}(?:Public School|School|Vidyalaya|Vidya Mandir|Inter College|Degree College|"
                         r"Shiksha Niketan|Madrasa|Gurukul|Convent)\b|(?:[\u0900-\u097F]+\s+){1,3}(?:विद्यालय|पाठशाला|मदरसा)")
SOFT_FESTIVAL = re.compile(r"(?i)\b(?:on|during|before|after|since|around|se pehle|ke baad|ke din|par)\s+((?:the\s+)?"
                           r"(?:holi|diwali|deepawali|eid(?:-ul-(?:fitr|adha))?|bakrid|chhath|navratri|dussehra|dasara|"
                           r"raksha bandhan|rakhi|karva chauth|janmashtami|makar sankranti|lohri|guru purab|gurpurab|"
                           r"christmas|muharram|ganesh chaturthi|teej|shivratri)(?:\s+festival)?)\b"
                           r"|\b((?:holi|diwali|eid|chhath|navratri|dussehra|rakhi)\s+(?:ke din|se pehle|ke baad|par))\b")
_OCC_CLASS = [(r"teacher|lecturer|professor|student|principal", "education"), (r"farmer|kisan|agricultur", "agricultural work"),
              (r"driver|rickshaw|transport|conductor", "transport"), (r"labou?rer|mazdoor|mason|carpenter|plumber|electrician|"
              r"weaver|potter|tailor|barber", "manual work"), (r"shopkeeper|vendor|business|trader", "trade"),
              (r"constable|soldier|jawan|guard|chowkidar|police", "security services"), (r"nurse|doctor|health", "health work"),
              (r"clerk|peon|accountant|engineer|lawyer|officer", "office work"), (r"priest|maulvi|granthi|pujari", "religious work")]


def occupation_class(occ: str) -> str:
    low = occ.lower()
    for pat, cls in _OCC_CLASS:
        if re.search(pat, low):
            return cls
    return "[OCCUPATION]"


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
        if is_initial(tok) or low in ("md", "mohd", "mohd.", "km", "smt", "shri", "sri", "sh", "mst", "master", "baby", "late", "kumari") \
                or bare in ("श्री", "श्रीमती", "स्व", "स्व.", "कुमारी", "सुश्री"):
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
        if tok.endswith(".") and not is_initial(tok) and low not in ("md", "mohd", "km", "smt", "shri", "sri", "sh", "mst"):
            break                    # "Kamal Rajput. C/O fever": a full stop after a word ends the name
        if i < n and text[i] in ",;:()[]|\n0123456789":
            break
    if start is None:
        return pos, pos, []
    # trim trailing initials-only
    return start, end, toks


def _place_run(text: str, pos: int) -> tuple:
    """Up to 3 capitalised / Devanagari words after a place marker. Unlike a name run, district-like words
    are allowed (villages are often named after districts); a nested marker word is skipped over."""
    m = re.compile(r"[ \t]*((?:(?:Gram\s+Panchayat|Panchayat|ग्राम\s+पंचायत)\s+)?)"
                   r"((?:[A-Z][A-Za-z'’]+|[\u0900-\u0963\u0970-\u097F]+)(?:[ \t]+(?:[A-Z][A-Za-z'’]+|[\u0900-\u0963\u0970-\u097F]+)){0,2})").match(text, pos)
    if not m:
        return pos, pos, []
    words = []
    for w in m.group(2).split():
        if w.lower() in gz.NON_NAME_WORDS - VILLAGE_OK or w in HINDI_FUNC:
            break
        words.append(w)
    if not words:
        return pos, pos, []
    st = m.start(2)
    return st, st + len(" ".join(words)), words


VILLAGE_OK = {"kalan", "khurd", "nagar", "pur", "ganj", "bazar", "colony", "basti"}


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
        self._generic_labels(text, f, spans)
        self._other_script_names(text, spans)
        self._generic_ids(text, f, spans)
        self._honorifics(text, f, spans)
        self._verbs(text, f, spans)
        addr = address_ctx or bool(ADDR_LABELS.search(text)) or bool(re.search(
            r"(?i)\btehsil\b|\bdistt?\b|\bdistrict\b|\bvill(?:age)?\b|\bpost\b|\bp\.o\.|\bthana\b|\bblock\b|तहसील|जिला|ग्राम|पोस्ट|पो\.|थाना|ब्लॉक", text))
        self._address(text, f, spans, addr)
        self._lexicon(text, f, spans)
        self._gazetteer(text, f, spans)
        self._model_names(text, f, spans)
        self._soft(text, f, spans)
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
        for m in DRUG_DOSE.finditer(t):
            w = m.group(0).split()[0]
            if not gz.is_known_name_token(w) or not re.search(r"(?i)\b(?:mr|mrs|ms|shri|smt|w/o|s/o|d/o)\b", t[max(0, m.start() - 12):m.start()]):
                spans.append(Span(m.start(), m.start() + len(w), "PROTECT", value="drug"))
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
        for rx, kind in ((RE_EMAIL, "EMAIL"), (RE_EMAIL_OBF, "EMAIL"), (RE_ABHA_ADDR, "ABHA_ADDR")):
            for m in rx.finditer(f):
                spans.append(Span(m.start(), m.end(), kind, value=m.group(0)))
        for m in RE_ABHA.finditer(f):
            spans.append(Span(m.start(), m.end(), "ABHA", value=re.sub(r"\D", "", m.group(0))))
        for m in RE_VID.finditer(f):         # Aadhaar Virtual ID (16 digits)
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
        for m in RE_LANDLINE.finditer(f):     # STD landlines: 0522 2234567, +91-522-2234567
            spans.append(Span(m.start(), m.end(), "PHONE", value=re.sub(r"\D", "", m.group(0))[-10:]))
        for m in RE_PHONE_INTL.finditer(f):     # non-Indian numbers (+977, +44 ...)
            spans.append(Span(m.start(), m.end(), "PHONE", value=re.sub(r"\D", "", m.group(0))[-10:]))
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
            vm = re.compile(r"[A-Za-z]{0,6}[\-/ ]?\d{2,8}(?:[\- /]\d{2,8}){1,5}|[A-Za-z]{0,6}[\-/ ]?[\dA-Za-z][\w\-/]{3,24}").match(f, m.end())
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

    def _other_script_names(self, t, spans):
        """'<name-word>: <run>' in Bengali, Gurmukhi, Gujarati, Odia, Tamil, Telugu, Kannada, Malayalam."""
        for m in OTHER_SCRIPT_NAME.finditer(t):
            g = next(i for i in range(1, len(m.groups()) + 1) if m.group(i))
            spans.append(Span(m.start(g), m.end(g), "NAME", role="", value=m.group(g), meta={"src": "label"}))

    def _generic_labels(self, t, f, spans):
        """'<short label><sep><name-shaped run>' where the label holds a name or person-role word."""
        for m in GENERIC_LABEL.finditer(t):
            label = m.group(1).strip()
            low = label.lower()
            if re.search(r"[a-z]{4}s$", low) and not re.search(r"(?:ss|us|is)$", low):
                low = low[:-1]          # plural labels ("Attendants:", "Witnesses:") read like the singular
            named = bool(NAME_WORD.search(low))
            if CLINICAL_LABEL.search(low) and not named:
                continue              # "Diagnosis:", "Age:" never start a name; "Name & Age:" does
            role = bool(ROLE_WORD.search(low))
            if not (named or role):
                continue
            s0, e0, toks = _name_run(t, m.end(), allow_lower=named, max_tokens=4)
            if not toks:
                continue
            r = "relative" if REL_ROLE_WORD.search(low) else ("patient" if named or PATIENT_ROLE_WORD.search(low) else "other")
            spans.append(Span(s0, e0, "NAME", role=r, value=" ".join(toks), meta={"src": "label"}))
            # "Visitors: Raju, Pinky and Bablu": a list of names after one label
            for _ in range(6):
                lm = re.compile(r"\s*(?:,|&|\band\b|\baur\b|और)\s*(?:and\s+)?").match(t, e0)
                if not lm:
                    break
                s1, e1, toks1 = _name_run(t, lm.end(), allow_lower=False, max_tokens=3)
                if not toks1 or s1 != lm.end():
                    break
                spans.append(Span(s1, e1, "NAME", role=r, value=" ".join(toks1), meta={"src": "label"}))
                e0 = e1
        for m in SALUTATION.finditer(t):
            if SALUTATION_NOT_NAME.match(t, m.end()):
                continue
            s0, e0, toks = _name_run(t, m.end(), allow_lower=False, max_tokens=3)
            if toks:
                spans.append(Span(s0, e0, "NAME", role="", value=" ".join(toks), meta={"src": "label"}))
        # "<NAME RUN> (F/47)", "Hmar, Lalrinpuii (47Y/F)": a name run right before an age/sex bracket
        for m in AGE_SEX_BRACKET.finditer(t):
            left = t[max(0, m.start() - 60):m.start()]
            mm = re.search(r"((?:[A-Z][A-Za-z'’]+|[A-Z]{2,})(?:,?\s+(?:[A-Z][A-Za-z'’]+|[A-Z]{2,})){0,3})\s*$", left)
            if mm:
                words = [w.strip(",") for w in mm.group(1).split()]
                words = [w for w in words if w.lower() not in ("patient", "pt", "name")]
                if words and all(is_name_token(w) for w in words):
                    txt = mm.group(1)
                    off = txt.find(words[0])
                    st = m.start() - len(left) + mm.start(1) + off
                    spans.append(Span(st, m.start() - len(left) + mm.end(1), "NAME", role="patient",
                                      value=" ".join(words), meta={"src": "age-bracket"}))
        for rx, role in ((NAME_AGE_BRACKET, "patient"), (REL_BRACKET_NAME, "relative")):
            for m in rx.finditer(t):
                words = m.group(1).split()
                if all(is_name_token(w.rstrip(".")) for w in words) and not re.match(r"(?i)dr\b", words[0]):
                    spans.append(Span(m.start(1), m.end(1), "NAME", role=role, value=m.group(1), meta={"src": "age-bracket"}))
        # Hinglish: "Rogi ka naam Bhagwandas hai", "uska naam Ramesh hai", "naam: ..." handled above
        for m in re.finditer(r"(?i)\b(?:ka|ki|ke|uska|uski|unka|iska|mera|mero)\s+naam\s+(?:hai\s+)?|का\s+नाम\s+(?:है\s+)?", t):
            s0, e0, toks = _name_run(t, m.end(), allow_lower=False, max_tokens=3)
            if toks:
                spans.append(Span(s0, e0, "NAME", role="", value=" ".join(toks), meta={"src": "label"}))
        # JSON-shaped text inside a note or log: "name": "Tsering Dolma"
        for m in re.finditer(r"[\"']([A-Za-z_ ]{2,30})[\"']\s*:\s*[\"']", t):
            low = m.group(1).lower().replace("_", " ")
            if (NAME_WORD.search(low) or ROLE_WORD.search(low)) and not CLINICAL_LABEL.search(low.replace("name", "")):
                s0, e0, toks = _name_run(t, m.end(), allow_lower=True, max_tokens=4)
                if toks:
                    spans.append(Span(s0, e0, "NAME", role="", value=" ".join(toks), meta={"src": "label"}))
        # role noun directly before a name: "patient Selvi informed", "मरीज़ श्यामलाल को बुखार"
        from .namemodel import is_name as _is_name
        for m in ROLE_NOUN.finditer(t):
            s0, e0, toks = _name_run(t, m.end(), max_tokens=3)
            strong = not re.match(r"(?i)(?:patient|pt|mareez|mariz|rogi|beneficiary|मरीज़|मरीज|रोगी)", m.group(0))
            if toks and (strong or all(gz.is_known_name_token(x) or _is_name(x) for x in toks)):
                spans.append(Span(s0, e0, "NAME", role="patient", value=" ".join(toks), meta={"src": "role-noun"}))
        # communication verbs: "<Name> called/phoned/visited ...", "told/informed <Name>"
        from .namemodel import is_name
        for m in SUBJ_VERB.finditer(t):
            w = m.group(1)
            if is_name_token(w) and (gz.is_known_name_token(w) or is_name(w)):
                spans.append(Span(m.start(1), m.end(1), "NAME", role="other", value=w, meta={"src": "verb"}))
        for m in OBJ_VERB.finditer(t):
            s0, e0, toks = _name_run(t, m.end(), max_tokens=3)
            if toks and all(gz.is_known_name_token(x) or is_name(x) for x in toks):
                spans.append(Span(s0, e0, "NAME", role="other", value=" ".join(toks), meta={"src": "verb"}))

    def _generic_ids(self, t, f, spans):
        """'<label ending in No/Number/ID/#/Code><sep><token with digits>' -> identifier."""
        for m in GENERIC_ID_LABEL.finditer(t):
            head = m.group(1).lower()
            if NON_ID_LABEL.search(head):
                continue
            vm = re.compile(r"(?:[A-Za-z]{1,3} (?=\d))?\d{2,8}(?:[ /\-]\d{2,8}){1,5}(?![\w])|(?:[A-Za-z]{1,3} (?=\d))?[A-Za-z0-9][A-Za-z0-9/\-]{3,30}").match(t, m.end())
            if not vm:
                continue
            val = vm.group(0).rstrip("-/")
            nd = sum(c.isdigit() for c in val)
            if nd >= 4 or (nd >= 3 and re.search(r"[A-Za-z]", val) and len(val) >= 6):
                spans.append(Span(vm.start(), vm.start() + len(val), "MRN", value=val, meta={"src": "id-label"}))

    def _relations(self, t, f, spans):
        for m in RELATION_RE.finditer(t):
            marker = (m.group(1) or m.group(2) or "").replace(" ", "").lower()
            after = t[m.end():m.end() + 40]
            if marker in ("c/o", "careof", "h/o"):
                # "C/O fever" is a complaint; "C/O Ramesh" is care-of a relative.
                tm = TOKEN_RE.match(after)
                if not tm:
                    continue
                first = tm.group(0).rstrip(".")
                if first.lower() in gz.NON_NAME_WORDS or not (first[0].isupper() or re.match(r"[\u0900-\u097F]", first)):
                    continue
                if marker == "h/o" and (first.isupper() and len(first) <= 5 or not is_name_token(first)):
                    continue          # H/o DM, H/o TB, H/o fall: history, not "husband of"
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
            # walk back over up to 3 name tokens, inside a bounded window (linear time on any input)
            base = max(0, m.start() - 80)
            seq = []
            cur = t[base:m.start()]
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
                seq.insert(0, (base + mm.start(1), base + mm.start(1) + len(tok)))
                cur = cur[:mm.start(1)]
                if re.search(r"(?i)\b(?:dr|doctor)\.?\s*$", cur):
                    seq = []
                    break
            if seq:
                if hon in ("beta", "beti", "baba", "uncle", "aunty") and len(seq) == 1:
                    from .namemodel import is_name
                    w = t[seq[0][0]:seq[0][1]]
                    if not (gz.is_known_name_token(w) or is_name(w)):
                        continue
                s, e = seq[0][0], seq[-1][1]
                spans.append(Span(s, e, "NAME", role="", value=t[s:e], meta={"src": "honorific"}))
        # prefix honorific: "Shri Ram Prasad", "Smt. Kamla"
        for m in re.finditer(r"(?i)(?<![a-z])(shri|sri|shree|smt|shrimati|srimati|kumari|km|mr|mrs|ms|janab|late|sh|mst|master|baby|श्रीमती|श्री|कुमारी|स्व)\.?\s+(?=[A-Z\u0900-\u097F])", t):
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
        for m in re.finditer(r"(?<![A-Za-z])((?:[A-Z][a-z]+\s+){0,1}[A-Z][a-z]{2,})[\s\-]+(?:ka|ki|ke)\s+(?i:tabiyat|tabiyet|tabeeyat|haalat|halat|bp|sugar|bukhar|pet|sar|report|dawai|dawa|ilaj|ilaaj|operation|condition|khana|neend|pulse|temp)\b", t):
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
        # "<नाम> 98765 43210" with no label in between (file names, contact lists): the Latin phone-adj rule's twin
        for m in re.finditer(r"((?:[ऀ-ॣ॰-ॿ]+\s+)?[ऀ-ॣ॰-ॿ]+)\s*[,:\-]?\s*(?=(?:\+91[\s\-]?)?[6-9]\d{4}\s?\d{5}(?!\d))", fold(t)):
            words = [w for w in m.group(1).split() if w not in HINDI_STOP and w not in DEVA_CONTACT_WORDS]
            if words and m.group(1).split()[-1] == words[-1]:
                st = m.start(1) + m.group(1).find(words[0])
                spans.append(Span(st, m.end(1), "NAME", role="other", value=" ".join(words), meta={"src": "deva-phone"}))
        # "<Name> (attendant, bed 12)"
        for m in re.finditer(r"\(\s*(?:attendant|relative|husband|wife|son|daughter|father|mother|guardian|visitor|caller|neighbou?r|friend|colleague|caretaker|employer|landlord|brother|sister|uncle|aunt|cousin|nephew|niece|grand(?:son|daughter|father|mother)|in-law)", t, flags=re.I):
            left = t[max(0, m.start() - 80):m.start()].rstrip()
            base = max(0, m.start() - 80)
            mm = re.search(r"((?:[A-Z][a-z]+\.?\s+){0,3}[A-Z][a-z]+)$", left)
            if mm:
                words = mm.group(1).split()
                while words and not is_name_token(words[0].rstrip(".")):
                    words.pop(0)              # "Visitor Tsungmerenla Imchen (neighbour)": drop the role word
                if words and all(is_name_token(x.rstrip(".")) for x in words):
                    st = base + mm.end(1) - len(" ".join(words))
                    spans.append(Span(st, base + mm.end(1), "NAME", role="relative", value=" ".join(words), meta={"src": "role"}))
        # chat sender "[30/05/26, 9:32 pm] Kamal Bhaiya:"
        for m in CHAT_SENDER.finditer(t):
            name = m.group(1).strip()
            if re.search(r"\d{6,}", name):
                continue
            spans.append(Span(m.start(1), m.start(1) + len(name), "NAME", role="relative", value=name, meta={"src": "chat"}))
        # "<Name> <phone>" or "<Name>, Mob. <phone>"
        for m in RE_PHONE.finditer(fold(t)):
            lb = max(0, m.start() - 80)              # bounded look-back keeps this linear
            left = t[lb:m.start()]
            mm = re.search(r"((?:[A-Z][a-z]+\s+){0,2}[A-Z][a-z]+)\s*(?:,|-|:)?\s*(?:\(?(?:mob(?:ile)?|ph(?:one)?|m)\.?\)?\s*(?:no\.?)?\s*[:\-]?\s*)?$", left)
            if mm:
                toks = mm.group(1).split()
                toks_ok = [x for x in toks if is_name_token(x)]
                if toks_ok and len(toks_ok) == len(toks) and (len(toks) >= 2 or gz.is_known_name_token(toks[0])):
                    if not re.search(r"(?i)\b(?:dr|doctor)\.?\s*$", left[:mm.start(1)]):
                        spans.append(Span(lb + mm.start(1), lb + mm.end(1), "NAME", role="other", value=mm.group(1), meta={"src": "phone-adj"}))

    def _address(self, t, f, spans, addr_ctx):
        for m in HOUSE_RE.finditer(t):
            spans.append(Span(m.start(), m.end(), "HOUSE", value=m.group(0)))
        for m in LOCALITY_RE.finditer(t):
            s = m.group(0)
            if re.match(r"(?i)ward|वार्ड", s):           # a ward number is clinical unless the text is an address
                tail = t[m.end():m.end() + 6]
                if not addr_ctx or re.match(r"\s*[\(/]", tail):
                    continue
            spans.append(Span(m.start(), m.end(), "LOCALITY", value=s.strip()))
        if addr_ctx:
            for m in LOCALITY_SUFFIX_RE.finditer(t):
                words = m.group(0).split()
                while len(words) > 2 and re.fullmatch(r"(?i)distt?|district|vill(?:age)?|tehsil|post|po|thana|block|near|opp|behind", words[0]):
                    words.pop(0)            # "Distt Ambedkar Nagar": the label word is not part of the place
                val = " ".join(words)
                if val.lower() in gz.DISTRICTS or re.match(r"(?i)(?:dr|doctor|hospital|distt?|district)\b", val):
                    continue
                st = m.end() - len(val)
                # a locality outranks a name found inside it ("Rajendra Nagar" is a place, not Rajendra)
                spans.append(Span(st, m.end(), "LOCALITY", value=val, meta={"prio": PRIORITY["NAME"] + 1}))
        for m in LANDMARK_RE.finditer(t):
            if not addr_ctx and not re.search(r"(?i)mandir|masjid|school|tanki|bhawan|gurudwara|church|chowk|temple|पास|पीछे|सामने", m.group(0)):
                continue
            spans.append(Span(m.start(), m.end(), "LANDMARK", value=m.group(0).strip()))
        for m in PIN_RE.finditer(f):
            before = t[max(0, m.start() - 20):m.start()]
            after = t[m.end():m.end() + 2]
            end_of_address = addr_ctx and re.match(r"\s*(?:[.,;)\n]|$)", after) is not None
            if addr_ctx and (re.search(r"[-–,]\s*$", before) or PIN_LABEL.search(before) or end_of_address) \
                    or PIN_LABEL.search(before):
                spans.append(Span(m.start(), m.end(), "PIN", value=re.sub(r"\D", "", m.group(0))))
        for m in PLACE_MARKER_ANY.finditer(t):                # Gram Panchayat X, Thana X, Native of X, r/o X
            s0, e0, toks = _place_run(t, m.end())
            if toks:
                spans.append(Span(s0, e0, "VILLAGE", value=" ".join(toks)))
        if addr_ctx:
            for m in PLACE_MARKER_ADDR.finditer(t):           # PO X, PS X, Block X, Tola X ... inside addresses
                s0, e0, toks = _place_run(t, m.end())
                if toks:
                    spans.append(Span(s0, e0, "VILLAGE", value=" ".join(toks)))
        if addr_ctx:
            for m in re.finditer(r"(?<![\w#])#\s?\d{1,5}[A-Za-z]?(?:/\d{1,4})?(?![\w])", t):
                spans.append(Span(m.start(), m.end(), "HOUSE", value=m.group(0)))
        for m in GALI_RE.finditer(t):
            spans.append(Span(m.start(), m.end(), "LOCALITY", value=m.group(0)))

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

    def _model_names(self, t, f, spans):
        """Lowest layer: 2-3 name-like tokens the trained scorer accepts, only on a line that also carries
        supporting context (age/sex, phone, ID or relation marker)."""
        from .namemodel import is_name
        support = re.compile(r"(?i)\b\d{1,3}\s*(?:yrs?|y)?\s*/\s*[mf]\b|वर्ष|\b[sdwc]\s*/\s*o\b|पुत्र|पत्नी|"
                             r"(?<!\d)[6-9]\d{9}(?!\d)|(?<!\d)[6-9]\d{4}[ \-]\d{5}(?!\d)|\b[a-z]{2,6}[\-/]?\d{4,}")
        pos = 0
        for line in t.split("\n"):
            if support.search(fold(line)):
                for m in re.finditer(r"(?<![\w\u0900-\u097F])(?:[A-Z][a-z]{2,}|[A-Z]{3,}|[\u0900-\u0963\u0970-\u097F]{2,})"
                                     r"(?:\s+(?:[A-Z][a-z]{2,}|[A-Z]{3,}|[\u0900-\u0963\u0970-\u097F]{2,})){1,2}(?![\w\u0900-\u097F])", line):
                    words = m.group(0).split()
                    if all(is_name_token(w) and w not in HINDI_STOP and is_name(w) for w in words):
                        pre = line[max(0, m.start() - 5):m.start()]
                        if not re.search(r"(?i)\b(?:dr|doctor)\.?\s*$|डॉ\.?\s*$", pre):
                            spans.append(Span(pos + m.start(), pos + m.end(), "NAME_MODEL", value=m.group(0),
                                              meta={"src": "model"}))
            pos += len(line) + 1

    def _soft(self, t, f, spans):
        """Soft identifiers next to a patient: occupation, employer, school, festival-dated events."""
        for m in SOFT_OCC_LABEL.finditer(t):
            vm = re.compile(r"[^\n,;|.()]{2,40}").match(t, m.end())
            if vm and vm.group(0).strip():
                spans.append(Span(vm.start(), vm.start() + len(vm.group(0).rstrip()), "SOFT", value="occupation",
                                  meta={"occ": vm.group(0).strip()}))
        for m in SOFT_OCC_PHRASE.finditer(t):
            spans.append(Span(m.start(1), m.end(1), "SOFT", value="occupation", meta={"occ": m.group(1)}))
        for m in SOFT_EMPLOYER.finditer(t):
            em = re.compile(r"(?:[A-Z][\w&'.\-]*)(?:\s+(?:[A-Z][\w&'.\-]*|of|and|&))*").match(t, m.end())
            if em:
                spans.append(Span(em.start(), em.start() + len(em.group(0).rstrip(" .")), "SOFT", value="employer"))
        for m in SOFT_SCHOOL.finditer(t):
            spans.append(Span(m.start(), m.end(), "SOFT", value="school"))
        for m in SOFT_FESTIVAL.finditer(t):
            g = 1 if m.group(1) else 2
            spans.append(Span(m.start(g), m.end(g), "SOFT", value="festival"))

    def _dates_ages(self, t, f, spans):
        for m in RE_ISO.finditer(f):
            spans.append(Span(m.start(), m.end(), "DATE", value=m.group(0), meta={"fmt": "iso"}))
        for m in RE_NUMDATE.finditer(f):
            spans.append(Span(m.start(), m.end(), "DATE", value=m.group(0), meta={"fmt": "num"}))
        for m in RE_TEXTDATE.finditer(f):
            spans.append(Span(m.start(), m.end(), "DATE", value=m.group(0), meta={"fmt": "text"}))
        for m in RE_ROMANDATE.finditer(t):
            spans.append(Span(m.start(), m.end(), "DATE", value=m.group(0), meta={"fmt": "roman"}))
        for m in RE_COMPACT.finditer(f):
            spans.append(Span(m.start(), m.end(), "DATE", value=m.group(0), meta={"fmt": "compact"}))
        for m in RE_HINDIDATE.finditer(f):
            spans.append(Span(m.start(), m.end(), "DATE", value=m.group(0), meta={"fmt": "hindi"}))
        for m in RE_MONDATE.finditer(f):
            spans.append(Span(m.start(), m.end(), "DATE", value=m.group(0), meta={"fmt": "mon"}))
        for m in RE_YMD.finditer(f):
            spans.append(Span(m.start(), m.end(), "DATE", value=m.group(0), meta={"fmt": "ymd"}))
        for m in RE_TEXTDATE2.finditer(f):
            spans.append(Span(m.start(), m.end(), "DATE", value=m.group(0), meta={"fmt": "text2"}))
        for m in RE_AGE.finditer(f):
            for g in range(1, 11):
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
    m = RE_ROMANDATE.match(t, pos)
    if m:
        return (m.start(), m.end(), m.group(0), {"fmt": "roman"})
    m = RE_TEXTDATE2.match(f, pos)
    if m:
        return (m.start(), m.end(), m.group(0), {"fmt": "text2"})
    for rx, fmt in ((RE_ISO, "iso"), (RE_NUMDATE, "num"), (RE_HINDIDATE, "hindi"), (RE_MONDATE, "mon"), (RE_YMD, "ymd"), (RE_TEXTDATE, "text")):
        m = rx.match(f, pos)
        if m:
            return (m.start(), m.end(), m.group(0), {"fmt": fmt})
    return None
