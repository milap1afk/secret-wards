"""Field semantics: what does a CSV header or JSON key hold?

Works on header text in English, transliterated Hindi ("Naam", "Pita/Pati ka Naam", "Gaon")
and Devanagari ("नाम", "पता"), and on JSON key paths with their ancestors
("guardian.name" is a relative, "facility.name" is an organisation, FHIR
"Practitioner.name" is a doctor). Unknown fields fall back to free-text detection.
"""
from __future__ import annotations

import re

from .translit import to_latin

# semantic labels
NAME, FIRST, LAST, LOCAL_NAME, REL_NAME, RELATION, GENDER, AGE, AGE_SEX, DOB = (
    "name", "first", "last", "local_name", "rel_name", "relation", "gender", "age", "age_sex", "dob")
ADDRESS, VILLAGE, LOCALITY, TEHSIL, DISTRICT, STATE, PIN = (
    "address", "village", "locality", "tehsil", "district", "state", "pin")
PHONE, EMAIL, AADHAAR, ABHA, ABHA_ADDR, PAN, INSURANCE, UHID, ENC = (
    "phone", "email", "aadhaar", "abha", "abha_addr", "pan", "insurance", "uhid", "enc")
DOCTOR, ORG, DATE, TEXT, KEEP, OTHER_PERSON = ("doctor", "org", "date", "text", "keep", "other_person")

PERSON_NAME_SEMS = {NAME, FIRST, LAST, LOCAL_NAME, REL_NAME, OTHER_PERSON}
IDENTIFIER_SEMS = {PHONE, EMAIL, AADHAAR, ABHA, ABHA_ADDR, PAN, INSURANCE, UHID, ENC}


def _vnorm(s: str) -> str:
    return s.replace("aa", "a").replace("ee", "i").replace("oo", "u")


_ABBREV = {"nm": "name", "nme": "name", "pt": "patient", "pts": "patient", "hosp": "hospital", "regn": "registration",
           "reg": "registration", "addr": "address", "mob": "mobile", "ph": "phone", "tel": "phone",
           "rel": "relative", "dob": "dob", "yr": "years", "yrs": "years", "num": "number", "nbr": "number",
           "dt": "date", "pin": "pin", "vill": "village", "dist": "district", "distt": "district", "fn": "first",
           "ln": "last", "mrd": "mrd", "ip": "ip", "op": "op",
           # possessive forms read as the relation itself ("fathers-name", "husband's name")
           "fathers": "father", "mothers": "mother", "husbands": "husband", "wifes": "wife", "guardians": "guardian",
           "spouses": "spouse", "sons": "son", "daughters": "daughter"}


def words_of(label: str) -> str:
    s = to_latin(label or "")
    s = re.sub(r"([a-z])([A-Z])", r"\1 \2", s)
    s = s.lower()
    s = re.sub(r"[^a-z0-9]+", " ", s)
    # expand record-keeping abbreviations so "pt_nm", "hosp_no", "regn_dt" read like their full forms
    s = " ".join(_ABBREV.get(w, w) for w in s.split())
    return _vnorm(" " + s.strip() + " ")


_RULES = [
    # order matters: first match wins
    (r" (ifsc|ifsc code|branch code|micr) ", KEEP),
    (r" (dak suchak|dak kod|dak sankhya|dak pin|post code|postcode|postal index) ", PIN),
    (r" (durbhash|doorbhash|dur bhash|sampark no|sampark sutra) ", PHONE),
    (r" (e dak|edak|ई मेल) ", EMAIL),
    (r" (janpad|janapad) ", DISTRICT),
    (r" (gali mohalla|gali|mohalla tola) ", LOCALITY),
    (r" (ref doctor|ref dr|ref by|referred by|referr?ed|referring|consultant|doctor|dr|physician|surgeon|treating|attending|author|performer|practitioner|daktar|doktar) ", DOCTOR),
    (r" (hospital|facility|organization|organisation|lab name|laboratory|centre|center|clinic|provider|insurer|tpa) (name )?$", ORG),
    (r" (abha|health) ?(address|addr) ", ABHA_ADDR),
    (r" (abha|health id|healthid|ndhm|abdm|phr) ", ABHA),
    (r" (aadhaa?r|adhaa?r|aadhar|aadhr|uid ?ai|uidai|aadhaar no) |^ uid ", AADHAAR),
    (r" (pan|pan no|pan number|payer pan) ", PAN),
    (r" (pmjay|ayushman|policy|insurance|ins no|claim id|member id|card no|beneficiary id|cghs|esic) ", INSURANCE),
    (r" (e ?mail|email id|mail) ", EMAIL),
    (r" (d o b|dob) ", DOB),
    (r" (mobile|mob|phone|ph|tel|telephone|contact no|contact number|cell|whatsapp|whats app|callback|call back|mobaail|phon) ", PHONE),
    (r" (relation|relationship|rishta|sambandh) $", RELATION),
    (r" (pita|pati|father|husband|guardian|relative|attendant|next of kin|kin|nok|mother|spouse|care of|c o|s o|d o|w o|parent|abhibhavak|parijan|emergency contact) ", REL_NAME),
    (r" (hospital no|hospital number|mrd sankhya|mrd no|panjiyan sankhya|panjiyan|panjikaran|registration sankhya|uhid|mrn|mr number|mr num|medical record|registration number|reg number|regn no|regn|ip op no|ip op|op no|cr no|crno|patient id|patientid|pt id|reg no|registration no|reg id|regno|hospital uhid|patient ref|patient uhid|hospital id|hospital no|ipd patient|panjikaran sankhya|record no|mr no|file no|opd no|patient number) ", UHID),
    (r" (ipd|ip no|admission no|adm no|admission id|encounter|inpatient no|bht) ", ENC),
    (r" (first|given|fname|first name|given name|pratham) ", FIRST),
    (r" (last|family|surname|lname|last name|family name|upnaam) ", LAST),
    (r" (local|hindi|devanagari|vernacular|native) (name )?", LOCAL_NAME),
    (r" (age sex|age gender|age s|umr ling|aayu ling) ", AGE_SEX),
    (r" (dob|date of birth|birth date|birthdate|janm tithi|janma tithi|janmatithi|jnm|born|janm) ", DOB),
    (r" (age|umar|umr|aayu|ayu|age yrs|age years) ", AGE),
    (r" (sex|gender|ling) ", GENDER),
    (r" (pin|pincode|pin code|zip|zipcode|postal|postal code|postalcode|post code) ", PIN),
    (r" (tehsil|tahsil|taluka|block|subdistrict|sub district) ", TEHSIL),
    (r" (district|distt|dist|jila|zila|jilaa) ", DISTRICT),
    (r" (state|rajya|country) ", STATE),
    (r" (village|vill|gaon|ganv|gav|gram|gramam|mauza|town|city) ", VILLAGE),
    (r" (mohalla|locality|colony|area|ward no|sector) ", LOCALITY),
    (r" (address|addr|street|line|house|makan|pata|residence|location address|res) ", ADDRESS),
    (r" (patient name|patient|pt name|name|naam|full name|nam|beneficiary|insured|rogi|rogi ka nam|mareez|mariz|marij|labharthi|purna nam|pura nam|pora nam) ", NAME),
    (r" (date|dt|on|time|timestamp|tarikh|tithi|dinank|collected|reported|admitted|discharged|registered|visit|generated|updated|created|exported) ", DATE),
]
_COMPILED = [(re.compile(_vnorm(p)), s) for p, s in _RULES]


def classify_header(label: str) -> str:
    w = words_of(label)
    if w.strip() == "":
        return TEXT
    for rx, sem in _COMPILED:
        if rx.search(w):
            return sem
    return TEXT


# JSON key classification ------------------------------------------------------------
_DOCTOR_CTX = {"practitioner", "doctor", "consultant", "author", "performer", "referred_by", "referredby",
               "ref_doctor", "attending", "physician", "surgeon", "requester", "practitionerrole", "authenticator",
               "attester", "participant", "doctor_name", "treating_doctor", "careteam"}
_ORG_CTX = {"facility", "organization", "organisation", "hospital", "lab", "laboratory", "serviceprovider",
            "custodian", "managingorganization", "insurer", "payer", "location", "department", "panel", "panels",
            "test", "tests", "results", "drug", "rx", "medication", "medicationcodeableconcept", "code", "coding",
            "diagnosis", "condition", "procedure", "observation", "category", "type", "class", "valuecodeableconcept",
            "interpretation", "bodysite", "method", "specimen", "section", "sections", "relationship", "qualification",
            "system", "export", "_export_meta", "meta", "profile", "composition", "bundle", "ward", "vaccine"}
_REL_CTX = {"guardian", "contact", "relative", "attendant", "kin", "nok", "father", "husband", "mother", "spouse",
            "next_of_kin", "nextofkin", "emergency_contact", "parent", "relatedperson", "linkage"}
_PATIENT_CTX = {"patient", "subject", "beneficiary", "member", "insured", "person", "patients", "pt", "rogi",
                "rogi_vivaran", "rogivivaran", "mareez", "mariz", "marij", "labharthi", "rogee", "patient_details",
                "patientdetails", "pt_details", "demographics"}
_OTHER_PERSON_CTX = {"raised_by", "raisedby", "caller", "informant", "witness", "reported_by", "requested_by",
                     "visitor", "escort", "brought_by", "submitted_by", "created_by", "user"}
_NAMEISH_KEYS = {"name", "text", "display", "given", "family", "first", "last", "local", "full", "fullname",
                 "full_name", "first_name", "last_name", "firstname", "lastname", "prefix", "suffix", "naam"}


def _norm_key(k: str) -> str:
    # hyphens, dots and spaces separate words like "_" does ("emergency-contact-phone" == "emergency_contact_phone")
    s = re.sub(r"[\s\-.]+", "_", to_latin(str(k)).lower().replace("'", "").replace("\u2019", ""))
    return re.sub(r"[^a-z0-9_]", "", s).strip("_")


def classify_json(key: str, ancestors: list, resource_type: str = "") -> str:
    """Semantic of a JSON leaf. ancestors: list of keys from root to parent (strings)."""
    k = _norm_key(key)
    if re.fullmatch(r"[a-z]+_?by", k) and k not in ("standby", "nearby", "hereby", "lobby", "hobby", "baby"):
        return OTHER_PERSON_IF_NAMED    # exported_by, verified_by, created_by: a person when the value is a name
    anc = [_norm_key(a) for a in ancestors if isinstance(a, str)]
    rt = resource_type.lower()
    if k not in _NAMEISH_KEYS and (k.endswith("_name") or k.endswith("name")):
        sem = classify_header(k.replace("_", " "))
        if sem in (NAME, DOCTOR, REL_NAME, ORG, OTHER_PERSON):
            return sem
    if k in _NAMEISH_KEYS or k.endswith("_name") or k.endswith("name"):
        # nearest person/org context decides
        for a in reversed(anc):
            if a in _DOCTOR_CTX:
                return DOCTOR
            if a in _REL_CTX:
                return REL_NAME
            if a in _OTHER_PERSON_CTX:
                return OTHER_PERSON
            if a in _PATIENT_CTX:
                if k in ("given", "first", "first_name", "firstname"):
                    return FIRST
                if k in ("family", "last", "last_name", "lastname"):
                    return LAST
                if k == "local":
                    return LOCAL_NAME
                return NAME
            if a in _ORG_CTX:
                return KEEP if k in ("text", "display") else ORG
        if rt == "patient":
            if anc and anc[-1] in ("contact",):
                return REL_NAME
            if k == "given":
                return FIRST
            if k == "family":
                return LAST
            if k in ("text",) and "name" in anc:
                return NAME
            if k == "text":
                return TEXT
            return NAME
        if rt in ("practitioner", "practitionerrole"):
            return DOCTOR
        if rt in ("organization", "location"):
            return ORG
        if rt == "relatedperson":
            return REL_NAME
        if k in ("text", "display"):
            return TEXT
        sem = classify_header(k.replace("_", " "))
        if sem in (NAME, DOCTOR, REL_NAME, ORG):
            return sem
        return TEXT if k in ("text", "display") else NAME_UNKNOWN
    sem = classify_header(k.replace("_", " "))
    # FHIR specifics
    if k == "birthdate":
        return DOB
    if k == "postalcode":
        return PIN
    if k == "city":
        return VILLAGE
    if k == "value" and anc:
        if "telecom" in anc:
            return PHONE
        if "identifier" in anc:
            return UHID  # refined by system in pipeline
    if k == "div":
        return TEXT
    if k in ("data",) and "attachment" in anc:
        return "attachment"
    if k in ("reference",):
        return KEEP
    return sem


NAME_UNKNOWN = "name_unknown"
OTHER_PERSON_IF_NAMED = "other_person_if_named"


# ---------------------------------------------------------------- content-based typing
_VERHOEFF_D = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
               [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
               [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
               [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_VERHOEFF_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
               [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
               [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]


def verhoeff_ok(digits: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


_V_PHONE = re.compile(r"^(?:\+?91[\s\-]?|0)?[6-9](?:[\s\-.]?\d){9}$")
_V_DATE = re.compile(r"^(?:\d{1,2}[/.\-]\d{1,2}[/.\-]\d{2,4}|\d{4}-\d{2}-\d{2}(?:T[\d:.+\-Z]+)?)$")
_V_PIN = re.compile(r"^[1-8]\d{2}\s?\d{3}$")
_ADDRESSY = re.compile(r"addr|pata|address|residence|location|postal|post|dak|zip|ghar")


def value_type(values, key: str = "", ancestors=()) -> str:
    """Type a column / JSON path by its values when its name says nothing. Returns a sem or "".

    Conservative on purpose: every rule needs 80% of non-empty values to agree, Aadhaar needs a valid
    Verhoeff checksum, and a 6-digit value counts as a PIN only inside an address-like field."""
    vals = [str(v).strip() for v in values if v is not None and not isinstance(v, bool) and str(v).strip()][:300]
    if len(vals) < 1:
        return ""
    n = len(vals)

    def share(pred):
        return sum(1 for v in vals if pred(v)) / n
    digits = [re.sub(r"[\s\-]", "", v) for v in vals]
    if share(lambda v: bool(_V_PHONE.match(v))) >= 0.8:
        return PHONE
    if sum(1 for d in digits if len(d) == 12 and d.isdigit() and d[0] in "23456789" and verhoeff_ok(d)) / n >= 0.8:
        return AADHAAR
    if share(lambda v: bool(_V_DATE.match(v))) >= 0.8:
        return DATE
    ctx = (key + " " + " ".join(str(a) for a in ancestors)).lower()
    if share(lambda v: bool(_V_PIN.match(v))) >= 0.8 and _ADDRESSY.search(ctx):
        return PIN
    from .detect import is_name_token   # local import: fields is imported by detect's users
    def namey(v):
        toks = v.replace(",", " ").split()
        return 1 <= len(toks) <= 4 and not re.search(r"\d", v) and all(is_name_token(t.strip(".")) for t in toks)
    if str(key).lower() in _STRUCTURAL_KEYS:
        return ""
    multi = sum(1 for v in vals if len(v.split()) >= 2) / n
    if n >= 2 and share(namey) >= 0.7 and multi >= 0.5:
        return NAME_UNKNOWN
    return ""


_STRUCTURAL_KEYS = {"resourcetype", "status", "code", "system", "use", "type", "unit", "url", "id", "fullurl",
                    "reference", "display", "text", "div", "contenttype", "version", "profile", "category", "class",
                    "intent", "mode", "kind", "format", "language", "department", "dept", "ward", "test", "panel",
                    "drug", "medicine", "procedure", "diagnosis", "specialty", "speciality", "hospital", "facility"}

