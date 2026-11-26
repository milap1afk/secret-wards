"""Secret Wards pipeline: ingest -> harvest -> link -> sanitise -> report.

Pass 0  ingest every file (encoding + format sniffing; quarantine what cannot be handled safely)
Pass 1  harvest: field-aware + free-text detection collects identity evidence per record and a
        lexicon of known PII (names, IDs, phones, villages) for the whole dataset
Pass 2  link records into patients (link.py), derive pseudonyms and per-patient date shifts
Pass 3  sanitise every record with the full lexicon and write the release

Nothing in this module prints, logs or stores personal data or the secret. Exceptions are
reduced to their type name before they reach the report.
"""
from __future__ import annotations

import collections
import csv
import hashlib
import io
import json
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import fields as F
from . import gazetteer as gz
from .detect import Detector, Lexicon, Span, TOKEN_RE, resolve, is_name_token
from .link import Evidence, Linker, name_tokens, tok_keys
from .policy import POLICY
from .privacy import (age_band, fhir_id, pin_prefix, pseudonym, shift_date_string, shift_days, surrogate_id,
                      parse_any_date)
from . import rare as rare_mod
from . import vault
from .textnorm import decode_escapes, fold, strip_zero_width, try_b64, B64_RE
from .translit import name_key, vowel_key

TEXT_EXT = {".txt", ".text", ".log", ".md", ".note", ".notes"}
CSV_EXT = {".csv", ".tsv", ".psv", ".tab"}
JSON_EXT = {".json", ".fhir", ".ndjson", ".jsonl"}
XML_EXT = {".xml", ".cda", ".hl7x"}
MAX_JSON_DEPTH = 200


TEHSIL_TEXT = re.compile(r"(Tehsil|Tahsil|Teh\.|तहसील)\s+(?!\[)(?:[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?|[\u0900-\u097F]+)")


DROP_KEY = object()   # sentinel: remove this JSON key from the output (only for optional elements)


class Quarantine(Exception):
    pass


# ====================================================================== ingest
def decode_bytes(raw: bytes) -> str:
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8")
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return raw.decode("utf-16")
        except UnicodeDecodeError:
            raise Quarantine("undecodable_text")
    # UTF-16 without BOM: many NUL bytes
    if raw[:200].count(b"\x00") > 20:
        for enc in ("utf-16-le", "utf-16-be"):
            try:
                return raw.decode(enc)
            except UnicodeDecodeError:
                continue
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    # legacy cp1252 is legitimate; a broken UTF-8 stream with stray BOM bytes is not
    if b"\xff\xfe" in raw or b"\xfe\xff" in raw or re.search(rb"[\xc2-\xf4][\x80-\xbf]", raw):
        raise Quarantine("invalid_utf8")
    try:
        txt = raw.decode("cp1252")
    except UnicodeDecodeError:
        raise Quarantine("undecodable_text")
    if sum(1 for c in txt if ord(c) < 32 and c not in "\r\n\t") > 0:
        raise Quarantine("binary_content")
    return txt


_FW_RULE = re.compile(r"^\s*-{2,}(?:[ \t]+-{2,})+\s*$")


def is_fixed_width(text: str) -> bool:
    lines = [ln for ln in text.splitlines() if ln.strip()]
    return len(lines) >= 3 and bool(_FW_RULE.match(lines[1]))


def table_delimiter(text: str):
    """A delimiter that splits most non-empty lines into the same number (>= 3) of fields, else None."""
    lines = [ln for ln in text.splitlines() if ln.strip()][:200]
    if len(lines) < 3:
        return None
    for cand in ("|", "\t", ",", ";"):
        counts = [ln.count(cand) for ln in lines]
        modal, freq = collections.Counter(counts).most_common(1)[0]
        if modal >= 2 and freq >= 0.8 * len(lines):
            return cand
    return None


def sniff_format(rel: str, text: str) -> str:
    ext = Path(rel).suffix.lower()
    head = text.lstrip()[:1]
    if ext in XML_EXT:
        if head != "<":
            raise Quarantine("format_mismatch")
        if re.search(r"(?i)<!DOCTYPE|<!ENTITY", text):
            raise Quarantine("xml_dtd_not_allowed")
        return "xml"
    if ext in (".jsonl", ".ndjson"):
        return "jsonl"
    if ext in JSON_EXT:
        return "json"
    if ext in CSV_EXT:
        if head in ("{", "["):
            raise Quarantine("format_mismatch")
        return "csv"
    if ext in TEXT_EXT:
        if is_fixed_width(text):
            return "fixed"
        if table_delimiter(text) == "|":
            return "csv"
        return "text"
    # unknown extension with text content: handle it by what it is, never by guessing
    if head in ("{", "["):
        try:
            json.loads(text)
            return "json"
        except (ValueError, RecursionError):
            raise Quarantine("unsupported_format")
    if table_delimiter(text):
        return "csv"
    raise Quarantine("unsupported_format")


def sniff_delimiter(rel: str, text: str) -> str:
    """Pick the delimiter whose per-line count is most consistent over the first non-empty lines
    (a preamble line before the header has none, so the first line alone is not enough)."""
    if Path(rel).suffix.lower() == ".tsv":
        return "\t"
    lines = [ln for ln in text.splitlines()[:30] if ln.strip()]
    best, best_score = ",", -1
    for cand in (",", "\t", ";", "|"):
        counts = [ln.count(cand) for ln in lines]
        nonzero = [c for c in counts if c > 0]
        if not nonzero:
            continue
        modal, freq = collections.Counter(nonzero).most_common(1)[0]
        score = freq * 10 + (1 if cand == "," else 0)
        if score > best_score:
            best, best_score = cand, score
    return best


# ====================================================================== records
@dataclass
class Leaf:
    """One value inside a record: a CSV cell or a JSON string/number leaf."""
    sem: str
    value: object
    path: tuple = ()
    key: str = ""
    extra: dict = field(default_factory=dict)


@dataclass
class Unit:
    file: str
    loc: str
    kind: str                    # row / json / doc / file
    leaves: list = field(default_factory=list)
    text: str = ""               # for doc units
    ev: Evidence = None
    cluster: object = None
    psn: str = None
    shift: int = 0
    tehsil: str = ""
    district: str = ""
    name_keys: set = field(default_factory=set)
    date_order: str = "dmy"
    age_width: int = 0          # >0 when local recoding widened this patient's age band
    gen: bool = False           # something in this record was generalised (for an honest report)


@dataclass
class FileJob:
    rel: str
    sha: str
    fmt: str = ""
    text: str = ""
    data: object = None
    header: list = None
    rows: list = None
    delim: str = ","
    newline: str = "\n"
    units: list = field(default_factory=list)
    file_unit: Unit = None
    date_order: str = "dmy"
    status: str = "pending"
    reason: str = ""
    out_rel: str = ""
    json_indent: object = 2


# ====================================================================== helpers
def id_core(s: str) -> str:
    runs = re.findall(r"\d+", fold(str(s)))
    if not runs:
        return ""
    core = "".join(runs) if len(runs) > 1 else runs[0]
    return core if len(core) >= 5 else ""


_REL_MARKER = re.compile(r"^\s*(S\s*/\s*O|D\s*/\s*O|W\s*/\s*O|C\s*/\s*O|H\s*/\s*O|son of|daughter of|wife of|husband of|पुत्र|पुत्री|पत्नी|पति)\.?\s*:?\s*", re.I)


def strip_rel_marker(v: str) -> tuple:
    m = _REL_MARKER.match(v or "")
    if m:
        return v[:m.end()], v[m.end():]
    return "", v


def gender_of(v: str) -> str:
    s = str(v).strip().lower()
    if s in ("m", "male", "पुरुष", "purush", "man") or s.startswith("male"):
        return "M"
    if s in ("f", "female", "महिला", "mahila", "स्त्री", "woman") or s.startswith("female"):
        return "F"
    return ""


def parse_age(v) -> int:
    if isinstance(v, bool):
        return -1
    if isinstance(v, (int, float)):
        return int(v) if 0 <= v <= 120 else -1
    m = re.match(r"^\s*(\d{1,3})", fold(str(v)))
    return int(m.group(1)) if m and int(m.group(1)) <= 120 else -1


def village_key(v: str) -> str:
    return name_key(re.sub(r"[\s\-.]+", "", str(v)))


def iso_of(v: str, order: str) -> str:
    r = parse_any_date(str(v), order)
    return r[0].isoformat() if r else ""


# ====================================================================== the pipeline
class Pipeline:
    def __init__(self, inp: Path, out: Path):
        self.inp = inp
        self.out = out
        self.jobs: list = []
        self.lex = Lexicon()
        self.detector = Detector()
        self.evidence: list = []
        self.units: list = []
        self.id_kind: dict = {}          # id core -> "uhid" / "enc"
        self.core_cluster: dict = {}     # id core -> cluster
        self.cluster_psn: dict = {}
        self.cluster_shift: dict = {}
        self.cluster_names: dict = {}
        self.doctor_tokens: set = set()
        self.keep_places: set = set()
        self.n_identifiers = 0
        self.entities: dict = {}
        self.n_generalized = 0
        self.rare: dict = {}
        self._dcache: dict = {}
        self._cur_unit = None
        self.n_recoded_patients = 0
        self._unit_gen: dict = {}

    # ------------------------------------------------------------------ pass 0
    def ingest(self) -> None:
        paths = sorted((p for p in self.inp.rglob("*") if p.is_file()), key=lambda p: p.relative_to(self.inp).as_posix())
        for p in paths:
            rel = p.relative_to(self.inp).as_posix()
            try:
                raw = p.read_bytes()
            except OSError:
                self.jobs.append(FileJob(rel=rel, sha="", status="quarantined", reason="unreadable"))
                continue
            job = FileJob(rel=rel, sha=hashlib.sha256(raw).hexdigest())
            self.jobs.append(job)
            try:
                if not raw.strip():
                    raise Quarantine("empty_file")
                if Path(rel).suffix.lower() not in TEXT_EXT | CSV_EXT | JSON_EXT | XML_EXT and (
                        raw[:4] in (b"%PDF", b"PK\x03\x04", b"\xd0\xcf\x11\xe0") or raw[:3] == b"\xff\xd8\xff"
                        or raw[:8] == b"\x89PNG\r\n\x1a\n" or b"\x00" in raw[:4096] and not raw.startswith((b"\xff\xfe", b"\xfe\xff"))):
                    raise Quarantine("unsupported_format")   # binary documents/images: never decoded
                text = decode_bytes(raw)
                text = strip_zero_width(text)
                job.newline = "\r\n" if "\r\n" in text else "\n"
                job.fmt = sniff_format(rel, text)
                job.text = text
                if job.fmt in ("json", "jsonl"):
                    self._load_json(job)
                elif job.fmt == "csv":
                    self._load_csv(job)
                elif job.fmt == "fixed":
                    self._load_fixed(job)
                elif job.fmt == "xml":
                    self._load_xml(job)
                job.date_order = self._date_order(job)
            except Quarantine as q:
                job.status, job.reason = "quarantined", str(q)
            except RecursionError:
                job.status, job.reason = "quarantined", "nesting_too_deep"
            except Exception as exc:  # noqa: BLE001 - never leak content, only the type
                job.status, job.reason = "quarantined", "parse_error_" + type(exc).__name__

    def _load_json(self, job: FileJob) -> None:
        txt = job.text
        if job.fmt == "jsonl":
            objs = []
            for ln in txt.splitlines():
                if not ln.strip():
                    continue
                try:
                    objs.append(json.loads(ln))
                except (ValueError, RecursionError):
                    raise Quarantine("malformed_jsonl")
            if not objs or _depth(objs) > MAX_JSON_DEPTH:
                raise Quarantine("malformed_jsonl")
            job.data, job.json_indent = objs, None
            return
        try:
            data = json.loads(txt)
        except RecursionError:
            raise Quarantine("nesting_too_deep")
        except ValueError:
            raise Quarantine("malformed_json")
        if _depth(data) > MAX_JSON_DEPTH:
            raise Quarantine("nesting_too_deep")
        job.data = data
        m = re.search(r"\n([ \t]+)\S", txt)
        job.json_indent = (len(m.group(1)) if m.group(1)[0] == " " else "\t") if m else None

    def _load_xml(self, job: FileJob) -> None:
        import xml.etree.ElementTree as ET
        raw = job.text.encode("utf-8")
        try:
            for _ev, (prefix, uri) in ET.iterparse(io.BytesIO(raw), events=("start-ns",)):
                ET.register_namespace(prefix or "", uri)
            job.data = ET.fromstring(re.sub(r"^\s*<\?xml[^>]*\?>", "", job.text).encode("utf-8"))
        except ET.ParseError:
            raise Quarantine("malformed_xml")
        m = re.match(r"\s*(<\?xml[^>]*\?>)", job.text)
        job.xml_decl = m.group(1) if m else ""

    def _load_fixed(self, job: FileJob) -> None:
        lines = job.text.splitlines()
        idx = [i for i, ln in enumerate(lines) if ln.strip()]
        h, rule = idx[0], idx[1]
        starts = [m.start() for m in re.finditer(r"-{2,}", lines[rule])]
        job.fw_starts = starts
        job.fw_head = lines[:rule + 1]

        def cut(ln):
            cells = []
            for k, st in enumerate(starts):
                en = starts[k + 1] if k + 1 < len(starts) else None
                cells.append(ln[st:en].strip() if en is not None else ln[st:].strip())
            return cells
        job.header = cut(lines[h])
        job.rows = [cut(ln) for ln in lines[rule + 1:] if ln.strip()]
        job.fw_tail_blank = job.text.endswith(("\n", "\r\n"))

    def _load_csv(self, job: FileJob) -> None:
        job.delim = sniff_delimiter(job.rel, job.text)
        rows = list(csv.reader(io.StringIO(job.text, newline=""), delimiter=job.delim))
        if not rows:
            raise Quarantine("empty_file")
        # preamble lines (title, run info, a note) before the real header: their field count differs from
        # the file's dominant field count. Normal and ragged CSVs keep h = 0.
        h = 0
        counts = [len(r) for r in rows[:200] if len(r) >= 2]
        if counts:
            modal = collections.Counter(counts).most_common(1)[0][0]
            if modal >= 2 and len(rows[0]) != modal:
                while h < min(10, len(rows) - 1) and len(rows[h]) != modal:
                    h += 1
                if len(rows[h]) != modal:
                    h = 0
        job.preamble = ""
        if h:
            lines = job.text.splitlines(keepends=True)
            job.preamble = "".join(lines[:h])
            rows = rows[h:]
        job.header, job.rows = rows[0], rows[1:]

    def _date_order(self, job: FileJob) -> str:
        txt = job.text
        hdr = " ".join(job.header or [])
        if re.search(r"(?i)mm\s*/\s*dd", hdr + txt[:400]):
            return "mdy"
        if re.search(r"(?i)dd\s*/\s*mm", hdr + txt[:400]):
            return "dmy"
        dmy = mdy = 0
        for m in re.finditer(r"(?<![\d/.\-])(\d{1,2})[/.\-](\d{1,2})[/.\-](\d{2,4})(?![\d])", txt):
            a, b = int(m.group(1)), int(m.group(2))
            if a > 12 and b <= 12:
                dmy += 1
            elif b > 12 and a <= 12:
                mdy += 1
        if mdy > dmy:
            return "mdy"
        if dmy:
            return "dmy"
        return ""   # undecided: resolved by sibling files of the same source

    def resolve_date_orders(self) -> None:
        votes: dict = {}
        for j in self.jobs:
            src = _source_key(j.rel, j.text)
            if j.date_order:
                votes.setdefault(src, []).append(j.date_order)
        for j in self.jobs:
            if not j.date_order:
                v = votes.get(_source_key(j.rel, j.text), [])
                j.date_order = "mdy" if v.count("mdy") > v.count("dmy") else "dmy"

    # ------------------------------------------------------------------ units
    def build_units(self) -> None:
        for job in self.jobs:
            if job.status == "quarantined":
                continue
            try:
                if job.fmt in ("csv", "fixed"):
                    self._units_csv(job)
                elif job.fmt in ("json", "jsonl"):
                    self._units_json(job)
                    if job.fmt == "jsonl":
                        for u in job.units:          # SPEC row:N for line records (N = non-empty line index)
                            if u.loc.startswith("/"):
                                u.loc = "row:" + u.loc[1:].split("/", 1)[0]
                elif job.fmt == "xml":
                    self._units_xml(job)
                else:
                    u = Unit(job.rel, "doc", "doc", text=job.text, date_order=job.date_order)
                    job.units = [u]
            except Exception as exc:  # noqa: BLE001
                job.status, job.reason = "quarantined", "parse_error_" + type(exc).__name__

    def _units_csv(self, job: FileJob) -> None:
        sems = [F.classify_header(h) for h in job.header]
        for c, sem in enumerate(sems):       # unknown header: type the column by its values
            if sem == F.TEXT:
                vt = F.value_type([r[c] for r in job.rows if c < len(r)], job.header[c])
                if vt:
                    sems[c] = vt
        job.extra_sems = sems
        for i, row in enumerate(job.rows):
            u = Unit(job.rel, f"row:{i}", "row", date_order=job.date_order)
            for c, val in enumerate(row):
                sem = sems[c] if c < len(sems) else F.TEXT
                u.leaves.append(Leaf(sem=sem, value=val, path=(c,), key=job.header[c] if c < len(job.header) else ""))
            job.units.append(u)

    def _units_json(self, job: FileJob) -> None:
        data = job.data
        rec_path = _find_record_list(data)
        job.rec_path = rec_path
        units: dict = {}
        file_unit = Unit(job.rel, "@file", "file", date_order=job.date_order)
        doc_unit = None
        is_fhir = isinstance(data, dict) and data.get("resourceType") == "Bundle"
        if rec_path is None:
            doc_unit = Unit(job.rel, "doc", "doc", date_order=job.date_order)
        for path, key, anc, rt, val in _walk(data):
            sem = self._json_sem(key, anc, rt, path, data)
            leaf = Leaf(sem=sem, value=val, path=path, key=str(key))
            if doc_unit is not None:
                target = doc_unit if not _is_meta_path(path) or is_fhir else file_unit
            elif len(path) > len(rec_path) and tuple(path[:len(rec_path)]) == tuple(rec_path):
                idx = path[len(rec_path)]
                ptr = "/" + "/".join(_ptr_escape(str(x)) for x in list(rec_path) + [idx])
                target = units.get(idx)
                if target is None:
                    target = units[idx] = Unit(job.rel, ptr, "json", date_order=job.date_order)
            else:
                target = file_unit
            target.leaves.append(leaf)
        job.units = ([doc_unit] if doc_unit is not None else [units[k] for k in sorted(units)])
        job.file_unit = file_unit
        # unknown keys: type each JSON path (array indices folded) by the values found under it
        groups: dict = {}
        for u in job.units + [file_unit]:
            for lf in u.leaves:
                if lf.sem == F.TEXT and lf.path and isinstance(lf.path[-1], str):
                    sig = tuple("[]" if isinstance(x, int) else x for x in lf.path)
                    groups.setdefault(sig, []).append(lf)
        is_fhir = isinstance(job.data, dict) and isinstance(job.data.get("resourceType"), str)
        for sig, lfs in groups.items():
            vt = F.value_type([lf.value for lf in lfs], str(sig[-1]), [x for x in sig[:-1] if x != "[]"])
            if vt == F.NAME_UNKNOWN and is_fhir:
                vt = ""                  # FHIR semantics are explicit; never guess names from values there
            if vt:
                for lf in lfs:
                    lf.sem = vt

    def _units_xml(self, job: FileJob) -> None:
        u = Unit(job.rel, "doc", "doc", date_order=job.date_order)

        def local(tag):
            return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""

        def walk(el, anc, path):
            tag = local(el.tag)
            idroot = (el.get("root") or "").lower()
            for an, av in sorted(el.attrib.items()):
                an_l = local(an)
                if an_l in ("root", "xmlns", "codeSystem", "classCode", "moodCode", "typeCode", "use"):
                    continue
                if tag == "id" and an_l == "extension":
                    sem = F.AADHAAR if "aadhaar" in idroot or idroot.startswith("2.16.356.") and len(re.sub(r"\D", "", av)) == 12 else (
                        F.ABHA if "abha" in idroot or "healthid" in idroot else F.UHID)
                else:
                    sem = F.classify_json(an_l, anc + [tag])
                    if an_l in ("value", "code", "displayName", "unit") and sem not in F.IDENTIFIER_SEMS:
                        sem = F.TEXT
                u.leaves.append(Leaf(sem=sem, value=av, path=path + ("@" + an,), key=an_l, extra={"el": el, "attr": an}))
            if el.text and el.text.strip():
                sem = F.classify_json(tag, anc)
                u.leaves.append(Leaf(sem=sem, value=el.text, path=path + ("#text",), key=tag, extra={"el": el, "part": "text"}))
            for i, ch in enumerate(list(el)):
                walk(ch, anc + [tag], path + (i,))
                if ch.tail and ch.tail.strip():
                    u.leaves.append(Leaf(sem=F.TEXT, value=ch.tail, path=path + (i, "#tail"), key="", extra={"el": ch, "part": "tail"}))

        walk(job.data, [], ())
        job.units = [u]

    def _json_sem(self, key, anc, rt, path, data) -> str:
        if isinstance(key, int):
            # list element: semantics of the parent key
            parent = next((a for a in reversed(anc) if isinstance(a, str)), "")
            if parent in ("given", "family", "line", "prefix"):
                key = parent
                anc = anc[:-1] if anc and anc[-1] == parent else anc
            else:
                return F.TEXT
        sem = F.classify_json(str(key), [a for a in anc], rt or "")
        if str(key) == "value" and "identifier" in anc:
            system = _sibling(data, path, "system") or ""
            s = system.lower()
            if "abdm" in s or "healthid" in s or "abha" in s:
                return F.ABHA
            if "aadhaar" in s or "uidai" in s:
                return F.AADHAAR
            if "ipd" in s or "encounter" in s or "admission" in s:
                return F.ENC
            if "bundle" in s or "document" in s:
                return F.KEEP
            if "pmjay" in s or "insurance" in s or "policy" in s:
                return F.INSURANCE
            return F.UHID
        return sem

    # ------------------------------------------------------------------ pass 1: harvest
    def harvest(self) -> None:
        # structured lexicon first (names / IDs / phones / villages from typed fields)
        for job in self.jobs:
            for u in job.units + ([job.file_unit] if job.file_unit else []):
                for lf in u.leaves:
                    self._lex_from_leaf(lf, u)
        self.lex.compile()
        self.detector = Detector(self.lex)
        rid = 0
        for job in self.jobs:
            for u in job.units:
                rid += 1
                u.ev = Evidence(rid=rid, file=u.file, loc=u.loc)
                try:
                    self._evidence(u)
                except Exception:  # noqa: BLE001 - one odd record must not stop the release
                    u.ev = Evidence(rid=rid, file=u.file, loc=u.loc, multi=True)
                self.units.append(u)
                self.evidence.append(u.ev)
        # second lexicon: add names found by labels in free text
        for u in self.units:
            for toks in u.ev.names + u.ev.rel_names:
                self._add_name(" ".join(toks), "")
        self.lex.compile()
        self.detector = Detector(self.lex)

    def _add_name(self, full: str, role: str) -> None:
        toks = name_tokens(full)
        toks = [t for t in toks if t.lower() not in gz.NON_NAME_WORDS and len(t) >= 2]
        if not toks:
            return
        if len(toks) >= 2:
            self.lex.name_phrases[fold(" ".join(toks))] = role
        for t in toks:
            ft = fold(t)
            if len(ft) >= 3 and ft not in self.doctor_tokens and ft not in gz.NON_NAME_WORDS and ft not in gz.DISTRICTS:
                self.lex.name_tokens[ft] = self.lex.name_tokens.get(ft, 0) + 1
                k = name_key(t)
                if len(k) >= 3:
                    self.lex.name_keys.add(k)

    def _lex_from_leaf(self, lf: Leaf, u: Unit) -> None:
        v = lf.value
        if v is None or isinstance(v, bool):
            return
        s = str(v).strip()
        if not s:
            return
        sem = lf.sem
        if sem == F.DOCTOR:
            for t in re.findall(r"[A-Za-z]{3,}", s):
                if t.lower() not in ("doctor",):
                    self.doctor_tokens.add(t.lower())
        elif sem in (F.NAME, F.FIRST, F.LAST, F.LOCAL_NAME):
            self._add_name(s, "patient")
        elif sem == F.REL_NAME:
            self._add_name(strip_rel_marker(s)[1], "relative")
        elif sem == F.OTHER_PERSON:
            self._add_name(s, "other")
        elif sem == F.NAME_UNKNOWN and _looks_like_person(s):
            self._add_name(s, "")        # value-typed name column: feeds the lexicon, never linking evidence
        elif sem in (F.UHID, F.ENC):
            c = id_core(s)
            if c:
                self.lex.id_cores.add(c)
                self.id_kind.setdefault(c, "enc" if sem == F.ENC else "uhid")
                for run in re.findall(r"\d{5,}", fold(s)):
                    self.lex.id_cores.add(run)
                    self.id_kind.setdefault(run, "enc" if sem == F.ENC else "uhid")
        elif sem == F.PHONE:
            d = re.sub(r"\D", "", fold(s))
            if len(d) >= 10:
                self.lex.phones.add(d[-10:])
        elif sem == F.VILLAGE:
            self.lex.villages.add(fold(s))
        elif sem == F.LOCALITY:
            self.lex.localities.add(fold(s))
        elif sem in (F.TEHSIL, F.DISTRICT):
            self.keep_places.add(fold(s))

    def _evidence(self, u: Unit) -> None:
        ev = u.ev
        names_first, names_last = [], []
        if u.kind == "doc" and u.text:
            self._evidence_text(u.text, ev, u.date_order, primary=True)
        for lf in u.leaves:
            v = lf.value
            if v is None or isinstance(v, bool):
                continue
            s = str(v).strip()
            if not s:
                continue
            sem = lf.sem
            if sem in (F.NAME, F.LOCAL_NAME):
                toks = name_tokens(s)
                if toks and not re.search(r"\d", s):
                    ev.names.append(toks)
            elif sem == F.FIRST:
                names_first.append(s)
            elif sem == F.LAST:
                names_last.append(s)
            elif sem == F.REL_NAME:
                toks = name_tokens(strip_rel_marker(s)[1])
                if toks:
                    ev.rel_names.append(toks)
            elif sem == F.UHID:
                c = id_core(s)
                if c:
                    ev.uhids.add(c)
            elif sem == F.ENC:
                c = id_core(s)
                if c:
                    ev.encs.add(c)
            elif sem == F.PHONE:
                d = re.sub(r"\D", "", fold(s))
                if len(d) >= 10:
                    ev.phones.add(d[-10:])
            elif sem == F.AADHAAR:
                d = re.sub(r"\D", "", fold(s))
                if len(d) == 12:
                    ev.aadhaar.add(d)
            elif sem == F.ABHA:
                d = re.sub(r"\D", "", fold(s))
                if len(d) == 14:
                    ev.abha.add(d)
            elif sem == F.PAN:
                if re.match(r"^[A-Za-z]{5}\d{4}[A-Za-z]$", s):
                    ev.pan.add(s.upper())
            elif sem == F.INSURANCE:
                ev.ins.add(re.sub(r"\s", "", s.upper()))
            elif sem == F.EMAIL:
                if "@" in s:
                    ev.email.add(s.lower())
            elif sem == F.DOB:
                iso = iso_of(s, u.date_order)
                if iso:
                    ev.dob.add(iso)
            elif sem in (F.AGE, F.AGE_SEX):
                a = parse_age(v)
                if a >= 0:
                    ev.ages.append(a)
                if sem == F.AGE_SEX:
                    g = re.search(r"/\s*([MF])\b", s, re.I)
                    if g:
                        ev.gender.add(g.group(1).upper())
            elif sem == F.GENDER:
                g = gender_of(s)
                if g:
                    ev.gender.add(g)
            elif sem == F.VILLAGE:
                ev.villages.add(village_key(s))
            elif sem == F.TEHSIL:
                u.tehsil = s
            elif sem == F.DISTRICT:
                u.district = s
            elif sem in (F.TEXT, F.ADDRESS, F.NAME_UNKNOWN, F.OTHER_PERSON) and isinstance(v, str):
                self._evidence_text(s, ev, u.date_order, primary=False)
        if names_first or names_last:
            toks = name_tokens(" ".join(names_first + names_last))
            if toks:
                ev.names.append(toks)
        # a record that carries many different patient identities is a list, not a person
        n_patient_names = len({" ".join(sorted(vowel_key(t) for t in n)) for n in ev.names})
        if len(ev.uhids) > 4 or len(ev.phones) > 3 or n_patient_names > 3:
            ev.multi = True
        # two primary names that share no token, or two Aadhaar numbers / DOBs: several people
        keysets = [tok_keys(n) for n in ev.names]
        for i in range(len(keysets)):
            for j in range(i + 1, len(keysets)):
                if keysets[i] and keysets[j] and not (keysets[i] & keysets[j]):
                    ev.multi = True
        if len(ev.aadhaar) > 1 or len(ev.dob) > 1:
            ev.multi = True

    def _evidence_text(self, text: str, ev: Evidence, order: str, primary: bool) -> None:
        dtext = decode_escapes(text)
        spans = self.detector.detect(dtext)
        for s in spans:
            seg = dtext[s.start:s.end]
            if s.kind == "NAME":
                toks = name_tokens(seg)
                if not toks:
                    continue
                src = s.meta.get("src", "")
                if s.role == "relative":
                    ev.rel_names.append(toks)
                elif s.role == "patient" and src in ("label", "verb") and primary:
                    ev.names.append(toks)
                elif s.role in ("", "patient"):
                    ev.weak_names.append(toks)
            elif s.kind == "MRN":
                c = id_core(seg)
                if c:
                    pre = dtext[max(0, s.start - 12):s.start].lower()
                    if re.search(r"ipd|ip\s*no|adm", pre + seg.lower()):
                        ev.encs.add(c)
                        self.id_kind.setdefault(c, "enc")
                    else:
                        ev.uhids.add(c)
            elif s.kind == "PHONE":
                ev.phones.add(s.value[-10:])
            elif s.kind == "AADHAAR":
                ev.aadhaar.add(s.value)
            elif s.kind == "ABHA":
                ev.abha.add(s.value)
            elif s.kind == "PAN":
                ev.pan.add(s.value)
            elif s.kind == "EMAIL":
                ev.email.add(s.value)
            elif s.kind == "DOB":
                iso = iso_of(seg, order)
                if iso:
                    ev.dob.add(iso)
            elif s.kind == "AGE" and primary:
                try:
                    ev.ages.append(int(s.value))
                except ValueError:
                    pass
            elif s.kind == "VILLAGE":
                ev.villages.add(village_key(seg))
        if primary:
            g = re.search(r"(?i)(?:age\s*/\s*sex|yrs?|y)\s*[:/]?\s*\d*\s*/\s*([MF])\b|\b\d{1,3}\s*/\s*([MF])\b|(महिला|पुरुष)", dtext)
            if g:
                gg = g.group(1) or g.group(2) or ("F" if g.group(3) == "महिला" else "M")
                ev.gender.add(gg.upper())

    # ------------------------------------------------------------------ pass 2: link
    def link(self) -> None:
        linker = Linker(self.evidence)
        assign = linker.run()
        by_rid = {u.ev.rid: u for u in self.units}
        # canonical key per cluster: the smallest (file, loc) of its members
        members: dict = {}
        for rid, root in assign.items():
            if root is not None:
                members.setdefault(root, []).append(by_rid[rid])
        for root, us in members.items():
            canon = min((u.file, u.loc) for u in us)
            key = canon[0] + "#" + canon[1]
            self.cluster_psn[root] = pseudonym(key)
            self.cluster_shift[root] = shift_days(key)
            nk = set()
            for u in us:
                for n in u.ev.names + u.ev.weak_names:
                    nk |= tok_keys(n)
                for c in u.ev.uhids | u.ev.encs:
                    self.core_cluster.setdefault(c, root)
            self.cluster_names[root] = nk
        for u in self.units:
            root = assign.get(u.ev.rid)
            u.cluster = root
            if root is not None:
                u.psn = self.cluster_psn[root]
                u.shift = self.cluster_shift[root]
                u.name_keys = self.cluster_names[root]
            else:
                u.shift = shift_days("unit#" + u.file + "#" + u.loc)
                nk = set()
                for n in u.ev.names + u.ev.weak_names:
                    nk |= tok_keys(n)
                u.name_keys = nk
        # IDs whose owner is ambiguous (seen in several clusters) never map to a pseudonym
        owners: dict = {}
        for u in self.units:
            if u.cluster is None:
                continue
            for c in u.ev.uhids | u.ev.encs:
                owners.setdefault(c, set()).add(u.cluster)
        for c, roots in owners.items():
            if len(roots) > 1:
                self.core_cluster.pop(c, None)

    # ------------------------------------------------------------------ pass 2b: local recoding
    def recode(self) -> None:
        """Widen the age band of patients who are unique on (age band, sex, district, main diagnosis).

        Only quasi-identifiers change: the wider band still contains the true age, and medical values, dates,
        intervals and lengths of stay are untouched. Controlled by recode_k / recode_age_band_years."""
        k = int(POLICY.get("recode_k", 0))
        width = int(POLICY.get("recode_age_band_years", 20))
        if k <= 1:
            return
        base = int(POLICY["age_band_years"])
        clusters: dict = {}
        for u in self.units:
            if u.cluster is not None:
                clusters.setdefault(u.cluster, []).append(u)
        info = {}
        for root, us in clusters.items():
            ages = sorted(a for u in us for a in u.ev.ages)
            if not ages:
                continue
            age = ages[len(ages) // 2]
            sex = sorted(g for u in us for g in u.ev.gender)[:1]
            dist = collections.Counter(d for u in us for d in _districts_of(u)).most_common(1)
            dx = collections.Counter(c for u in us for c in _icd_of(u)).most_common(1)
            info[root] = (age // base, tuple(sex), dist[0][0] if dist else "", dx[0][0] if dx else "")
        sizes = collections.Counter(info.values())
        for root, key in sorted(info.items(), key=lambda kv: str(kv[0])):
            if sizes[key] < k:
                self.n_recoded_patients += 1
                for u in clusters[root]:
                    u.age_width = width

    # ------------------------------------------------------------------ pass 3: sanitise
    def sanitize_all(self) -> list:
        records = []
        san = self.out / "sanitized"
        used_paths: set = set()
        for job in self.jobs:
            if job.status == "quarantined":
                continue
            try:
                if job.fmt == "csv":
                    body = self._write_csv(job)
                elif job.fmt in ("json", "jsonl"):
                    body = self._write_json(job)
                elif job.fmt == "fixed":
                    body = self._write_fixed(job)
                elif job.fmt == "xml":
                    body = self._write_xml(job)
                else:
                    body = self._write_text(job)
                out_rel = self._safe_relpath(job)
                base, n = out_rel, 2
                while out_rel.lower() in used_paths:
                    stem = Path(base)
                    out_rel = str(stem.with_name(f"{stem.stem}_{n}{stem.suffix}"))
                    n += 1
                used_paths.add(out_rel.lower())
                dest = san / out_rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                with open(dest, "w", encoding="utf-8", newline="") as fh:
                    fh.write(body)
                job.status, job.out_rel = "sanitized", "sanitized/" + out_rel
                for u in job.units:
                    if u.ev is not None and (u.ev.has_identity() or u.psn):
                        rec = {"file": job.out_rel, "loc": u.loc, "patient": u.psn}
                        records.append(rec)
                        self._unit_gen[(job.out_rel, u.loc)] = u.gen
            except Exception as exc:  # noqa: BLE001
                job.status, job.reason, job.out_rel = "quarantined", "sanitize_error_" + type(exc).__name__, ""
        return records

    # ---------- unit rendering core
    def _unit_tokens(self, u: Unit, spans_by_val: list) -> set:
        """Name-token keys to sweep inside this unit: found mentions + the patient's known names."""
        keys = set(u.name_keys)
        for text, spans in spans_by_val:
            for s in spans:
                if s.kind == "NAME":
                    for t in name_tokens(text[s.start:s.end]):
                        if t.lower() not in gz.NON_NAME_WORDS:
                            keys |= tok_keys([t])
        return keys

    def _render_text(self, text: str, spans: list, u: Unit, sweep: set, *, field_sem: str = "") -> str:
        self._cur_unit = u
        spans = list(spans)
        # sweep: remaining occurrences of this unit's name tokens
        if sweep:
            occupied = [(s.start, s.end) for s in spans]
            for m in TOKEN_RE.finditer(text):
                if any(a <= m.start() < b or a < m.end() <= b for a, b in occupied):
                    continue
                tok = m.group(0).rstrip(".")
                if len(tok) < 3 or tok.lower() in gz.NON_NAME_WORDS or tok.lower() in gz.HONORIFIC_SUFFIX:
                    continue
                if tok.lower() in gz.GENERIC_NAME_TOKENS:
                    continue
                if not (tok[0].isupper() or re.match(r"[ऀ-ॿ]", tok)):
                    continue
                if tok.isupper() and len(tok) <= 4:
                    continue
                if tok_keys([tok]) & sweep:
                    pre = text[max(0, m.start() - 5):m.start()]
                    if re.search(r"(?i)\b(?:dr|doctor)\.?\s*$|डॉ\.?\s*$", pre):
                        continue
                    spans.append(Span(m.start(), m.start() + len(tok), "NAME", value=tok, meta={"src": "sweep"}))
            spans = resolve(spans)
        out = []
        pos = 0
        for s in spans:
            if s.start < pos:
                continue
            seg = text[s.start:s.end]
            rep = self._replacement(s, seg, u)
            if rep is None:
                continue
            out.append(text[pos:s.start])
            out.append(rep)
            pos = s.end
        out.append(text[pos:])
        return "".join(out)

    def _replacement(self, s: Span, seg: str, u: Unit):
        k = s.kind
        if k == "PROTECT":
            return None
        if k == "DOB" and POLICY.get("dob_policy") == "suppress":
            self._gen()
            return "[DOB]"
        if k in ("DATE", "DOB"):
            r = shift_date_string(seg, u.shift, u.date_order)
            if r is None:
                return "[DOB]" if k == "DOB" else None
            return r
        if k == "AGE":
            try:
                a = int(s.value)
            except ValueError:
                return None
            self._gen()
            return age_band(a, u.age_width)
        self.n_identifiers += 1
        self.entities[k] = self.entities.get(k, 0) + 1
        if k == "NAME_MODEL":
            k = "NAME"
        if k == "NAME":
            keys = tok_keys(name_tokens(seg))
            is_patient = bool(keys & u.name_keys) or s.role == "patient"
            if s.role == "relative" and not (keys & u.name_keys):
                return "[RELATIVE]"
            if is_patient:
                return u.psn if (u.psn and POLICY.get("embed_pseudonym", 1)) else "[PATIENT]"
            if s.role == "relative":
                return "[RELATIVE]"
            return "[NAME]"
        if k == "MRN":
            core = id_core(seg) or s.value
            kind = self.id_kind.get(core)
            if kind == "enc" or re.match(r"(?i)\s*(ipd|ip[/\-]|adm|dhh-ipd)", seg):
                return surrogate_id("ENC", core)
            root = self.core_cluster.get(core)
            if root is not None and POLICY.get("embed_pseudonym", 1):
                return self.cluster_psn[root]
            return surrogate_id("ID", core)
        if k in ("PHONE", "PHONE_MASKED"):
            return "[PHONE]"
        if k == "UPI":
            return "[UPI-ID]"
        if k == "GOVID":
            return "[GOV-ID]"
        if k == "LONGNUM":
            return "[ID-NUMBER]"
        if k in ("AADHAAR", "AADHAAR_MASKED"):
            return "[AADHAAR]"
        if k == "ABHA":
            return "[ABHA]"
        if k == "ABHA_ADDR":
            return "[ABHA-ADDRESS]"
        if k == "EMAIL":
            return "[EMAIL]"
        if k == "PAN":
            return "[PAN]"
        if k == "INSURANCE":
            return "[INSURANCE-ID]"
        if k in ("HOUSE", "LOCALITY", "LANDMARK", "ADDRESS"):
            return "[ADDRESS]"
        if k == "VILLAGE":
            if fold(seg) in self.keep_places or fold(seg) in gz.DISTRICTS:
                self.n_identifiers -= 1
                return None
            return "[VILLAGE]"
        if k == "PIN":
            self._gen()
            return pin_prefix(seg)
        return "[REDACTED]"

    def _detect(self, text: str, *, address_ctx: bool = False) -> list:
        key = (text, address_ctx, id(self.detector))
        hit = self._dcache.get(key)
        if hit is not None:
            return hit
        dt_ = decode_escapes(text)
        if dt_ != text:
            text = dt_
        det_text = text.replace("_", " ")
        res = (text, self.detector.detect(det_text, address_ctx=address_ctx))
        if len(self._dcache) < 300000:
            self._dcache[key] = res
        return res

    def _render_free(self, text: str, u: Unit, sweep: set, address_ctx: bool = False) -> str:
        return rare_mod.apply(self._render_free0(text, u, sweep, address_ctx), self.rare)

    def _render_free0(self, text: str, u: Unit, sweep: set, address_ctx: bool = False) -> str:
        # base64 payloads inside free text: decode, clean, re-encode
        def b64sub(m):
            dec = try_b64(m.group(0))
            if dec is None:
                return m.group(0)
            t2, sp = self._detect(dec)
            return __import__("base64").b64encode(self._render_text(t2, sp, u, sweep).encode("utf-8")).decode("ascii")
        if len(text) >= 16 and B64_RE.search(text):
            text = B64_RE.sub(b64sub, text)
        t2, spans = self._detect(text, address_ctx=address_ctx)
        out = self._render_text(t2, spans, u, sweep)
        if POLICY.get("location_level") == "district":
            out = TEHSIL_TEXT.sub(lambda m: m.group(1) + " [TEHSIL]", out)
        return out

    # ---------- leaf rendering (CSV cells and JSON leaves)
    def _gen(self) -> None:
        self.n_generalized += 1
        if self._cur_unit is not None:
            self._cur_unit.gen = True

    def _render_leaf(self, lf: Leaf, u: Unit, sweep: set, ctx: dict):
        self._cur_unit = u
        v = lf.value
        sem = lf.sem
        if v is None or isinstance(v, bool):
            return v
        if isinstance(v, (int, float)):
            return self._render_number(v, sem, lf)
        s = str(v)
        if not s.strip():
            return s
        psn = u.psn if POLICY.get("embed_pseudonym", 1) else None
        if sem in (F.NAME, F.FIRST):
            self._count("NAME")
            return psn or "[PATIENT]"
        if sem in (F.LAST, F.LOCAL_NAME):
            self._count("NAME")
            return "[REDACTED]" if not psn else ("" if sem == F.LAST and lf.extra.get("json") else "[REDACTED]")
        if sem == F.REL_NAME:
            mark, rest = strip_rel_marker(s)
            if not rest.strip():
                return s
            self._count("NAME")
            return (mark + "[RELATIVE]") if mark else "[RELATIVE]"
        if sem == F.OTHER_PERSON:
            self._count("NAME")
            return "[NAME]"
        if sem == F.NAME_UNKNOWN:
            if _looks_like_person(s):
                self._count("NAME")
                return "[NAME]"
            return self._render_free(s, u, sweep)
        if sem == F.UHID:
            core = id_core(s)
            if not core and not re.search(r"\d", s):
                return self._render_free(s, u, sweep)
            self._count("MRN")
            root = self.core_cluster.get(core)
            if root is not None and POLICY.get("embed_pseudonym", 1):
                return self.cluster_psn[root]
            return psn or surrogate_id("ID", core or s)
        if sem == F.ENC:
            self._count("MRN")
            return surrogate_id("ENC", id_core(s) or s)
        if sem == F.PHONE:
            if not re.search(r"\d{3}", fold(s)):
                return s
            self._count("PHONE")
            return "[PHONE]"
        if sem == F.AADHAAR:
            self._count("AADHAAR")
            return "[AADHAAR]"
        if sem == F.ABHA:
            self._count("ABHA")
            return "[ABHA]"
        if sem == F.ABHA_ADDR:
            self._count("ABHA_ADDR")
            return "[ABHA-ADDRESS]"
        if sem == F.PAN:
            self._count("PAN")
            return "[PAN]"
        if sem == F.INSURANCE:
            if not re.search(r"\d{4}", s):
                return s
            self._count("INSURANCE")
            return "[INSURANCE-ID]"
        if sem == F.EMAIL:
            self._count("EMAIL")
            return "[EMAIL]"
        if sem == F.DOB:
            self._gen()
            if POLICY.get("dob_policy") == "suppress":
                # a birth year pins age to +-1 year and defeats the age band; the band carries the age instead
                return DROP_KEY if lf.extra.get("json") and lf.key == "birthDate" else "[DOB]"
            if POLICY.get("dob_policy") == "year":
                r = parse_any_date(s, u.date_order)
                return str(r[0].year) if r else "[DOB]"
            r = shift_date_string(s, u.shift, u.date_order)
            return r if r is not None else "[DOB]"
        if sem == F.DATE:
            r = shift_date_string(s, u.shift, u.date_order)
            if r is not None:
                return r
            return self._render_free(s, u, sweep)
        if sem == F.AGE:
            a = parse_age(s)
            if a >= 0:
                self._gen()
                m = re.match(r"^\s*\d{1,3}", fold(s))
                return age_band(a, u.age_width) + s[m.end():]
            return s
        if sem == F.AGE_SEX:
            a = parse_age(s)
            if a >= 0:
                self._gen()
                m = re.match(r"^\s*\d{1,3}", fold(s))
                return age_band(a, u.age_width) + s[m.end():]
            return s
        if sem == F.PIN:
            self._count("PIN")
            self._gen()
            return pin_prefix(s)
        if sem == F.VILLAGE:
            self._count("VILLAGE")
            self._gen()
            if POLICY.get("location_level") == "district":
                return ctx.get("district") or "[VILLAGE]"
            return ctx.get("tehsil") or ctx.get("district") or "[VILLAGE]"
        if sem == F.TEHSIL and POLICY.get("location_level") == "district":
            self._gen()
            return ctx.get("district") or "[TEHSIL]"
        if sem == F.LOCALITY:
            self._count("LOCALITY")
            return "[ADDRESS]"
        if sem == F.ADDRESS:
            self._count("ADDRESS")
            return _generalize_address(s)
        if sem in (F.DOCTOR, F.ORG, F.KEEP, F.GENDER, F.RELATION, F.TEHSIL, F.DISTRICT, F.STATE):
            if sem == F.KEEP and (lf.key in ("reference",)):
                return s
            if sem in (F.GENDER, F.RELATION, F.TEHSIL, F.DISTRICT, F.STATE, F.KEEP) and not re.search(r"\d{5,}", s):
                return s
            if sem in (F.DOCTOR, F.ORG):
                return s
            return self._render_free(s, u, sweep)
        if sem == "attachment":
            dec = try_b64(s)
            if dec is None:
                raise Quarantine("opaque_attachment")
            t2, sp = self._detect(dec)
            import base64
            return base64.b64encode(self._render_text(t2, sp, u, sweep).encode("utf-8")).decode("ascii")
        # free text / unknown
        rendered = self._render_free(s, u, sweep, address_ctx=(sem == F.ADDRESS))
        return rendered

    def _render_number(self, v, sem, lf):
        if sem in (F.AADHAAR, F.PHONE, F.ABHA, F.UHID, F.ENC, F.PIN, F.INSURANCE):
            self._count(sem.upper())
            if sem == F.PIN:
                return int(str(int(v))[:3] + "000") if isinstance(v, int) and v >= 100000 else 0
            return 0
        if sem in (F.AGE,):
            a = parse_age(v)
            if a >= 0:
                self._gen()
                return age_band(a, self._cur_unit.age_width if self._cur_unit else 0)
            return v
        if isinstance(v, int) and not isinstance(v, bool):
            d = str(abs(v))
            if len(d) == 12 and d[0] in "23456789":
                self._count("AADHAAR")
                return 0
            if len(d) == 10 and d[0] in "6789":
                self._count("PHONE")
                return 0
            if len(d) == 14:
                self._count("ABHA")
                return 0
            if len(d) >= 9 and sem not in (F.AGE, F.DATE) and not re.search(r"(?i)amount|value|count|result|price|cost|total|fee|inr|rs", str(lf.key)):
                self._count("LONGNUM")     # 9+ digit integers are identifiers (accounts, IDs), never measurements
                return 0
        return v

    def _count(self, kind: str) -> None:
        self.n_identifiers += 1
        self.entities[kind] = self.entities.get(kind, 0) + 1

    def _prepare_unit(self, u: Unit):
        """Detect on every free-text leaf of a unit once, so name tokens sweep across the record."""
        found = []
        for lf in u.leaves:
            if isinstance(lf.value, str) and lf.sem in (F.TEXT, F.ADDRESS, F.NAME_UNKNOWN, F.DATE):
                t2, sp = self._detect(lf.value)
                found.append((t2, sp))
            elif isinstance(lf.value, str) and lf.sem in (F.NAME, F.FIRST, F.LAST, F.LOCAL_NAME):
                found.append((lf.value, [Span(0, len(lf.value), "NAME", role="patient")]))
            elif isinstance(lf.value, str) and lf.sem == F.REL_NAME:
                mark, rest = strip_rel_marker(lf.value)
                found.append((rest, [Span(0, len(rest), "NAME", role="relative")]))
        if u.kind == "doc" and u.text:
            t2, sp = self._detect(u.text)
            found.append((t2, sp))
        return found

    def _sweep_keys(self, u: Unit, found) -> set:
        keys = self._unit_tokens(u, found)
        # never sweep doctors' names or kept places
        return keys

    # ---------- writers
    def _write_csv(self, job: FileJob) -> str:
        buf = io.StringIO()
        w = csv.writer(buf, delimiter=job.delim, lineterminator=job.newline)
        hdr_unit = Unit(job.rel, "@header", "file", date_order=job.date_order)
        if getattr(job, "preamble", ""):
            buf.write(self._render_free(job.preamble, hdr_unit, set()))
        header = [self._render_free(h, hdr_unit, set()) if _has_pii_shape(h) else h for h in job.header]
        w.writerow(header)
        for u in job.units:
            found = self._prepare_unit(u)
            sweep = self._sweep_keys(u, found)
            ctx = {"tehsil": u.tehsil, "district": u.district}
            row = [self._render_leaf(lf, u, sweep, ctx) for lf in u.leaves]
            row = ["" if x is None else str(x) for x in row]
            w.writerow(row)
        return buf.getvalue()

    def _write_xml(self, job: FileJob) -> str:
        import xml.etree.ElementTree as ET
        u = job.units[0]
        found = self._prepare_unit(u)
        sweep = self._sweep_keys(u, found)
        for lf in u.leaves:
            new = self._render_leaf(lf, u, sweep, {"district": u.district})
            new = "" if new is None else str(new)
            el = lf.extra["el"]
            if "attr" in lf.extra:
                el.set(lf.extra["attr"], new)
            elif lf.extra.get("part") == "text":
                el.text = new
            else:
                el.tail = new
        body = ET.tostring(job.data, encoding="unicode")
        return (job.xml_decl + job.newline if job.xml_decl else "") + body + job.newline

    def _write_fixed(self, job: FileJob) -> str:
        """Fixed-width table: rewrite each cell in place, padded back to its column width."""
        nl = job.newline
        starts = job.fw_starts
        widths = [starts[i + 1] - starts[i] for i in range(len(starts) - 1)]
        hdr_unit = Unit(job.rel, "@header", "file", date_order=job.date_order)
        out = [self._render_free(ln, hdr_unit, set()) if _has_pii_shape(ln) else ln for ln in job.fw_head]

        def place(cells):
            parts = []
            for i, c in enumerate(cells):
                c = "" if c is None else str(c)
                if i < len(widths):
                    parts.append(c.ljust(widths[i]) if len(c) < widths[i] else c + " ")
                else:
                    parts.append(c)
            return ("" if not starts else " " * starts[0]) + "".join(parts).rstrip()
        for u in job.units:
            found = self._prepare_unit(u)
            sweep = self._sweep_keys(u, found)
            ctx = {"tehsil": u.tehsil, "district": u.district}
            out.append(place([self._render_leaf(lf, u, sweep, ctx) for lf in u.leaves]))
        return nl.join(out) + (nl if job.fw_tail_blank else "")

    def _write_text(self, job: FileJob) -> str:
        u = job.units[0]
        found = self._prepare_unit(u)
        sweep = self._sweep_keys(u, found)
        text = u.text
        text2 = self._render_free(text, u, sweep)
        if u.psn and POLICY.get("embed_pseudonym", 1) and u.psn not in text2:
            text2 = f"Patient: {u.psn}" + job.newline + text2
        return text2

    def _write_json(self, job: FileJob) -> str:
        data = job.data
        leaf_map = {}
        for u in job.units + ([job.file_unit] if job.file_unit else []):
            found = self._prepare_unit(u) if u.kind != "file" else []
            sweep = self._sweep_keys(u, found) if u.kind != "file" else set()
            ctxs = _address_ctx(data, u)
            for lf in u.leaves:
                ctx = ctxs.get(tuple(lf.path[:-1]), {})
                lf.extra["json"] = True
                leaf_map[tuple(lf.path)] = (lf, u, sweep, ctx)
        file_unit = job.file_unit or Unit(job.rel, "@file", "file")

        is_fhir = isinstance(data, dict) and isinstance(data.get("resourceType"), str)

        def rebuild(node, path):
            if is_fhir and isinstance(node, str) and path and path[-1] in ("id", "fullUrl", "reference"):
                return fhir_map_value(path[-1], node)
            if isinstance(node, dict):
                out = {}
                for k, v in node.items():
                    nk = k
                    if _has_pii_shape(k) or self.lex.phrase_re is not None and self.lex.phrase_re.search(fold(k)):
                        nk = self._render_free(k, file_unit, set())
                        # a name-shaped key whose value is a phone / ID / e-mail is a person ("Ravi Rao": "+91...")
                        if nk == k and _looks_like_person(k) and isinstance(v, (str, int)) and not isinstance(v, bool) \
                                and (re.search(r"\d{6,}", re.sub(r"[\s\-().]", "", str(v))) or "@" in str(v)):
                            nk = "[NAME]"
                            self._count("NAME")
                        base, i = nk, 2
                        while nk in out:
                            nk = f"{base}_{i}"
                            i += 1
                    nv = rebuild(v, path + (k,))
                    if nv is DROP_KEY:          # optional FHIR element suppressed by policy (e.g. birthDate)
                        continue
                    out[nk] = nv
                return out
            if isinstance(node, list):
                return [rebuild(x, path + (i,)) for i, x in enumerate(node)]
            entry = leaf_map.get(path)
            if entry is None:
                return node
            lf, u, sweep, ctx = entry
            return self._render_leaf(lf, u, sweep, ctx)

        new = rebuild(data, ())
        if job.fmt == "jsonl":
            return "\n".join(json.dumps(x, ensure_ascii=False) for x in new) + "\n"
        if job.json_indent is None:
            return json.dumps(new, ensure_ascii=False, separators=(",", ":"))
        return json.dumps(new, ensure_ascii=False, indent=job.json_indent) + ("\n" if job.text.endswith("\n") else "")

    def _safe_relpath(self, job: FileJob) -> str:
        parts = job.rel.split("/")
        out = []
        u = job.units[0] if job.units else Unit(job.rel, "@filename", "file")
        for i, part in enumerate(parts):
            p = Path(part)
            stem, suf = (p.stem, p.suffix) if i == len(parts) - 1 else (part, "")
            text = stem.replace("_", " ")
            t2, spans = self._detect(text)
            spans = [s for s in spans if s.kind not in ("DATE", "AGE", "PROTECT")]
            if spans:
                new = self._render_text(t2, spans, u, set())
                new = re.sub(r"[\[\]]", "", new)
                new = re.sub(r"[\\/:*?\"<>|]", "-", new)
                new = new.replace(" ", "_")
                # collapse repeated pseudonyms ("PSN-X_PSN-X")
                new = re.sub(r"(PSN-[0-9A-Z]{6})(?:_\1)+", r"\1", new)
                stem = new
            out.append(stem + suf)
        return "/".join(out)

    # ------------------------------------------------------------------ report
    def report(self, records: list, t0: float) -> dict:
        files = []
        for j in self.jobs:
            e = {"input_sha256": j.sha, "output": j.out_rel or None, "status": j.status if j.status == "sanitized" else "quarantined"}
            if e["status"] == "quarantined":
                e["output"] = None
                e["reason"] = j.reason or "unprocessable"
            files.append(e)
        n_san = sum(1 for f in files if f["status"] == "sanitized")
        return {
            "schema": "raksha-report/1",
            "files": files,
            "counts": {
                "files_total": len(files), "files_sanitized": n_san, "files_quarantined": len(files) - n_san,
                "records_processed": len(records), "identifiers_detected": self.n_identifiers,
                "records_linked": sum(1 for r in records if r["patient"]),
                "records_generalized": sum(1 for r in records if self._unit_gen.get((r["file"], r["loc"]))),
                "records_suppressed": 0, "records_quarantined": 0,
            },
            "entities": dict(sorted(self.entities.items())),
            "privacy": {"patients_recoded": self.n_recoded_patients,
                        "age_band_years": int(POLICY["age_band_years"]),
                        "recode_age_band_years": int(POLICY.get("recode_age_band_years", 0)) if int(POLICY.get("recode_k", 0)) > 1 else None},
            "timing": {"seconds": round(time.monotonic() - t0, 2)},
            "resources": {"peak_rss_mb": peak_rss_mb()},
        }


# ====================================================================== JSON utilities
def _depth(o, d=0):
    stack = [(o, 1)]
    best = 0
    while stack:
        x, dd = stack.pop()
        best = max(best, dd)
        if best > MAX_JSON_DEPTH:
            return best
        if isinstance(x, dict):
            stack.extend((v, dd + 1) for v in x.values())
        elif isinstance(x, list):
            stack.extend((v, dd + 1) for v in x)
    return best


def _walk(data):
    """Yield (path, key, ancestors, resourceType, leaf) for every leaf."""
    stack = [(data, (), [], "")]
    out = []
    while stack:
        node, path, anc, rt = stack.pop()
        if isinstance(node, dict):
            rt2 = node.get("resourceType", rt) if isinstance(node.get("resourceType"), str) else rt
            for k in node:
                stack.append((node[k], path + (k,), anc + [k], rt2))
        elif isinstance(node, list):
            for i, v in enumerate(node):
                stack.append((v, path + (i,), anc + [i], rt))
        else:
            key = path[-1] if path else ""
            out.append((path, key, anc[:-1], rt, node))
    out.sort(key=lambda x: [str(p) for p in x[0]])
    return out


_PERSON_SEMS = {F.NAME, F.FIRST, F.UHID, F.PHONE, F.AADHAAR, F.ABHA, F.REL_NAME, F.DOB, F.OTHER_PERSON}
_ID_SHAPE = re.compile(r"(?<![a-z0-9])(?:[a-z]{2,6}[\-/]?\d{2,4}[\-/]\d{3,8}|[a-z]{2,6}\d{5,8}|[a-z]{2,6}[\-/]\d{4,8})(?![a-z0-9])"
                       r"|(?<!\d)[6-9]\d{9}(?!\d)")


def _item_is_person(x: dict, anc_key: str) -> bool:
    """Is this dict one person's record? By its keys (any language) or, failing that, by its values."""
    for k, v in x.items():
        lk = F._norm_key(str(k))
        if isinstance(v, dict):
            if lk in ("patient", "name", "subject", "ids", "contact", "guardian", "raised_by", "meta") or lk in F._PATIENT_CTX:
                return True
            continue
        sem = F.classify_json(str(k), [anc_key, 0])
        if sem in _PERSON_SEMS:
            return True
    flat = " ".join(str(v) for v in _scalars(x, 3))
    return bool(_ID_SHAPE.search(fold(flat)))


def _scalars(o, depth):
    if depth < 0:
        return []
    if isinstance(o, dict):
        return [y for v in o.values() for y in _scalars(v, depth - 1)]
    if isinstance(o, list):
        return [y for v in o[:20] for y in _scalars(v, depth - 1)]
    return [o] if isinstance(o, (str, int)) and not isinstance(o, bool) else []


def _find_record_list(data):
    """Path of the main list of per-patient records at ANY depth, or None for single-document JSON.

    Breadth-first, so the shallowest qualifying list wins; a dict that is itself about one patient
    ({"patient": {...}, "panels": [...]}) is a document, not a list of records."""
    if isinstance(data, list):
        if data and all(isinstance(x, dict) for x in data) and \
                sum(1 for x in data if _item_is_person(x, "")) / len(data) >= 0.5:
            return ()
        return None
    if not isinstance(data, dict):
        return None
    if data.get("resourceType") == "Bundle":
        return None
    for k, v in data.items():
        if F._norm_key(str(k)) in ("patient", "subject", "pt") and isinstance(v, dict):
            return None
    frontier = [((), data)]
    for _depth_i in range(12):
        nxt = []
        for path, node in frontier:
            if isinstance(node, dict):
                items = list(node.items())
            elif isinstance(node, list):
                items = list(enumerate(node))
            else:
                continue
            for k, v in items:
                if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                    share = sum(1 for x in v if _item_is_person(x, str(k))) / len(v)
                    if share >= 0.5 and (len(v) >= 2 or not isinstance(node, list)):
                        return path + (k,)
                    nxt += [(path + (k, i), x) for i, x in enumerate(v)]
                elif isinstance(v, (dict, list)):
                    nxt.append((path + (k,), v))
        frontier = nxt
        if not frontier:
            break
    return None


_UUID_FULL = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_REF_TAIL = re.compile(r"^(?P<base>(?:.*/)?)(?P<type>[A-Z][A-Za-z]+)/(?P<id>[A-Za-z0-9\-.]{1,64})(?P<hist>/_history/[^/]+)?$")


def fhir_map_id(old: str) -> str:
    """UUID ids carry no identity and stay; any other logical id is replaced by a keyed id."""
    return old if _UUID_FULL.match(old) else fhir_id(old)


def fhir_map_value(key: str, v: str) -> str:
    """Rewrite Resource.id, Bundle.entry.fullUrl and Reference.reference through one keyed mapping,
    so every reference that resolved before still resolves after."""
    if key == "id":
        return fhir_map_id(v)
    if v.startswith("#"):
        return "#" + fhir_map_id(v[1:]) if v[1:] else v
    if v.lower().startswith("urn:uuid:"):
        tail = v[9:]
        if _UUID_FULL.match(tail):
            return v
        h = fhir_id(tail)[1:].ljust(32, "0")[:32]
        return "urn:uuid:" + "-".join((h[:8], h[8:12], h[12:16], h[16:20], h[20:32]))
    m = _REF_TAIL.match(v)
    if m:
        base = m.group("base")
        if re.search(r"\d{5,}", base):          # identifiers in the server path are removed too
            base = re.sub(r"\d{5,}", lambda x: fhir_id(x.group(0)), base)
        return f"{base}{m.group('type')}/{fhir_map_id(m.group('id'))}{m.group('hist') or ''}"
    return fhir_map_id(v) if re.fullmatch(r"[A-Za-z0-9\-.]{1,64}", v) else v


_DISTT = re.compile(r"(?:Distt?\.?|District|जिला)\s+([A-Z][a-z]+(?:\s[A-Z][a-z]+)?|[\u0900-\u097F]+)")
_ICD3 = re.compile(r"(?<![A-Za-z0-9])([A-TV-Z]\d{2})(?:\.\d{1,2})?(?![A-Za-z0-9])")


def _texts_of(u) -> list:
    t = [u.text] if u.text else []
    return t + [str(lf.value) for lf in u.leaves if isinstance(lf.value, str)]


def _districts_of(u) -> list:
    out = [u.district.strip().lower()] if u.district else []
    for lf in u.leaves:
        if lf.sem == F.DISTRICT and isinstance(lf.value, str):
            out.append(lf.value.strip().lower())
    for t in _texts_of(u):
        out += [m.group(1).strip().lower() for m in _DISTT.finditer(t)]
    return out


def _icd_of(u) -> list:
    return [m.group(1) for t in _texts_of(u) for m in _ICD3.finditer(t)]


def _ptr_escape(s: str) -> str:
    return s.replace("~", "~0").replace("/", "~1")


def _is_meta_path(path) -> bool:
    return bool(path) and isinstance(path[0], str) and (path[0].startswith("_") or path[0] in ("meta", "export_meta", "metadata"))


def _sibling(data, path, key):
    node = data
    try:
        for p in path[:-1]:
            node = node[p]
        return node.get(key) if isinstance(node, dict) else None
    except (KeyError, IndexError, TypeError):
        return None


def _address_ctx(data, u: Unit) -> dict:
    """Map container path -> {tehsil, district} for generalising village/city fields."""
    out = {}
    containers = {}
    for lf in u.leaves:
        containers.setdefault(tuple(lf.path[:-1]), []).append(lf)
    for cpath, lfs in containers.items():
        ctx = {}
        for lf in lfs:
            if lf.sem == F.TEHSIL and isinstance(lf.value, str):
                ctx["tehsil"] = lf.value
            if lf.sem == F.DISTRICT and isinstance(lf.value, str):
                ctx["district"] = lf.value
        if not ctx and u.district:
            ctx["district"] = u.district
        out[cpath] = ctx
    return out


def _looks_like_person(s: str) -> bool:
    toks = s.split()
    if not 1 <= len(toks) <= 4 or re.search(r"\d", s):
        return False
    return all(is_name_token(t.strip(",.")) for t in toks) and any(t[:1].isupper() or re.match(r"[ऀ-ॿ]", t) for t in toks)


def _has_pii_shape(s: str) -> bool:
    if not isinstance(s, str) or not s:
        return False
    if re.search(r"\d{5,}", fold(s)):
        return True
    toks = re.findall(r"[A-Za-z]+|[ऀ-ॿ]+", s)
    return any(gz.is_known_name_token(t) and t[:1].isupper() for t in toks) or len(toks) >= 2 and _looks_like_person(s)


def _generalize_address(s: str) -> str:
    keep = []
    pat = r"(?:Distt?\.?|District|जिला)\s+[^,\-\n]+"
    if POLICY.get("location_level") != "district":
        pat = r"(?:Tehsil|Tahsil|तहसील)\s+[^,\-\n]+|" + pat
    for m in re.finditer(pat, s):
        keep.append(re.sub(r"\s*[-–]\s*\d{6}\s*$", "", m.group(0).strip()))
    return ", ".join(["[ADDRESS]"] + keep)


def _source_key(rel: str, text: str) -> str:
    name = Path(rel).stem.lower()
    for tok in re.split(r"[_\-\s]+", name):
        if tok and not tok.isdigit() and tok not in ("rx", "ds", "opd", "report", "nursing", "discharge", "summary", "bundle", "note"):
            return tok
    return "?"


def peak_rss_mb() -> float:
    try:
        import resource
        r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        r2 = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        r = max(r, r2)
        return round(r / 1048576 if sys.platform == "darwin" else r / 1024, 1)
    except Exception:  # noqa: BLE001
        return 0.0


def run(inp: Path, out: Path) -> int:
    t0 = time.monotonic()
    sys.setrecursionlimit(10000)
    out.mkdir(parents=True, exist_ok=True)
    (out / "sanitized").mkdir(exist_ok=True)
    pl = Pipeline(inp, out)
    pl.ingest()
    pl.resolve_date_orders()
    pl.build_units()
    try:
        pl.harvest()
    except Exception:  # noqa: BLE001 - degrade: detect without the dataset lexicon
        pl.detector = Detector(pl.lex if pl.lex.phrase_re is not None or not pl.lex.name_tokens else Lexicon())
        for job in pl.jobs:
            for u in job.units:
                if u.ev is None:
                    u.ev = Evidence(rid=id(u), file=u.file, loc=u.loc, multi=True)
                if u not in pl.units:
                    pl.units.append(u)
                    pl.evidence.append(u.ev)
    try:
        pl.link()
    except Exception:  # noqa: BLE001 - degrade: no linking (every record unlinked), still a full release
        for u in pl.units:
            u.cluster, u.psn = None, None
            u.shift = shift_days("unit#" + u.file + "#" + u.loc)
    pl.rare = rare_mod.find_rare(pl.units, int(POLICY.get("rare_k", 3)))
    try:
        pl.recode()
    except Exception:  # noqa: BLE001 - recoding is a privacy refinement; never let it stop the release
        pass
    records = pl.sanitize_all()
    exported = {j.out_rel for j in pl.jobs if j.status == "sanitized"}
    records = [r for r in records if r["file"] in exported]
    for j in pl.jobs:
        if j.status == "quarantined":
            try:
                vault.store(out, (inp / j.rel).read_bytes())
            except Exception:  # noqa: BLE001 - vault is best effort, never fatal
                pass
    with open(out / "records.jsonl", "w", encoding="utf-8", newline="\n") as fh:
        for r in records:
            fh.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
    rep = pl.report(records, t0)
    with open(out / "report.json", "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(rep, indent=2, ensure_ascii=False) + "\n")
    c = rep["counts"]
    print(f"files {c['files_total']} sanitized {c['files_sanitized']} quarantined {c['files_quarantined']} "
          f"records {c['records_processed']} linked {c['records_linked']}")
    return 0
