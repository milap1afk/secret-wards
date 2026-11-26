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
from .privacy import (age_band, pin_prefix, pseudonym, shift_date_string, shift_days, surrogate_id,
                      parse_any_date)
from .textnorm import decode_escapes, fold, strip_zero_width, try_b64, B64_RE
from .translit import name_key, vowel_key

TEXT_EXT = {".txt", ".text", ".log", ".md", ".note", ".notes"}
CSV_EXT = {".csv", ".tsv", ".psv", ".tab"}
JSON_EXT = {".json", ".fhir", ".ndjson", ".jsonl"}
MAX_JSON_DEPTH = 200


TEHSIL_TEXT = re.compile(r"(Tehsil|Tahsil|Teh\.|तहसील)\s+(?!\[)(?:[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?|[\u0900-\u097F]+)")


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


def sniff_format(rel: str, text: str) -> str:
    ext = Path(rel).suffix.lower()
    head = text.lstrip()[:1]
    if ext in JSON_EXT:
        return "json"
    if ext in CSV_EXT:
        if head in ("{", "["):
            raise Quarantine("format_mismatch")
        return "csv"
    if ext in TEXT_EXT:
        if head == "{" and text.rstrip().endswith("}"):
            try:
                json.loads(text)
                return "text"
            except ValueError:
                pass
        return "text"
    raise Quarantine("unsupported_format")


def sniff_delimiter(rel: str, text: str) -> str:
    first = text.split("\n", 1)[0]
    if Path(rel).suffix.lower() == ".tsv" or first.count("\t") > first.count(","):
        return "\t"
    if first.count(";") > first.count(",") and first.count(";") >= 2:
        return ";"
    if first.count("|") > first.count(",") and first.count("|") >= 2:
        return "|"
    return ","


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
                text = decode_bytes(raw)
                text = strip_zero_width(text)
                job.newline = "\r\n" if "\r\n" in text else "\n"
                job.fmt = sniff_format(rel, text)
                job.text = text
                if job.fmt == "json":
                    self._load_json(job)
                elif job.fmt == "csv":
                    self._load_csv(job)
                job.date_order = self._date_order(job)
            except Quarantine as q:
                job.status, job.reason = "quarantined", str(q)
            except RecursionError:
                job.status, job.reason = "quarantined", "nesting_too_deep"
            except Exception as exc:  # noqa: BLE001 - never leak content, only the type
                job.status, job.reason = "quarantined", "parse_error_" + type(exc).__name__

    def _load_json(self, job: FileJob) -> None:
        txt = job.text
        if Path(job.rel).suffix.lower() in (".ndjson", ".jsonl"):
            raise Quarantine("unsupported_format")
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

    def _load_csv(self, job: FileJob) -> None:
        job.delim = sniff_delimiter(job.rel, job.text)
        rows = list(csv.reader(io.StringIO(job.text, newline=""), delimiter=job.delim))
        if not rows:
            raise Quarantine("empty_file")
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
                if job.fmt == "csv":
                    self._units_csv(job)
                elif job.fmt == "json":
                    self._units_json(job)
                else:
                    u = Unit(job.rel, "doc", "doc", text=job.text, date_order=job.date_order)
                    job.units = [u]
            except Exception as exc:  # noqa: BLE001
                job.status, job.reason = "quarantined", "parse_error_" + type(exc).__name__

    def _units_csv(self, job: FileJob) -> None:
        sems = [F.classify_header(h) for h in job.header]
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
                self._evidence(u)
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
                elif job.fmt == "json":
                    body = self._write_json(job)
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
            self.n_generalized += 1
            return age_band(a)
        self.n_identifiers += 1
        self.entities[k] = self.entities.get(k, 0) + 1
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
            return pin_prefix(seg)
        return "[REDACTED]"

    def _detect(self, text: str, *, address_ctx: bool = False) -> list:
        dt_ = decode_escapes(text)
        if dt_ != text:
            text = dt_
        det_text = text.replace("_", " ")
        return text, self.detector.detect(det_text, address_ctx=address_ctx)

    def _render_free(self, text: str, u: Unit, sweep: set, address_ctx: bool = False) -> str:
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
    def _render_leaf(self, lf: Leaf, u: Unit, sweep: set, ctx: dict):
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
            self.n_generalized += 1
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
                self.n_generalized += 1
                m = re.match(r"^\s*\d{1,3}", fold(s))
                return age_band(a) + s[m.end():]
            return s
        if sem == F.AGE_SEX:
            a = parse_age(s)
            if a >= 0:
                self.n_generalized += 1
                m = re.match(r"^\s*\d{1,3}", fold(s))
                return age_band(a) + s[m.end():]
            return s
        if sem == F.PIN:
            self._count("PIN")
            return pin_prefix(s)
        if sem == F.VILLAGE:
            self._count("VILLAGE")
            self.n_generalized += 1
            if POLICY.get("location_level") == "district":
                return ctx.get("district") or "[VILLAGE]"
            return ctx.get("tehsil") or ctx.get("district") or "[VILLAGE]"
        if sem == F.TEHSIL and POLICY.get("location_level") == "district":
            self.n_generalized += 1
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
                self.n_generalized += 1
                return age_band(a)
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

        def rebuild(node, path):
            if isinstance(node, dict):
                out = {}
                for k, v in node.items():
                    nk = k
                    if _has_pii_shape(k) or self.lex.phrase_re is not None and self.lex.phrase_re.search(fold(k)):
                        nk = self._render_free(k, file_unit, set())
                        base, i = nk, 2
                        while nk in out:
                            nk = f"{base}_{i}"
                            i += 1
                    out[nk] = rebuild(v, path + (k,))
                return out
            if isinstance(node, list):
                return [rebuild(x, path + (i,)) for i, x in enumerate(node)]
            entry = leaf_map.get(path)
            if entry is None:
                return node
            lf, u, sweep, ctx = entry
            return self._render_leaf(lf, u, sweep, ctx)

        new = rebuild(data, ())
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
                "records_generalized": sum(1 for u in self.units if u.ev and (u.ev.ages or u.ev.dob or u.ev.villages)),
                "records_suppressed": 0, "records_quarantined": 0,
            },
            "entities": dict(sorted(self.entities.items())),
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


def _item_is_person(x: dict, anc_key: str) -> bool:
    for k, v in x.items():
        if isinstance(v, dict):
            if str(k).lower() in ("patient", "name", "subject", "ids", "contact", "guardian", "raised_by", "meta"):
                return True
            continue
        sem = F.classify_json(str(k), [anc_key, 0])
        if sem in _PERSON_SEMS:
            return True
    return False


def _find_record_list(data):
    """Path of the main list of per-patient records, or None for single-document JSON."""
    if not isinstance(data, dict):
        return None
    if data.get("resourceType") == "Bundle":
        return None
    # a document about ONE patient: {"patient": {...}, "panels": [...]}
    for k, v in data.items():
        if str(k).lower() in ("patient", "subject", "pt") and isinstance(v, dict):
            return None
    frontier = [((), data)]
    for _depth_i in range(3):
        nxt = []
        for path, node in frontier:
            if not isinstance(node, dict):
                continue
            for k, v in node.items():
                if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                    share = sum(1 for x in v if _item_is_person(x, str(k))) / len(v)
                    if share >= 0.5:
                        return path + (k,)
                elif isinstance(v, dict):
                    nxt.append((path + (k,), v))
        frontier = nxt
    return None


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
    pl.harvest()
    pl.link()
    records = pl.sanitize_all()
    exported = {j.out_rel for j in pl.jobs if j.status == "sanitized"}
    records = [r for r in records if r["file"] in exported]
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
