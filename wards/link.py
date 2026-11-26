"""Cross-document identity resolution.

Two records are linked only when the data itself connects them:
  1. a shared strong identifier (UHID/MRN digit core, IPD number, Aadhaar, ABHA, PAN,
     insurance ID, e-mail) and the names do not contradict each other; a shared phone
     additionally needs a compatible given name (families share phones);
  2. otherwise, the same name plus a second clue (DOB, relative's name, or village + age +-2)
     and that combination must point to exactly ONE existing cluster.
Clusters are merged only if they have no hard conflict (Aadhaar, DOB, gender, age).
A wrong merge costs more than a missed link, so every rule errs towards not linking.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import gazetteer as gz
from .translit import name_key, vowel_key


def name_tokens(text: str) -> list:
    import re
    out = []
    for tok in re.findall(r"[A-Za-zÀ-ɏ]+|[ऀ-ॣ॰-ॿ]+", text or ""):
        low = tok.lower()
        if low in gz.HONORIFIC_SUFFIX or low in gz.HONORIFIC_PREFIX or low in gz.DOCTOR_PREFIX:
            continue
        if low in gz.GENERIC_NAME_TOKENS and low not in ("md", "mohd"):
            continue
        if low in ("s", "o", "d", "w", "c"):
            continue
        out.append(tok)
    return out


def tok_keys(tokens) -> set:
    keys = set()
    for t in tokens:
        vk = vowel_key(t)
        nk = name_key(t)
        if vk:
            keys.add("v:" + vk)
        if nk and (len(nk) >= 3 or nk == "mhmd"):
            keys.add("n:" + nk)
    return keys


def _is_surname_key(k: str) -> bool:
    return k[2:] in _SURNAME_KEYSET


_SURNAME_KEYSET = {("n:" + name_key(s))[2:] for s in gz.SURNAMES} | {vowel_key(s) for s in gz.SURNAMES}
_GIVEN_KEYSET = {name_key(s) for s in gz.GIVEN_NAMES} | {vowel_key(s) for s in gz.GIVEN_NAMES}


@dataclass
class Evidence:
    rid: int
    file: str
    loc: str
    names: list = field(default_factory=list)        # list of token lists (patient names)
    weak_names: list = field(default_factory=list)   # honorific / gazetteer mentions
    rel_names: list = field(default_factory=list)
    uhids: set = field(default_factory=set)
    encs: set = field(default_factory=set)
    phones: set = field(default_factory=set)
    aadhaar: set = field(default_factory=set)
    abha: set = field(default_factory=set)
    pan: set = field(default_factory=set)
    ins: set = field(default_factory=set)
    email: set = field(default_factory=set)
    dob: set = field(default_factory=set)
    ages: list = field(default_factory=list)
    gender: set = field(default_factory=set)
    villages: set = field(default_factory=set)
    multi: bool = False                              # unit mentions several patients: never link

    def strong(self) -> list:
        """Identifiers that belong to ONE person (hospital IDs, Aadhaar, ABHA)."""
        out = []
        for kind, vals in (("uhid", self.uhids), ("enc", self.encs), ("aadhaar", self.aadhaar), ("abha", self.abha)):
            for v in vals:
                out.append((kind, v))
        return out

    def shared(self) -> list:
        """Identifiers a family can share (payer PAN, family insurance / policy, family e-mail): like phones,
        they link only together with an agreeing given name."""
        out = []
        for kind, vals in (("pan", self.pan), ("ins", self.ins), ("email", self.email)):
            for v in vals:
                out.append((kind, v))
        return out

    def has_identity(self) -> bool:
        return bool(self.names or self.weak_names or self.strong() or self.shared() or self.phones)


class _Cluster:
    __slots__ = ("members", "name_keys", "given_keys", "rel_keys", "dob", "aadhaar", "gender", "ages", "villages", "anchored")

    def __init__(self, ev: Evidence):
        self.members = [ev.rid]
        self.name_keys = set()
        self.given_keys = set()
        self.rel_keys = set()
        self.dob = set(ev.dob)
        self.aadhaar = set(ev.aadhaar)
        self.gender = set(ev.gender)
        self.ages = list(ev.ages)
        self.villages = set(ev.villages)
        self.anchored = bool(ev.strong() or ev.shared() or ev.phones)
        for n in ev.names + ev.weak_names:
            ks = tok_keys(n)
            self.name_keys |= ks
            self.given_keys |= {k for k in ks if not _is_surname_key(k)}
        for n in ev.rel_names:
            self.rel_keys |= {k for k in tok_keys(n) if not _is_surname_key(k)}

    def absorb(self, o: "_Cluster") -> None:
        self.members += o.members
        self.name_keys |= o.name_keys
        self.given_keys |= o.given_keys
        self.rel_keys |= o.rel_keys
        self.dob |= o.dob
        self.aadhaar |= o.aadhaar
        self.gender |= o.gender
        self.ages += o.ages
        self.villages |= o.villages
        self.anchored = self.anchored or o.anchored


def shared_signals(x: "Evidence", y: "Evidence") -> int:
    """Independent PERSON-level signals two records share (family-shareable identifiers do not count)."""
    n = 0
    for attr in ("uhids", "encs", "aadhaar", "abha", "dob"):
        if getattr(x, attr) & getattr(y, attr):
            n += 1
    return n


def _conflict(a: _Cluster, b: _Cluster, *, strict_names: bool, names_ok: bool = False) -> bool:
    if a.aadhaar and b.aadhaar and not (a.aadhaar & b.aadhaar):
        return True
    if a.dob and b.dob and not (a.dob & b.dob):
        return True
    if a.gender and b.gender and not (a.gender & b.gender):
        return True
    if strict_names and a.ages and b.ages and min(abs(x - y) for x in a.ages for y in b.ages) > 3:
        return True
    if not names_ok and a.name_keys and b.name_keys and not (a.name_keys & b.name_keys):
        return True
    if strict_names and a.given_keys and b.given_keys and not (a.given_keys & b.given_keys):
        return True
    if strict_names and a.villages and b.villages and not (a.villages & b.villages):
        return True               # same name and relative, different villages: homonyms, not one person
    return False


class Linker:
    def __init__(self, evidence: list):
        self.ev = sorted(evidence, key=lambda e: (e.file, e.loc))
        self.parent = {e.rid: e.rid for e in self.ev}
        self.cl = {e.rid: _Cluster(e) for e in self.ev}
        self.byrid = {e.rid: e for e in self.ev}

    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b, *, strict_names: bool, names_ok: bool = False) -> bool:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return True
        ca, cb = self.cl[ra], self.cl[rb]
        if _conflict(ca, cb, strict_names=strict_names, names_ok=names_ok):
            return False
        if ra > rb:
            ra, rb, ca, cb = rb, ra, cb, ca
        self.parent[rb] = ra
        ca.absorb(cb)
        del self.cl[rb]
        return True

    def _matches(self, r, by_given) -> list:
        """Clusters that share a given name AND a second clue with cluster r, without any conflict."""
        c = self.cl[r]
        cands = set()
        for k in c.given_keys:
            cands |= by_given.get(k, set())
        cands = {self.find(x) for x in cands} - {r}
        matches = []
        for o in sorted(cands):
            oc = self.cl.get(o)
            if oc is None or _conflict(c, oc, strict_names=True) or not (c.given_keys & oc.given_keys):
                continue
            if c.dob and oc.dob and (c.dob & oc.dob):
                matches.append(o)
            elif c.rel_keys and oc.rel_keys and (c.rel_keys & oc.rel_keys):
                matches.append(o)
            elif c.villages and oc.villages and (c.villages & oc.villages) and c.ages and oc.ages and \
                    min(abs(x - y) for x in c.ages for y in oc.ages) <= 2:
                matches.append(o)
        anchored = [o for o in matches if self.cl[o].anchored]
        if len(anchored) == 1 and (c.anchored is False or len(matches) == 1):
            # the other candidates must be compatible with the anchored one (duplicates of this fragment)
            a0 = self.cl[anchored[0]]
            if all(not _conflict(self.cl[o], a0, strict_names=True) for o in matches if o != anchored[0]):
                return anchored
        return matches

    def run(self) -> dict:
        usable = [e for e in self.ev if not e.multi and e.has_identity()]
        # ---- phase 1: strong identifiers
        index: dict = {}
        for e in usable:
            for key in e.strong():
                index.setdefault(key, []).append(e.rid)
        for key in sorted(index):
            rids = index[key]
            for r in rids[1:]:
                # two independent strong signals outweigh a name mismatch (e.g. a transliteration miss)
                ok = shared_signals(self.byrid[rids[0]], self.byrid[r]) >= 2
                self.union(rids[0], r, strict_names=False, names_ok=ok)
        # ---- phase 1b: phones and family-shareable IDs (need a compatible given name)
        pidx: dict = {}
        for e in usable:
            for p in e.phones:
                pidx.setdefault(("phone", p), []).append(e.rid)
            for key in e.shared():
                pidx.setdefault(key, []).append(e.rid)
        def fits(a, b):
            ca, cb = self.cl[a], self.cl[b]
            if _conflict(ca, cb, strict_names=True):
                return False
            return bool(ca.given_keys & cb.given_keys) or not ca.name_keys or not cb.name_keys

        for p in sorted(pidx):
            # a cluster joins others through a shared phone / family ID only when everything it fits is one
            # person (all mutually compatible): father and son "Rajesh Verma" on one phone stay apart, and a
            # note that fits both is left unlinked instead of joined to whichever came first
            for _ in range(len(pidx[p])):
                roots = sorted({self.find(r) for r in pidx[p]})
                if len(roots) < 2 or len(roots) > 50:      # > 50 people on one number: a helpline, not a person
                    break
                merged = False
                for a in roots:
                    comp = [b for b in roots if b != a and fits(a, b)]
                    grp = set(comp) | {a}
                    # one person both ways: the group is mutually compatible and nothing in it fits anyone outside
                    if comp and all(fits(x, y) for i, x in enumerate(comp) for y in comp[i + 1:]) and \
                            all(not fits(b, c) for b in comp for c in roots if c not in grp):
                        for b in comp:
                            merged = self.union(a, b, strict_names=True) or merged
                        if merged:
                            break
                if not merged:
                    break
        # ---- phase 2: name + second clue, only when unique
        for _round in range(2):
            changed = False
            roots = sorted(set(self.find(e.rid) for e in usable))
            by_given: dict = {}
            for r in roots:
                for k in self.cl[r].given_keys:
                    by_given.setdefault(k, set()).add(r)
            for r in roots:
                if self.find(r) != r:
                    continue
                c = self.cl[r]
                if not c.given_keys:
                    continue
                matches = self._matches(r, by_given)
                if len(matches) == 1:
                    # uniqueness the other way round: the match must not also fit another cluster
                    o = matches[0]
                    rev = self._matches(o, by_given)
                    cr = self.cl[r]
                    if r not in rev or not all(x == r or (not self.cl[x].anchored and
                                                          not _conflict(self.cl[x], cr, strict_names=True)) for x in rev):
                        continue          # o also fits a different person: ambiguous, do not link
                    if self.union(r, o, strict_names=True):
                        changed = True
            if not changed:
                break
        # ---- assign cluster keys
        out = {}
        for e in self.ev:
            if e.multi or not e.has_identity():
                out[e.rid] = None
                continue
            root = self.find(e.rid)
            c = self.cl[root]
            if len(c.members) == 1 and not (e.strong() or e.phones):
                out[e.rid] = None      # a lone name with no identifier: too weak to pseudonymise
                continue
            out[e.rid] = root
        return out

    def cluster_of(self, rid):
        return self.find(rid)
