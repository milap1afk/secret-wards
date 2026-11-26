#!/usr/bin/env python3
"""Linking safety: every path found in a line-by-line review of wards/link.py that could merge two different
people, plus positive controls that must still link. Run: python3 tests/test_linking.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from wards.link import Evidence, Linker  # noqa: E402

_rid = [0]


def ev(**kw):
    _rid[0] += 1
    e = Evidence(rid=_rid[0], file=f"f{_rid[0]}", loc="doc")
    for k, v in kw.items():
        setattr(e, k, v)
    return e


def linked(a, b, *others):
    out = Linker([a, b, *others]).run()
    return out[a.rid] is not None and out[a.rid] == out[b.rid]


CASES = []


def case(name, want_linked):
    def deco(fn):
        CASES.append((name, want_linked, fn))
        return fn
    return deco


@case("spouses billed under one payer PAN, policy and phone (same surname) stay apart", False)
def _():
    h = ev(names=[["Ramesh", "Yadav"]], uhids={"1110001"}, pan={"ABCPY1234K"}, ins={"POL/1/2345678"}, phones={"9811100001"})
    w = ev(names=[["Sunita", "Yadav"]], uhids={"1110002"}, pan={"ABCPY1234K"}, ins={"POL/1/2345678"}, phones={"9811100001"})
    return h, w


@case("family e-mail shared by two siblings stays apart", False)
def _():
    a = ev(names=[["Kavita", "Pal"]], uhids={"2220001"}, email={"palfamily@gmail.com"})
    b = ev(names=[["Sunil", "Pal"]], uhids={"2220002"}, email={"palfamily@gmail.com"})
    return a, b


@case("two 'Sunita W/o Ramesh' from different villages stay apart", False)
def _():
    a = ev(names=[["Sunita"]], rel_names=[["Ramesh"]], villages={"rmpr"}, phones={"9811100002"}, ages=[40])
    b = ev(names=[["Sunita"]], rel_names=[["Ramesh"]], villages={"sngr"}, phones={"9811100003"}, ages=[41])
    return a, b


@case("ambiguous fragment 'Asha W/o Kamal' fitting two anchored patients is not linked to either", False)
def _():
    frag = ev(names=[["Asha"]], rel_names=[["Kamal"]])
    p1 = ev(names=[["Asha", "Rajput"]], rel_names=[["Kamal", "Rajput"]], uhids={"3330001"})
    p2 = ev(names=[["Asha", "Verma"]], rel_names=[["Kamal", "Verma"]], uhids={"3330002"})
    return frag, p1, p2


@case("fragment without a village fitting one anchored patient AND a different person (other village) is not linked", False)
def _():
    frag = ev(names=[["Asha"]], rel_names=[["Kamal"]])
    p1 = ev(names=[["Asha", "Rajput"]], rel_names=[["Kamal", "Rajput"]], uhids={"3330011"}, villages={"rmpr"})
    other = ev(names=[["Asha"]], rel_names=[["Kamal"]], villages={"sngr"})
    return frag, p1, other


@case("CONTROL: same patient, two UHIDs, same name and DOB, links", True)
def _():
    a = ev(names=[["Mahesh", "Chauhan"]], uhids={"4440001"}, dob={"1977-04-12"})
    b = ev(names=[["Mahesh", "Chauhan"]], uhids={"4440002"}, dob={"1977-04-12"})
    return a, b


@case("CONTROL: same UHID and Aadhaar, name in Latin vs a divergent Devanagari spelling, links", True)
def _():
    a = ev(names=[["Lalremruati"]], uhids={"5550001"}, aadhaar={"234123412346"})
    b = ev(names=[["ललरेम"]], uhids={"5550001"}, aadhaar={"234123412346"})
    return a, b


@case("CONTROL: unique fragment 'Meera W/o Rajan' links to its one anchored patient", True)
def _():
    frag = ev(names=[["Meera"]], rel_names=[["Rajan"]])
    p = ev(names=[["Meera", "Nair"]], rel_names=[["Rajan", "Nair"]], uhids={"6660001"})
    return frag, p


@case("CONTROL: patient's own phone in two records with the same given name links", True)
def _():
    a = ev(names=[["Irfan", "Malik"]], phones={"9811100009"})
    b = ev(names=[["Irfan"]], phones={"9811100009"})
    return a, b


def main():
    fails = 0
    for name, want, fn in CASES:
        recs = fn()
        got = linked(*recs)
        ok = got == want
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}  (linked={got})")
    print(f"linking safety: {len(CASES)} cases, {fails} failures")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
