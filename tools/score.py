#!/usr/bin/env python3
"""Local re-implementation of the published Secret Wards scoring (docs/SCORING.md), for tuning.

Usage: python3 tools/score.py --dev kit/dev --output out [--show 20]
Prints detection recall/precision, leak list, clinical-probe retention, linkage P/R/F0.5,
canary and side-channel checks. It approximates the official evaluator; it is not it.
"""
import argparse
import base64
import collections
import csv
import io
import json
import re
import sys
import unicodedata
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from wards.textnorm import fold  # noqa: E402

TYPE_W = {"AADHAAR": 1, "ABHA_NUMBER": 1, "ABHA_ADDRESS": 1, "PHONE": 1, "EMAIL": 1, "MRN": 1, "PAN": 1,
          "INSURANCE_ID": .8, "PATIENT_NAME": 1, "RELATIVE_NAME": .8, "DOB": .7, "HOUSE": .6, "LOCALITY": .6,
          "LANDMARK": .5, "VILLAGE": .5, "PIN": .5, "AADHAAR_MASKED": .5, "CANARY": 1}


def norm(s):
    s = unicodedata.normalize("NFKC", s)
    s = fold(s)
    s = "".join(c for c in unicodedata.normalize("NFD", s) if not unicodedata.combining(c) or "ऀ" <= c <= "ॿ")
    s = unicodedata.normalize("NFC", s)
    extra = []
    for m in re.finditer(r"[A-Za-z0-9+/]{16,}={0,2}", s):
        try:
            extra.append(base64.b64decode(m.group(0) + "=" * (-len(m.group(0)) % 4)).decode("utf-8"))
        except Exception:
            pass
    return (s + " " + " ".join(fold(x) for x in extra)).casefold()


def digits_view(s):
    return re.sub(r"(?<=\d)[\s\-./]+(?=\d)", "", s)


def count_key(text, ent):
    m = ent.get("match")
    if m == "digits":
        k = ent.get("key") or re.sub(r"\D", "", ent["surface"])
        return len(re.findall(r"(?<!\d)" + re.escape(k) + r"(?!\d)", digits_view(text)))
    if m == "name":
        return None
    k = norm(ent["surface"]).strip()
    return text.count(k) if k else 0


def tok_count(text, tok):
    return len(re.findall(r"(?<![\wऀ-ॿ])" + re.escape(tok) + r"(?![\wऀ-ॿ])", text))


def load_unit_text(path, fmt, loc, raw_text=None):
    """Return the text of one unit inside a file (input or output)."""
    if raw_text is None:
        try:
            raw = path.read_bytes()
        except OSError:
            return None
        for enc in ("utf-8-sig", "utf-16", "cp1252"):
            try:
                raw_text = raw.decode(enc)
                break
            except UnicodeDecodeError:
                continue
        if raw_text is None:
            return ""
    if loc in ("doc", "@file") or fmt in ("text", "binary", "pdf", "xml", "fhir"):
        return raw_text
    if loc.startswith("row:") or loc == "@header":
        delim = "\t" if fmt == "tsv" else ","
        first = raw_text.split("\n", 1)[0]
        if first.count("\t") > first.count(","):
            delim = "\t"
        rows = list(csv.reader(io.StringIO(raw_text, newline=""), delimiter=delim))
        if loc == "@header":
            return delim.join(rows[0]) if rows else ""
        i = int(loc[4:]) + 1
        return delim.join(rows[i]) if i < len(rows) else None
    if loc.startswith("/"):
        try:
            data = json.loads(raw_text)
        except ValueError:
            return raw_text
        node = data
        for part in loc[1:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            try:
                node = node[int(part)] if isinstance(node, list) else node[part]
            except (KeyError, IndexError, ValueError, TypeError):
                return raw_text
        return json.dumps(node, ensure_ascii=False)
    return raw_text


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev", default="kit/dev")
    ap.add_argument("--output", default="out")
    ap.add_argument("--show", type=int, default=25)
    ap.add_argument("--type", default="")
    a = ap.parse_args()
    dev, out = Path(a.dev), Path(a.output)
    truth = json.loads((dev / "truth" / "truth.json").read_text(encoding="utf-8"))
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    by_sha = {f["input_sha256"]: f for f in report["files"]}
    by_out = {f["output"]: f for f in report["files"] if f.get("output")}

    type_tot = collections.Counter(); type_leak = collections.Counter()
    script_tot = collections.Counter(); script_leak = collections.Counter()
    chan_tot = collections.Counter(); chan_leak = collections.Counter()
    leaks = []
    probe_tot = probe_keep = 0.0
    lost_probes = []
    trap_tot = collections.Counter(); trap_keep = collections.Counter()
    quarantined_sanitize = []
    canary_hits = []

    for rel, f in truth["files"].items():
        entry = by_out.get("sanitized/" + rel) or by_sha.get(f["sha256"])
        outp = out / entry["output"] if entry and entry.get("output") else None
        if entry is None or outp is None:
            if f["expect"] == "sanitize":
                quarantined_sanitize.append(rel)
            continue
        fmt = f["format"]
        out_name = entry["output"]
        for loc, un in f["units"].items():
            if loc == "@filename":
                tin, tout = norm(Path(rel).name), norm(Path(out_name).name)
            else:
                tin = load_unit_text(dev / "input" / rel, fmt, loc)
                tout = load_unit_text(outp, fmt, loc)
                if tin is None:
                    continue
                tin = norm(tin)
                tout = norm(tout) if tout is not None else norm(outp.read_text(encoding="utf-8", errors="replace"))
            probes = [norm(p["text"]).strip() for p in un.get("preserve", [])]
            for e in un["entities"]:
                w = TYPE_W.get(e["type"], 1)
                if e.get("match") == "name":
                    keys = e.get("tokens") or []
                    vals = []
                    for k in keys:
                        k2 = norm(k).strip()
                        inn = tok_count(tin, k2)
                        allowed = sum(tok_count(p, k2) for p in probes if p in tin)
                        pii = max(inn - allowed, 1)
                        o = tok_count(tout, k2)
                        vals.append(min(max(o - allowed, 0), pii) / pii)
                    leak = sum(vals) / len(vals) if vals else 0
                else:
                    inn = count_key(tin, e)
                    o = count_key(tout, e)
                    allowed = 0
                    pii = max(inn - allowed, 1)
                    leak = min(max(o - allowed, 0), pii) / pii
                type_tot[e["type"]] += 1; type_leak[e["type"]] += leak
                script_tot[e["script"]] += 1; script_leak[e["script"]] += leak
                chan_tot[e["channel"]] += 1; chan_leak[e["channel"]] += leak
                if leak > 0:
                    leaks.append((leak, e["type"], e["channel"], rel, loc, e["surface"]))
                if e.get("canary") and leak > 0:
                    canary_hits.append((rel, e["surface"]))
            for p in un.get("preserve", []):
                w = p.get("weight", 1.0)
                probe_tot += w
                ok = norm(p["text"]).strip() in tout
                if ok:
                    probe_keep += w
                else:
                    lost_probes.append((rel, loc, p["kind"], p["text"]))
                if p.get("trap"):
                    trap_tot[p["trap"]] += 1
                    trap_keep[p["trap"]] += ok

    # side channels: report / records / stdout not available here; scan report+records for canary/name surfaces
    side = ""
    for name in ("report.json", "records.jsonl"):
        p = out / name
        if p.exists():
            side += norm(p.read_text(encoding="utf-8"))
    side_hits = []
    for rel, f in truth["files"].items():
        for loc, un in f["units"].items():
            for e in un["entities"]:
                if e.get("critical") and e["match"] != "name":
                    if count_key(side, e):
                        side_hits.append(e["surface"])
    # ------- detection score
    per_type = {t: 1 - type_leak[t] / type_tot[t] for t in type_tot}
    wsum = sum(TYPE_W.get(t, 1) for t in per_type)
    r_type = sum(TYPE_W.get(t, 1) * v for t, v in per_type.items()) / wsum
    r_script = sum(1 - script_leak[s] / script_tot[s] for s in script_tot) / len(script_tot)
    recall = 0.5 * r_type + 0.5 * r_script
    prec = sum(trap_keep[t] / trap_tot[t] for t in trap_tot) / max(len(trap_tot), 1)
    f2 = 5 * prec * recall / (4 * prec + recall) if prec + recall else 0

    # ------- linkage
    recs = {}
    rp = out / "records.jsonl"
    file_map = collections.defaultdict(list)
    for rel, f in truth["files"].items():
        file_map[f["sha256"]].append(rel)
    out_to_in = {}
    for e in report["files"]:
        if not e.get("output"):
            continue
        cands = file_map.get(e["input_sha256"], [])
        same = [c for c in cands if "sanitized/" + c == e["output"]]
        out_to_in[e["output"]] = same[0] if same else (cands[0] if cands else None)
    for line in rp.read_text(encoding="utf-8").splitlines():
        r = json.loads(line)
        rel = out_to_in.get(r["file"])
        if rel:
            recs[(rel, r["loc"])] = r["patient"]
    units = []
    for rel, f in truth["files"].items():
        for loc, un in f["units"].items():
            if loc.startswith("@"):
                continue
            units.append(((rel, loc), un["patient"], un["link"], recs.get((rel, loc))))
    tp = fp = 0
    by_psn = collections.defaultdict(list)
    for key, pt, lk, psn in units:
        if psn:
            by_psn[psn].append((pt, lk))
    wrong_merges = collections.Counter()
    for psn, mem in by_psn.items():
        for i in range(len(mem)):
            for j in range(i + 1, len(mem)):
                if mem[i][0] and mem[i][0] == mem[j][0]:
                    tp += 1
                else:
                    fp += 1
                    wrong_merges[(mem[i][0], mem[j][0])] += 1
    by_pt = collections.defaultdict(list)
    for key, pt, lk, psn in units:
        if pt and lk == "required":
            by_pt[pt].append(psn)
    linkable = good = 0
    for pt, ps in by_pt.items():
        for i in range(len(ps)):
            for j in range(i + 1, len(ps)):
                linkable += 1
                good += bool(ps[i]) and ps[i] == ps[j]
    P = tp / (tp + fp) if tp + fp else 0
    R = good / linkable if linkable else 0
    f05 = 1.25 * P * R / (0.25 * P + R) if P + R else 0
    missing_rec = sum(1 for k, pt, lk, psn in units if lk == "required" and psn is None)

    print("=== DETECTION")
    for t in sorted(per_type, key=lambda t: per_type[t]):
        print(f"  {t:16} recall {per_type[t]:.3f}  (n={type_tot[t]})")
    for s in script_tot:
        print(f"  script {s:9} recall {1 - script_leak[s] / script_tot[s]:.3f}")
    for c in chan_tot:
        print(f"  channel {c:9} recall {1 - chan_leak[c] / chan_tot[c]:.3f} (n={chan_tot[c]})")
    print(f"  recall {recall:.3f}  contextual precision {prec:.3f}  F2 {f2:.3f}")
    for t in sorted(trap_tot):
        print(f"    trap {t:20} kept {trap_keep[t]}/{trap_tot[t]}")
    print("=== UTILITY probes kept %.3f (%d lost)" % (probe_keep / probe_tot, len(lost_probes)))
    print("=== LINKAGE  P %.3f  R %.3f  F0.5 %.3f  (pairs tp=%d fp=%d linkable=%d; required units unlinked=%d)" % (P, R, f05, tp, fp, linkable, missing_rec))
    print("  wrong merges:", wrong_merges.most_common(8))
    print("=== CANARY leaks:", canary_hits)
    print("=== side-channel critical hits:", side_hits[:10])
    print("=== quarantined but expected sanitize:", quarantined_sanitize)
    print("=== LEAKS (worst first)")
    lk = [l for l in leaks if not a.type or l[1] == a.type]
    for l in sorted(lk, key=lambda x: (-x[0], x[1]))[:a.show]:
        print(f"  {l[0]:.2f} {l[1]:14} {l[2]:9} {l[3]} {l[4]} :: {l[5]}")
    print("=== LOST PROBES (sample)")
    kinds = collections.Counter(p[2] for p in lost_probes)
    print("  by kind:", kinds.most_common())
    for p in lost_probes[:a.show]:
        print("  ", p)


if __name__ == "__main__":
    main()
