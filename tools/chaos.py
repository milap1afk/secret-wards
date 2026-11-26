#!/usr/bin/env python3
"""Build an 'unseen-format' variant of the practice dataset (and its answer key) to test generalisation.

  python3 tools/chaos.py --dev kit/dev --out chaos

Changes applied consistently to the input files AND truth.json:
  * every Latin patient/relative name token -> a name that is NOT in our gazetteer
  * CSV headers / JSON keys / text labels renamed to unseen synonyms
  * hospital ID prefixes and phone formats changed (digit cores unchanged, as in the scorer)
Devanagari text and base64 payloads are left as they are.
"""
import argparse
import hashlib
import json
import random
import re
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from wards import gazetteer as gz  # noqa: E402

GIVEN_POOL = """Bhagirath Chandrakala Shivangi Tejaswini Kamakshi Ilaiyaraja Murugan Senthil Thangam Lalremruati
Zothanpuii Ngurang Tashi Dorjee Pemba Kunzang Yangchen Bhumika Devyani Hemangi Jhanvi Kritika Lavanya Mrinal
Niharika Ojaswi Pallavi Rutuja Sanyukta Tanushree Urvashi Vaidehi Yamini Aniruddh Bhavesh Chirag Daksh Eklavya
Girdhari Hrithik Indrajeet Jaivardhan Keshavdev Lokendra Mithilesh Nityanand Omveer Parmanand Rudransh Sukhpal
Trilok Upendra Vasudev Yudhishthir Zorawar Balkishan Chhedilal Dhaniram Fakira Gangadin Hiralal Jhabbulal
Kanhaiya Lakhpati Mangru Nankau Pancham Rajaram Sukkhu Thakurdin Udairaj Vishambhar Badrunnisa Hasina Jahanara
Kulsum Mehrunnisa Naziya Qamar Roshanara Shaheda Tahira Ummehani Wahida Zubaida Altaf Ehsan Fahim Ghufran
Hammad Imtiyaz Junaid Kaleem Luqman Mujeeb Nadir Obaid Parvez Rafiq Saqib Taufeeq Usman Waqar Yasir""".split()
SUR_POOL = """Bhadauria Tomar Sengar Parihar Kachhwaha Chandel Bundela Sisodia Jadon Gaharwar Vishwakarma Rajak
Lohar Kurmi Gangwar Shakya Katiyar Sachan Niranjan Pundir Rathi Baliyan Dhaka Malviya Bhadoria Kanaujiya
Raikwar Dohare Bharadwaj Kamboj Ghosi Mansoori Idrisi Salmani Rayeen Kasgar Lalwani Uniyal Bisht Negi
Rautela Bhandari Kandpal Dobhal Thapliyal Semwal Nautiyal Gairola Pokhriyal""".split()

HEADER_MAP = {
    "Patient Name": "Name of Patient", "patient_name": "pt_full_name", "Relative Name": "Father/Husband Name",
    "Mobile": "Contact No.", "Aadhaar No": "UID Number", "ABHA No": "Health ID", "UHID": "MR Number",
    "Village/Mohalla": "Gram", "PIN": "Postal Code", "Reg Date": "Date of Registration", "uhid": "mrn",
    "Naam": "Rogi ka Naam", "Mobile No": "Phone No", "Gaon": "Gram Panchayat", "age_sex": "age/gender",
    "PatientID": "MRN", "Guardian": "Next of Kin", "Phone": "Cell", "Zip": "Pincode",
    "payer_pan": "pan_no", "pmjay_id": "ayushman_id", "ref_doctor": "referring_dr",
}
JSON_KEY_MAP = {"patient_ref": "pt_mrn", "hospital_uhid": "registration_no", "mobile": "phone_no",
                "phone": "contact_number", "guardian": "next_of_kin", "aadhar_no": "uid_no", "patient_name": "pt_name"}
LABEL_MAP = [("Patient Name:", "Name of Patient:"), ("Mobile:", "Contact:"), ("UHID:", "MR No:"),
             ("Attendant:", "Relative:"), ("Name:", "Pt:"), ("Mob:", "Ph:"), ("Reg No:", "Regn:")]
ID_MAP = [(r"SNJ/(\d{2})/(\d{6})", r"SNJH-\1-\2"), (r"JJH-(\d{7})", r"JJCH/\1"), (r"UHID-(\d{6})", r"ASS\1"),
          (r"DHH(\d{4})-(\d{6})", r"HRD/\1/\2")]


_C2 = [("chh", "छ"), ("kh", "ख"), ("gh", "घ"), ("ch", "च"), ("jh", "झ"), ("th", "थ"), ("dh", "ध"), ("ph", "फ"),
       ("bh", "भ"), ("sh", "श"), ("k", "क"), ("g", "ग"), ("j", "ज"), ("t", "त"), ("d", "द"), ("n", "न"), ("p", "प"),
       ("b", "ब"), ("m", "म"), ("y", "य"), ("r", "र"), ("l", "ल"), ("v", "व"), ("w", "व"), ("s", "स"), ("h", "ह"),
       ("f", "फ़"), ("z", "ज़"), ("q", "क़"), ("x", "क्स"), ("c", "क")]
_V = [("aa", "आ", "ा"), ("ee", "ई", "ी"), ("ii", "ई", "ी"), ("oo", "ऊ", "ू"), ("uu", "ऊ", "ू"), ("ai", "ऐ", "ै"),
      ("au", "औ", "ौ"), ("a", "अ", ""), ("i", "इ", "ि"), ("u", "उ", "ु"), ("e", "ए", "े"), ("o", "ओ", "ो")]


def latin_to_deva(word):
    """Simple Hindi-style transliteration of a Latin name (final -a written long, n/m before consonant -> anusvara)."""
    w = word.lower()
    out, i, prev_cons = [], 0, False
    while i < len(w):
        for lat, dev, mat in _V:
            if w.startswith(lat, i):
                if lat == "a" and i == len(w) - 1 and prev_cons:
                    out.append("ा")
                elif prev_cons:
                    out.append(mat)
                else:
                    out.append(dev)
                i += len(lat)
                prev_cons = False
                break
        else:
            for lat, dev in _C2:
                if w.startswith(lat, i):
                    nxt = w[i + len(lat):i + len(lat) + 1]
                    if lat in ("n", "m") and nxt and nxt not in "aeiou" and prev_cons is False and out:
                        out.append("ं")
                        i += len(lat)
                        break
                    if prev_cons:
                        out.append("्")
                    out.append(dev)
                    i += len(lat)
                    prev_cons = True
                    break
            else:
                i += 1
    return "".join(out)


def case_like(src, new):
    if src.isupper():
        return new.upper()
    if src.islower():
        return new.lower()
    return new


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev", default="kit/dev")
    ap.add_argument("--out", default="chaos")
    a = ap.parse_args()
    dev, out = Path(a.dev), Path(a.out)
    if out.exists():
        shutil.rmtree(out)
    truth = json.loads((dev / "truth" / "truth.json").read_text(encoding="utf-8"))
    rng = random.Random(7)
    given = [g for g in GIVEN_POOL if not gz.is_known_name_token(g)]
    surs = [s for s in SUR_POOL if not gz.is_known_name_token(s)]
    rng.shuffle(given)
    rng.shuffle(surs)
    # collect Latin name tokens from truth
    toks = set()
    for f in truth["files"].values():
        for u in f["units"].values():
            for e in u["entities"]:
                if e.get("match") == "name" and e["type"] in ("PATIENT_NAME", "RELATIVE_NAME"):
                    for t in e.get("tokens", []):
                        if re.fullmatch(r"[a-z]{3,}", t) and t not in gz.GENERIC_NAME_TOKENS and t not in ("asha", "bhaiya", "sahab", "behenji", "amma", "didi"):
                            toks.add(t)
    from wards.translit import name_key
    mapping = {}
    by_key = {}
    gi = si = 0
    for t in sorted(toks):
        k = name_key(t)
        if k in by_key:                      # spelling variants (Harish/Hareesh) -> the same new name
            mapping[t] = by_key[k]
            continue
        if t in gz.SURNAMES:
            mapping[t] = surs[si % len(surs)] + ("" if si < len(surs) else str(si // len(surs)))
            si += 1
            by_key[k] = mapping[t]
            continue
        else:
            mapping[t] = given[gi % len(given)] + ("" if gi < len(given) else chr(97 + gi // len(given)))
            gi += 1
        by_key[k] = mapping[t]
    rx = re.compile(r"(?<![A-Za-z])(" + "|".join(sorted((re.escape(k) for k in mapping), key=len, reverse=True)) + r")(?![A-Za-z])", re.I)
    # Devanagari tokens of the same names -> the NEW name written in Devanagari
    lat_by_key = {}
    for t in mapping:
        lat_by_key.setdefault(name_key(t), t)
    deva_map = {}
    for f in truth["files"].values():
        for u in f["units"].values():
            for e in u["entities"]:
                if e.get("match") == "name" and e.get("script") == "deva":
                    for t in e.get("tokens", []):
                        lt = lat_by_key.get(name_key(t))
                        if lt and t not in deva_map:
                            deva_map[t] = latin_to_deva(mapping[lt])
    drx = re.compile(r"(?<![\u0900-\u097F])(" + "|".join(sorted((re.escape(k) for k in deva_map), key=len, reverse=True)) + r")(?![\u0900-\u097F])") if deva_map else None

    def sub_names(s):
        s = rx.sub(lambda m: case_like(m.group(0), mapping[m.group(0).lower()]), s)
        if drx is not None:
            s = drx.sub(lambda m: deva_map[m.group(0)], s)
        return s

    def transform(text, fmt):
        text = sub_names(text)
        for pat, rep in ID_MAP:
            text = re.sub(pat, rep, text)
        text = re.sub(r"\+91 (\d{5}) (\d{5})", r"(+91) \1-\2", text)
        if fmt in ("csv", "tsv"):
            lines = text.split("\n", 1)
            hdr = lines[0]
            for k, v in HEADER_MAP.items():
                hdr = re.sub(r"(?<![\w ])" + re.escape(k) + r"(?![\w])", v, hdr)
            text = hdr + ("\n" + lines[1] if len(lines) > 1 else "")
        elif fmt in ("json", "fhir"):
            for k, v in JSON_KEY_MAP.items():
                text = text.replace(f'"{k}":', f'"{v}":')
        else:
            for k, v in LABEL_MAP:
                text = text.replace(k, v)
        return text

    def tsurf(s):
        s2 = sub_names(s)
        for pat, rep in ID_MAP:
            s2 = re.sub(pat, rep, s2)
        return s2

    new_files = {}
    for rel, f in truth["files"].items():
        src = dev / "input" / rel
        raw = src.read_bytes()
        enc = f.get("encoding") or "utf-8"
        fmt = f["format"]
        new_rel = "/".join(sub_names(p) for p in rel.split("/"))
        for pat, rep in ID_MAP:
            new_rel = re.sub(pat.replace("/", "-"), rep.replace("/", "-"), new_rel)
        dst = out / "input" / new_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if fmt in ("binary", "pdf", "xml") or f["expect"] == "either" and fmt not in ("json",):
            dst.write_bytes(raw)
        else:
            pyenc = {"utf-8-sig": "utf-8-sig", "utf-8-bom": "utf-8-sig", "utf-16": "utf-16", "cp1252": "cp1252"}.get(enc, enc)
            try:
                text = raw.decode(pyenc)
                text = transform(text, fmt)
                dst.write_bytes(text.encode(pyenc, errors="strict"))
            except (UnicodeError, LookupError):
                dst.write_bytes(raw)
        f2 = json.loads(json.dumps(f))
        f2["path"] = new_rel
        f2["sha256"] = hashlib.sha256(dst.read_bytes()).hexdigest()
        for u in f2["units"].values():
            for e in u["entities"]:
                e["surface"] = tsurf(e["surface"])
                if e.get("tokens"):
                    e["tokens"] = [deva_map.get(t, mapping.get(t, t).lower() if t in mapping else t) for t in e["tokens"]]
            for p in u.get("preserve", []):
                p["text"] = tsurf(p["text"])
        new_files[new_rel] = f2
    truth["files"] = new_files
    (out / "truth").mkdir(parents=True, exist_ok=True)
    (out / "truth" / "truth.json").write_text(json.dumps(truth, ensure_ascii=False), encoding="utf-8")
    print(f"mapped {len(mapping)} Latin name tokens and {len(deva_map)} Devanagari name tokens; files {len(new_files)}")


if __name__ == "__main__":
    main()
