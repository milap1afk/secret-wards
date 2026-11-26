# Secret Wards: an offline privacy firewall for Indian hospital records

**Team Artificially Intelligent**: Milap Kothari, Arman Barbhuiya, Sourabh Srivastva, Rohan Singh

Track 3 · Yugaantar DevForge. Offline, CPU-only, **LLM-free**, standard-library Python.

It reads a dump of hospital exports (CSV/TSV, nested JSON, FHIR R4, free-text notes in English,
Devanagari Hindi and Hinglish) and writes a research release in which:

* every piece of personal data is removed (content, file names, JSON keys, CSV headers, export metadata,
  FHIR narrative, base64 attachments, `\u`-escaped text);
* every medical value survives exactly (medicines, doses, `1-0-1`, vitals, labs, diagnoses, doctors, wards);
* one real patient gets one stable, keyed pseudonym across all files, scripts and hospitals, and two
  different people with the same name are never merged;
* quasi-identifiers are generalised by a measured policy so a voter-list attacker cannot single people out.

## Run

```bash
pip install -r requirements.txt                 # optional: only for the encrypted quarantine vault
RAKSHA_SECRET=<secret> python main.py --input <input dir> --output <empty output dir>
```

The output contains `sanitized/` (same tree and formats), `report.json` and `records.jsonl`.
`raksha.toml` is the evaluator entry point. Python 3.9+. No network, no models, no GPU.

## Architecture

```
input/ ──► 0. ingest ──► 1. harvest ──► 2. link ──► 3. sanitise ──► sanitized/ + report.json + records.jsonl
           encodings     field-aware     union-find     detector + lexicon
           format sniff  evidence +      strong IDs,    keyed pseudonyms,
           quarantine    PII lexicon     name + clue    date shift, bands
```

| Module | Role |
|---|---|
| `wards/pipeline.py` | the four passes, file writers (CSV/TSV, JSON, FHIR, text), report |
| `wards/detect.py` | context-aware detector for free text (12 layers, see the module docstring) |
| `wards/fields.py` | what a CSV header / JSON key means (English, transliterated Hindi, Devanagari, FHIR) |
| `wards/link.py` | cross-document identity resolution |
| `wards/translit.py` | Devanagari → Latin transliteration and phonetic name keys |
| `wards/gazetteer.py` | names, honorifics, relation markers, UP districts, clinical vocabulary |
| `wards/privacy.py` | HMAC pseudonyms, per-patient date shifts, age bands, PIN prefixes |
| `wards/rare.py` | optional ICD-chapter generalisation of rare diagnoses |
| `wards/vault.py` | encrypted quarantine vault |
| `config/policy.yaml` | every privacy knob, with the reason for its value |

### 0. Ingestion
Encodings are detected from BOMs and content (UTF-8, UTF-8-BOM, UTF-16 with or without BOM, cp1252).
The format is sniffed from content, not just the extension: JSON hiding behind `.csv` is quarantined.
Empty, truncated, over-deep (>200 levels), binary, PDF, JPEG, XML and broken-UTF-8 files are quarantined
with a reason. **A file is never copied out unless it was fully processed.**

### 1. Detection
* **Field semantics** (`fields.py`): `Pita/Pati ka Naam` and `guardian.name` are relatives, `facility.name`
  and FHIR `Practitioner.name` are not people, `aadhar_no` (misspelled) is Aadhaar, FHIR `identifier.value`
  is classified by its `system`. Headers in Devanagari are transliterated before matching.
* **Free text** (`detect.py`), run on a same-length folded copy so homoglyphs, Indic digits and diacritics
  cannot hide anything:
  * protected spans first: `Dr. …`, hospital and lab names, `Ward 4 (Medicine)`, eponyms such as
    "Parkinson's disease", `ASHA worker`, UUIDs;
  * identifier patterns: Aadhaar (plain and masked), ABHA number and address, PAN, PMJAY and policy IDs,
    phones in every Indian format, hospital IDs (UHID / IPD / MRN shapes);
  * labels (`Patient Name:`, `नाम:`, `Attendant:`, `Mob.`) and relation markers (`S/o`, `W/o`, `पत्नी`).
    `C/O Ramesh` is a relative, while `C/O fever` and `K/C/O` are complaints;
  * honorifics (`Shahid sahab`, `Asha ji`, `Kamal Bhaiya`), possessives (`Hasina ka BP`), roles
    (`Zorawar Qadri (attendant`), verbs (`called by`, `witnessed by`), chat senders, name + phone;
  * address parts (house numbers, mohalla, landmarks, village markers, PINs in address context);
  * a dataset-wide lexicon of names, IDs and phones harvested from structured columns. This is how
    `Anita_Sharma_010565` inside an export path is caught;
  * a per-record sweep: once a name is known in a record, every other mention of its tokens (any
    script) is removed too, except inside protected doctor spans.
* Doses (`Dolo 650 BD x 5 days`, `1-0-1`), lab ranges and history durations (`DM2 x 8 yrs`) are never
  read as phones, IDs or ages.

### 2. Linkage and pseudonyms (`link.py`)
Union-find over records:
1. a shared strong identifier (UHID digit core, IPD number, Aadhaar, ABHA, PAN, insurance ID, e-mail),
   unless the names contradict each other. Two independent strong signals outweigh a name mismatch,
   which covers a transliteration miss;
2. a shared phone, only with a compatible given name (families share phones);
3. name + a second clue (DOB, relative's name, or village + age ±2), **only if that combination points to
   exactly one identifier-anchored patient**.

Clusters never merge across a hard conflict (different Aadhaar, DOB or gender). Names are compared with
phonetic keys that are identical for `Mohammad / Mohd / Md. / मोहम्मद` and `Reena / Rina / रीना`.
Pseudonyms are `PSN-` + 6 letters derived with HMAC-SHA256 keyed by `RAKSHA_SECRET`. They cannot be
inverted by hashing a dictionary of IDs, they change with the secret, and they are letters only so they
never look like a PIN, phone or age.

### 3. Privacy layer (`config/policy.yaml`)
| Quasi-identifier | Treatment |
|---|---|
| dates | shifted by a secret **per-patient** offset (7–180 days) so every interval and stay length is exact |
| age | 10-year band that always contains the true age; 85+ top-coded |
| date of birth | birth year only |
| village, tehsil | generalised to district (district is kept for research) |
| PIN | first 3 digits (`229***`) |
| house, mohalla, landmark | removed |

### Security design
* Raw and intermediate data are **never written to disk**. Everything is processed in memory and only
  sanitised output is written.
* Quarantined files are optionally kept in `output/quarantine/` as Fernet ciphertext (AES + HMAC). The key
  is derived from `RAKSHA_SECRET` with HKDF and never stored. Without the `cryptography` package nothing
  is stored at all (fail closed).
* The secret is read once from the environment and never logged or written. stdout carries counts only;
  exceptions are reduced to their type name; nothing is written to `TMPDIR` or `HOME`.
* `report.json` identifies files by SHA-256, never by name. Renamed files (a name or phone in the file
  name) are declared there.

## Measured results (local re-implementation of the published scoring)

| Measure | Practice data | Unseen-format variant¹ |
|---|---|---|
| PII recall (overall / Hindi / Hinglish) | 1.000 / 1.000 / 1.000 | 1.000 / 1.000 / 1.000 |
| contextual precision (doctors, doses, C/O, eponyms…) | 1.000 | 1.000 |
| clinical values kept | 99.97 % | 99.97 % |
| linking precision / recall / F0.5 | 1.000 / 1.000 / 1.000 | 1.000 / 0.886 / 0.975 |
| canaries leaked | 0 / 4 | 0 / 4 |
| run time / peak memory | 2.4 s / 31 MB | 2.4 s / 31 MB |
| repeat run, same secret | byte-identical | byte-identical |
| run with a different secret | 0 pseudonyms shared | – |

¹ `tools/chaos.py`: 115 name tokens replaced by names absent from our gazetteer, renamed headers, JSON keys
and labels, changed ID and phone formats. Its Devanagari text keeps the old names, so the lower recall is
partly an artefact of the test itself.

**Re-identification risk** (`tools/attack.py`, our implementation of A2–A5 from `ATTACKS.md`, relative to
the same attack on raw data):

| Policy | Record linkage | Profile re-id | Targeted |
|---|---|---|---|
| tehsil, shifted DOB, 5-year bands | 0.20 | 0.77 | 0.60 |
| **district, birth year, 10-year bands (chosen)** | **0.09** | **0.40** | **0.61** |

The chosen policy costs about 0.2 points of generalisation credit and removes about a third of the attack
surface. Generalising rare ICD codes to their chapter was measured too: it cost 1.4 % of clinical probes
and gave no attack gain, so it is off by default (`rare_k: 0`).

## Tools (development only, practice data)
```bash
python3 tools/score.py  --dev kit/dev --output out       # detection, utility, linkage, canaries, leak list
python3 tools/attack.py --dev kit/dev --output out       # re-identification attacks vs raw
python3 tools/chaos.py  --dev kit/dev --out chaos        # build the unseen-format variant
python3 tools/linkdiag.py out                            # patients split across pseudonyms
```

## Models
None. No LLMs, no generative models, no pretrained transformers. Rules, gazetteers, transliteration and
union-find only.

## Known limitations
* Names with no context at all (no label, honorific, relation, role or nearby identifier) that are also
  missing from every structured column cannot be found.
* Devanagari names that our transliteration renders very differently from their Latin form may stay
  unlinked. Linking then errs on the side of not merging.
* XML/HL7 CDA, PDF and images are quarantined rather than sanitised.
* Profile-level risk is still dominated by district + gender + age band for patients with many records.
  Coarser bands would trade research value for privacy.
