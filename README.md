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

`RAKSHA_SECRET` is required. If it is missing or empty the program exits with code 2 and writes nothing:
an empty HMAC key would make pseudonyms and date shifts guessable.

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
| `tests/` | adversarial detector cases, header variants, end-to-end file shapes |
| `config/policy.yaml` | every privacy knob, with the reason for its value |

### 0. Ingestion
Encodings are detected from BOMs and content (UTF-8, UTF-8-BOM, UTF-16 with or without BOM, cp1252).
The format is sniffed from content, not just the extension: JSON hiding behind `.csv` is quarantined.
XML / HL7 CDA is parsed and sanitised element by element (`id/@extension` under an Aadhaar OID is an Aadhaar,
`patient/name` is the patient); XML with a DOCTYPE or entities is refused (no entity-expansion attacks).
Empty, truncated, over-deep (>200 levels), binary, PDF, JPEG and broken-UTF-8 files are quarantined
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
FHIR logical ids that are not plain UUIDs (e.g. `Patient/SNJ-26-064127`) are replaced by a keyed HMAC id,
and every `fullUrl` and `reference` pointing at them is rewritten through the same mapping, so references
still resolve. UUID ids carry no identity and are kept.
Pseudonyms are `PSN-` + 6 letters derived with HMAC-SHA256 keyed by `RAKSHA_SECRET`. They cannot be
inverted by hashing a dictionary of IDs, they change with the secret, and they are letters only so they
never look like a PIN, phone or age.

### 3. Privacy layer (`config/policy.yaml`)
| Quasi-identifier | Treatment |
|---|---|
| dates | shifted by a secret **per-patient** offset (7–180 days) so every interval and stay length is exact |
| age | 10-year band that always contains the true age; 85+ top-coded; 20-year band for patients unique on (band, sex, district, main diagnosis) |
| date of birth | suppressed (a birth year would pin age to ±1 year) |
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

## Reproducing the checks

```bash
python3 tools/get_kit.py              # official toolkit -> ./kit (git-ignored), pinned to commit 6c0a85a
python3 tools/run_official_checks.py  # official validate_output / check_dev / check_submission (clean clone)
python3 tests/run_all.py              # every local suite; NOT VERIFIED (exit 2) when the kit is missing
```

The full, unedited output of the last official run is kept in
[`docs/results/official_practice_checks.md`](docs/results/official_practice_checks.md), with the project and
toolkit commits it ran on. `check_submission.py` is run on a clean clone of HEAD, so git-ignored files in a
working copy (the kit, its practice PDF, a local `.venv`) cannot make it pass by accident.

## Measured results

**[O]** = the kit's own scripts (`check_dev.py`, `validate_output.py`, `check_submission.py`): practice
self-checks, not the hidden-data evaluator. **[L]** = our local tools in `tools/` and `tests/`, written from
the published `SCORING.md` / `ATTACKS.md`; guides, not official scores. Raw numbers:
`docs/results/final_head.json` (this code) and `docs/results/final_start.json` (code before the last tuning
round, scored with the same tools); the full official log is `docs/results/official_practice_checks.md`.

| Measure | Practice | Unseen-format variant¹ | Blind holdout² |
|---|---|---|---|
| contract [O] | CONTRACT OK | CONTRACT OK | CONTRACT OK |
| personal data still visible [O] | 0 / 3230 | 0 / 3230 | 0 / 3273 (before: 46) |
| canaries found [O] | 0 / 4 | 0 / 4 | 0 / 7 (before: 2) |
| medical values kept [O] | 4855 / 4855 | 4855 / 4855 | 4855 / 4855 (before: 4669 / 4669) |
| linking P / R / F0.5 [O] | 1.00 / 1.00 / 1.00 | 1.00 / 0.99 / 1.00 | 1.00 / 0.97 / 0.99 (before: 0.74 / 0.63 / 0.71) |
| false merges [O] | 0 | 0 | 0 (before: 11) |
| raw copies of unsupported files [O] | 0 | 0 | 0 |
| A2/A3 · A4 · A5 risk vs raw [L] | 0.066 · 0.229 · 0.571 | 0.147 · 0.213 · 0.558 | 0.077 · 0.354 · 0.578 |
| A1 · A6 · A7 [L] | 0 · 0 · 0.006 | 0 · 0 · 0.006 | 0 · 0 · 0 |
| combined risk, SCORING.md weights [L] | 0.174 (before 0.342) | 0.184 (before 0.402) | 0.202 (before 0.425) |
| FHIR R4: fhir.resources 6.5 and tools/fhir_check.py [L] | 19 / 19 valid | 19 / 19 | 19 / 19 |
| run time / peak memory [L] | 2.8 s / 33 MB | 3.4 s / 32 MB | 3.1 s / 33 MB |

Also measured [O]: `check_submission.py --run` on a clean clone prints READY TO SUBMIT (same secret →
identical output, different secret → different output, secret never written, input untouched).
[L]: contextual precision 1.000 and token retention 0.986 on practice; 100× practice (20,000 files) in 263 s
at 0.95 GB peak, scaling exponent ≈ 1.04 (25× → 50×); six adversarial 5 MB single-line files in ≈ 70 s each;
byte-identical output in Linux containers on Python 3.10 and 3.12 with no network, 2 CPUs, 4 GB, `LC_ALL=C`
and a forced ASCII default encoding (`tools/run_in_container.sh`).

¹ `tools/chaos.py`: all 115 Latin and 51 Devanagari patient/relative name tokens replaced by unseen names
written consistently in both scripts, base64 payloads rewritten, headers, keys, labels, ID and phone formats
changed. The checkers are official; the dataset and its answer key are ours.
² `tools/blind_variant.py`: written by a separate agent that read only the kit, never our code. New names in
both scripts (incl. North-East, South and East Indian), new ID types (UPI, bank, DL, passport, voter ID,
vehicle, ration card, employee ID), new phone/date formats, JSONL, top-level arrays, deep nesting, CSV
preambles, pipe and fixed-width tables, mismatched extensions and 3 new canaries. Its unit locators for the
new layouts are its own choice; the official convention for them is unknown.

**Privacy choices, measured [L]** (`tools/attack.py`, `tools/kanon.py`, `docs/results/privacy_metrics.md`):

| Change | Combined risk |
|---|---|
| tehsil, shifted DOB, 5-year bands → district, birth year, 10-year bands | profile re-id 0.77 → 0.40 of raw |
| attacker taught to read bare birth years (honest re-measurement) | 0.219 → 0.341 |
| DOB suppressed (a birth year pins age to ±1 year) | 0.341 → 0.194 |
| local recoding: 20-year band for patients unique on (band, sex, district, main diagnosis) | 0.194 → 0.173 |

Population k (register people consistent with what we publish): median 11; patients with k ≤ 5 fell from 16
to 7 of 48. Generalising rare ICD codes cost 1.4 % of medical values for no gain, so it is off. The date
shift stays 7–180 days because no scored statistic is seasonal (`docs/scoring_notes.md`).

## Tests and tools (development only)
```bash
python3 tests/run_all.py              # all suites; NOT VERIFIED (exit 2) where the kit is missing
#   test_detect (78 remove/keep cases), test_fields (99 headers and value columns), test_shapes (file layouts),
#   test_fhir_ids, test_fhir_valid (11 controls), test_secret, test_dob_policy, test_linking (9 merge cases),
#   test_attack_checks (A1/A6/A7 positive controls)
python3 tools/get_kit.py && python3 tools/run_official_checks.py   # official checks -> docs/results/
python3 tools/eval_all.py --name practice --dev kit/dev --name blind --dev blind   # [O]+[L] summary
python3 tools/blind_variant.py --dev kit/dev --out blind           # blind holdout
python3 tools/chaos.py --dev kit/dev --out chaos                   # unseen-format variant
tools/run_in_container.sh python:3.10-slim                         # Linux, no network, C locale
python3 tools/demo.py "Patient Name: Asha Rajput 48/F, W/o Kamal. C/O fever. Mob 9876543210"
.venv/bin/python tools/fhir_validate_lib.py --input kit/dev/input --output out   # needs fhir.resources 6.5
```

## Models
One small model, trained by us; no LLMs, no generative models, no pretrained models of any kind.

| | |
|---|---|
| What | `wards/data/name_model.json` (about 150 KB): character 2–4-gram multinomial naive Bayes, "is this token an Indian personal name?", Latin and Devanagari |
| Training | `python3 tools/train_name_model.py`: standard library, deterministic. Positives: gazetteer names plus rule-generated spelling variants and rule-based Devanagari forms. Negatives: drug names, clinical terms and ordinary words from the practice corpus' medical values and clean documents |
| Held-out test | 20 % of names (208 names never seen in training) and 20 % of negatives: recall 0.989, precision 0.955 (per token) |
| Use | lowest-priority detector layer (`Detector._model_names`); fires only for 2–3 name-like tokens on a line that also carries an age/sex marker, phone, ID or relation marker. It never feeds patient linking |

## Known limitations
* Names with no context at all (no label, honorific, relation, role or nearby identifier) that are also
  missing from every structured column cannot be found.
* Devanagari names that our transliteration renders very differently from their Latin form may stay
  unlinked. Linking then errs on the side of not merging.
* PDF and images are quarantined rather than sanitised (no OCR).
* Profile-level risk is still dominated by district + gender + age band for patients with many records.
  Coarser bands would trade research value for privacy.
* All attack numbers are local approximations; the official attacker and the hidden datasets are not
  public, and A5's use of exact stay lengths (which we keep for clinical utility) is not modelled closely.
