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

Every number below says what produced it. **Official** = the kit's own scripts (`check_dev.py`,
`validate_output.py`, `check_submission.py`); those are practice self-checks, not the hidden-data evaluator.
**Local** = our own approximations in `tools/` and `tests/`, written from the published `SCORING.md` and
`ATTACKS.md`; they are guides, not official scores.

| Measure | Practice data | Unseen-format variant¹ | Source |
|---|---|---|---|
| contract | CONTRACT OK | CONTRACT OK | official `validate_output.py` |
| personal data still visible | 0 / 3230 | 0 / 3230 | official `check_dev.py` |
| leaked by script (Latin / Devanagari / Hinglish) | 0 % / 0 % / 0 % | 0 % / 0 % / 0 % | official `check_dev.py` |
| canaries found | 0 / 4 | 0 / 4 | official `check_dev.py` |
| medical values kept | 4855 / 4855 | 4855 / 4855 | official `check_dev.py` |
| linking precision / recall / F0.5 | 1.00 / 1.00 / 1.00 | 1.00 / 1.00 / 1.00 | official `check_dev.py` |
| raw copies of unsupported files | 0 | 0 | official `check_dev.py` |
| same secret twice → identical; different secret → different; secret never written; input untouched | pass | – | official `check_submission.py --run` |
| contextual precision (doctors, doses, C/O, eponyms…) | 1.000 | 1.000 | local `tools/score.py` |
| token retention (over-redaction) | 0.986 | – | local `tools/retention.py` |
| FHIR structure (ids, required elements, value sets, date/instant syntax, base64, references) | 19/19 bundles, 0 new issues | 19/19, 0 new issues | local `tools/fhir_check.py`¹ |
| run time / peak memory | 2.4 s / 31 MB; 20× data 28 s / 330 MB | 2.4 s / 31 MB | `report.json`, `/usr/bin/time` |

¹ The kit ships no FHIR validator (the official one, `raksha_eval/scoring/fhir.py`, is not public), so FHIR
validity is local only: `tools/fhir_check.py` reports 0 issues on the organisers' own input bundles (sanity)
and `tests/test_fhir_valid.py` confirms it flags 10 kinds of breakage.

The unseen-format variant is built by `tools/chaos.py` from the practice data (the checkers are official,
the dataset and its answer key are ours). It replaces all 115 Latin name tokens of patients and relatives with names absent from
our gazetteer, writes the **same new names in Devanagari** wherever the original appeared in Devanagari
(51 tokens, via a separate Latin→Devanagari transliterator in the test tool, not the sanitiser's), maps
spelling variants (Harish/Hareesh) to one new name, renames headers, JSON keys and text labels, and changes
ID and phone formats, and decodes, rewrites and re-encodes base64 payloads (FHIR attachments, scanned forms)
so the base64 channel is genuinely tested. Limitations: names are drawn from one small pool; Hinglish word order, file layouts
and date formats are not changed; the hidden data may vary things this variant does not.

**Re-identification risk** (local `tools/attack.py`, an approximation of A1–A7 in `ATTACKS.md`; A2–A5 are
relative to the same attack on raw data, combined with the `SCORING.md` weights):

| Attack | Practice data |
|---|---|
| A1 direct exposure (patients with a surviving direct identifier or full name) | 0.000 (raw 1.000) |
| A2/A3 record linkage | 0.090 of raw |
| A4 profile re-identification | 0.396 of raw |
| A5 targeted (known facts) | 0.606 of raw |
| A6 pseudonym inversion (hashes, base64, reversal, digit cores of originals) | 0.000 |
| A7 cross-release (same pseudonym or same shifted date under another secret) | 0.000 |
| combined risk → resistance | 0.218 → 0.782 (before the utility coupling) |

`tests/test_attack_checks.py` verifies that A1, A6 and A7 do fire on deliberately broken releases (a surviving
phone, SHA-256(UHID) pseudonyms, an identical second release).

Policy choice, measured with the same tool:

| Policy | Record linkage | Profile re-id | Targeted |
|---|---|---|---|
| tehsil, shifted DOB, 5-year bands | 0.20 | 0.77 | 0.60 |
| **district, birth year, 10-year bands (chosen)** | **0.09** | **0.40** | **0.61** |

Generalising rare ICD codes to their chapter cost 1.4 % of clinical probes for no measured attack gain, so it
is off (`rare_k: 0`). Coarser 20-year bands or dropping the PIN prefix lowered profile re-id only to about
0.29 and did not move A5 in our approximation, so we did not trade that much research value for it.

## Tests and tools (development only)
```bash
python3 tests/run_all.py            # runs all suites below
python3 tests/test_detect.py        # 59 adversarial detector cases (remove / keep)
python3 tests/test_fields.py        # 89 unseen header variants
python3 tests/test_shapes.py        # end-to-end: unusual file shapes, XML/CDA, DTD refusal
python3 tests/test_fhir_ids.py      # identifier-like FHIR ids/references: removed, keyed, still resolving
python3 tests/test_fhir_valid.py    # local FHIR validator: 10 positive controls + practice output (needs kit)
python3 tests/test_secret.py        # missing/empty RAKSHA_SECRET fails closed; secret never written
python3 tests/test_attack_checks.py # positive controls for local A1/A6/A7 (needs kit)
python3 tools/score.py      --dev kit/dev --output out
python3 tools/attack.py     --dev kit/dev --output out --output2 out_other_secret
python3 tools/fhir_check.py --input kit/dev/input --output out
python3 tools/chaos.py      --dev kit/dev --out chaos
```

## Models
None. No LLMs, no generative models, no pretrained transformers. Rules, gazetteers, transliteration and
union-find only.

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
