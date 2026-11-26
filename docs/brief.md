# Artificially Intelligent: a privacy firewall that reads Indian hospital records the way a clerk does

**Track 3 · Secret Wards** · Milap Kothari, Arman Barbhuiya, Sourabh Srivastva, Rohan Singh · github.com/milap1afk/secret-wards

Numbers marked **[O]** come from the organisers' kit scripts (`validate_output.py`, `check_dev.py`, `check_submission.py`), which are practice self-checks, not the hidden-data evaluator. **[L]** marks our own local tools, written from the published `SCORING.md` and `ATTACKS.md`.

## 1. USP

- **Context, not word lists.** Patients are learnt from the typed columns of the whole dataset and found again in free text through Indian context: labels in three scripts, S/o / W/o / पत्नी, *sahab / ji / didi*, *X ka BP*, *bete X ne*, *(पड़ोसी)*, name next to a phone. What must survive is protected first: doctors, doses, `1-0-1`, *C/O fever*, eponyms, wards, ASHA worker.
- **Robust to formats it has never seen.** Unknown columns are typed by their values; records are found at any JSON depth and in JSON Lines, fixed-width, pipe and preamble CSVs. Tested on a blind holdout built by an agent that never saw our code.
- **Linking that refuses to guess.** One keyed pseudonym per patient across scripts and hospitals, with zero false merges on every dataset we have.
- **A measured privacy policy.** We rebuilt the A1–A7 attacks and chose every setting by its numbers.

## 2. Architecture

```
input/ → ingest → harvest → link → recode → sanitise → sanitized/ + report.json + records.jsonl
         encoding,  field + value  union-find   rare-QI     detector + lexicon + sweep,
         format,    typing, text   (strong IDs, age bands   keyed pseudonyms, per-patient
         quarantine detector,      name+clue    widened     date shift, generalisation
                    PII lexicon    both ways)
```

## 3. How it works

- **Ingestion:** BOM/UTF-16/cp1252 detection; format by content (JSON in `.csv`, tables in `.txt`, JSONL); XML/CDA per element, DTDs refused; PDF/images/broken files quarantined, never copied. Per-file size cap and time budget, global deadline: a run always ends with a full report.
- **Detection (3 scripts):** field classifier for English, transliterated-Hindi and Devanagari headers and JSON paths, plus value typing (Verhoeff-checked Aadhaar, phones, dates, PINs, name columns); a 13-layer text detector on a homoglyph- and Indic-digit-folded copy; identifier shapes incl. UPI, DL, passport, vehicle, EPIC, bank accounts, international phones; soft identifiers (occupation → class; employer, school, festival dates); a small char-n-gram naive Bayes name scorer we trained (held-out names: recall 0.989, precision 0.955) used only with supporting context. Linear time on adversarial input.
- **Linkage & pseudonyms:** union-find on person-unique IDs (UHID core, IPD, Aadhaar, ABHA); phones and family-shareable IDs (payer PAN, policy, e-mail) only with an agreeing given name; name + DOB / relative / village+age only when unique in both directions; conflicts on Aadhaar, DOB, sex, age, village. Phonetic keys equate *Mohammad / Mohd / Md. / मोहम्मद*. Pseudonyms `PSN-` + HMAC-SHA256(`RAKSHA_SECRET`), letters only; FHIR non-UUID ids remapped with the same keyed mapping so references resolve.
- **Privacy layer:** per-patient secret date shift (7–180 days; intervals and stay lengths exact); 10-year age bands, 85+ top-coded; DOB suppressed; village and tehsil → district; PIN → 3 digits; patients unique on (band, sex, district, main diagnosis) get a 20-year band.
- **Security:** raw and intermediate data never touch disk; quarantined files kept only as Fernet ciphertext with an HKDF key from the secret (fail closed); missing secret → exit 2, nothing written; counts-only stdout; files identified by SHA-256.

## 4. Privacy–utility trade-off and results

| Measure | Practice | Unseen-format variant¹ | Blind holdout² |
|---|---|---|---|
| personal data still visible **[O]** | 0 / 3230 | 0 / 3230 | 0 / 3273 (start of tuning: 46) |
| canaries found **[O]** | 0 / 4 | 0 / 4 | 0 / 7 (start: 2) |
| medical values kept **[O]** | 4855 / 4855 | 4855 / 4855 | 4855 / 4855 |
| linking P / R / F0.5, false merges **[O]** | 1.00 / 1.00 / 1.00, 0 | 1.00 / 0.99 / 1.00, 0 | 1.00 / 0.97 / 0.99, 0 (start: 0.74 / 0.63 / 0.71, 11) |
| contract; submission check (clean clone) **[O]** | CONTRACT OK; READY TO SUBMIT | CONTRACT OK | CONTRACT OK |
| attack risk vs raw: record / profile / targeted **[L]** | 0.07 / 0.23 / 0.57 | 0.15 / 0.21 / 0.56 | 0.08 / 0.35 / 0.58 |
| direct exposure, pseudonym inversion, cross-release **[L]** | 0 / 0 / 0.006 | 0 / 0 / 0.006 | 0 / 0 / 0 |
| combined risk (SCORING.md weights) **[L]** | 0.174 (start 0.342) | 0.184 (start 0.402) | 0.202 (start 0.425) |
| FHIR R4 (fhir.resources 6.5) **[L]** | 19 / 19 valid | 19 / 19 | 19 / 19 |
| run time / peak memory **[L]** | 2.8 s / 33 MB; 100× data 263 s / 0.95 GB | 3.4 s / 32 MB | 3.1 s / 33 MB |

¹ practice data with 115 Latin and 51 Devanagari name tokens, headers, labels and ID formats replaced (`tools/chaos.py`). ² new names in both scripts, new ID types, new layouts and canaries, generated without access to our code (`tools/blind_variant.py`). "Start" = our code before this tuning round, scored with the same tools.

**Choices, measured [L]:** publishing birth year pinned age to ±1 year and lifted profile re-identification to 0.85 of raw, so DOB is suppressed (combined risk 0.341 → 0.194, about 0.2–0.3 points of generalisation credit). Recoding rare patients took risk to 0.173. District instead of tehsil and 10- instead of 5-year bands cut profile risk from 0.77 to 0.40 of raw earlier. Generalising rare ICD codes cost 1.4 % of medical values for no attack gain, so it is off. The date shift stays wide because no research statistic is seasonal. Population k (register people matching what we publish): median 11; 7 of 48 patients have k ≤ 5 (before: 16).

## 5. Known limitations

The attack and FHIR numbers are local approximations; the official attacker, validator and hidden data are unpublished. A5 (targeted) stays highest because exact stays must be kept. On the small practice set every patient is "rare", so recoding widens all bands; on larger data it is selective. Names with no context that never appear in a typed column can be missed. Divergent Devanagari spellings may stay unlinked (by design: no link rather than a wrong one). PDF and images are quarantined, not OCR'd.
