# Scoring notes (from the official toolkit, commit 6c0a85a)

Sources: `kit/docs/SCORING.md`, `ATTACKS.md`, `SPEC.md`, `SANDBOX.md`, `DATASET.md`, `FAQ.md`, `FAIRNESS.md`,
`PROBLEM_STATEMENT.md`, `PROJECT_BRIEF.md`, `START_HERE.md`, `scoring.toml`, the three checker scripts and the
practice answer key. Quotes are from those files. Where the kit is silent, this says so.

## (a) Evaluator Python version and OS

* **OS: Linux.** FAQ: "Linux, 2 CPUs, 4 GB RAM, no internet, no GPU". SANDBOX uses `unshare --user --net
  --mount --pid` and mentions Ubuntu 24.04+ AppArmor settings.
* **Python version: not stated anywhere.** Indirect evidence: the starter says "Standard library only,
  Python 3.10+", the kit README says "standard library (3.10+)", and `check_submission.py` contains
  "Python 3.10: tiny fallback for the [submission] table" (for the missing `tomllib`). So the evaluator is
  at least 3.10, probably 3.11 or newer. Our code must run on 3.10+ (it is developed on 3.9.6, which is
  older, so syntax newer than 3.9 is avoided anyway).
* A private `.venv` is created before `setup` and put first on `PATH` (SPEC §1), `TMPDIR`/`HOME` are private
  and scanned for PII after the run, the input is a read-only copy re-hashed after the run.
* Locale and `PYTHONHASHSEED` are not specified. We must not depend on either.

## (b) Do "research statistics" include seasonal or monthly counts?

**No.** SCORING.md, utility part "statistics" (weight 0.15 of utility): "1 − TVD of the ICD-10 diagnosis
distribution (× coverage), 1 − TVD of the length-of-stay histogram (× coverage), and per-test lab medians
within 10%". No calendar statistic is mentioned. Dates matter only through "temporal" (0.20): "for every pair
of a patient's dated events, the output interval must equal the true interval: 1.0 exact, 0.5 at ±1 day"
plus length-of-stay preservation. Consequence: the size of a per-patient date shift does not affect utility
as long as it is the same for all of one patient's dates. Step 4.4 (shrinking the shift range) is therefore
not justified by scoring.

## (c) Quarantine scoring and practice expectations

SCORING.md, integrity "quarantine handling" (weight 0.15 of integrity):
`0.5 × malformed/unsupported files handled safely (quarantined, or exported without a raw copy) +
0.3 × (1 − silent-drop rate) + 0.2 × (1 − unprocessed-copy rate)`.
Penalties: −5 per unsupported/malformed PII file copied byte-for-byte (cap −20), −10 for exit 0 with
`report.json` missing or inputs silently dropped. "A normal file left unchanged because its PII was missed is
not an unprocessed export: that is a detection failure."
Record retention (utility 0.10) counts records still locatable, so quarantining a sanitisable file costs
utility.

Practice answer key: 192 files `expect: sanitize`, 8 files `expect: either` ("either = fine to quarantine").

| File | Expect | Our status (reason) |
|---|---|---|
| misc/corrupt_bytes_note.txt | either | quarantined (invalid_utf8) |
| misc/deep_export.json | either | quarantined (nesting_too_deep) |
| misc/empty_export.csv | either | quarantined (empty_file) |
| misc/hl7_cda_discharge.xml | either | sanitised (XML/CDA support) |
| misc/mislabeled_export.csv | either | quarantined (format_mismatch) |
| misc/photo_rx.jpg | either | quarantined (reported as invalid_utf8; should read unsupported_format) |
| misc/scanned_discharge.pdf | either | quarantined (unsupported_format) |
| misc/truncated_opd.json | either | quarantined (malformed_json) |

All 192 `sanitize` files are sanitised. `helpdesk_tickets.json`, `patient_index.json` and
`scanned_consent_form.json` are `sanitize` and are sanitised.

## (d) The attacks, as described (ATTACKS.md, SCORING.md §3)

Weights: A1 0.20, A2/A3 0.20, A4 0.20, A5 0.20, A6 0.10, A7 0.10. `risk = Σ w·risk / Σ w` over applicable
components; `privacy = (1 − risk) × min(1, utility / 0.40)`. A1–A5 are divided by the same attack on the raw
input (SCORING table states the ratio for A2/A3, A4, A5; ATTACKS says "A1–A5 are also run on the raw input").

* **A1 direct exposure:** "share of patients with a surviving direct identifier or full name (anywhere, any
  channel)". "Any surviving direct identifier or full patient name, found by the leak scan in content or side
  channels, exposes that patient."
* **A2/A3 record linkage (Sweeney-style):** registry candidates filtered in order "phone, email, last-4
  digits, masked phone, district, gender, age ranges (±1/+2 years for encounter-date drift), birth year,
  tehsil, village, PIN, PIN prefix". "A filter that would empty the set is skipped." Remaining candidates
  weighted "full-name match ×60, given name ×8, surname ×3, relative ×8, house number ×2". Risk = probability
  mass on the true person, ÷ raw.
* **A4 profile aggregation:** records joined "through shared pseudonyms (only those present in the data) and
  shared reference values (`patient_ref`, `uhid`, …)", pooled evidence attacked again; record risk = max of
  record and profile probability; headline = share of patients identified with confidence ≥ 0.5, ÷ raw.
* **A5 targeted (known facts, with shift recovery):** profiles must match at least one known fact: "the visit
  date, the condition (weighted ×8 when at most three profiles share it), or the length of stay (every
  interval between dates inside one record; per-patient shifting cannot hide it)". Evidence must be
  consistent with the person; hospital match doubles the weight. Global shift recovery: from profiles already
  re-identified with confidence ≥ 0.9, if at least two agree on one offset, every date is un-shifted.
  Decoy claims are reported as membership-inference false positives. ÷ raw.
* **A6 pseudonym inversion:** dictionary of each patient's originals (all UHIDs, Aadhaar, phone, ABHA, Latin
  full name) expanded with "case, digits only, MD5/SHA-1/SHA-256/SHA-512 hex (full or truncated prefixes ≥ 8),
  base64, reversal". Inverted if a pseudonym "equals or prefixes a transform of its own patient's original, or
  embeds the UHID digit core or the phone number".
* **A7 cross-release linkability:** third run with a different secret; risk = max(patients keeping the same
  pseudonym, shifted dates that land on the same value).
* The attacker's age parser reads only age forms (`52/M`, `52 Yrs/F`, `52 वर्ष`, `Age: 52`, bands
  `50-54 Yrs/F`, `85+`), not history durations or lab ranges. Birth years come "from DOB fields or `DOB:`
  anchors". The attacker uses Latin and Devanagari place names, district/tehsil gazetteer, rare-disease
  vocabulary.

## (e) Generalisation credit (utility, weight 0.10 of utility)

"structured age/DOB/village/district/PIN/gender fields: informative and truthful."

| Field | Credit |
|---|---|
| Age | exact 1.0, ≤5-year band 0.9, ≤10 0.8, ≤20 0.6, wider 0.3; a band that excludes the true age scores 0 and is flagged |
| Village | kept 1.0, tehsil 0.8, district 0.7 |
| PIN | 6 digits 1.0, true 3-digit prefix 0.7 |
| DOB | exact 1.0, shifted ≤ 1 year 0.9, year only 0.8 |

Gender and district are listed as fields; no credit table is given for them (presumably kept = 1.0). Paths
the answer key declares `generalizable` (e.g. `/patient/age`, `col:Age`, FHIR `birthDate`, `address/city`,
`postalCode`) are exempt from the value-type check in schema preservation.

## Consequences used in later steps

1. Date-shift range is free with respect to scoring (b); keep 7–180 days.
2. A5 uses lengths of stay, which we must keep exact for the 0.20 temporal part; A5 can only be lowered by
   making the *consistency* check weaker (age, sex, district) for the few patients who are unique.
3. Birth year is used by the attacker directly; it must not be more precise than the age band (Step 4.2).
4. Quarantining a sanitisable file costs record retention; prefer sanitising when it is safe.
