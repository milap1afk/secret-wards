**main WAS updated (final session, 2026-11-27): main = overnight head. A follow-up speed fix (`textnorm.fold`, output byte-identical) made the 100× container test pass: 19,300 / 19,300 processable files sanitised in 682 s (pre-overnight: 668 s), 60× in 181 s, 30× in 78 s. Re-run on a clean clone: GATE PASS (all numbers unchanged), READY TO SUBMIT, container determinism/locale/secret checks OK, brief 2 pages with re-measured numbers. The original overnight outcome is kept below for the record.**

**(Original overnight outcome, superseded above:) main was NOT updated. It is still at f4484eb (tag `pre-overnight`). The final gate failed at step 3 (100× scale test in the container): see below. All overnight work is on branch `overnight` (head after this report is committed).**

# Overnight report — 2026-11-27

Branch `overnight`, started from `pre-overnight` (f4484eb) at about 03:00; Step 3 loop stopped at about 06:40; final gate run 06:45–07:45. Every commit is authored by milap1afk and signed off with `git commit -s`; no AI attribution lines anywhere. Nothing was force-pushed. All pushes of `overnight` succeeded.

## Why main was not updated

| Final-gate step | Result |
|---|---|
| 1. Fresh clone of `overnight` (3cdeee8), `tools/get_kit.py`, `tools/run_official_checks.py` | **pass**: READY TO SUBMIT, no warnings; 0/3230 leaked, 0/4 canaries, 4855/4855 medical, linking P/R 1.00/1.00, 0 false merges, 0 raw copies, CONTRACT OK [O] |
| 2. Container (`tools/run_in_container.sh python:3.10-slim`: Python 3.10.22, no network, 2 CPUs, 4 GB, C locale) | **pass**: identical output under ASCII locale and across PYTHONHASHSEED 1 and 4242; another secret changes records.jsonl; secret never in output; CONTRACT OK |
| 3. 100× practice data (20,000 files) inside the limits | **fail** (regression), details below |
| 4. `docs/brief.pdf` exists, ≤ 2 pages | pass (2 pages, unchanged tonight) |

100× scale, same input, same machine [L]:

| | wall time | peak memory | files sanitised (of 19,300 processable) |
|---|---|---|---|
| host, pre-overnight code | 247 s | 1.09 GB | 19,300 |
| host, overnight code | 462 s | 1.07 GB | 19,300 |
| container (2 CPU, 4 GB), pre-overnight code | 668 s | 1.29 GB | 19,300 |
| container (2 CPU, 4 GB), overnight code | 816 s (exit 0, full report) | 1.26 GB | **6,306**; 12,994 quarantined by the 720 s global time budget |

The run stays inside 15 min and 4 GB and fails closed (nothing raw is written, the report is complete), but it no longer finishes the work in the evaluator-like container where the old code did. The cause is the detector: on a 10× profile, `detect()` is called the same number of times as before (≈ 74 k) but costs ≈ 47 % more per call because of tonight's new rules; at 100× the difference grows to 1.8× CPU time (194 s → 343 s user). Practice is barely affected (≈ 2.7 s → ≈ 3.0 s). I stopped here rather than start a performance fix plus a second full gate after the five-hour budget.

## Before / after

Before = `pre-overnight` (f4484eb) scored with the same tools (`docs/results/overnight_before.json`; blind2 from the Step 2 scoring). After = `overnight` head 3cdeee8 (`docs/results/overnight_after.json`). [O] = organisers' kit scripts, [L] = our local tools.

| Measure | Practice before → after | Unseen-format variant (chaos) | Blind holdout 1 | Blind holdout 2 |
|---|---|---|---|---|
| personal data still visible [O] | 0/3230 → 0/3230 | 0/3230 → 0/3230 | 0/3273 → 0/3273 | 24/3251 → **0/3251** |
| canaries found [O] | 0/4 → 0/4 | 0/4 → 0/4 | 0/7 → 0/7 | 2/13 → **0/13** |
| medical values kept [O] | 4855 → 4855 | 4855 → 4855 | 4855 → 4855 | 4855 → 4855 |
| linking precision / recall [O] | 1.00/1.00 → 1.00/1.00 | 1.00/0.99 → 1.00/1.00 | 1.00/0.97 → 1.00/0.97 | 1.00/0.67 → 1.00/0.98 |
| false merges [O] | 0 → 0 | 0 → 0 | 0 → 0 | 0 → 0 |
| combined attack risk [L] | 0.174 → 0.174 | 0.184 → 0.187 | 0.202 → 0.187 | 0.194 → 0.193 |
| run time [L] | 2.7 s → 2.6–4.0 s (one eval run under load: 6.5 s) | 2.8 s → 3.5 s | 4.1 s → 3.4 s | not recorded → 3.3 s |
| peak memory [L] | 34 MB → 34 MB | 33 MB → 32 MB | 33 MB → 34 MB | not recorded → 34 MB |

Also measured every gate run [L]: practice contextual precision 1.000 and token retention 0.9849 throughout (never below the reference). Chaos risk rose 0.003 because its linking recall rose 0.99 → 1.00 (more correctly linked records give the targeted attack A5 more to work with: 0.558 → 0.570).

## Every fix, with its commit

Gate infrastructure
- 1b625a4 `tests/run_all.py` discovers every suite (two suites were silently not run); DOB test fixed for 20-year bands.
- e9658e2 `tools/gate.py`, the per-fix gate.

Step 1 (known gaps) — e80e6b8: generic mechanisms for labels, relations (F/o, M/o, B/o, H/o), titles, role nouns, generic ID labels, place markers, compact/text dates, age forms.

Step 2 (second blind holdout, `tools/blind_variant2.py`, written by an agent that never saw our code; scored before fixing: 24 leaks, 2/13 canaries, recall 0.67)
- 5e3bb0e generator bug (its own commit): it rewrote the clinical "Ward 3 (Surgery)" into an address.
- 2c2a9ef IDs with dot/colon separators, role words before or bracketed after names, `*_by` keys.
- d29e633 header/key abbreviations (pt_nm, hosp_no, regn_dt…); blind2 recall 0.69 → 0.98.

Step 3 (rounds of 40 new probes, empty-lexicon detector run plus an end-to-end mini dataset)
- a640f2b Round 1: labels with & / () and spaced hyphens, role nouns, card IDs, bracketed phones, Devanagari DOB label, # house numbers, name-keyed JSON objects.
- 2bf1228 Round 2: noun ID labels, letter-prefixed IDs, "of"/Roman/ordinal dates, Devanagari address markers, JSON-shaped text.
- ab1e6aa Round 3: hyphenated surnames, 'ka naam X', +91 landlines, space-grouped IDs, month-first DOBs, 'aged about N'.
- 2037b30 Round 4: 16-digit Aadhaar VIDs, [at]/[dot] e-mails, 'DOB/Age:', universities/institutes protected.
- 4e3fd58 Round 5: FHIR extension values typed by their url; hyphen/possessive JSON keys; Devanagari name before a bare phone (file names); '(Name, 41F)', 'spouse (Name)'; Devanagari hospital ward kept.
- 9b1219d Round 6: **HL7 v2 support**: a `.txt` HL7 message leaked the PID name, address and PIN through the pipe-table path; now recognised by its MSH header, fields typed by position, timestamps shifted.
- caf1d28 Round 7: numbered/plural labels with name lists, drug-before-dose protected, multi-word eponyms, salutations.
- fa402a8 Round 7: JSON label/value pairs typed by their label.
- d69a1ae Round 8: name labels in eight more Indian scripts; suffix-named localities.
- 0fee19c Round 9 (linking): a shared phone or family ID links only when the match is one person both ways (a note fitting father and son of the same name on one phone was joined to whichever came first).
- 8c40132 Fix of a round-7 regression found in round 9 ("Kush Tiwari, DOB …" read as two patients); end-to-end linking traps test.
- 87ee724 Round 10: vehicle/DL numbers need an RTO code (a date range was removed as a vehicle number); "Born 1929." suppressed (birth year undid 85+ top-coding); infant ages in days/months not banded.
- f76b752 Round 10: dose schedules (10-8-12 units) are not dates; ID-label suffix must be its own word.
- 5eb015c Round 11: @handles; "Name: NA/Unknown" and "Name of test/lab:" are not patients.
- d06a20c Round 12: a relative inside the patient's cell is relative evidence; ठिकाना/निवास are address headers (a Devanagari village leaked).
- bd66ccb Round 13: FHIR telecom typed by ContactPoint.system (an e-mail in telecom was kept); non-numeric phone-slot values detected; marker-led localities outrank surnames.
- 031db43 Round 14 (renderer audit): no typed cell is returned unchanged when it does not fit its type (names in gender/insurance/age/tehsil cells were kept).
- 34d429a Round 14b: integral floats checked like integers (a phone stored as 9837300001.0 was kept).
- 5423f39 Round 15 (CDA): next-of-kin/guardian persons are relatives, not doctors (an NOK name was kept); TS timestamps shifted, birthTime suppressed.
- 5d23cae Round 16: other people in a note no longer get the patient's pseudonym; named clinical wards protected; localities never cross a line break. (Two fixes in one commit: both touch `detect.py` and interactive staging was not available.)
- 3ef9888 Round 17: English kin noun + name, "Mama ji X", bracketed STD codes, bare house number after Address, road names.
- Round 18 found nothing (output-level invariants on a 24-file mixed folder; no commit).
- 6f3c1b5 Round 19: **organisation pattern swallowed a patient** ("ABHAY PRATAP SINGH   Lab No" was protected as a lab); names after "namely"; age after a name; house number before a named locality; "Baby boy" placeholder.
- 073ad6c Round 20: initials, clinical subject verbs, English possessive, aliases, Urdu-script labels, deities protected.
- Round 21 found nothing (rounds 17/19/20 combined into one note; no commit).
- 1bfb4e0 Round 22: GSTIN removed (it embeds the holder's PAN). 265d80b removes dead code from the reverted attempt below.
- "Gate reference after …" commits only update `docs/results/gate_ref.json` after a passing gate.

The loop stopped at about 3 h 40 min of Step 3 work because the final gate and report had to fit inside the five-hour budget; the "two empty rounds in a row" condition was not met (rounds 18 and 21 were empty, 19, 20 and 22 were not).

## Reverted, and why

- Round 22: deciding "Ward N = address" from the ward's own line (instead of the whole document) to stop clinical ward numbers in long notes being removed. It leaked 2 practice values (and 2/2/1 on chaos/blind/blind2) because some address fields hold ward numbers without a cue on that line. Two attempts (field-level context, two-line window) still leaked; reverted within the time box. Effect: in a long note that contains an address anywhere, a bare "Ward 11" elsewhere may be removed (utility, not privacy).
- Deliberately not fixed: a bare place with no marker ("from Bakshi Ka Talab"); "approx 35 yrs" with no age word (indistinguishable from a duration, and under 85).

## Other things found and explained

- A stress run from before tonight (00:50, pre-overnight code) on a 9.8 MB Devanagari file was still running after 4 h 15 min; I stopped it. Current code finishes the same file in 112 s; other 5–7 MB adversarial files finish in 49–132 s. Not bisected.
- `report.json` differs between identical runs only in `timing.seconds` and `resources.peak_rss_mb`; SPEC §7 requires determinism for `sanitized/` and `records.jsonl` (both byte-identical) and asks for those two report fields.
- A PII-free file can come out byte-identical to its input; the kit counts a raw copy only when the file has personal data.

## Could not be verified

- The official hidden-data evaluator, attacker and FHIR validator (unpublished); attack and FHIR numbers are local [L].
- Behaviour on the real Linux evaluator at 100× scale: only measured in Docker on macOS (bind-mounted files are slower than native Linux).
- Whether the hidden data is anywhere near 100× practice size (the kit does not say).
- The brief and README numbers were not re-rendered tonight; they are still the earlier, correctly marked [O]/[L] figures. Tonight's chaos combined risk is 0.187 (brief: 0.184) and blind 0.187 (brief: 0.202).

## What a human should check before submitting

1. Decide which branch to submit. **main (f4484eb) is unchanged and was READY TO SUBMIT** before tonight. `overnight` closes many real leaks found tonight (HL7 in .txt, FHIR telecom e-mail, CDA next-of-kin, names in typed cells, float phones, lab-header names, GSTIN, blind2 24 → 0 leaks) but is ≈ 1.8× slower at large scale.
2. If you want `overnight`: first speed up the detector (profile `wards/detect.py`; the new rules each scan every text), then re-run the 100× container test: `tools/run_in_container.sh` plus the scale command in this report. Merge only if all 19,300 files are sanitised.
3. If the expected hidden data is small (practice-sized), the slowdown is irrelevant (practice 3 s); you may decide to merge anyway — that is a judgement call I did not make for you.
4. If any brief number is updated, re-measure it and keep its [O]/[L] mark.
5. Commits on `overnight` carry `Signed-off-by: milap1afk`; check that is what you want on main.
