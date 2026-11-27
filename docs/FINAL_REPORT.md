# Secret Wards: final project report

**Team Artificially Intelligent** · Milap Kothari, Arman Barbhuiya, Sourabh Srivastva, Rohan Singh · Yugaantar DevForge, Track 3 · github.com/milap1afk/secret-wards (main = `6321dbb`)

## 1. What we built

Secret Wards is an offline privacy firewall for synthetic Indian hospital records in English, Hindi and Hinglish. It finds and removes personal data across many file formats. It gives each patient one keyed pseudonym that stays the same across scripts and hospitals. It keeps every medical value, so the output stays useful for research.

It is built under strict rules: no LLM, no pretrained or generative model, no network, Python standard library only (`cryptography` optional), and it must run within 2 CPUs, 4 GB and 15 minutes. The same input and the same `RAKSHA_SECRET` give byte-identical output.

The pipeline runs in five steps: **ingest → harvest → link → recode → sanitise**.

- **Ingest.** Works out each file's encoding and format from its content:
  - CSV, JSON, JSONL, fixed-width, FHIR, CDA/XML, and HL7 v2 under any file extension.
  - Unsupported or broken files are quarantined as encrypted files, never copied raw.
- **Harvest.**
  - Field classification works on English, transliterated Hindi and Devanagari headers, and on JSON keys.
  - Unlabelled columns are typed by their values, for example a valid Aadhaar checksum, a phone number or a PIN code.
  - A layered text detector looks for Indian context: S/o and W/o, पत्नी, *ji / sahab*, *X ka BP*, a name next to a phone number, and similar cues.
  - Doctors, doses, eponyms and wards are protected first, so they are never removed.
- **Link.**
  - Records are joined with union-find on person-unique IDs.
  - Weaker clues, such as a shared phone, a family ID, or a name plus DOB or a relative, link records only when they match one person in both directions.
  - Records with conflicting details are never merged.
- **Recode (privacy layer).**
  - Each patient's dates move by their own secret shift.
  - Ages become 10-year bands, with 85+ top-coded.
  - DOB is suppressed.
  - Villages are generalised to district and PIN codes to 3 digits.
  - Patients who stand out get a 20-year age band.
- **Sanitise.**
  - Output is written as `sanitized/`, `records.jsonl` and `report.json`.
  - Pseudonyms are `PSN-` codes made with HMAC-SHA256 keyed by the secret.
  - FHIR references still resolve.

## 2. Timeline

| When | What |
|---|---|
| 26 Nov, day | Built the pipeline, a local scorer and our own rebuild of the A1–A7 attacks. Chose the privacy settings from measured attack risk. Speed work cut a practice run from 7 s to 2.6 s. |
| 26 Nov, evening | Wrote the unseen-format and blind-holdout test sets, ran the clean-clone and container checks, and wrote the README and the 2-page brief. Tagged `pre-overnight` (`f4484eb`). |
| 27 Nov, overnight | Ran 22 rounds of an automated probe loop. Each round we wrote new tricky records, found leaks, fixed the cause rather than the example, and re-ran the full gate before committing. About 30 fix commits. |
| 27 Nov, morning | The last gate check, a 100× size run, failed because of a speed regression, so main was held back. One speed fix with identical output made it pass. All checks were re-run on a fresh clone, and main was updated and pushed. |

## 3. Final results

**[O]** marks results from the organisers' kit scripts. Those scripts are practice self-checks, not the hidden evaluator. **[L]** marks results from our own local tools.

| Measure | Practice | Unseen-format variant | Blind holdout | Blind holdout 2 |
|---|---|---|---|---|
| personal data still visible [O] | 0 / 3230 | 0 / 3230 | 0 / 3273 | 0 / 3251 |
| canaries found [O] | 0 / 4 | 0 / 4 | 0 / 7 | 0 / 13 |
| medical values kept [O] | 4855 / 4855 | 4855 / 4855 | 4855 / 4855 | 4855 / 4855 |
| linking precision / recall [O] | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 / 0.97 | 1.00 / 0.98 |
| false merges [O] | 0 | 0 | 0 | 0 |
| combined attack risk vs raw data [L] | 0.174 | 0.187 | 0.187 | 0.193 |

The official submission check on a fresh clone printed **READY TO SUBMIT** [O].

The container checks used no network, 2 CPUs, 4 GB and the C locale [L]:
- the output was identical under an ASCII locale and across hash seeds;
- a different secret changed the output;
- the secret never appeared in the output.

Practice runs in 2.6 s using 34 MB of memory [L].

Scale tests ran in the same container [L]:

| Size | Files sanitised | Time |
|---|---|---|
| 30× | every processable file | 78 s |
| 60× | every processable file | 181 s |
| 100× (20,000 files) | every processable file (19,300) | 682 s |

## 4. What the overnight rounds fixed

Each of these was a real leak or a real loss of useful data. The full list with commit IDs is in [overnight_report.md](overnight_report.md).

- **New formats:**
  - HL7 v2 messages saved as `.txt` used to leak the patient's name, address and PIN.
  - CDA timestamps are now shifted, and the CDA birth time is suppressed.
- **Typed fields:**
  - an e-mail in a FHIR `telecom` field;
  - names inside gender, insurance and age cells;
  - phone numbers stored as decimals such as `9837300001.0`;
  - FHIR extension values;
  - a CDA next-of-kin name that was being kept as if it were a doctor.
- **Free text:**
  - name labels in 9 more scripts, including Urdu;
  - relatives written as "Mama ji X" or "spouse (Name)";
  - aliases, salutations and initials;
  - addresses with a house number and locality;
  - GSTINs, which contain the holder's PAN;
  - a patient name in a lab-report header that a lab-name rule had wrongly protected.
- **Utility:** these are no longer removed by mistake:
  - dose schedules that look like dates;
  - drug names before a dose;
  - named wards, deities, universities, and multi-word eponyms.
- **Linking:**
  - A note that fitted both a father and son with the same name on one phone used to be linked to whichever came first. It is now left unlinked.
  - Other people named in a note no longer get the patient's pseudonym.
- **Second blind holdout:** leaks went from 24 to 0, canaries from 2/13 to 0/13, and linking recall from 0.67 to 0.98.

**Reverted:** one round-22 attempt to keep clinical ward numbers in long notes. It leaked 2 practice values, so it was rolled back within its 30-minute time box.

## 5. How the work was checked

- **The gate** (`tools/gate.py`) runs after every fix:
  - every test suite;
  - the official kit checks on the practice, unseen-format, blind and blind-2 datasets;
  - no worse leaks, linking or attack risk than the saved reference;
  - run time and memory limits.
- Any fix that failed the gate was reverted.
- **The last checks** before main was updated:
  - the official checks on a fresh clone;
  - the container determinism, locale and secret checks;
  - the 100× size run;
  - a 2-page check of the brief.
- **Security:**
  - raw data never touches disk;
  - quarantined files are stored encrypted;
  - a missing secret means exit code 2 and nothing written;
  - output to the screen is counts only;
  - the input is never modified.

## 6. Known limitations

- The attack and FHIR numbers are our local approximations, because the official attacker, validator and hidden data are not published.
- Targeted-attack risk (A5) stays the highest, because exact stay lengths must be kept for research use.
- Some names are still missed: a name with no context that never appears in a typed column, and a bare place name with no marker word.
- Devanagari spellings that differ a lot from the Latin version may stay unlinked. This is deliberate: no link is better than a wrong one.
- PDFs and images are quarantined, not read with OCR.
- In a long note that contains an address, a bare "Ward 11" elsewhere may be removed. This costs a little utility, not privacy.
- Scale was measured in Docker on macOS, not on the real Linux evaluator.

## 7. Submission

- **Repository:** github.com/milap1afk/secret-wards (branch `main`)
- **Brief:** `docs/brief.pdf` (2 pages; a copy is on the Desktop as `SecretWards_Brief.pdf`)
- **Supporting documents:**
  - `README.md` (setup, design, results);
  - `docs/overnight_report.md` (every fix with its commit);
  - `docs/results/` (saved measurements).
