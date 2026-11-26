# Artificially Intelligent: a privacy firewall that reads Indian hospital records the way a clerk does

**Track 3 · Secret Wards** · Members: Milap Kothari, Arman Barbhuiya, Sourabh Srivastva, Rohan Singh · Repo: https://github.com/milap1afk/secret-wards

## 1. In one paragraph
Our firewall de-identifies a mixed dump of registrations, OPD JSON, FHIR bundles, discharge summaries and
Hinglish nursing notes, offline and without any LLM. Its core idea is **context, not word lists**. It
learns who the patients are from the structured columns of the whole dataset, then uses Indian-specific
context (labels, S/o-W/o, `sahab`/`ji`/`didi`, `ka BP`, `(attendant`, `called by`) to find them in free
text, in any script, while protecting what must survive (`Dr. Ramesh`, `C/O fever`, `Dolo 650 BD x 5
days`, `Parkinson's disease`, `ASHA worker`). Linking only merges records when the data proves it.

## 2. Architecture
`input/` → **ingest** (encoding + format sniffing, quarantine) → **harvest** (field semantics + detector →
evidence + PII lexicon) → **link** (union-find: strong IDs, then name + unique second clue) → **sanitise**
(detector + lexicon + per-record sweep, keyed pseudonyms, per-patient date shift, generalisation) →
`sanitized/` + `report.json` + `records.jsonl`

## 3. How it works
- **Ingestion:** BOM and content detection (UTF-8/BOM/UTF-16/cp1252); JSON behind `.csv`, truncated or
  1,500-deep JSON, broken UTF-8, PDF, JPEG and XML are quarantined, never copied raw.
- **Detection:** a field classifier for English, transliterated-Hindi and Devanagari headers and for
  FHIR/JSON key paths; a 12-layer text detector on a homoglyph- and Indic-digit-folded copy; a
  dataset-wide lexicon catches names and ID digit cores hidden in paths, keys, headers and base64; a
  per-record sweep removes every other mention of a known name in any script.
- **Linkage & pseudonyms:** union-find on UHID digit cores, IPD numbers, Aadhaar, ABHA, PAN, insurance and
  e-mail; phones only with a matching given name; name + DOB/relative/village-and-age only when the match
  is unique. Phonetic keys make `Mohammad/Mohd/Md./मोहम्मद` equal. Pseudonyms: HMAC-SHA256 keyed with
  `RAKSHA_SECRET`, letters only.
- **Privacy layer:** secret per-patient date shift (7–180 days), so every interval and stay length is
  exact; 10-year age bands (85+ top-coded); birth year only; village and tehsil → district; PIN → 3 digits.
- **Security:** no raw or intermediate data ever touches disk; quarantined files are kept only as Fernet
  ciphertext with an HKDF-derived key (fail closed); counts-only stdout; exceptions reduced to type names;
  files identified by SHA-256.

## 4. USP
- **Cross-script identity:** one pseudonym for `Mohd. Shahid` (nursing note), `Shahid sahab`, `मोहम्मद शाहिद`
  (Hindi prescription) and `Mohammad Shahid` (registration), with zero false merges of same-name people.
- **Meaning traps solved by context:** 100 % of doctors, doses, `1-0-1`, C/O complaints, K/C/O, H/O,
  eponyms and wards kept, while 100 % of relatives' names were removed.
- **A measured privacy policy:** we rebuilt the published attacks and chose the policy by numbers.

## 5. Privacy–utility trade-off (measured)

| Measure | Practice | Unseen-format variant |
|---|---|---|
| PII leaked (overall / Hindi / Hinglish) | 0 % / 0 % / 0 % | 0 % / 0 % / 0 % |
| medical values kept | 99.97 % | 99.97 % |
| linking precision / recall / F0.5 | 1.00 / 1.00 / 1.00 | 1.00 / 0.89 / 0.975 |
| attack risk vs raw: record / profile / targeted | 0.09 / 0.40 / 0.61 | – |
| run time / peak memory | 2.4 s / 31 MB (10× data: linear) | 2.4 s / 31 MB |

Moving from tehsil + shifted DOB + 5-year bands to district + birth year + 10-year bands cut profile
re-identification from 0.77 to 0.40 of raw for about 0.2 points of generalisation credit. Generalising rare
ICD codes cost 1.4 % of clinical values with no measured gain, so we left it off. The unseen-format variant
swaps in 115 unknown names, renamed columns and labels, and new ID and phone formats.

## 6. Known limitations
Names with no context that never appear in a structured column; Devanagari names whose transliteration
diverges strongly (we then leave records unlinked rather than risk a merge); XML/PDF/images are quarantined,
not cleaned; profile risk for patients with many records is still dominated by district + gender + age band.
