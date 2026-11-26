# Official toolkit checks
date: 2026-11-26T16:10:00
project commit: 6f9c6cd
toolkit commit: 6c0a85a
python: 3.9.6

## run
$ RAKSHA_SECRET=practice python3 main.py --input kit/dev/input --output out
files 200 sanitized 193 quarantined 7 records 778 linked 777
exit 0

## validate_output.py
$ python3 kit/validate_output.py --input kit/dev/input --output out
CONTRACT OK
exit 0

## check_dev.py
$ python3 kit/check_dev.py --output out
================================================================
 SECRET WARDS practice self-check (rough guide, not the official score)
================================================================

1) PERSONAL DATA: 0 of 3230 pieces still visible (  0.0% leaked; lower is better)
   PATIENT_NAME     leaked    0 / 962    0.0%
   AADHAAR_MASKED   leaked    0 / 16     0.0%
   ABHA_NUMBER      leaked    0 / 46     0.0%
   VILLAGE          leaked    0 / 150    0.0%
   EMAIL            leaked    0 / 1      0.0%
   HOUSE            leaked    0 / 136    0.0%
   LOCALITY         leaked    0 / 103    0.0%
   LANDMARK         leaked    0 / 64     0.0%
   PAN              leaked    0 / 22     0.0%
   MRN              leaked    0 / 850    0.0%
   DOB              leaked    0 / 111    0.0%
   PIN              leaked    0 / 136    0.0%
   PHONE            leaked    0 / 308    0.0%
   INSURANCE_ID     leaked    0 / 22     0.0%
   RELATIVE_NAME    leaked    0 / 232    0.0%
   AADHAAR          leaked    0 / 71     0.0%
   by language: latin 0.0%, deva 0.0%, hinglish 0.0%
   by hiding place: content 0.0%, filename 0.0%, base64 0.0%, metadata 0.0%, key 0.0%, header 0.0%

2) CANARIES: 0 of 4 planted canaries found in your output folder (each one costs -3 officially)

3) MEDICAL DATA KEPT: 4855 of 4855 medical values survived (100.0%; higher is better)

4) PATIENT LINKING: precision 1.00, recall 1.00, F0.5 1.00  (pseudonyms that wrongly merge different people: 0)

5) RAW COPIES: 0 broken/unsupported files were copied out unchanged instead of quarantined (each costs -5 officially)

Next: fix the biggest leak rows first, keep the medical values, then link patients.
Also run: python3 validate_output.py --input dev/input --output <tmp>/out
exit 0

## check_submission.py (clean clone of HEAD)
$ python3 kit/check_submission.py --repo <clean clone> --run
Secret Wards pre-submit check: <tmp>/clean_clone

1) Repository files
  ✅ raksha.toml found at the root
  ✅ team name: artificially-intelligent
  ✅ run: python3 main.py --input {input} --output {output}
  ✅ setup: python3 -m pip install -r requirements.txt || true
  ✅ README.md found (2001 words)
  ⚠️  no PDF in the repo: you must ALSO submit the 2-page Project Brief PDF (see docs/PROJECT_BRIEF.md)
  ✅ requirements.txt has no LLM / hosted-AI packages
  ✅ config/policy.yaml found

2) Running your system on the practice data (3 runs)
  ✅ exit code 0 in 2.1s
  ✅ output contract: CONTRACT OK
  ✅ same secret twice → identical sanitized/ and records.jsonl
  ✅ different secret → different output (pseudonyms / date shifts are keyed)
  ✅ RAKSHA_SECRET is never written to output or logs
  ✅ input folder left unchanged

   Next: python3 check_dev.py --output <your output>  shows how GOOD the output is.
   Event day has NO internet: also test with your network switched off.

READY TO SUBMIT (check the 1 ⚠️ notes)
Submit: your GitHub repo link + your 2-page Project Brief PDF, before the deadline.
exit 0

