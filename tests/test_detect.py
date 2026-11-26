#!/usr/bin/env python3
"""Adversarial regression suite for the detector.

Each case: (text, must_remove, must_keep). A string in must_remove has to be fully covered by a
PII span; a string in must_keep must not be touched by any PII span.
Run: python3 tests/test_detect.py   (exit code 1 on failure)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from wards.detect import Detector  # noqa: E402

CASES = [
    # --- labels in many spellings
    ("Pt. Name: Ramkali Devi  Age: 62/F", ["Ramkali Devi"], ["62/F"]),
    ("Name of the patient: Bhagwati Prasad Gupta", ["Bhagwati Prasad Gupta"], []),
    ("Patient's Name - Sushila Kumari", ["Sushila Kumari"], []),
    ("Father's Name: Ram Avtar", ["Ram Avtar"], []),
    ("Husband's Name: Jagdish", ["Jagdish"], []),
    ("Guardian: Kallu Ram, Mob 9876543210", ["Kallu Ram", "9876543210"], []),
    ("मरीज़ का नाम: सुनीता देवी", ["सुनीता देवी"], []),
    ("पति का नाम: रमेश कुमार", ["रमेश कुमार"], []),
    # --- meaning traps
    ("C/O fever x 3 days. C/O Ramesh Yadav, H.No. 12", ["Ramesh Yadav", "H.No. 12"], ["C/O fever x 3 days"]),
    ("Seen by Dr. Ramesh Srivastava. Attendant Mukesh (brother) informed.", ["Mukesh"], ["Dr. Ramesh Srivastava"]),
    ("Tab Dolo 650 BD x 5 days, 1-0-1, Inj Ceftriaxone 1 g IV", [], ["Dolo 650 BD x 5 days", "1-0-1"]),
    ("K/C/O HTN on treatment. H/O TB 8 yrs back.", [], ["K/C/O HTN on treatment", "H/O TB 8 yrs back"]),
    ("Diagnosis: Parkinson's disease (G20); Bell's palsy", [], ["Parkinson's disease", "Bell's palsy"]),
    ("Referred by ASHA worker of the village.", [], ["ASHA worker"]),
    ("Ward 4 (Medicine) / Bed 12", [], ["Ward 4 (Medicine)"]),
    ("Haemoglobin 9.2 g/dL (12.0-16.0), Sodium 133 mmol/L", [], ["12.0-16.0", "133 mmol/L"]),
    # --- honorifics / Hinglish
    ("Sunita didi ka BP 140/90 hai", ["Sunita"], ["BP 140/90"]),
    ("Raju bhaiya ne dawai le li", ["Raju"], []),
    ("Shri Ram Prasad Verma ko discharge kiya", ["Ram Prasad Verma"], []),
    ("Smt. Kalawati ki tabiyat theek hai", ["Kalawati"], []),
    ("Mohd. Irfan sahab ka sugar 220", ["Irfan"], []),
    ("सुनीता जी को बुखार है", ["सुनीता"], []),
    ("Raat ko Nankau ki tabiyat kharab hui. Uske bete Pancham ne bataya.", ["Nankau", "Pancham"], []),
    ("Sunita ka sugar 240 tha, pati Ramesh ko bataya", ["Sunita", "Ramesh"], []),
    ("BP ki dawai ka time 8 baje", [], ["BP ki dawai"]),
    # --- identifiers in many formats
    ("Mob: +91-98765-43210", ["98765-43210"], []),
    ("ph 098765 43210", ["98765 43210"], []),
    ("Contact: 0522-2345678", ["0522-2345678"], []),
    ("Aadhaar 2345.6789.0123", ["2345.6789.0123"], []),
    ("Aadhaar: XXXX-XXXX-4521", ["XXXX-XXXX-4521"], []),
    ("ABHA: 91-1234-5678-9012, ABHA addr ramesh.k@abdm", ["91-1234-5678-9012", "ramesh.k@abdm"], []),
    ("PAN ABCPD1234K, PMJAY-UP-1234567890", ["ABCPD1234K", "PMJAY-UP-1234567890"], []),
    ("UHID: KGMU/2026/004512", ["KGMU/2026/004512"], []),
    ("MRN 20260045123 admitted", ["20260045123"], []),
    ("CR No. 45123/26", ["45123/26"], []),
    ("email: sunita.devi1980@gmail.com", ["sunita.devi1980@gmail.com"], []),
    # --- dates of birth in many formats
    ("DOB: 12-Apr-1977", ["12-Apr-1977"], []),
    ("Date of Birth: 1977/04/12", ["1977/04/12"], []),
    ("D.O.B. 12.04.77", ["12.04.77"], []),
    ("W/o Kamal Rajput. C/O fever x 3 days", ["Kamal Rajput"], ["C/O fever x 3 days"]),
    ("Pt seen with R. K. Sharma, S/o Late Shri M. L. Sharma.", ["M. L. Sharma"], []),
    # --- label variants (round 2)
    ("Rogi: Kamla Devi, Umar 55", ["Kamla Devi"], []),
    ("Naam - Ramesh Chandra", ["Ramesh Chandra"], []),
    ("मरीज: रमेश यादव", ["रमेश यादव"], []),
    ("Patient : Sunil Kumar Mishra", ["Sunil Kumar Mishra"], []),
    ("Name/Age/Sex: Mahendra Pal/45/M", ["Mahendra Pal"], []),
    ("Pt: Mrs. Asha Verma (W/o Late Shri Ram Verma)", ["Asha Verma", "Ram Verma"], []),
    ("IPD#: 2026-00045 UHID No.: 123/2026", ["2026-00045", "123/2026"], []),
    ("Reg. No. JJ/45123, Bed 4", ["JJ/45123"], ["Bed 4"]),
    ("Mob. no. 9876-543-210", ["9876-543-210"], []),
    ("Ph: (+91) 98765 43210", ["98765 43210"], []),
    ("Attendant name: Ram Lakhan; relation: husband", ["Ram Lakhan"], []),
    ("D/O SHRI RAMESH CHANDRA, AGE 23 YRS", ["RAMESH CHANDRA"], []),
    ("Next of kin - Sushma (wife) 9123456780", ["Sushma", "9123456780"], []),
    ("Admitted on 05.03.2026, discharged on 12.03.2026", [], []),
    # --- identifier shapes from the blind holdout (round 3)
    ("ph 683.865.6785, Cell# (+91) 846-312-2585", ["683.865.6785", "846-312-2585"], []),
    ("UPI debashish.811@paytm; mail a.b@gmail.com", ["debashish.811@paytm", "a.b@gmail.com"], []),
    ("A/c 899062550917419 IFSC SBIN0097854", ["899062550917419"], ["SBIN0097854"]),
    ("UHID: JJCH0077305", ["JJCH0077305"], []),
    ("DL UP15 20140589114, vehicle UP62 EN 4137, Passport P6324328, EPIC ABC1234567",
     ["UP15 20140589114", "UP62 EN 4137", "P6324328", "ABC1234567"], []),
    ("दवा लेने आए: थोकचोम इबोम्चा (पड़ोसी), मो. ९४३६० २१७७५", ["थोकचोम इबोम्चा", "९४३६० २१७७५"], []),
    ("जन्म तिथि: 12 अप्रैल 1977", ["12 अप्रैल 1977"], []),
    ("Escalation: +977 984-1052736, UK +44 20 7946 0958", ["+977 984-1052736", "+44 20 7946 0958"], []),
    ("Platelet 250000 /uL, WBC 13000, Temp 101.2 F", [], ["250000", "13000", "101.2"]),
    # --- trained name scorer: unseen names, only with supporting context on the line
    ("ललिता गायकवाड़ 51 वर्ष", ["ललिता गायकवाड़"], []),
    ("Tab Telmisartan Amlodipine 49/M", [], ["Telmisartan", "Amlodipine"]),
    ("Haemoglobin Random Blood Sugar 45/F", [], ["Haemoglobin", "Random Blood Sugar"]),
    # --- soft identifiers next to a patient (generalised, not deleted)
    ("Occupation: Primary school teacher, Rampur", ["Primary school teacher"], []),
    ("Pt works as a rickshaw puller and works at Lucknow Cold Storage", ["rickshaw puller", "Lucknow Cold Storage"], []),
    ("Beti Saraswati Shishu Vidya Mandir mein padhti hai", ["Saraswati Shishu Vidya Mandir"], []),
    ("Fever started on Holi, admitted 2 days after Diwali", ["Holi", "Diwali"], []),
    ("Holi ke din se bukhar hai", ["Holi ke din"], []),
    # --- overnight step 1: known gaps (empty lexicon)
    ("Beneficiary: Zoramthanga Pachuau; Insured person: Kunjumon Varkey", ["Zoramthanga Pachuau", "Kunjumon Varkey"], []),
    ("Emergency contact: Olivia D'Souza 91 9876543210", ["Olivia D'Souza", "9876543210"], []),
    ("रोगी: लालरिनपुई, उम्र ४७ वर्ष। अभिभावक: ज़ोरमथंगा", ["लालरिनपुई", "ज़ोरमथंगा"], []),
    ("Patient LALRINPUII HMAR (F/47) admitted under Dr. IYER.", ["LALRINPUII HMAR"], ["Dr. IYER"]),
    ("Hmar, Lalrinpuii (47Y/F) — bed 12", ["Hmar, Lalrinpuii"], []),
    ("pt name:lalrinpuii hmar age:47 sex:f mob:9876543210", ["lalrinpuii hmar", "9876543210"], []),
    ("Diagnosis: Typhoid Fever. Advice: Plenty Fluids. Consultant: Dr. Rao", [], ["Typhoid Fever", "Plenty Fluids", "Dr. Rao"]),
    ("F/o Chinnaswamy, H/o Mangayarkarasi. H/o DM x 5 yrs, H/o fall.", ["Chinnaswamy", "Mangayarkarasi"], ["H/o DM x 5 yrs", "H/o fall"]),
    ("Smt. Mangaleshwari Devi w/o Sh. Bhupendranath r/o Qazipura", ["Mangaleshwari Devi", "Bhupendranath", "Qazipura"], []),
    ("Zoramthanga uncle complained of chest pain.", ["Zoramthanga"], ["chest pain"]),
    ("Master Rehaan, 6 yrs, S/O Imtiyaz.", ["Rehaan", "Imtiyaz"], []),
    ("Chinnaswamy called at 14:00. Told Mangayarkarasi about discharge.", ["Chinnaswamy", "Mangayarkarasi"], []),
    ("MR# 2026/000123; Hosp. No. H-554321", ["2026/000123", "H-554321"], []),
    ("TPA ID 99887766, PMJAY ID PMJ9K2L7Q", ["99887766", "PMJ9K2L7Q"], []),
    ("OPD No. OPD/26/02/00085, Bill No BL/26/000235, Sample ID S26000187", [], ["OPD/26/02/00085", "BL/26/000235", "S26000187"]),
    ("Address: H.No. 12/4, Gali No. 3, Mohalla Qazipura, PO Itaunja, PS Mahona, Distt Lucknow 226203",
     ["H.No. 12/4", "Gali No. 3", "Mohalla Qazipura", "Itaunja", "Mahona"], ["Lucknow"]),
    ("Native of Gram Panchayat Kheri Kalan.", ["Kheri Kalan"], []),
    # --- canary-style names with role context only
    ("Consent witnessed by Tsering Wangmo, phone 8010993510.", ["Tsering Wangmo", "8010993510"], []),
    ("called by Kaveri Nambiar 94054-71434", ["Kaveri Nambiar", "94054-71434"], []),
    ("Informant: Lalremruati Pachuau", ["Lalremruati Pachuau"], []),
    ("Brought by her son Vikram", ["Vikram"], []),
    # --- address
    ("Address: H.No. 45, Mohalla Naya Tola, near Shiv Mandir, Vill. Rampur Khurd, Tehsil Bilgram - 241406",
     ["H.No. 45", "Mohalla Naya Tola", "near Shiv Mandir", "Rampur Khurd", "241406"], []),
    ("पता: मकान नं. 12, मोहल्ला गांधी नगर, हनुमान मंदिर के पास", ["मकान नं. 12", "मोहल्ला गांधी नगर", "हनुमान मंदिर के पास"], []),
]

PII_KINDS = {"NAME", "PHONE", "PHONE_MASKED", "AADHAAR", "AADHAAR_MASKED", "ABHA", "ABHA_ADDR", "EMAIL", "PAN",
             "INSURANCE", "MRN", "DOB", "HOUSE", "LOCALITY", "LANDMARK", "VILLAGE", "PIN", "ADDRESS",
             "UPI", "GOVID", "LONGNUM", "NAME_MODEL", "SOFT"}


def covered(spans, text, needle):
    i = text.find(needle)
    if i < 0:
        return None
    j = i + len(needle)
    pos = i
    for s in sorted(spans, key=lambda s: s.start):
        if s.kind not in PII_KINDS:
            continue
        if s.start <= pos < s.end:
            pos = s.end
            while pos < j and text[pos] in " ,.-":
                pos += 1
        if pos >= j:
            return True
    return pos >= j


def touched(spans, text, needle):
    i = text.find(needle)
    j = i + len(needle)
    return any(s.kind in PII_KINDS and s.start < j and i < s.end for s in spans)


def main():
    d = Detector()
    fails = 0
    for text, remove, keep in CASES:
        spans = d.detect(text)
        for r in remove:
            if not covered(spans, text, r):
                fails += 1
                print(f"MISS  {r!r:32} in {text!r}")
        for k in keep:
            if touched(spans, text, k):
                fails += 1
                print(f"HARM  {k!r:32} in {text!r}")
    print(f"{len(CASES)} cases, {fails} failures")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
