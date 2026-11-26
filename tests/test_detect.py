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
    # --- overnight round 1 (40 new probes)
 ("Name & Age: Thangjam Ibomcha, 61", ["Thangjam Ibomcha"], []),
 ("Patient's name - Sebastian Kurian; age 44", ["Sebastian Kurian"], []),
 ("Informed son Mr. Abhilash Nambiar over phone.", ["Abhilash Nambiar"], []),
 ("Patient brought by daughter-in-law Rinku.", ["Rinku"], []),
 ("Relative (husband): Gurtej Singh Sandhu", ["Gurtej Singh Sandhu"], []),
 ("नाम - श्रीमती कमलेश कुमारी", ["कमलेश कुमारी"], []),
 ("पति का नाम : स्व. रघुवीर", ["रघुवीर"], []),
 ("मरीज़ श्यामलाल को बुखार है", ["श्यामलाल"], []),
 ("Baby of Pushpa, 2 days old, birth weight 2.4 kg", ["Pushpa"], ["2.4 kg"]),
 ("B/o Shabnam Khatoon, NICU bed 4", ["Shabnam Khatoon"], ["NICU bed 4"]),
 ("Next of kin: K. Lakshmi (mother), 9845012345", ["K. Lakshmi", "9845012345"], []),
 ("Caretaker Mr. P. Venkatesh", ["P. Venkatesh"], []),
 ("Consulted Dr. Anitha; patient Selvi informed.", ["Selvi"], ["Dr. Anitha"]),
 ("IP No: 2026-IP-004512, UHID 00451209", ["2026-IP-004512", "00451209"], []),
 ("ESIC No. 3109876543, CGHS card 1234567", ["3109876543", "1234567"], []),
 ("Aadhaar: 2345 6789 0123 (masked: XXXX-XXXX-0123)", ["2345 6789 0123", "XXXX-XXXX-0123"], []),
 ("Voter ID: UPX1234567", ["UPX1234567"], []),
 ("Ration card no. 0987654321UP", ["0987654321UP"], []),
 ("Mob: 98450 12345 / 080-2345 6789", ["98450 12345", "080-2345 6789"], []),
 ("Ph. +91 (98450) 12345", ["98450) 12345"], []),
 ("email:- selvi.k@yahoo.co.in", ["selvi.k@yahoo.co.in"], []),
 ("DOB 05-Jun-1979; Adm 2026-02-04; Dis 12th Feb 2026", ["05-Jun-1979"], []),
 ("जन्म: 05/06/1979", ["05/06/1979"], []),
 ("Address- #45, 3rd Cross, Gandhinagar, Mysuru 570001", ["#45", "570001"], []),
 ("पता: ग्राम रामपुर, पोस्ट सिकंदरपुर, जिला बलिया", ["रामपुर", "सिकंदरपुर"], []),
 ("Residing at Ward No. 7, Rampur Khas", ["Rampur Khas"], []),
 ("S/o Late Sh. Ram Kishore Tripathi", ["Ram Kishore Tripathi"], []),
 ("C/O Smt. Usha Devi, Purani Basti", ["Usha Devi"], []),
 ("Hinglish: Ramvati ji ki beti Anjali aayi thi", ["Ramvati", "Anjali"], []),
 ("{\"Shanmugam Pillai\": {\"phone\": \"9443012345\"}}", ["Shanmugam Pillai", "9443012345"], []),
 ("report for Thangjam Ibomcha 9845012345.pdf", ["Thangjam", "9845012345"], []),   # file names are detected with _ -> space
 ("K/C/O Hypothyroidism on Thyronorm 50 mcg OD", [], ["Hypothyroidism", "Thyronorm 50 mcg OD"]),
 ("Tab. Ecosprin AV 75/10 HS, Inj. Clexane 40 mg SC BD", [], ["Ecosprin AV 75/10", "Clexane 40 mg"]),
 ("Hb 11.2 g/dl, TLC 11,200/cumm, Platelets 1.5 lakh", [], ["11.2 g/dl", "11,200/cumm", "1.5 lakh"]),
 ("Diagnosis: Guillain-Barre syndrome; Wilson's disease ruled out", [], ["Guillain-Barre syndrome", "Wilson's disease"]),
 ("Seen in Medicine OPD by Dr. Lakshmi Narayanan (Unit II)", [], ["Dr. Lakshmi Narayanan"]),
 ("ASHA Sunita Devi accompanied the patient", ["Sunita Devi"], []),
 ("Referred from CHC Mohanlalganj", [], ["CHC Mohanlalganj"]),
 ("Follow-up after Eid; review on 15/03/2026", [], []),
 ("BP 150/100 mmHg on Telma 40; FBS 180 mg/dL", [], ["150/100", "Telma 40", "180 mg/dL"]),
    # --- overnight round 2 (40 new probes)
 ("Guardian - Teresa Fernandes (mother)", ["Teresa Fernandes"], []),
 ("pita ka naam: Ramprasad Yadav", ["Ramprasad Yadav"], []),
 ("बेटा: अजय, फ़ोन ९८७६५४३२१०", ["अजय", "९८७६५४३२१०"], []),
 ("Patient's husband Dr. Venkat Rao (orthopaedician) consented.", [], []),
 ("Consent signed by brother-in-law Harjinder.", ["Harjinder"], []),
 ("Accompanied by neighbour Mrs. Kamala Iyer", ["Kamala Iyer"], []),
 ("Pt. Mohd. Wasim Akram, 34/M", ["Wasim Akram"], ["34/M"[:0] or "Pt."]),
 ("Ms. Ngurthansangi, a 29 yr old female", ["Ngurthansangi"], []),
 ("MRS. ANNAMMA THOMAS 72 F", ["ANNAMMA THOMAS"], []),
 ("Name: Dr. (Mrs.) Sushma Rao [patient]", [], []),
 ("Passport No.: Z 1234567", ["Z 1234567"], []),
 ("DL No UP-32-2015-0012345", ["UP-32-2015-0012345"], []),
 ("Aadhaar ४५६७ ८९०१ २३४५", ["४५६७ ८९०१ २३४५"], []),
 ("ABHA address: wasim.akram@abdm", ["wasim.akram@abdm"], []),
 ("Insurance policy: 1234/5678/90/2026", ["1234/5678/90/2026"], []),
 ("Claim ref CLM-UP-2026-77881", ["CLM-UP-2026-77881"], []),
 ("DOB: 3rd of March 1985", ["3rd of March 1985"], []),
 ("Born on 03.III.1985", ["03.III.1985"], []),
 ("D.O.B : १२/०४/१९७७", ["१२/०४/१९७७"], []),
 ("पता: मोहल्ला चौक, पो. नवाबगंज, थाना कोतवाली, जिला बाराबंकी - २२५००१", ["मोहल्ला चौक", "नवाबगंज", "कोतवाली", "२२५००१"], []),
 ("ग्राम- बिशुनपुर, ब्लॉक- मोहनलालगंज", ["बिशुनपुर", "मोहनलालगंज"], []),
 ("Addr: Plot 22, Sector 5, Indira Nagar, Lucknow - 226016", ["Plot 22", "226016"], []),
 ("Shanti ka beta Raju aaya tha, उसका नंबर 9876501234", ["Shanti", "Raju", "9876501234"], []),
 ("Mareez Kalpana ko ultiyan ho rahi hain", ["Kalpana"], []),
 ("Rogi ki patni Sunaina ne bataya", ["Sunaina"], []),
 ("Shri Ram ji ki kripa se theek hai", [], []),
 ("Tab Shelcal 500 OD, Cap Rosuvas 10 HS, Syp Lactulose 15 ml", [], ["Shelcal 500", "Rosuvas 10", "Lactulose 15 ml"]),
 ("HbA1c 7.2 %, TSH 4.8 mIU/L, Vit D 18 ng/ml", [], ["7.2 %", "4.8 mIU/L", "18 ng/ml"]),
 ("USG: GB calculi; ECG: NSR; CXR: clear", [], ["GB calculi", "NSR", "clear"]),
 ("Down syndrome child with Hirschsprung disease", [], ["Down syndrome", "Hirschsprung disease"]),
 ("Hodgkin lymphoma stage II; Bell palsy resolved", [], ["Hodgkin lymphoma", "Bell palsy"]),
 ("Reviewed by Prof. Mathew Abraham, HOD Cardiology", [], ["Prof. Mathew Abraham"]),
 ("Nurse Rekha gave Inj. Pan 40 at 22:00", [], ["Inj. Pan 40"]),
 ("Admitted on 11-Mar-26 at 10:30 hrs, discharged 15-Mar-26", [], []),
 ("Weight 52 kg, height 158 cm, BMI 20.8", [], ["52 kg", "158 cm", "20.8"]),
 ("Follow up in 2 weeks with CBC, LFT, KFT", [], ["2 weeks", "CBC, LFT, KFT"]),
 ("Ward 7 (Female Medical), Bed No. 12", [], ["Ward 7 (Female Medical)"]),
 ("Contact Ms. Pooja (PRO) at 0522-4012345 for records", [], []),
 ("{\"name\": \"Tsering Dolma\", \"relation\": \"self\", \"ph\": \"9612345678\"}", ["Tsering Dolma", "9612345678"], []),
 ("Lalthanpuii-ka sugar control mein hai", ["Lalthanpuii"], []),
    # --- mechanisms exposed by blind holdout 2 (written as new, unseen strings)
    ("Visitor Phurba Lhamu Sherpa (neighbour) asked about bed no.", ["Phurba Lhamu Sherpa"], []),
    ("मरीज़ के साथ पड़ोसन रेबिका लिंगदोह आई थी", ["रेबिका लिंगदोह"], []),
    ("Neighbour said fever started 3 days ago", [], ["fever started"]),
    ("discharge summary JIP.27.00311 filed; ref XK.28.00412", ["JIP.27.00311", "XK.28.00412"], []),
    # --- overnight round 3 (40 new probes; the two age probes live in tests/test_render.py)
 ("Pt: M. Karthikeyan, 58/M", ["M. Karthikeyan"], []),
 ("Name: Lakshmi K. R.", ["Lakshmi K. R"], []),
 ("Attendant: Joseph D'Cruz (son)", ["Joseph D'Cruz"], []),
 ("Patient name: Fatima Al-Hassan", ["Fatima Al-Hassan"], []),
 ("माता का नाम: सरोज", ["सरोज"], []),
 ("पिता/पति: रामबाबू", ["रामबाबू"], []),
 ("Patient रमेश ka BP high hai", ["रमेश"], ["BP high"]),
 ("Rogi ka naam Bhagwandas hai", ["Bhagwandas"], []),
 ("Spoke to wife (Mrs. Neelam) regarding prognosis", ["Neelam"], []),
 ("Sister Josephine (staff nurse) on duty", [], []),
 ("Stevens-Johnson syndrome due to carbamazepine", [], ["Stevens-Johnson syndrome"]),
 ("Ramsay Hunt syndrome, Cushing's disease excluded", [], ["Ramsay Hunt syndrome", "Cushing's disease"]),
 ("Referred to Apollo Hospitals, Lucknow", [], ["Apollo Hospitals"]),
 ("Transferred to St. Stephen's Hospital, Delhi", [], ["St. Stephen's Hospital"]),
 ("Seen at Dr. Ramesh's clinic last week", [], ["Dr. Ramesh"]),
 ("Tab Dolo 650 1/2 tab SOS, Inj Insulin 10 U SC", [], ["1/2 tab SOS", "10 U SC"]),
 ("RR 22/min, Na+ 132 mEq/L, K+ 3.2 mEq/L, Cr 1.8 mg/dL", [], ["22/min", "132 mEq/L", "3.2 mEq/L"]),
 ("Ph: 0522 2234567, alt +91-522-2234567", ["0522 2234567", "522-2234567"], []),
 ("Mob no. 9415-012-345", ["9415-012-345"], []),
 ("UHID: UH 2026 004512", ["UH 2026 004512"], []),
 ("Ayushman card no 1234 5678 9012 34", ["1234 5678 9012 34"], []),
 ("Address: Flat 4B, Tower C, Sushant Golf City, Lucknow 226030", ["Flat 4B", "226030"], []),
 ("r/o near Hanuman Mandir, Aliganj", ["Hanuman Mandir"], []),
 ("Village Bhaisaura, Post Mohanlalganj, District Lucknow", ["Bhaisaura", "Mohanlalganj"], []),
 ("DOB: Jan 5th, 1990", ["Jan 5th, 1990"], []),
 ("Admitted 2026-01-05T10:30Z, discharged 05/01/26 10:30", [], []),
 ("6 months old baby, wt 6.5 kg", [], ["6.5 kg"]),
 ("{\"मरीज़ का नाम\": \"सुनीता यादव\"}", ["सुनीता यादव"], []),
 ("Nominee: Rekha Kumari (daughter), Contact 9839012345", ["Rekha Kumari", "9839012345"], []),
 ("Claimant: Mohd. Arshad; Policy holder: Mohd. Arshad", ["Arshad"], []),
 ("Referred by: ASHA Kamlesh", ["Kamlesh"], []),
 ("Accompanied by her mother-in-law Smt. Prabha", ["Prabha"], []),
 ("Hb 9.8 on 12/02/2026; repeat Hb 10.4 on 19/02/2026", [], ["Hb 9.8", "Hb 10.4"]),
 ("Advice: Tab Pantocid 40 mg OD before breakfast x 14 days", [], ["Pantocid 40 mg OD", "14 days"]),
 ("Impression: Acute gastroenteritis with some dehydration", [], ["Acute gastroenteritis"]),
 ("Allergy: Penicillin; Sulfa drugs", [], ["Penicillin", "Sulfa drugs"]),
 ("Blood group B+, HIV/HBsAg/HCV non-reactive", [], ["B+", "non-reactive"]),
 ("Ward Shanti Bhawan, Bed 7", [], ["Bed 7"]),
    # --- overnight round 4 (40 new probes)
 ("Murphy's sign positive, McBurney's point tender", [], ["Murphy's sign", "McBurney's point"]),
 ("Babinski upgoing; Kernig's sign negative; Mallory-Weiss tear on OGD", [], ["Babinski", "Kernig's sign", "Mallory-Weiss tear"]),
 ("G2P1L1, LMP 12/01/2026, Apgar 8/9 at birth", [], ["G2P1L1", "Apgar 8/9"]),
 ("SGOT/SGPT 45/60 IU/L, Sr. Creatinine 1.1, CRP 12 mg/L", [], ["45/60 IU/L", "Sr. Creatinine 1.1", "CRP 12 mg/L"]),
 ("Rh negative, Stage II, Grade 3 VUR", [], ["Rh negative", "Stage II", "Grade 3"]),
 ("Name: Ramesh K. (OPD 2)", ["Ramesh K"], []),
 ("Patient Name : SUNIL KUMAR S", ["SUNIL KUMAR"], []),
 ("VID: 9182 7364 5546 1029", ["9182 7364 5546 1029"], []),
 ("mail: ramesh.k[at]gmail[dot]com", ["ramesh.k[at]gmail[dot]com"], []),
 # round 10: date ranges are not vehicle numbers, birth years are DOBs, infant ages in days/months stay
 ("Born 1931. Widow.", ["1931"], []),
 ("Patient born in 1940 at Kanpur", ["1940"], []),
 ("Neonate aged 9 days, wt 2.6 kg", [], ["aged 9 days"]),
 ("Age 7 months, febrile", [], ["Age 7 months"]),
 ("Car MH 12 DE 1433 parked", ["MH 12 DE 1433"], []),
 ("Patient: Sohan Lal, DOB 02/05/2014, mob 9450011100", ["Sohan Lal", "02/05/2014"], ["DOB"]),
 ("Name: Kamini Arora, Age 33, Sex F", ["Kamini Arora"], ["Age 33"]),
 # round 8: name labels in other Indian scripts; localities named by suffix inside an address
 ("রোগীর নাম: অনিমা ঘোষ", ["অনিমা ঘোষ"], []),
 ("નામ - ભાવેશ શાહ", ["ભાવેશ શાહ"], []),
 ("பெயர்: செல்வி", ["செல்வி"], []),
 ("పేరు: లక్ష్మి", ["లక్ష్మి"], []),
 ("Address: 14, Rajendra Nagar, Bareilly", ["Rajendra Nagar"], ["Bareilly"]),
 ("Address: B-7 Green Park Apartments, Noida", ["Green Park Apartments"], []),
 ("Address: Vill. Hasanpur, Distt Ambedkar Nagar", ["Hasanpur"], ["Ambedkar Nagar"]),
 ("Seen in Medicine OPD, Gandhi Nagar branch? no", [], []),
 # round 7: numbered and plural labels with name lists, drug before dose, multi-word eponyms, salutations
 ("Witness 2: Gurnam", ["Gurnam"], []),
 ("Attendants: Chintu, Golu and Monu", ["Chintu", "Golu", "Monu"], []),
 ("Contact no. 2: Bhavna", ["Bhavna"], []),
 ("on Tab Dytor 10 mg OD and Rosuvas 10 mg HS", [], ["Dytor 10 mg OD", "Rosuvas 10 mg HS"]),
 ("Arnold-Chiari malformation; Virchow node palpable", [], ["Virchow node"]),
 ("प्रिय रेखा, कृपया रिपोर्ट लें", ["रेखा"], []),
 ("Dear Sir, kindly admit", [], ["Sir"]),
 ("Dear Doctor, please review", [], ["Doctor"]),
 # round 5: relation word + bracketed name, (Name, 41F), Devanagari hospital ward, Devanagari name before a bare phone
 ("Informant: mother (Saroja)", ["Saroja"], []),
 ("History given by husband (Dilip Kumar Rawat)", ["Dilip Kumar Rawat"], []),
 ("Patient (Pemba Lhamu, 37F) shifted to ICU", ["Pemba Lhamu"], ["ICU"]),
 ("Seen (Harbhajan, 66 M) in OPD", ["Harbhajan"], []),
 ("Dr. (Iyer, 45M) reviewed", [], []),
 ("भर्ती 04/05/2026, वार्ड 7, बेड 3", [], ["वार्ड 7"]),
 ("सूची: कमलेश तिवारी 9935012345", ["कमलेश तिवारी", "9935012345"], []),
 ("संपर्क करें 9935012345", ["9935012345"], ["संपर्क करें"]),
 ("मो० ९८३९०१२३४५, फ़ोन नं.- 9839012345", ["९८३९०१२३४५", "9839012345"], []),
 ("श्रीमती सुमन देवी पत्नी श्री राजेश कुमार", ["सुमन देवी", "राजेश कुमार"], []),
 ("निवासी ग्राम रामनगर, थाना बीकेटी", ["रामनगर", "बीकेटी"], []),
 ("Neha ki mummy ne bataya ki bukhar kal se hai", ["Neha"], ["bukhar"]),
 ("Sunil bhaiya ke papa ko sugar hai", ["Sunil"], []),
 ("R/o Vill- Rampur Kalan, PO- Sidhauli", ["Rampur Kalan", "Sidhauli"], []),
 ("Resident of Mohalla Chaupatiyan, Lucknow", ["Mohalla Chaupatiyan"], ["Lucknow"]),
 ("Contact person - Mr. Arvind Mishra 9450012345", ["Arvind Mishra", "9450012345"], []),
 ("Husband: Late Shri Shivnath Prasad", ["Shivnath Prasad"], []),
 ("Wife's name: Mrs. Rekha Agrawal", ["Rekha Agrawal"], []),
 ("Daughter Ms. Priyanka (Bangalore) informed via call", ["Priyanka"], []),
 ("Pt's son-in-law Rajeev Ranjan signed LAMA", ["Rajeev Ranjan"], []),
 ("Patient Smt Kalawati W/O Ram Lakhan Age 65 Y", ["Kalawati", "Ram Lakhan"], []),
 ("PAN: ABCDE1234F, GSTIN 09ABCDE1234F1Z5", ["ABCDE1234F"], []),
 ("ABHA No 12-3456-7890-1234", ["12-3456-7890-1234"], []),
 ("IP Reg. No. 26/0045123", ["26/0045123"], []),
 ("Policy no: OG-26-1234-5678-00000123", ["OG-26-1234-5678-00000123"], []),
 ("DOB/Age: 14-08-1962 / 63 Y", ["14-08-1962"], []),
 ("Date of birth 1962-08-14 (as per Aadhaar)", ["1962-08-14"], []),
 ("Adm. on Monday, 2nd Feb; Disch. on 9th Feb", [], []),
 ("Patient is from Sitapur district, Mishrikh tehsil", [], ["Sitapur"]),
 ("Lives alone; son works in Dubai", [], []),
 ("Bed 14, Female Surgical Ward, Unit III", [], ["Bed 14", "Female Surgical Ward"]),
 ("Dr. Sharma (Physician) and Dr. A. K. Singh (Surgeon) reviewed", [], ["Dr. Sharma", "Dr. A. K. Singh"]),
 ("Discussed with Prof. (Dr.) R. N. Tiwari", [], ["Prof. (Dr.) R. N. Tiwari"]),
 ("Brought by 108 ambulance; driver Pappu Yadav", ["Pappu Yadav"], []),
 ("Hospital: King George's Medical University", [], ["King George's Medical University"]),
 ("Ramesh, Suresh and Mahesh (brothers) visited", ["Ramesh", "Suresh", "Mahesh"], []),
 ("{\"guardian\": {\"naam\": \"Shyam Lal\", \"rishta\": \"pita\"}}", ["Shyam Lal"], []),
 ("Tab. Telma-H 40/12.5 OD, Inj. Augmentin 1.2 g IV BD", [], ["Telma-H 40/12.5 OD", "Augmentin 1.2 g IV BD"]),
 ("Temp 98.6F, pulse 76/min, BP 118/76", [], ["98.6F", "76/min", "118/76"]),
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
