#!/usr/bin/env python3
"""Header / key classification on unseen-but-plausible column names. Run: python3 tests/test_fields.py"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from wards.fields import classify_header as c  # noqa: E402

EXPECT = {
    "name": ["pt_nm", "pt name", "Name of Patient", "Pt Name", "PATIENT_NAME", "Patient Full Name", "Beneficiary Name", "Rogi ka Naam",
             "मरीज़ का नाम", "रोगी का नाम", "Name", "pt_full_name", "Insured Name", "Client Name", "Patient"],
    "rel_name": ["Father/Husband Name", "Guardian Name", "Next of Kin", "Attendant Name", "Relative's Name",
                 "पिता/पति का नाम", "Spouse Name", "Mother Name", "NOK", "Care Of", "Emergency Contact Name"],
    "phone": ["Contact No.", "Mobile Number", "Phone No", "Cell", "WhatsApp No", "मोबाइल", "Alt Mobile",
              "Emergency Contact No", "Ph. No.", "Telephone"],
    "aadhaar": ["UID Number", "Aadhar No.", "Aadhaar Card", "आधार", "आधार संख्या", "UIDAI No"],
    "abha": ["Health ID", "ABHA Number", "ABHA ID"],
    "uhid": ["hosp_no", "Hosp. No.", "MR Number", "MRN", "CR No", "Hospital No", "Reg. No.", "Registration Number", "Patient ID", "IP/OP No",
             "UHID No", "पंजीकरण संख्या", "Medical Record No"],
    "dob": ["Date of Birth", "D.O.B.", "Birth Date", "जन्म तिथि", "DOB (DD/MM/YYYY)"],
    "age": ["Age (Yrs)", "Umar", "आयु", "उम्र", "Age in years"],
    "village": ["Gram", "Village Name", "गांव", "ग्राम", "Gram Panchayat", "Town/Village", "City/Village"],
    "pin": ["Postal Code", "Pincode", "PIN Code", "पिन कोड", "Zip"],
    "address": ["Residential Address", "Permanent Address", "पता", "Address Line 1", "Street"],
    "email": ["E-mail", "Email ID", "Mail"],
    "text": ["ref_range", "sample_id", "bill_no", "loinc"],
    "doctor": ["Referring Dr", "Consultant", "Treating Doctor", "Ref. By", "Doctor Name"],
}


VALUE_CASES = [  # (values, key, ancestors, expected sem) for columns whose NAME says nothing
    (["241606", "229073"], "dak_suchak", ["pata"], "pin"),
    (["241606", "229073"], "x9", ["pata"], "pin"),
    (["137130", "250000"], "value", ["results"], ""),           # platelet counts are not PINs
    (["8599253525", "+91 98765 43210"], "col7", [], "phone"),
    (["234123412346", "499118665246"], "col8", [], "aadhaar"),   # Verhoeff-valid
    (["234123412345", "499118665247"], "col9", [], ""),          # 12 digits, invalid checksum
    (["Lalita Gaikwad", "Ramesh Rao", "Sohan Lal Murmu"], "col3", [], "name_unknown"),
    (["Observation", "Encounter", "Composition"], "resourceType", [], ""),
    (["Medicine", "Surgery", "Pulmonology"], "col4", [], ""),
    (["2024-06-28", "2025-01-02"], "darj", [], "date"),
]


def main():
    from wards.fields import value_type, classify_json, OTHER_PERSON_IF_NAMED
    for key in ("exported_by", "verified_by", "createdBy"):
        if classify_json(key, ["_export_meta"]) != OTHER_PERSON_IF_NAMED:
            print(f"{key}: not treated as a possible person")
            return 1
    from wards.fields import classify_header
    for h in ("ठिकाना", "निवास", "thikana"):
        if classify_header(h) != "address":
            print(f"{h!r}: not an address header")
            return 1
    from wards.pipeline import split_embedded_relation
    for cell, want in (("Mrs. Kanta w/o Suraj Bhan", ("Mrs. Kanta", "Suraj Bhan")), ("Ramesh S/O Mohan Lal", ("Ramesh", "Mohan Lal")),
                       ("सीमा पत्नी राजेश", ("सीमा", "राजेश")), ("Sunita Devi", ("Sunita Devi", ""))):
        if split_embedded_relation(cell) != want:
            print(f"{cell!r}: split {split_embedded_relation(cell)} (want {want})")
            return 1
    # hyphen / space / possessive spellings of a key mean the same as the underscore form
    for a, b in (("emergency-contact-phone", "emergency_contact_phone"), ("mothers-name", "mother_name"),
                 ("Husband's Name", "husband_name"), ("guardian.name", "guardian_name")):
        if classify_json(a, []) != classify_json(b, []):
            print(f"{a!r} -> {classify_json(a, [])} but {b!r} -> {classify_json(b, [])}")
            return 1
    fails = 0
    n = 0
    for vals, key, anc, want in VALUE_CASES:
        n += 1
        got = value_type(vals, key, anc)
        if got != want:
            fails += 1
            print(f"values {vals[:2]} key={key!r}: expected {want!r} got {got!r}")
    for want, labels in EXPECT.items():
        for lab in labels:
            n += 1
            got = c(lab)
            if got != want:
                fails += 1
                print(f"{lab!r:28} expected {want:9} got {got}")
    print(f"{n} headers and value columns, {fails} failures")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
