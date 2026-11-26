#!/usr/bin/env python3
"""Header / key classification on unseen-but-plausible column names. Run: python3 tests/test_fields.py"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from wards.fields import classify_header as c  # noqa: E402

EXPECT = {
    "name": ["Name of Patient", "Pt Name", "PATIENT_NAME", "Patient Full Name", "Beneficiary Name", "Rogi ka Naam",
             "मरीज़ का नाम", "रोगी का नाम", "Name", "pt_full_name", "Insured Name", "Client Name", "Patient"],
    "rel_name": ["Father/Husband Name", "Guardian Name", "Next of Kin", "Attendant Name", "Relative's Name",
                 "पिता/पति का नाम", "Spouse Name", "Mother Name", "NOK", "Care Of", "Emergency Contact Name"],
    "phone": ["Contact No.", "Mobile Number", "Phone No", "Cell", "WhatsApp No", "मोबाइल", "Alt Mobile",
              "Emergency Contact No", "Ph. No.", "Telephone"],
    "aadhaar": ["UID Number", "Aadhar No.", "Aadhaar Card", "आधार", "आधार संख्या", "UIDAI No"],
    "abha": ["Health ID", "ABHA Number", "ABHA ID"],
    "uhid": ["MR Number", "MRN", "CR No", "Hospital No", "Reg. No.", "Registration Number", "Patient ID", "IP/OP No",
             "UHID No", "पंजीकरण संख्या", "Medical Record No"],
    "dob": ["Date of Birth", "D.O.B.", "Birth Date", "जन्म तिथि", "DOB (DD/MM/YYYY)"],
    "age": ["Age (Yrs)", "Umar", "आयु", "उम्र", "Age in years"],
    "village": ["Gram", "Village Name", "गांव", "ग्राम", "Gram Panchayat", "Town/Village", "City/Village"],
    "pin": ["Postal Code", "Pincode", "PIN Code", "पिन कोड", "Zip"],
    "address": ["Residential Address", "Permanent Address", "पता", "Address Line 1", "Street"],
    "email": ["E-mail", "Email ID", "Mail"],
    "doctor": ["Referring Dr", "Consultant", "Treating Doctor", "Ref. By", "Doctor Name"],
}


def main():
    fails = 0
    n = 0
    for want, labels in EXPECT.items():
        for lab in labels:
            n += 1
            got = c(lab)
            if got != want:
                fails += 1
                print(f"{lab!r:28} expected {want:9} got {got}")
    print(f"{n} headers, {fails} failures")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
