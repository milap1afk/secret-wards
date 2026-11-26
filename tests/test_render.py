#!/usr/bin/env python3
"""Output-level checks of free-text rendering (what a span test cannot see): ages banded, PINs cut to
3 digits, compact dates shifted, durations / doses / vitals / labs untouched. Run: python3 tests/test_render.py"""
import os
import re
import sys
from pathlib import Path

os.environ.setdefault("RAKSHA_SECRET", "render-test")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from wards.pipeline import Pipeline, Unit  # noqa: E402
from wards.privacy import shift_days  # noqa: E402

# (input, substrings that must be GONE from the output, substrings that must SURVIVE unchanged)
CASES = [
    ("Patient LALRINPUII HMAR (F/47) admitted under Dr. IYER.", ["F/47", "LALRINPUII"], ["Dr. IYER"]),
    ("Hmar, Lalrinpuii (47Y/F) — bed 12", ["47Y/F", "Lalrinpuii"], ["bed 12"]),
    ("Date of Birth: 12/04/1977 (52 yrs)", ["52 yrs", "1977"], []),
    ("a 52-year-old lady, 52 y/o F, umr 52 saal", ["52-year-old", "52 y/o", "umr 52"], ["lady"]),
    ("aged 52 years, 52 वर्षीय", ["aged 52", "52 वर्षीय"], []),
    ("Address: Mohalla Qazipura, PO Itaunja, Distt Lucknow 226203", ["226203", "Itaunja"], ["226***", "Lucknow"]),
    ("discharged 20260219.", ["20260219"], []),
    ("seen on 3rd of March 2026 and 03.III.2026", ["3rd of March 2026", "03.III.2026"], ["seen on"]),
    ("Ref 202602190045 sample", [], ["Ref", "sample"]),       # a 12-digit reference is an ID: removing it is right
    ("DM2 x 8 yrs, H/O TB 2 yrs back, fever for 8 days, HTN since 10 years, Tab Metformin 500 mg 1-0-1 x 5 days",
     [], ["x 8 yrs", "2 yrs back", "for 8 days", "since 10 years", "500 mg", "1-0-1", "x 5 days"]),
    ("BP 140/90 mmHg, Pulse 88/min, SpO2 97%, Hb 9.2 g/dL, RBS 216 mg/dL", [],
     ["140/90", "88/min", "97%", "9.2 g/dL", "216 mg/dL"]),
]


def main():
    pl = Pipeline(Path("."), Path("."))
    fails = 0
    for text, gone, keep in CASES:
        u = Unit("t", "doc", "doc", text=text)
        u.shift = shift_days("render#" + text)
        out = pl._render_free(text, u, set())
        for g in gone:
            if g in out:
                fails += 1
                print(f"STILL THERE {g!r:22} in {out!r}")
        for k in keep:
            if k not in out:
                fails += 1
                print(f"LOST        {k!r:22} in {out!r}")
    print(f"render test: {len(CASES)} cases, {fails} failures")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
