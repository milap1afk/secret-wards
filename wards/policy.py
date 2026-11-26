"""Privacy policy loader. Reads config/policy.yaml (simple `key: value` lines, no PyYAML)."""
from __future__ import annotations

from pathlib import Path

DEFAULTS = {
    "age_band_years": 5,          # ages become bands such as 45-49 (always containing the true age)
    "age_top_code": 85,           # ages >= this become "85+" (very old patients are rare)
    "date_shift_max_days": 180,   # per-patient secret date shift in [-max, -min] U [min, max]
    "date_shift_min_days": 7,
    "village_policy": "tehsil",   # village -> tehsil (falls back to district)
    "pin_policy": "prefix3",      # 229678 -> 229***
    "dob_policy": "shift",        # DOB shifted with the patient's own date shift
    "rare_k": 3,                  # quasi-identifier groups smaller than k are generalised harder
    "embed_pseudonym": 1,         # write the pseudonym inside each exported record
}


def load(path: Path) -> dict:
    pol = dict(DEFAULTS)
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if ":" not in line:
                continue
            k, v = (x.strip() for x in line.split(":", 1))
            if not k:
                continue
            if v.lstrip("-").isdigit():
                pol[k] = int(v)
            else:
                pol[k] = v
    except OSError:
        pass
    return pol


POLICY = load(Path(__file__).resolve().parent.parent / "config" / "policy.yaml")
