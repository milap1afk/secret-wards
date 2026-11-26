#!/usr/bin/env python3
"""Secret Wards privacy firewall. Usage: python main.py --input <dir> --output <empty dir>"""
import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wards.pipeline import run  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Offline, CPU-only, LLM-free de-identification pipeline")
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    a = ap.parse_args()
    if not os.environ.get("RAKSHA_SECRET", "").strip():
        # fail closed: an empty HMAC key would make pseudonyms and date shifts guessable
        sys.stderr.write("error: RAKSHA_SECRET is not set; refusing to run (nothing was written)\n")
        return 2
    try:
        return run(Path(a.input), Path(a.output))
    except Exception as exc:  # noqa: BLE001 - never print content, only the error type
        sys.stderr.write(f"fatal: {type(exc).__name__}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
