#!/usr/bin/env python3
"""Fetch the official Track 3 toolkit into ./kit (git-ignored), pinned to the commit we validated against.

  python3 tools/get_kit.py            # needs git and network
"""
import shutil
import subprocess
import sys
from pathlib import Path

URL = "https://github.com/Reinforce-SST/Secret-Wards-ToolKit.git"
PINNED = "6c0a85a"   # "Final review: keep sealed details out of the public kit" (2026-11-26)
ROOT = Path(__file__).resolve().parent.parent
KIT = ROOT / "kit"


def main():
    if (KIT / "check_dev.py").exists():
        print(f"kit already present at {KIT}")
        return 0
    if KIT.exists():
        shutil.rmtree(KIT)
    subprocess.run(["git", "clone", "--quiet", URL, str(KIT)], check=True)
    subprocess.run(["git", "-C", str(KIT), "checkout", "--quiet", PINNED], check=True)
    head = subprocess.run(["git", "-C", str(KIT), "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()
    print(f"kit ready at {KIT} (commit {head})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
