#!/usr/bin/env python3
"""Run the OFFICIAL toolkit checks on the practice data and save their full output to docs/results/.

  python3 tools/get_kit.py && python3 tools/run_official_checks.py

* validate_output.py and check_dev.py run on a fresh release of the practice data;
* check_submission.py --run runs on a CLEAN CLONE of HEAD, so files that only exist in this working copy
  (the git-ignored kit, its practice PDF, a local .venv) cannot make it pass by accident.
These are the toolkit's practice self-checks, not the hidden-data evaluator.
"""
import datetime
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KIT = Path(os.environ.get("SECRET_WARDS_KIT", ROOT / "kit"))


def sh(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", **kw)
    return r.returncode, (r.stdout + r.stderr).strip()


def main():
    if not (KIT / "check_dev.py").exists():
        print("NOT VERIFIED: toolkit not found. Run: python3 tools/get_kit.py (or set SECRET_WARDS_KIT)")
        return 2
    head = sh(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"])[1]
    dirty = sh(["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=no"])[1]
    kit_head = sh(["git", "-C", str(KIT), "rev-parse", "--short", "HEAD"])[1] if (KIT / ".git").exists() else "unknown (no .git)"
    lines = [f"# Official toolkit checks", f"date: {datetime.datetime.now().isoformat(timespec='seconds')}",
             f"project commit: {head}{' (working tree has uncommitted changes)' if dirty else ''}",
             f"toolkit commit: {kit_head}", f"python: {sys.version.split()[0]}", ""]
    rc_all = 0
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "out"
        env = dict(os.environ, RAKSHA_SECRET="practice")
        rc, txt = sh([sys.executable, str(ROOT / "main.py"), "--input", str(KIT / "dev" / "input"), "--output", str(out)], env=env)
        lines += ["## run", f"$ RAKSHA_SECRET=practice python3 main.py --input kit/dev/input --output out", txt, f"exit {rc}", ""]
        rc_all |= rc
        rc, txt = sh([sys.executable, str(KIT / "validate_output.py"), "--input", str(KIT / "dev" / "input"), "--output", str(out)])
        lines += ["## validate_output.py", "$ python3 kit/validate_output.py --input kit/dev/input --output out", txt, f"exit {rc}", ""]
        rc_all |= rc
        rc, txt = sh([sys.executable, str(KIT / "check_dev.py"), "--output", str(out)])
        lines += ["## check_dev.py", "$ python3 kit/check_dev.py --output out", txt, f"exit {rc}", ""]
        rc_all |= rc
        clone = Path(td) / "clean_clone"
        sh(["git", "clone", "--quiet", str(ROOT), str(clone)])
        rc, txt = sh([sys.executable, str(KIT / "check_submission.py"), "--repo", str(clone), "--run"])
        lines += ["## check_submission.py (clean clone of HEAD)", "$ python3 kit/check_submission.py --repo <clean clone> --run", txt, f"exit {rc}", ""]
        tmp_forms = {td, os.path.realpath(td)}
        for i, ln in enumerate(lines):
            for t in sorted(tmp_forms, key=len, reverse=True):
                ln = ln.replace(t, "<tmp>")
            lines[i] = ln.replace("/private<tmp>", "<tmp>")
    res = ROOT / "docs" / "results"
    res.mkdir(parents=True, exist_ok=True)
    (res / "official_practice_checks.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"saved to {res / 'official_practice_checks.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
