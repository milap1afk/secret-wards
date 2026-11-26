#!/usr/bin/env bash
# Run the pipeline the way the evaluator does (Linux, no network, 2 CPUs, 4 GB, C locale), then the official
# checks on the output. Also checks determinism across PYTHONHASHSEED values and that another secret changes
# the output.
#
#   tools/run_in_container.sh [python-image]      default image: python:3.10-slim (the kit implies >= 3.10)
#
# Needs Docker and the toolkit in ./kit (python3 tools/get_kit.py). The repo and the kit are mounted read-only.
# setup (pip install) is NOT run: there is no network, which also exercises the fail-closed vault path.
set -euo pipefail
IMAGE="${1:-python:3.10-slim}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KIT="${SECRET_WARDS_KIT:-$ROOT/kit}"
[ -f "$KIT/check_dev.py" ] || { echo "NOT VERIFIED: toolkit not found (python3 tools/get_kit.py)"; exit 2; }
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

docker run --rm --network none --cpus 2 --memory 4g --memory-swap 4g \
  -e LANG=C -e LC_ALL=C -e PYTHONDONTWRITEBYTECODE=1 \
  -v "$ROOT":/repo:ro -v "$KIT":/kit:ro -v "$OUT":/out \
  "$IMAGE" sh -euc '
    python3 --version
    cd /repo
    python3 -c "import locale; print(\"locale encoding:\", locale.getpreferredencoding(False))"
    # PEP 540 turns on UTF-8 mode under the C locale; PYTHONUTF8=0 forces the ASCII default as a worst case
    PYTHONUTF8=0 python3 -c "import locale; print(\"forced locale encoding:\", locale.getpreferredencoding(False))"
    RAKSHA_SECRET=practice PYTHONUTF8=0 PYTHONHASHSEED=1 python3 main.py --input /kit/dev/input --output /out/ascii
    RAKSHA_SECRET=practice PYTHONHASHSEED=1    python3 main.py --input /kit/dev/input --output /out/a
    if diff -r /out/a/sanitized /out/ascii/sanitized >/dev/null && cmp -s /out/a/records.jsonl /out/ascii/records.jsonl; then
      echo "locale: identical output with an ASCII default encoding"; else echo "locale: output DIFFERS under ASCII default"; exit 1; fi
    RAKSHA_SECRET=practice PYTHONHASHSEED=4242 python3 main.py --input /kit/dev/input --output /out/b
    RAKSHA_SECRET=another  PYTHONHASHSEED=7    python3 main.py --input /kit/dev/input --output /out/c
    if diff -r /out/a/sanitized /out/b/sanitized >/dev/null && cmp -s /out/a/records.jsonl /out/b/records.jsonl; then
      echo "determinism: identical across PYTHONHASHSEED=1 and 4242"; else echo "determinism: DIFFERENT"; exit 1; fi
    if cmp -s /out/a/records.jsonl /out/c/records.jsonl; then echo "secret: records UNCHANGED with another secret"; exit 1;
      else echo "secret: another secret changes records.jsonl"; fi
    if grep -rq -- practice /out/a /out/b 2>/dev/null; then echo "secret: FOUND in output"; exit 1; else echo "secret: not found in output"; fi
    python3 /kit/validate_output.py --input /kit/dev/input --output /out/a
    python3 /kit/check_dev.py --output /out/a
  '
