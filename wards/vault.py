"""Encrypted quarantine vault.

Files that cannot be sanitised safely are never copied in clear text. If the `cryptography`
package is available they are kept as Fernet (AES-128-CBC + HMAC-SHA256) ciphertext under
output/quarantine/, named by a keyed hash, so an operator holding RAKSHA_SECRET can review
them later. The key is derived from RAKSHA_SECRET with HKDF and never written anywhere.
Without `cryptography`, nothing is stored (fail closed).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
from pathlib import Path

try:  # optional dependency: fail closed when missing
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except Exception:  # noqa: BLE001
    Fernet = None


def _key() -> bytes | None:
    secret = os.environ.get("RAKSHA_SECRET", "").encode("utf-8")
    if Fernet is None or not secret:
        return None
    raw = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"secret-wards-vault", info=b"quarantine").derive(secret)
    return base64.urlsafe_b64encode(raw)


def store(out: Path, raw: bytes) -> bool:
    key = _key()
    if key is None:
        return False
    name = hmac.new(key, raw, hashlib.sha256).hexdigest()[:24] + ".bin"
    qdir = out / "quarantine"
    qdir.mkdir(parents=True, exist_ok=True)
    # random IV per file (correct practice); quarantine/ is outside the release and not compared
    token = Fernet(key).encrypt_at_time(raw, 0)
    (qdir / name).write_bytes(token)
    return True
