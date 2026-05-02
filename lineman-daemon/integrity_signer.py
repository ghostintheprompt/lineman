"""
integrity_signer.py — Forensic Report Signing Engine (v2.0)
==========================================================
Provides asymmetric signing for forensic reports using Ed25519.
Ensures that reports are immutable and originated from the trusted
lineman-daemon.

Elevation v2.0:
  - Persistent Ed25519 keypair.
  - Fallback key storage for development/restricted environments.
"""

import os
import base64
import logging
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

log = logging.getLogger(__name__)

# Primary storage: root-only system dir. Fallback: local project dir.
SYSTEM_KEYS_DIR = Path("/var/run/lineman_keys")
LOCAL_KEYS_DIR  = Path(__file__).parent.parent / "keys"

class IntegritySigner:
    """
    Handles key management and asymmetric signing.
    """

    def __init__(self):
        self._private_key = None
        self._public_key  = None
        self._keys_dir    = SYSTEM_KEYS_DIR
        self._load_or_generate_keys()

    def _load_or_generate_keys(self):
        try:
            # 1. Choose directory (with fallback)
            try:
                if not self._keys_dir.exists():
                    self._keys_dir.mkdir(parents=True, mode=0o700)
            except PermissionError:
                log.warning("[integrity] System key dir inaccessible. Falling back to local storage.")
                self._keys_dir = LOCAL_KEYS_DIR
                if not self._keys_dir.exists():
                    self._keys_dir.mkdir(parents=True, mode=0o700)

            priv_path = self._keys_dir / "lineman_ed25519.priv"
            pub_path  = self._keys_dir / "lineman_ed25519.pub"

            # 2. Load or Generate
            if priv_path.exists():
                with open(priv_path, "rb") as f:
                    self._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(f.read())
                self._public_key = self._private_key.public_key()
                log.info("[integrity] Loaded Ed25519 keypair from %s", self._keys_dir)
            else:
                self._private_key = ed25519.Ed25519PrivateKey.generate()
                self._public_key = self._private_key.public_key()
                
                # Save Raw bytes
                with open(priv_path, "wb") as f:
                    f.write(self._private_key.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
                
                with open(pub_path, "wb") as f:
                    f.write(self._public_key.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    ))
                
                os.chmod(priv_path, 0o400)
                log.info("[integrity] Generated NEW Ed25519 keypair in %s", self._keys_dir)
                
        except Exception as e:
            log.error("[integrity] Fatal Key Error: %s", e)

    def sign_payload(self, data: bytes) -> str:
        if not self._private_key: return ""
        return base64.b64encode(self._private_key.sign(data)).decode('utf-8')

    def get_public_key_b64(self) -> str:
        if not self._public_key: return ""
        pk_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return base64.b64encode(pk_bytes).decode('utf-8')

# ── Singleton access ──────────────────────────────────────────────────────────

_instance = None

def get_instance() -> IntegritySigner:
    global _instance
    if _instance is None:
        _instance = IntegritySigner()
    return _instance
