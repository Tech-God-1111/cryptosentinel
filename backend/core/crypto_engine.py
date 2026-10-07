"""
CRYPTOSENTINEL — Crypto Engine
AES-256-GCM authenticated encryption for military-style messaging.
"""

import os
import base64
import hashlib
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.config import AES_KEY_BYTES, NONCE_BYTES

class CryptoEngine:
    def __init__(self, master_key: Optional[bytes] = None):
        if master_key is not None:
            if len(master_key) != AES_KEY_BYTES:
                raise ValueError(f"Key must be {AES_KEY_BYTES} bytes")
            self.key = master_key
        else:
            self.key = AESGCM.generate_key(bit_length=AES_KEY_BYTES * 8)

        self.aesgcm = AESGCM(self.key)
        print(f"[CRYPTO] ✅ AES-256-GCM engine ready "
              f"(key fingerprint: {self.key_fingerprint()})")

    def key_fingerprint(self) -> str:
        digest = hashlib.sha256(self.key).hexdigest()
        return digest[:12].upper()

    def encrypt(self, plaintext: str) -> dict:
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode("utf-8")
        else:
            plaintext_bytes = plaintext

        nonce = os.urandom(NONCE_BYTES)
        ct_with_tag = self.aesgcm.encrypt(nonce, plaintext_bytes, None)

        ct = ct_with_tag[:-16]
        tag = ct_with_tag[-16:]
        plaintext_hash = hashlib.sha256(plaintext_bytes).hexdigest()

        return {
            "ciphertext": base64.b64encode(ct).decode("utf-8"),
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "tag": base64.b64encode(tag).decode("utf-8"),
            "tag_included": True,
            "hash": plaintext_hash,
        }

    def decrypt(self, ciphertext_b64: str, nonce_b64: str, tag_b64: str) -> str:
        ct = base64.b64decode(ciphertext_b64)
        nonce = base64.b64decode(nonce_b64)
        tag = base64.b64decode(tag_b64)
        ct_with_tag = ct + tag

        try:
            plaintext = self.aesgcm.decrypt(nonce, ct_with_tag, None)
            return plaintext.decode("utf-8")
        except Exception as e:
            raise ValueError(f"Decryption failed (tampered or wrong key): {e}")

    def verify(self, ciphertext_b64: str, nonce_b64: str, tag_b64: str) -> bool:
        try:
            self.decrypt(ciphertext_b64, nonce_b64, tag_b64)
            return True
        except Exception:
            return False

    @staticmethod
    def hash_plaintext(plaintext: str) -> str:
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        return hashlib.sha256(plaintext).hexdigest()

crypto_engine = CryptoEngine()