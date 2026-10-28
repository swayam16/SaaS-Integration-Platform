"""Envelope encryption for OAuth tokens and other secrets at rest.

Each value is encrypted with a fresh 256-bit data key using AES-256-GCM. In AWS the data key
comes from KMS GenerateDataKey and only its KMS-encrypted form is stored next to the
ciphertext; decrypting requires kms:Decrypt on the customer-managed key, which only the
functions that need tokens are granted. An encryption context (purpose + provider) is bound to
both the KMS call and the GCM associated data, so a ciphertext copied to another record will not
decrypt.

Locally (dev server, tests) a static key from LOCAL_ENCRYPTION_KEY wraps the data keys instead.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


class KeyProvider(Protocol):
    name: str

    def generate(self, context: dict[str, str]) -> tuple[bytes, bytes]: ...

    def unwrap(self, wrapped: bytes, context: dict[str, str]) -> bytes: ...


class LocalKeyProvider:
    name = "local"

    def __init__(self, master_key: bytes):
        if len(master_key) != 32:
            raise ValueError("LOCAL_ENCRYPTION_KEY must be 32 bytes (base64)")
        self._aes = AESGCM(master_key)

    def generate(self, context: dict[str, str]) -> tuple[bytes, bytes]:
        key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        return key, nonce + self._aes.encrypt(nonce, key, _aad(context))

    def unwrap(self, wrapped: bytes, context: dict[str, str]) -> bytes:
        return self._aes.decrypt(wrapped[:12], wrapped[12:], _aad(context))


class KmsKeyProvider:
    name = "kms"

    def __init__(self, key_id: str, client=None):
        import boto3

        self.key_id = key_id
        self.client = client or boto3.client("kms")

    def generate(self, context: dict[str, str]) -> tuple[bytes, bytes]:
        resp = self.client.generate_data_key(
            KeyId=self.key_id, KeySpec="AES_256", EncryptionContext=context
        )
        return resp["Plaintext"], resp["CiphertextBlob"]

    def unwrap(self, wrapped: bytes, context: dict[str, str]) -> bytes:
        return self.client.decrypt(
            CiphertextBlob=wrapped, EncryptionContext=context, KeyId=self.key_id
        )["Plaintext"]


def _aad(context: dict[str, str]) -> bytes:
    return json.dumps(context, sort_keys=True, separators=(",", ":")).encode()


class Envelope:
    def __init__(self, provider: KeyProvider):
        self.provider = provider

    def encrypt(self, plaintext: bytes, context: dict[str, str]) -> dict:
        key, wrapped = self.provider.generate(context)
        nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(nonce, plaintext, _aad(context))
        return {
            "v": 1,
            "kp": self.provider.name,
            "ek": b64e(wrapped),
            "n": b64e(nonce),
            "ct": b64e(ct),
        }

    def decrypt(self, blob: dict, context: dict[str, str]) -> bytes:
        key = self.provider.unwrap(b64d(blob["ek"]), context)
        return AESGCM(key).decrypt(b64d(blob["n"]), b64d(blob["ct"]), _aad(context))


# --- HMAC helpers ------------------------------------------------------------------------------


def hmac_sha256_hex(secret: str | bytes, message: bytes) -> str:
    key = secret.encode() if isinstance(secret, str) else secret
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()
