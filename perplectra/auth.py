"""
API-key generation, hashing, and verification.

Keys are generated as:  pxk_live_<64 hex chars>  (32 random bytes)
Storage format:         <16-byte-salt-hex>:<32-byte-pbkdf2-hex>
Comparison:             hmac.compare_digest (constant-time)
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

KEY_PREFIX = "pxk_live_"
_ITERATIONS = 260_000
_HASH_LEN = 32     # bytes
_KEY_RANDOM_BYTES = 32


def generate_api_key() -> str:
    """Return a fresh plaintext API key. Call once; do not persist."""
    return KEY_PREFIX + secrets.token_hex(_KEY_RANDOM_BYTES)


def hash_api_key(plaintext_key: str) -> str:
    """
    Derive a stored hash from *plaintext_key*.

    Returns ``"<salt_hex>:<dk_hex>"``; safe to persist in the database.
    The plaintext key is never retained.
    """
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        plaintext_key.encode("utf-8"),
        salt,
        _ITERATIONS,
        _HASH_LEN,
    )
    return salt.hex() + ":" + dk.hex()


def verify_api_key(plaintext_key: str, stored_hash: str) -> bool:
    """
    Return True iff *plaintext_key* matches *stored_hash*.

    Uses constant-time comparison to resist timing attacks.
    Returns False (never raises) on any malformed input.
    """
    try:
        salt_hex, dk_hex = stored_hash.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(dk_hex)
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            plaintext_key.encode("utf-8"),
            salt,
            _ITERATIONS,
            _HASH_LEN,
        )
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def key_prefix_index(plaintext_key: str) -> str:
    """
    Return the first 20 chars of the random suffix for fast DB lookup.

    Stored alongside the hash so we can narrow candidate rows before
    the expensive PBKDF2 comparison.
    """
    suffix_start = len(KEY_PREFIX)
    return plaintext_key[suffix_start : suffix_start + 20]
