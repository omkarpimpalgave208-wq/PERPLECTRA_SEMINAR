"""
Tests for perplectra.auth — key generation, hashing, and verification.
"""
from __future__ import annotations

import pytest
from perplectra.auth import (
    KEY_PREFIX,
    generate_api_key,
    hash_api_key,
    key_prefix_index,
    verify_api_key,
)


class TestKeyGeneration:
    def test_prefix(self):
        key = generate_api_key()
        assert key.startswith(KEY_PREFIX)

    def test_length(self):
        key = generate_api_key()
        # pxk_live_ (9) + 64 hex chars (32 bytes)
        assert len(key) == len(KEY_PREFIX) + 64

    def test_uniqueness(self):
        keys = {generate_api_key() for _ in range(20)}
        assert len(keys) == 20, "Keys must be unique"

    def test_hex_suffix(self):
        key = generate_api_key()
        suffix = key[len(KEY_PREFIX):]
        int(suffix, 16)  # raises ValueError if not valid hex


class TestKeyHashing:
    def test_format(self):
        key = generate_api_key()
        stored = hash_api_key(key)
        parts = stored.split(":")
        assert len(parts) == 2
        salt_hex, dk_hex = parts
        # 16-byte salt → 32 hex chars
        assert len(salt_hex) == 32
        # 32-byte dk → 64 hex chars
        assert len(dk_hex) == 64

    def test_roundtrip_correct_key(self):
        key = generate_api_key()
        stored = hash_api_key(key)
        assert verify_api_key(key, stored) is True

    def test_roundtrip_wrong_key(self):
        key = generate_api_key()
        wrong = generate_api_key()
        stored = hash_api_key(key)
        assert verify_api_key(wrong, stored) is False

    def test_different_salts_each_call(self):
        key = generate_api_key()
        h1 = hash_api_key(key)
        h2 = hash_api_key(key)
        # Different salts → different stored hashes even for same key
        assert h1 != h2
        # But both verify correctly
        assert verify_api_key(key, h1) is True
        assert verify_api_key(key, h2) is True

    def test_malformed_stored_hash(self):
        key = generate_api_key()
        assert verify_api_key(key, "notahash") is False
        assert verify_api_key(key, ":") is False
        assert verify_api_key(key, "") is False

    def test_empty_key(self):
        stored = hash_api_key(generate_api_key())
        assert verify_api_key("", stored) is False


class TestKeyPrefixIndex:
    def test_length(self):
        key = generate_api_key()
        idx = key_prefix_index(key)
        assert len(idx) == 20

    def test_consistent(self):
        key = generate_api_key()
        assert key_prefix_index(key) == key_prefix_index(key)

    def test_different_keys_different_prefix(self):
        k1 = generate_api_key()
        k2 = generate_api_key()
        # Astronomically unlikely to collide
        assert key_prefix_index(k1) != key_prefix_index(k2)
