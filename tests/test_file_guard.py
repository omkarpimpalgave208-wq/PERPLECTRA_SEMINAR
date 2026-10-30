"""
Tests for perplectra.file_guard — path safety enforcement.
"""
from __future__ import annotations

import os
import pytest
from pathlib import Path

from perplectra.file_guard import PathViolationError, safe_resolve, ALLOWED_FILENAMES


class TestSafeResolve:
    def test_valid_target(self, tmp_path: Path):
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / "target.txt").write_text("hello")
        resolved = safe_resolve("target.txt", ws)
        assert resolved == (ws / "target.txt").resolve()

    def test_dotdot_rejected(self, tmp_path: Path):
        ws = tmp_path / "ws"
        ws.mkdir()
        with pytest.raises(PathViolationError):
            safe_resolve("../secret.txt", ws)

    def test_absolute_path_rejected(self, tmp_path: Path):
        ws = tmp_path / "ws"
        ws.mkdir()
        with pytest.raises(PathViolationError):
            safe_resolve("/etc/passwd", ws)

    def test_path_with_directory_rejected(self, tmp_path: Path):
        ws = tmp_path / "ws"
        ws.mkdir()
        with pytest.raises(PathViolationError):
            safe_resolve("subdir/target.txt", ws)

    def test_unknown_filename_rejected(self, tmp_path: Path):
        ws = tmp_path / "ws"
        ws.mkdir()
        with pytest.raises(PathViolationError):
            safe_resolve("other_file.txt", ws)

    def test_empty_filename_rejected(self, tmp_path: Path):
        ws = tmp_path / "ws"
        ws.mkdir()
        with pytest.raises(PathViolationError):
            safe_resolve("", ws)

    def test_null_byte_rejected(self, tmp_path: Path):
        ws = tmp_path / "ws"
        ws.mkdir()
        with pytest.raises((PathViolationError, ValueError)):
            safe_resolve("target.txt\x00evil", ws)

    def test_symlink_rejected(self, tmp_path: Path):
        ws = tmp_path / "ws"
        ws.mkdir()
        outside = tmp_path / "outside.txt"
        outside.write_text("secret")
        link = ws / "target.txt"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            pytest.skip("Symlinks not supported on this platform/user")
        with pytest.raises(PathViolationError):
            safe_resolve("target.txt", ws)

    def test_traversal_via_encoded_dotdot(self, tmp_path: Path):
        ws = tmp_path / "ws"
        ws.mkdir()
        # URL-encoded or other obfuscation — all treated as plain string
        with pytest.raises(PathViolationError):
            safe_resolve("..%2Fsecret", ws)

    def test_nonexistent_workspace_root(self, tmp_path: Path):
        missing = tmp_path / "does_not_exist"
        with pytest.raises(PathViolationError):
            safe_resolve("target.txt", missing)

    def test_workspace_root_is_file_not_dir(self, tmp_path: Path):
        not_a_dir = tmp_path / "file.txt"
        not_a_dir.write_text("I am a file")
        with pytest.raises(PathViolationError):
            safe_resolve("target.txt", not_a_dir)

    def test_allowed_filenames_constant(self):
        assert "target.txt" in ALLOWED_FILENAMES
