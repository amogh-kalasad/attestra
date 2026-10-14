"""Tests for file hashing used in durable job artifact tracking."""
from __future__ import annotations

import hashlib

from attestra.jobs.durable import _hash_file


def test_hash_file_matches_hashlib_small(tmp_path):
    data = b"hello world" * 1000
    f = tmp_path / "small.bin"
    f.write_bytes(data)
    expected = hashlib.sha256(data).hexdigest()
    assert _hash_file(f) == expected


def test_hash_file_matches_hashlib_large(tmp_path):
    """Write >1MB file and verify chunked hash equals hashlib.sha256."""
    # 1.5 MB of repeating pattern
    data = b"A" * 1024 * 1024 + b"B" * 512 * 1024
    f = tmp_path / "large.bin"
    f.write_bytes(data)
    expected = hashlib.sha256(data).hexdigest()
    assert _hash_file(f) == expected


def test_hash_file_different_content_differs(tmp_path):
    f1 = tmp_path / "a.bin"
    f2 = tmp_path / "b.bin"
    f1.write_bytes(b"content-a")
    f2.write_bytes(b"content-b")
    assert _hash_file(f1) != _hash_file(f2)


def test_hash_file_empty(tmp_path):
    f = tmp_path / "empty.bin"
    f.write_bytes(b"")
    expected = hashlib.sha256(b"").hexdigest()
    assert _hash_file(f) == expected
