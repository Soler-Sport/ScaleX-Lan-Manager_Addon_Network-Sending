"""Tests for own_manager's disk-retention sweep (_cleanup_old_captures) -
the fix for RECEIVED_DIR/PENDING_DIR filling the disk within days by
never being cleaned up. Uses monkeypatch on the module's own directory/
retention-window globals so real C:\\own_manager is never touched."""
import os
import time

import own_manager


def _touch(path, age_days):
    path.write_bytes(b"x" * 1024)
    ts = time.time() - age_days * 86400
    os.utime(path, (ts, ts))


def test_removes_files_older_than_retention_window(tmp_path, monkeypatch):
    received = tmp_path / "received"
    pending = tmp_path / "pending"
    received.mkdir()
    pending.mkdir()
    monkeypatch.setattr(own_manager, "RECEIVED_DIR", str(received))
    monkeypatch.setattr(own_manager, "PENDING_DIR", str(pending))
    monkeypatch.setattr(own_manager, "RECEIVED_RETENTION_DAYS", 3)

    old_received = received / "old.ctb"
    old_pending = pending / "old.ctb"
    _touch(old_received, age_days=5)
    _touch(old_pending, age_days=5)

    own_manager._cleanup_old_captures()

    assert not old_received.exists()
    assert not old_pending.exists()


def test_keeps_files_within_retention_window(tmp_path, monkeypatch):
    received = tmp_path / "received"
    received.mkdir()
    monkeypatch.setattr(own_manager, "RECEIVED_DIR", str(received))
    monkeypatch.setattr(own_manager, "PENDING_DIR", str(tmp_path / "pending"))
    monkeypatch.setattr(own_manager, "RECEIVED_RETENTION_DAYS", 3)

    fresh = received / "fresh.ctb"
    _touch(fresh, age_days=1)

    own_manager._cleanup_old_captures()

    assert fresh.exists()


def test_mixed_old_and_fresh_only_removes_old(tmp_path, monkeypatch):
    received = tmp_path / "received"
    received.mkdir()
    monkeypatch.setattr(own_manager, "RECEIVED_DIR", str(received))
    monkeypatch.setattr(own_manager, "PENDING_DIR", str(tmp_path / "pending"))
    monkeypatch.setattr(own_manager, "RECEIVED_RETENTION_DAYS", 3)

    old_file = received / "old.ctb"
    fresh_file = received / "fresh.ctb"
    _touch(old_file, age_days=10)
    _touch(fresh_file, age_days=0.1)

    own_manager._cleanup_old_captures()

    assert not old_file.exists()
    assert fresh_file.exists()


def test_nonexistent_directories_do_not_raise(tmp_path, monkeypatch):
    monkeypatch.setattr(own_manager, "RECEIVED_DIR", str(tmp_path / "does_not_exist_received"))
    monkeypatch.setattr(own_manager, "PENDING_DIR", str(tmp_path / "does_not_exist_pending"))
    monkeypatch.setattr(own_manager, "RECEIVED_RETENTION_DAYS", 3)

    own_manager._cleanup_old_captures()  # must not raise


def test_ignores_subdirectories(tmp_path, monkeypatch):
    # Only files are swept - a subdirectory (e.g. a leftover timestamped
    # capture folder) must not be removed or cause an error.
    received = tmp_path / "received"
    received.mkdir()
    monkeypatch.setattr(own_manager, "RECEIVED_DIR", str(received))
    monkeypatch.setattr(own_manager, "PENDING_DIR", str(tmp_path / "pending"))
    monkeypatch.setattr(own_manager, "RECEIVED_RETENTION_DAYS", 3)

    subdir = received / "old_subdir"
    subdir.mkdir()
    old_ts = time.time() - 10 * 86400
    os.utime(subdir, (old_ts, old_ts))

    own_manager._cleanup_old_captures()  # must not raise

    assert subdir.exists()


def test_empty_directories_produce_no_removals(tmp_path, monkeypatch):
    received = tmp_path / "received"
    received.mkdir()
    monkeypatch.setattr(own_manager, "RECEIVED_DIR", str(received))
    monkeypatch.setattr(own_manager, "PENDING_DIR", str(tmp_path / "pending"))
    monkeypatch.setattr(own_manager, "RECEIVED_RETENTION_DAYS", 3)

    own_manager._cleanup_old_captures()  # must not raise, nothing to remove
