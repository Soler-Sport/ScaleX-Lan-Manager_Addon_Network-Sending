"""Tests for _pending_dir_watcher_pass() - the 2026-09-09 backstop that
catches a PENDING_DIR file CHITUBOX actually finished writing even when
the TCP connection that requested it died first (CHITUBOX resets its own
connection to us every ~5-6 minutes regardless of activity; a slice that
outlives that window orphans handle_client()'s in-flight SaveFile
request - see PENDING_ORPHAN_GRACE_SEC's own comment in slm_chitu_send.py).

controller.file_captured.emit(...) is exercised here (via
_capture_and_emit()/_finish_goo_v5_capture()) with a plain stand-in object
instead of the real AppController - no QApplication exists in this test
process (see conftest.py's own docstring: only main() creates one), and
none of these tests need real Qt signal delivery, just to observe what
would have been emitted."""
import os
import time

import slm_chitu_send


class _FakeController:
    """Stands in for the real AppController - .file_captured.emit(...) is
    the only thing _capture_and_emit()/_finish_goo_v5_capture() touch on
    it."""
    def __init__(self):
        self.captured = []
        self.file_captured = self

    def emit(self, dest, chandle):
        self.captured.append((dest, chandle))


def _age_file(path, seconds_old):
    """Backdates a file's mtime so PENDING_ORPHAN_GRACE_SEC's age check
    sees it as already old, without actually sleeping in the test."""
    t = time.time() - seconds_old
    os.utime(path, (t, t))


def test_young_file_is_skipped_and_not_marked_seen(tmp_path, monkeypatch):
    monkeypatch.setattr(slm_chitu_send, "PENDING_DIR", str(tmp_path))
    monkeypatch.setattr(slm_chitu_send, "PENDING_ORPHAN_GRACE_SEC", 120)
    fake = _FakeController()
    monkeypatch.setattr(slm_chitu_send, "controller", fake)

    f = tmp_path / "job_abc12345.ctb"
    f.write_bytes(b"x" * 100)  # fresh - mtime is "now", well under the grace period

    seen = set()
    slm_chitu_send._pending_dir_watcher_pass(seen)
    slm_chitu_send._pending_dir_watcher_pass(seen)  # a second pass - still too young

    assert fake.captured == []
    assert seen == set()  # deliberately never marked "seen" while still too young
    assert f.exists()  # untouched


def test_v5_prefixed_file_is_always_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(slm_chitu_send, "PENDING_DIR", str(tmp_path))
    monkeypatch.setattr(slm_chitu_send, "PENDING_ORPHAN_GRACE_SEC", 1)
    fake = _FakeController()
    monkeypatch.setattr(slm_chitu_send, "controller", fake)

    f = tmp_path / "v5_job_abc12345.goo"
    f.write_bytes(b"V5.1" + b"x" * 100)
    _age_file(f, seconds_old=999)  # old enough that only the v5_ prefix could be saving it

    slm_chitu_send._pending_dir_watcher_pass(set())

    assert fake.captured == []
    assert f.exists()  # a real live capture (or handle_client()'s own thread) owns this file, not this watcher


def test_orphaned_ctb_file_gets_captured(tmp_path, monkeypatch):
    pending = tmp_path / "pending"
    received = tmp_path / "received"
    pending.mkdir()
    monkeypatch.setattr(slm_chitu_send, "PENDING_DIR", str(pending))
    monkeypatch.setattr(slm_chitu_send, "RECEIVED_DIR", str(received))
    monkeypatch.setattr(slm_chitu_send, "PENDING_ORPHAN_GRACE_SEC", 1)
    fake = _FakeController()
    monkeypatch.setattr(slm_chitu_send, "controller", fake)

    f = pending / "Box(1,2)_deadbeef.ctb"
    f.write_bytes(b"fake ctb bytes")
    _age_file(f, seconds_old=999)

    seen = set()
    slm_chitu_send._pending_dir_watcher_pass(seen)

    # Captured into RECEIVED_DIR, PENDING copy removed, picker signal fired
    # with chandle=None (no live connection - this is exactly what
    # slicer_file_watcher()'s own backstop path already does).
    assert not f.exists()
    dest = received / "Box(1,2)_deadbeef.ctb"
    assert dest.read_bytes() == b"fake ctb bytes"
    assert fake.captured == [(str(dest), None)]
    assert str(f) in seen


def test_file_claimed_by_live_connection_during_wait_is_left_alone(tmp_path, monkeypatch):
    """The near-miss case: this watcher's PENDING_ORPHAN_GRACE_SEC gate and
    _wait_for_stable_file() both passed, but the live handle_client()
    connection (which was actually still alive) claimed and removed the
    file in that same window - must not error or double-report a
    capture."""
    pending = tmp_path / "pending"
    pending.mkdir()
    monkeypatch.setattr(slm_chitu_send, "PENDING_DIR", str(pending))
    monkeypatch.setattr(slm_chitu_send, "PENDING_ORPHAN_GRACE_SEC", 1)
    fake = _FakeController()
    monkeypatch.setattr(slm_chitu_send, "controller", fake)

    f = pending / "Box(1,2)_deadbeef.ctb"
    f.write_bytes(b"fake ctb bytes")
    _age_file(f, seconds_old=999)

    def _stability_wait_but_someone_else_grabs_it(path, max_polls, poll_interval=0.2):
        os.remove(path)

    monkeypatch.setattr(slm_chitu_send, "_wait_for_stable_file", _stability_wait_but_someone_else_grabs_it)

    slm_chitu_send._pending_dir_watcher_pass(set())

    assert fake.captured == []  # this watcher did nothing - the live path already won


def test_orphaned_goo_file_dispatches_to_finish_goo_v5_capture(tmp_path, monkeypatch):
    """.goo candidates must go through _finish_goo_v5_capture() (so they
    still get the goo_hook v5-sibling wait/magic-byte safety check a plain
    _capture_and_emit() call would skip), not straight to _capture_and_emit()."""
    pending = tmp_path / "pending"
    received = tmp_path / "received"
    pending.mkdir()
    monkeypatch.setattr(slm_chitu_send, "PENDING_DIR", str(pending))
    monkeypatch.setattr(slm_chitu_send, "RECEIVED_DIR", str(received))
    monkeypatch.setattr(slm_chitu_send, "PENDING_ORPHAN_GRACE_SEC", 1)
    fake = _FakeController()
    monkeypatch.setattr(slm_chitu_send, "controller", fake)
    # Skip the real up-to-60s wait entirely - _goo_hook_convert_enabled()
    # is exercised on its own in test_chitubox_protocol.py; here we only
    # care that _pending_dir_watcher_pass() routes to the right function.
    monkeypatch.setattr(slm_chitu_send, "_goo_hook_convert_enabled", lambda: False)

    f = pending / "Box(1,2)_deadbeef.goo"
    f.write_bytes(b"V3.0" + b"x" * 100)  # native v3 magic - safe to forward per _looks_like_native_v3_goo
    _age_file(f, seconds_old=999)

    slm_chitu_send._pending_dir_watcher_pass(set())

    assert not f.exists()
    dest = received / "Box(1,2)_deadbeef.goo"
    assert dest.read_bytes() == b"V3.0" + b"x" * 100
    assert fake.captured == [(str(dest), None)]


def test_missing_pending_dir_is_a_noop(tmp_path, monkeypatch):
    monkeypatch.setattr(slm_chitu_send, "PENDING_DIR", str(tmp_path / "does_not_exist"))
    slm_chitu_send._pending_dir_watcher_pass(set())  # must not raise
