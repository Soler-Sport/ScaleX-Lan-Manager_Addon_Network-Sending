"""Tests for _wait_for_stable_file - the fix for a real, recurring bug
(2026-08-31): CHITUBOX's SaveFile confirmation can arrive before the file
write is actually flushed to disk, so a single immediate isfile() check
sometimes lost that race and silently dropped the capture entirely (7
"SaveFile reply but file not found" occurrences in the log, matching the
"first click doesn't open the picker" report). Shared by handle_client()
and slicer_file_watcher()."""
import threading
import time

import own_manager


def test_returns_promptly_once_file_is_stable(tmp_path):
    path = tmp_path / "already_there.ctb"
    path.write_bytes(b"x" * 1000)

    start = time.monotonic()
    own_manager._wait_for_stable_file(str(path), max_polls=25, poll_interval=0.05)
    elapsed = time.monotonic() - start

    # Two consecutive equal-size polls end it early - should not run out
    # the full ~1.25s budget (25 * 0.05) for a file that never changes.
    assert elapsed < 0.5


def test_waits_out_a_file_that_appears_late(tmp_path):
    path = tmp_path / "delayed.ctb"

    def _write_later():
        time.sleep(0.15)
        path.write_bytes(b"x" * 500)

    threading.Thread(target=_write_later, daemon=True).start()
    own_manager._wait_for_stable_file(str(path), max_polls=25, poll_interval=0.05)

    assert path.is_file()
    assert path.stat().st_size == 500


def test_waits_out_a_file_still_growing(tmp_path):
    # The exact real-world scenario this fixes: the file exists (CHITUBOX
    # has started writing) but its size is still changing when the first
    # check happens. Growth here is continuous (each increment lands
    # faster than poll_interval, like a real streaming write) rather than
    # paused between chunks - _wait_for_stable_file only requires two
    # consecutive equal-and-positive polls to declare "done" (see its own
    # docstring for that known, pre-existing limitation), so a writer that
    # pauses mid-write for longer than poll_interval isn't what this test
    # is checking; a genuinely still-growing file is.
    path = tmp_path / "growing.ctb"
    path.write_bytes(b"x" * 100)
    stop = threading.Event()

    def _grow():
        size = 100
        while not stop.is_set() and size < 5000:
            size += 200
            path.write_bytes(b"x" * size)
            time.sleep(0.005)

    t = threading.Thread(target=_grow, daemon=True)
    t.start()
    try:
        own_manager._wait_for_stable_file(str(path), max_polls=400, poll_interval=0.01)
    finally:
        stop.set()
        t.join(timeout=1)

    # Whatever size it settled on, it must not have been the very first
    # size seen (100) - i.e. it genuinely waited for growth to stop, not
    # short-circuited by the initial "already exists" false positive.
    assert path.stat().st_size > 100
    # And it must actually be stable now - re-checking shortly after
    # shouldn't show anything different.
    settled_size = path.stat().st_size
    time.sleep(0.1)
    assert path.stat().st_size == settled_size


def test_gives_up_after_max_polls_if_file_never_appears(tmp_path):
    path = tmp_path / "never_written.ctb"

    start = time.monotonic()
    own_manager._wait_for_stable_file(str(path), max_polls=5, poll_interval=0.05)
    elapsed = time.monotonic() - start

    assert not path.exists()
    assert elapsed >= 5 * 0.05 * 0.8  # ran close to the full budget, didn't return instantly


def test_zero_byte_file_never_counts_as_stable(tmp_path):
    # size > 0 is required - an empty file (e.g. just-created, not yet
    # written) must not be mistaken for "done".
    path = tmp_path / "empty.ctb"
    path.write_bytes(b"")

    start = time.monotonic()
    own_manager._wait_for_stable_file(str(path), max_polls=5, poll_interval=0.05)
    elapsed = time.monotonic() - start

    assert elapsed >= 5 * 0.05 * 0.8  # never short-circuited, ran the full budget
