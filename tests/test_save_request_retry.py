"""Tests for _request_save_with_retry: CHITUBOX drops ~15% of SaveFile
requests without ever calling saveSliceFile (goo_hook's sidecar JSON, written
at the START of that call, is the "it started" signal). The helper sends the
request a beat after the click (the stock manager never asks sooner than
2.6 s), watches for the sidecar/target, and re-sends only when the hook has
proven it works this run. Timing constants are shrunk and files are faked in
tmp_path - no real CHITUBOX."""
import json
import os
import threading
import time
from unittest.mock import MagicMock

import pytest

from chitu_send import app_controller, capture, config, protocol


class FakeConn:
    def __init__(self, ok=True):
        self.sent = []
        self.ok = ok

    def send(self, data):
        self.sent.append(data.decode("utf-8"))
        return self.ok


def _state():
    return {"awaiting": None, "lock": threading.Lock()}


@pytest.fixture(autouse=True)
def fast_env(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "PENDING_DIR", str(tmp_path))
    monkeypatch.setattr(protocol, "SAVE_REQUEST_DELAY_SEC", 0.0)
    monkeypatch.setattr(protocol, "SAVE_ACCEPT_WAIT_SEC", 0.5)
    monkeypatch.setattr(protocol, "SAVE_WATCH_POLL_SEC", 0.02)
    monkeypatch.setattr(app_controller, "controller", MagicMock())
    monkeypatch.setattr(capture, "_hook_sidecar_seen", False)


def _requested_names(conn):
    return [os.path.basename(json.loads(s)["FilePath"]) for s in conn.sent]


def _wait_for_awaiting(state):
    while not state["awaiting"]:
        time.sleep(0.005)


def test_dropped_request_is_resent_when_hook_is_known_to_work(monkeypatch):
    monkeypatch.setattr(capture, "_hook_sidecar_seen", True)
    conn, state = FakeConn(), _state()

    protocol._request_save_with_retry(conn, state, "Box", ".ctb")

    assert len(conn.sent) == 1 + protocol.SAVE_MAX_RETRIES
    assert len(set(_requested_names(conn))) == len(conn.sent)  # each re-send uses a fresh name


def test_no_retry_without_proof_the_hook_works():
    conn, state = FakeConn(), _state()

    protocol._request_save_with_retry(conn, state, "Box", ".ctb")

    assert len(conn.sent) == 1


def test_sidecar_appearing_stops_the_retries_and_marks_the_hook_working(tmp_path, monkeypatch):
    monkeypatch.setattr(capture, "_hook_sidecar_seen", True)
    conn, state = FakeConn(), _state()

    def hook_starts_saving():
        _wait_for_awaiting(state)
        (tmp_path / (os.path.splitext(os.path.basename(state["awaiting"]))[0] + ".json")).write_text("[]")

    t = threading.Thread(target=hook_starts_saving)
    t.start()
    protocol._request_save_with_retry(conn, state, "Box", ".ctb")
    t.join()

    assert len(conn.sent) == 1
    assert capture._hook_sidecar_seen is True


def test_reply_clears_awaiting_and_ends_the_watchdog(monkeypatch):
    monkeypatch.setattr(capture, "_hook_sidecar_seen", True)
    conn, state = FakeConn(), _state()

    def reply_arrives():
        _wait_for_awaiting(state)
        with state["lock"]:
            state["awaiting"] = None

    t = threading.Thread(target=reply_arrives)
    t.start()
    protocol._request_save_with_retry(conn, state, "Box", ".ctb")
    t.join()

    assert len(conn.sent) == 1


def test_failed_send_does_not_retry_and_leaves_nothing_awaited(monkeypatch):
    monkeypatch.setattr(capture, "_hook_sidecar_seen", True)
    conn, state = FakeConn(ok=False), _state()

    protocol._request_save_with_retry(conn, state, "Box", ".ctb")

    assert len(conn.sent) == 1
    assert state["awaiting"] is None


def test_resend_is_skipped_when_a_newer_request_took_over_meanwhile(monkeypatch):
    conn, state = FakeConn(), _state()
    state["awaiting"] = "C:/pending/Newer_deadbeef.ctb"

    protocol._request_save_with_retry(conn, state, "Box", ".ctb", replaces="C:/pending/Older_00000000.ctb")

    assert conn.sent == []
    assert state["awaiting"] == "C:/pending/Newer_deadbeef.ctb"


def test_tray_notice_fires_once_per_click_not_per_resend(monkeypatch):
    monkeypatch.setattr(capture, "_hook_sidecar_seen", True)
    conn, state = FakeConn(), _state()

    protocol._request_save_with_retry(conn, state, "Box", ".ctb")

    assert len(conn.sent) > 1
    app_controller.controller.save_requested.emit.assert_called_once_with("Box")


def test_missing_controller_does_not_break_the_request(monkeypatch):
    monkeypatch.setattr(app_controller, "controller", None)
    conn, state = FakeConn(), _state()

    protocol._request_save_with_retry(conn, state, "Box", ".ctb")

    assert len(conn.sent) == 1


def test_sidecar_seen_marks_the_hook_as_working(tmp_path):
    src = tmp_path / "Box_ab12cd34.ctb"
    src.write_bytes(b"x")
    (tmp_path / "Box_ab12cd34.json").write_text("[]")
    dest = tmp_path / "out" / "Box_ab12cd34.ctb"
    dest.parent.mkdir()
    dest.write_bytes(b"x")

    capture._copy_chitu_hook_sidecar(str(src), str(dest))

    assert capture._hook_sidecar_seen is True
