"""Tests for _request_save_with_retry: CHITUBOX drops ~15% of SaveFile
requests without ever calling saveSliceFile (goo_hook's sidecar JSON, written
at the START of that call, is the "it started" signal). The helper sends the
request a beat after the LoadWindow reply, watches for the sidecar/target,
and re-sends only when the hook has proven it works this run. Timing
constants are shrunk and files are faked in tmp_path - no real CHITUBOX."""
import json
import os
import threading
import time
from unittest.mock import MagicMock

import pytest

import slm_chitu_send as m


class FakeConn:
    def __init__(self):
        self.sent = []

    def send(self, data):
        self.sent.append(data.decode("utf-8"))
        return True


@pytest.fixture(autouse=True)
def fast_env(monkeypatch, tmp_path):
    monkeypatch.setattr(m, "PENDING_DIR", str(tmp_path))
    monkeypatch.setattr(m, "SAVE_REQUEST_DELAY_SEC", 0.0)
    monkeypatch.setattr(m, "SAVE_ACCEPT_WAIT_SEC", 0.3)
    monkeypatch.setattr(m, "controller", MagicMock())
    monkeypatch.setattr(m, "_hook_sidecar_seen", False)


def _requested_names(conn):
    return [os.path.basename(json.loads(s)["FilePath"]) for s in conn.sent]


def test_dropped_request_is_resent_when_hook_is_known_to_work(monkeypatch):
    monkeypatch.setattr(m, "_hook_sidecar_seen", True)
    conn, state = FakeConn(), {"awaiting": None}

    m._request_save_with_retry(conn, state, "Box", ".ctb")

    assert len(conn.sent) == 1 + m.SAVE_MAX_RETRIES
    assert len(set(_requested_names(conn))) == len(conn.sent)  # each re-send uses a fresh name


def test_no_retry_without_proof_the_hook_works():
    conn, state = FakeConn(), {"awaiting": None}

    m._request_save_with_retry(conn, state, "Box", ".ctb")

    assert len(conn.sent) == 1


def test_sidecar_appearing_stops_the_retries(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "_hook_sidecar_seen", True)
    conn, state = FakeConn(), {"awaiting": None}

    def hook_starts_saving():
        while not state["awaiting"]:
            time.sleep(0.01)
        (tmp_path / (os.path.splitext(os.path.basename(state["awaiting"]))[0] + ".json")).write_text("[]")

    t = threading.Thread(target=hook_starts_saving)
    t.start()
    m._request_save_with_retry(conn, state, "Box", ".ctb")
    t.join()

    assert len(conn.sent) == 1


def test_reply_clears_awaiting_and_ends_the_watchdog(monkeypatch):
    monkeypatch.setattr(m, "_hook_sidecar_seen", True)
    conn, state = FakeConn(), {"awaiting": None}

    def reply_arrives():
        while not state["awaiting"]:
            time.sleep(0.01)
        state["awaiting"] = None

    t = threading.Thread(target=reply_arrives)
    t.start()
    m._request_save_with_retry(conn, state, "Box", ".ctb")
    t.join()

    assert len(conn.sent) == 1


def test_sidecar_seen_marks_the_hook_as_working(tmp_path):
    src = tmp_path / "Box_ab12cd34.ctb"
    src.write_bytes(b"x")
    (tmp_path / "Box_ab12cd34.json").write_text("[]")
    dest = tmp_path / "out" / "Box_ab12cd34.ctb"
    dest.parent.mkdir()
    dest.write_bytes(b"x")

    m._copy_chitu_hook_sidecar(str(src), str(dest))

    assert m._hook_sidecar_seen is True
