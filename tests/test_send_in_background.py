"""Integration-style tests for send_in_background() itself - the real
orchestration function (memory pre-check, prepared/deferred-start
branching, patched-vs-plain upload choice) that had two real bugs found
live this session (missing lastUploadedPath for patched uploads, and the
retry-flicker debounce). http.client.HTTPConnection is mocked at the
transport level, keyed off request path, so the whole pipeline runs for
real except the actual network - only send_in_background() itself is
exercised, not internal helpers already covered directly in
test_network.py."""
import json
import threading
from unittest.mock import MagicMock, patch

import own_manager


def _fake_connection_factory(responses_by_path_suffix):
    """Returns a callable standing in for http.client.HTTPConnection(...).
    Each call records the request and looks up a canned (status, body)
    response by matching the request path's suffix against the given
    dict - good enough since every call site here does exactly one
    request per connection."""
    calls = []

    def _factory(*args, **kwargs):
        conn = MagicMock()

        def _request(method, path, body=None, headers=None):
            calls.append((method, path, body, headers))
            conn._last_path = path

        def _getresponse():
            for suffix, (status, body) in responses_by_path_suffix.items():
                if conn._last_path.endswith(suffix):
                    resp = MagicMock()
                    resp.status = status
                    resp.read.return_value = body if isinstance(body, bytes) else json.dumps(body).encode()
                    return resp
            raise AssertionError("no canned response for path %r" % conn._last_path)

        conn.request.side_effect = _request
        conn.getresponse.side_effect = _getresponse
        return conn

    _factory.calls = calls
    return _factory


def _wait_for_terminal(report_cb_calls, event, timeout=5):
    assert event.wait(timeout), "send_in_background never reached a terminal aggregate phase"


def test_prepared_printer_starts_immediately_no_recommendations(tmp_path):
    """A prepared printer with no recommendations selected: plain upload
    (forward_to_scalex), X-Start-Print honored as-is, no deferred-start
    detour at all."""
    f = tmp_path / "test.ctb"
    f.write_bytes(b"fake ctb data")

    printer = {
        "id": "p1", "displayName": "Printer 1", "operatorPrepared": True,
        "status": {"remainingMemory": 999999999},
    }
    responses = {
        "/files": (202, {"uploadId": "up-1", "lastUploadedPath": "/local/test.ctb"}),
        "/api/uploads/up-1": (200, {"done": True, "success": True, "percent": 100.0, "state": "upload_done"}),
    }
    factory = _fake_connection_factory(responses)

    done_event = threading.Event()
    results = []

    def report_cb(phase, percent, targets_out):
        results.append((phase, percent, targets_out))
        if phase in ("done", "error"):
            done_event.set()

    with patch("own_manager.fetch_printers", return_value=[printer]), \
         patch("own_manager.http.client.HTTPConnection", side_effect=factory):
        own_manager.send_in_background(
            str(f), [{"printerId": "p1", "applyRecommendations": False}],
            display_name="test.ctb", start_print=True, report_cb=report_cb,
        )
        _wait_for_terminal(results, done_event)

    final_phase, _, final_targets = results[-1]
    assert final_phase == "done"
    assert final_targets[0]["phase"] == "done"

    # Plain upload path used (no patch endpoint hit), X-Start-Print true.
    upload_call = next(c for c in factory.calls if c[1].endswith("/files"))
    assert upload_call[3]["X-Start-Print"] == "true"
    assert not any(c[1] == "/api/ctb/patch-and-upload" for c in factory.calls)


def test_unprepared_printer_with_recommendations_defers_start(tmp_path):
    """The exact real scenario from 2026-08-27: a printer with
    recommendations selected (patched-upload path) that ISN'T
    operatorPrepared, with start_print requested - must upload with
    autoStart off and then register a deferred start via
    queueIfNotPrepared, ending in the "queued_prepared" phase, not "done"
    and not a blind autoStart."""
    f = tmp_path / "test.ctb"
    f.write_bytes(b"fake ctb data")

    printer = {
        "id": "p1", "displayName": "Test", "operatorPrepared": False,
        "status": {"remainingMemory": 999999999},
        "recommendedNormalExposure": 2.8, "recommendedBottomExposure": 38.0,
    }
    responses = {
        "/api/ctb/params": (200, {"draftId": "draft-1"}),
        "/api/ctb/patch-and-upload": (202, {"uploadId": "up-1", "state": "queued", "autoStart": False}),
        "/api/uploads/up-1": (200, {"done": True, "success": True, "percent": 100.0,
                                      "lastUploadedPath": "/local/test for Test.ctb"}),
        "/stored-files/start": (200, {"ok": True, "queued": True, "state": "waiting_preparation"}),
    }
    factory = _fake_connection_factory(responses)

    done_event = threading.Event()
    results = []

    def report_cb(phase, percent, targets_out):
        results.append((phase, percent, targets_out))
        if phase in ("done", "error"):
            done_event.set()

    with patch("own_manager.fetch_printers", return_value=[printer]), \
         patch("own_manager.http.client.HTTPConnection", side_effect=factory):
        own_manager.send_in_background(
            str(f), [{"printerId": "p1", "applyRecommendations": True}],
            display_name="test.ctb", start_print=True, report_cb=report_cb,
        )
        _wait_for_terminal(results, done_event)

    final_phase, _, final_targets = results[-1]
    assert final_targets[0]["phase"] == "queued_prepared"

    # The actual upload request must NOT have asked ScaleX to autoStart -
    # the whole point is not starting on an unconfirmed printer.
    patch_call = next(c for c in factory.calls if c[1] == "/api/ctb/patch-and-upload")
    sent_body = json.loads(patch_call[2])
    assert sent_body["autoStart"] is False

    # And the deferred-start call must have actually gone out, with the
    # path taken from the polled status (not the initial 202, which for
    # patch-and-upload never carries lastUploadedPath at all).
    start_call = next(c for c in factory.calls if c[1].endswith("/stored-files/start"))
    sent_start_body = json.loads(start_call[2])
    assert sent_start_body == {"path": "/local/test for Test.ctb", "queueIfNotPrepared": True}


def test_insufficient_memory_skips_without_any_http_call(tmp_path):
    """The memory pre-check must reject before any network call at all -
    confirmed live against a real 0-byte-free printer."""
    f = tmp_path / "test.ctb"
    f.write_bytes(b"x" * 1000)

    printer = {"id": "p1", "displayName": "Full Printer", "operatorPrepared": True,
               "status": {"remainingMemory": 10}}
    factory = _fake_connection_factory({})  # any HTTP call at all should raise (no canned response)

    done_event = threading.Event()
    results = []

    def report_cb(phase, percent, targets_out):
        results.append((phase, percent, targets_out))
        if phase in ("done", "error"):
            done_event.set()

    with patch("own_manager.fetch_printers", return_value=[printer]), \
         patch("own_manager.http.client.HTTPConnection", side_effect=factory):
        own_manager.send_in_background(
            str(f), [{"printerId": "p1", "applyRecommendations": False}],
            display_name="test.ctb", start_print=False, report_cb=report_cb,
        )
        _wait_for_terminal(results, done_event)

    final_phase, _, final_targets = results[-1]
    assert final_phase == "error"
    assert final_targets[0]["phase"] == "error"
    assert final_targets[0]["errorReason"] == "low_memory"
    assert factory.calls == []  # no HTTP request was ever made


def test_multiple_targets_dispatched_independently(tmp_path):
    """One printer with plenty of memory, one without - the low-memory one
    must not block or affect the other."""
    f = tmp_path / "test.ctb"
    f.write_bytes(b"x" * 1000)

    printers = [
        {"id": "ok", "displayName": "OK Printer", "operatorPrepared": True,
         "status": {"remainingMemory": 999999999}},
        {"id": "full", "displayName": "Full Printer", "operatorPrepared": True,
         "status": {"remainingMemory": 10}},
    ]
    responses = {
        "/files": (202, {"uploadId": "up-ok"}),
        "/api/uploads/up-ok": (200, {"done": True, "success": True, "percent": 100.0}),
    }
    factory = _fake_connection_factory(responses)

    done_event = threading.Event()
    results = []

    def report_cb(phase, percent, targets_out):
        results.append((phase, percent, targets_out))
        if phase in ("done", "error"):
            done_event.set()

    with patch("own_manager.fetch_printers", return_value=printers), \
         patch("own_manager.http.client.HTTPConnection", side_effect=factory):
        own_manager.send_in_background(
            str(f), [{"printerId": "ok", "applyRecommendations": False},
                     {"printerId": "full", "applyRecommendations": False}],
            display_name="test.ctb", start_print=False, report_cb=report_cb,
        )
        _wait_for_terminal(results, done_event)

    final_targets = {t["printerId"]: t for t in results[-1][2]}
    assert final_targets["ok"]["phase"] == "done"
    assert final_targets["full"]["phase"] == "error"
    assert final_targets["full"]["errorReason"] == "low_memory"
