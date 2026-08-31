"""Tests for own_manager's ScaleX HTTP call sites - forward_to_scalex,
patch_and_upload_single, start_stored_file, and poll_scalex_upload's
terminal-state detection. http.client.HTTPConnection is mocked throughout
so these never touch a real network - real end-to-end behavior against
the live farm was already verified manually during development (see
git log); these pin the request shape (path/headers/body) and response
handling so a regression is caught without needing the real farm."""
import json
from unittest.mock import MagicMock, patch

import own_manager


def _mock_conn(status=200, body=b'{"ok": true}'):
    """A MagicMock standing in for http.client.HTTPConnection(...) -
    conn.getresponse().read() returns `body`, .status returns `status`."""
    conn = MagicMock()
    resp = MagicMock()
    resp.status = status
    resp.read.return_value = body
    conn.getresponse.return_value = resp
    return conn


class TestForwardToScalex:
    def test_posts_to_correct_path_with_file_bytes(self, tmp_path):
        f = tmp_path / "test.ctb"
        f.write_bytes(b"fake ctb bytes")
        conn = _mock_conn(status=202, body=b'{"uploadId": "abc123"}')
        with patch("own_manager.http.client.HTTPConnection", return_value=conn):
            status, body = own_manager.forward_to_scalex(str(f), "printer-1", display_name="test.ctb", start_print=True)

        assert status == 202
        assert json.loads(body)["uploadId"] == "abc123"
        call_args = conn.request.call_args
        assert call_args[0][0] == "POST"
        assert call_args[0][1] == "/api/printers/printer-1/files"
        assert call_args[1]["body"] == b"fake ctb bytes"

    def test_start_print_true_sets_header(self, tmp_path):
        f = tmp_path / "test.ctb"
        f.write_bytes(b"x")
        conn = _mock_conn()
        with patch("own_manager.http.client.HTTPConnection", return_value=conn):
            own_manager.forward_to_scalex(str(f), "p1", start_print=True)
        headers = conn.request.call_args[1]["headers"]
        assert headers["X-Start-Print"] == "true"

    def test_start_print_false_sets_header(self, tmp_path):
        f = tmp_path / "test.ctb"
        f.write_bytes(b"x")
        conn = _mock_conn()
        with patch("own_manager.http.client.HTTPConnection", return_value=conn):
            own_manager.forward_to_scalex(str(f), "p1", start_print=False)
        headers = conn.request.call_args[1]["headers"]
        assert headers["X-Start-Print"] == "false"

    def test_display_name_used_over_file_basename(self, tmp_path):
        f = tmp_path / "internal_name_abc123.ctb"
        f.write_bytes(b"x")
        conn = _mock_conn()
        with patch("own_manager.http.client.HTTPConnection", return_value=conn):
            own_manager.forward_to_scalex(str(f), "p1", display_name="Pretty Name.ctb")
        headers = conn.request.call_args[1]["headers"]
        assert "Pretty" in headers["X-File-Name"] or "Pretty%20Name" in headers["X-File-Name"]


class TestPatchAndUploadSingle:
    def test_sends_correct_json_body(self):
        conn = _mock_conn(status=202, body=b'{"ok": true}')
        with patch("own_manager.http.client.HTTPConnection", return_value=conn):
            status, body = own_manager.patch_and_upload_single(
                "draft-1", "printer-1", {"normalExposure": 2.8}, True)

        assert status == 202
        call_args = conn.request.call_args
        assert call_args[0][1] == "/api/ctb/patch-and-upload"
        sent = json.loads(call_args[1]["body"])
        assert sent == {"printerId": "printer-1", "draftId": "draft-1",
                         "patch": {"normalExposure": 2.8}, "autoStart": True}

    def test_auto_start_coerced_to_bool(self):
        conn = _mock_conn()
        with patch("own_manager.http.client.HTTPConnection", return_value=conn):
            own_manager.patch_and_upload_single("d1", "p1", {}, "truthy-string")
        sent = json.loads(conn.request.call_args[1]["body"])
        assert sent["autoStart"] is True


class TestStartStoredFile:
    def test_posts_path_and_queue_flag(self):
        conn = _mock_conn(status=200, body=b'{"ok": true, "queued": true, "state": "waiting_preparation"}')
        with patch("own_manager.http.client.HTTPConnection", return_value=conn):
            status, body = own_manager.start_stored_file("printer-1", "/local/file.ctb", True)

        assert status == 200
        assert json.loads(body)["state"] == "waiting_preparation"
        call_args = conn.request.call_args
        assert call_args[0][1] == "/api/printers/printer-1/stored-files/start"
        sent = json.loads(call_args[1]["body"])
        assert sent == {"path": "/local/file.ctb", "queueIfNotPrepared": True}

    def test_queue_if_not_prepared_false(self):
        conn = _mock_conn()
        with patch("own_manager.http.client.HTTPConnection", return_value=conn):
            own_manager.start_stored_file("p1", "/local/f.ctb", False)
        sent = json.loads(conn.request.call_args[1]["body"])
        assert sent["queueIfNotPrepared"] is False

    def test_printer_id_url_encoded(self):
        conn = _mock_conn()
        with patch("own_manager.http.client.HTTPConnection", return_value=conn):
            own_manager.start_stored_file("printer with spaces", "/local/f.ctb", True)
        path = conn.request.call_args[0][1]
        assert " " not in path


class TestPollScalexUpload:
    def _run_poll(self, statuses):
        """statuses: list of dicts, one per simulated GET tick."""
        conn = MagicMock()
        responses = []
        for s in statuses:
            resp = MagicMock()
            resp.read.return_value = json.dumps(s).encode("utf-8")
            responses.append(resp)
        conn.getresponse.side_effect = responses
        calls = []

        def progress_cb(is_terminal, is_error, job_percent, message, status):
            calls.append((is_terminal, is_error, job_percent, message, status))

        with patch("own_manager.http.client.HTTPConnection", return_value=conn), \
             patch("own_manager.time.sleep"):
            own_manager.poll_scalex_upload("/api/uploads/x", "test.ctb", progress_cb=progress_cb)
        return calls

    def test_single_terminal_success_tick(self):
        calls = self._run_poll([{"done": True, "success": True, "percent": 100.0, "state": "upload_done"}])
        assert len(calls) == 1
        is_terminal, is_error, percent, message, status = calls[0]
        assert is_terminal is True
        assert is_error is False
        assert percent == 100.0

    def test_multiple_ticks_then_terminal(self):
        calls = self._run_poll([
            {"done": False, "percent": 10.0, "state": "uploading"},
            {"done": False, "percent": 50.0, "state": "uploading"},
            {"done": True, "success": True, "percent": 100.0, "state": "upload_done"},
        ])
        assert len(calls) == 3
        assert calls[0][0] is False
        assert calls[1][0] is False
        assert calls[2][0] is True

    def test_bulk_shape_terminal_state_values(self):
        for terminal_state in ("completed", "failed", "error", "cancelled"):
            calls = self._run_poll([{"state": terminal_state}])
            assert calls[0][0] is True, terminal_state

    def test_error_states_flagged_as_error(self):
        for state in ("failed", "error", "cancelled"):
            calls = self._run_poll([{"state": state}])
            assert calls[0][1] is True, state

    def test_raw_status_passed_through_to_callback(self):
        # The bug fixed live 2026-08-27: lastUploadedPath only appears in
        # the *polled* status for a patched upload, not the initial 202 -
        # send_in_background needs the raw dict, not just (percent, msg).
        calls = self._run_poll([{"done": True, "success": True, "percent": 100.0,
                                  "lastUploadedPath": "/local/preptest for Test.ctb"}])
        raw_status = calls[0][4]
        assert raw_status.get("lastUploadedPath") == "/local/preptest for Test.ctb"

    def test_connection_failure_reports_terminal_error(self):
        with patch("own_manager.http.client.HTTPConnection", side_effect=OSError("network down")), \
             patch("own_manager.time.sleep"):
            calls = []
            own_manager.poll_scalex_upload("/api/uploads/x", "test.ctb",
                                            progress_cb=lambda *a: calls.append(a))
        assert len(calls) == 1
        assert calls[0][0] is True
        assert calls[0][1] is True

    def test_non_json_response_gives_up_gracefully(self):
        conn = MagicMock()
        resp = MagicMock()
        resp.read.return_value = b"not json at all"
        conn.getresponse.return_value = resp
        with patch("own_manager.http.client.HTTPConnection", return_value=conn), \
             patch("own_manager.time.sleep"):
            calls = []
            own_manager.poll_scalex_upload("/api/uploads/x", "test.ctb",
                                            progress_cb=lambda *a: calls.append(a))
        assert len(calls) == 1
        assert calls[0][0] is True  # terminal
        assert calls[0][1] is False  # treated as done, not error

    def test_no_progress_cb_does_not_raise(self):
        conn = _mock_conn(status=200, body=json.dumps({"done": True, "percent": 100.0}).encode())
        with patch("own_manager.http.client.HTTPConnection", return_value=conn):
            own_manager.poll_scalex_upload("/api/uploads/x", "test.ctb", progress_cb=None)
