"""Tests for the CHITUBOX-protocol-adjacent helpers added/changed by the
2026-09-08 code review fixes: _ChituboxConn (thread-safe connection
wrapper, findings #4/#5), _goo_hook_convert_enabled/_looks_like_native_v3_goo
(the goo_hook.dll interop helpers behind findings #2/#3). extract_field's
last-match fix (finding #8) is covered in test_filenames_and_parsing.py
alongside its other tests; the CTB-patch format gate (finding #1) is
covered in test_send_in_background.py alongside the rest of
send_in_background()'s tests."""
import threading
from unittest.mock import MagicMock

import own_manager


class TestChituboxConn:
    def test_send_delegates_to_underlying_socket(self):
        raw = MagicMock()
        chandle = own_manager._ChituboxConn(raw)
        assert chandle.send(b"hello") is True
        raw.send.assert_called_once_with(b"hello")

    def test_recv_delegates_to_underlying_socket(self):
        raw = MagicMock()
        raw.recv.return_value = b"data"
        chandle = own_manager._ChituboxConn(raw)
        assert chandle.recv(65536) == b"data"
        raw.recv.assert_called_once_with(65536)

    def test_send_failure_returns_false_not_raise(self):
        raw = MagicMock()
        raw.send.side_effect = OSError("boom")
        chandle = own_manager._ChituboxConn(raw)
        assert chandle.send(b"hello") is False

    def test_close_is_idempotent(self):
        raw = MagicMock()
        chandle = own_manager._ChituboxConn(raw)
        chandle.close()
        chandle.close()  # must not raise or double-close the real socket
        raw.close.assert_called_once()

    def test_send_after_close_returns_false_without_touching_socket(self):
        # 2026-09-08 (code-review fix, finding #4): closeEvent()'s
        # out-of-band notify racing handle_client()'s own conn.close() used
        # to be an unsynchronized cross-thread hazard - now close() sets a
        # flag under the same lock send() checks, so a send arriving after
        # close() is a clean, expected no-op rather than touching an
        # already-closed (or reused-fd) socket object at all.
        raw = MagicMock()
        chandle = own_manager._ChituboxConn(raw)
        chandle.close()
        raw.send.reset_mock()
        assert chandle.send(b"hello") is False
        raw.send.assert_not_called()

    def test_close_swallows_oserror(self):
        raw = MagicMock()
        raw.close.side_effect = OSError("already gone")
        chandle = own_manager._ChituboxConn(raw)
        chandle.close()  # must not raise

    def test_concurrent_send_and_close_do_not_raise(self):
        # Not a proof of absence of races (that's not really provable with
        # a unit test), just a smoke test that hammering send()/close()
        # from multiple threads at once doesn't crash or deadlock, unlike
        # the old bare socket.send()/socket.close() with no lock at all.
        raw = MagicMock()
        chandle = own_manager._ChituboxConn(raw)
        errors = []

        def _sender():
            for _ in range(200):
                try:
                    chandle.send(b"x")
                except Exception as e:  # pragma: no cover - failure path
                    errors.append(e)

        def _closer():
            chandle.close()

        threads = [threading.Thread(target=_sender) for _ in range(4)]
        threads.append(threading.Thread(target=_closer))
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert errors == []


class TestGooHookConvertEnabled:
    def test_missing_flag_file_means_enabled(self, tmp_path, monkeypatch):
        monkeypatch.setattr(own_manager, "_V5CONVERT_FLAG_PATH", str(tmp_path / "does_not_exist.flag"))
        assert own_manager._goo_hook_convert_enabled() is True

    def test_flag_content_zero_means_disabled(self, tmp_path, monkeypatch):
        # Matches goo_hook.c's V5_IsConvertEnabled() exactly: a leading '0'
        # byte, and only a leading '0', means disabled.
        flag = tmp_path / "flag"
        flag.write_bytes(b"0")
        monkeypatch.setattr(own_manager, "_V5CONVERT_FLAG_PATH", str(flag))
        assert own_manager._goo_hook_convert_enabled() is False

    def test_any_other_content_means_enabled(self, tmp_path, monkeypatch):
        flag = tmp_path / "flag"
        flag.write_bytes(b"1")
        monkeypatch.setattr(own_manager, "_V5CONVERT_FLAG_PATH", str(flag))
        assert own_manager._goo_hook_convert_enabled() is True

    def test_empty_flag_file_means_enabled(self, tmp_path, monkeypatch):
        flag = tmp_path / "flag"
        flag.write_bytes(b"")
        monkeypatch.setattr(own_manager, "_V5CONVERT_FLAG_PATH", str(flag))
        assert own_manager._goo_hook_convert_enabled() is True


class TestLooksLikeNativeV3Goo:
    def test_true_for_v3_magic(self, tmp_path):
        f = tmp_path / "x.goo"
        f.write_bytes(b"V3.0" + b"\x00" * 100)
        assert own_manager._looks_like_native_v3_goo(str(f)) is True

    def test_false_for_v5_magic(self, tmp_path):
        # 2026-09-08 (code-review fix, finding #2): once goo_hook.dll has
        # rewritten the file in place, its magic is "V5.1" - must not be
        # mistaken for a still-native, safe-to-forward v3 file.
        f = tmp_path / "x.goo"
        f.write_bytes(b"V5.1" + b"\x00" * 100)
        assert own_manager._looks_like_native_v3_goo(str(f)) is False

    def test_false_for_truncated_mid_rewrite_file(self, tmp_path):
        # The exact race window this guards: goo_hook.c's CREATE_ALWAYS
        # reopen truncates the file to 0 bytes before it starts writing v5
        # content - caught at that instant, this must not look like a
        # trustworthy v3 file either.
        f = tmp_path / "x.goo"
        f.write_bytes(b"")
        assert own_manager._looks_like_native_v3_goo(str(f)) is False

    def test_false_for_missing_file(self, tmp_path):
        assert own_manager._looks_like_native_v3_goo(str(tmp_path / "nope.goo")) is False
