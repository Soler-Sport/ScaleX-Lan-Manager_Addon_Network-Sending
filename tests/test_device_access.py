"""ScaleX device access: the enrolled cookie is stored and sent with every request, and
ensure_device_access tells the operator what is still missing. ScaleX is faked at the
http.client level, like the other network tests."""
import json
from unittest.mock import patch

import pytest

from chitu_send import device_access, scalex


class FakeScaleX:
    """Stands in for http.client.HTTPConnection: answers by (method, path), records requests."""

    def __init__(self, answers):
        self.answers = answers
        self.requests = []

    def __call__(self, *args, **kwargs):
        return _FakeConn(self)


class _FakeConn:
    def __init__(self, server):
        self.server = server

    def request(self, method, path, body=None, headers=None):
        self.server.requests.append((method, path, body, dict(headers or {})))
        self.key = (method, path)

    def getresponse(self):
        status, payload, set_cookies = self.server.answers[self.key]
        return _FakeResp(status, payload, set_cookies)

    def close(self):
        pass


class _FakeResp:
    def __init__(self, status, payload, set_cookies):
        self.status = status
        self._body = json.dumps(payload).encode("utf-8")
        self._cookies = set_cookies

    def read(self):
        return self._body

    def getheaders(self):
        return [("Set-Cookie", c) for c in self._cookies] + [("Content-Type", "application/json")]


def _fake(answers):
    server = FakeScaleX(answers)
    return server, patch("http.client.HTTPConnection", server)


ME = ("GET", "/api/access/me")
ENROLL = ("POST", "/api/access/enroll")


def test_no_cookie_file_means_no_extra_headers():
    assert device_access.device_headers() == {}


def test_enroll_stores_the_cookie_from_set_cookie_headers():
    server, ctx = _fake({ENROLL: (200, {"ok": True}, ["scalex_device=abc123; Path=/; HttpOnly", "extra=1; Max-Age=60"])})
    with ctx:
        device_access.enroll("PC 1")

    assert device_access.device_headers() == {"Cookie": "scalex_device=abc123; extra=1"}
    assert json.loads(server.requests[0][2]) == {"name": "PC 1"}


def test_every_scalex_request_carries_the_cookie(tmp_path):
    (tmp_path / "scalex_device.json").write_text(json.dumps({"cookie": "scalex_device=abc"}))
    server, ctx = _fake({("GET", "/api/printers"): (200, [], [])})
    with ctx:
        scalex.fetch_printers()

    assert server.requests[0][3] == {"Cookie": "scalex_device=abc"}


def test_refused_printer_list_names_the_reason():
    server, ctx = _fake({("GET", "/api/printers"): (403, {"code": "device_access_denied"}, [])})
    with ctx, pytest.raises(RuntimeError) as err:
        scalex.fetch_printers()

    assert "device_access_denied" in str(err.value)


def test_access_not_enforced_means_nothing_to_do():
    _, ctx = _fake({ME: (200, {"enabled": False, "device": None}, [])})
    with ctx:
        assert device_access.ensure_device_access() == ""


def test_approved_device_has_access():
    _, ctx = _fake({ME: (200, {"enabled": True, "device": {"name": "PC", "role": "user", "sections": ["printers"]}}, [])})
    with ctx:
        assert device_access.ensure_device_access() == ""


def test_unknown_device_enrolls_and_reports_it():
    server, ctx = _fake({ME: (200, {"enabled": True, "device": None}, []), ENROLL: (200, {}, ["scalex_device=zzz; Path=/"])})
    with ctx:
        message = device_access.ensure_device_access()

    assert "одобрить" in message
    assert [r[:2] for r in server.requests] == [ME, ENROLL]
    assert device_access.device_headers() == {"Cookie": "scalex_device=zzz"}


def test_pending_device_is_not_enrolled_again():
    server, ctx = _fake({ME: (200, {"enabled": True, "device": {"name": "PC", "role": "pending", "sections": []}}, [])})
    with ctx:
        message = device_access.ensure_device_access()

    assert "ждёт одобрения" in message
    assert [r[:2] for r in server.requests] == [ME]


def test_revoked_device_is_told_so():
    _, ctx = _fake({ME: (200, {"enabled": True, "device": {"name": "PC", "role": "revoked", "sections": []}}, [])})
    with ctx:
        assert "отозвал" in device_access.ensure_device_access()


def test_unreachable_scalex_gives_none_not_an_exception():
    with patch("http.client.HTTPConnection", side_effect=OSError("down")):
        assert device_access.ensure_device_access() is None
