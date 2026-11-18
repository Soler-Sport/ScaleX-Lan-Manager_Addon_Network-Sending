"""ScaleX device access (2026-11): every /api request now needs a device that a ScaleX administrator
has approved and given sections to; anything else gets 403 {"code": "device_access_denied"}.

The device identity is the cookie ScaleX sets in answer to POST /api/access/enroll. It is kept in
data/scalex_device.json and sent with every request (device_headers). After enrolling, an admin
approves the device in ScaleX (access section) - from then on the same cookie just works."""
import http.client
import json
import os
import socket

from . import config
from .logs import logmsg


def _load_cookie():
    try:
        with open(config.DEVICE_FILE, encoding="utf-8") as f:
            return json.load(f).get("cookie") or ""
    except (OSError, ValueError):
        return ""


def device_headers():
    """{"Cookie": ...} once this machine has enrolled, else {} (so ScaleX without device access still works)."""
    cookie = _load_cookie()
    return {"Cookie": cookie} if cookie else {}


def _cookie_from_response(resp):
    """'name=value; name2=value2' from the Set-Cookie headers (attributes dropped)."""
    pairs = [v.split(";", 1)[0].strip() for k, v in resp.getheaders() if k.lower() == "set-cookie"]
    return "; ".join(p for p in pairs if "=" in p)


def _call(method, path, payload=None):
    conn = http.client.HTTPConnection(config.SCALEX_HOST, config.SCALEX_PORT, timeout=10)
    try:
        headers = dict(device_headers())
        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        data = json.loads(resp.read().decode("utf-8", "replace") or "{}")
        if resp.status != 200:
            raise RuntimeError("HTTP %d: %s" % (resp.status, data.get("detail", "")))
        return data, _cookie_from_response(resp)
    finally:
        conn.close()


def access_status():
    """ScaleX's view of this machine: GET /api/access/me -> {enabled, device: {name, role, sections} | None, ...}."""
    return _call("GET", "/api/access/me")[0]


def enroll(name=None):
    """Ask ScaleX for access as a new device and remember the cookie it hands back."""
    name = name or "slm_chitu_send (%s)" % socket.gethostname()
    data, cookie = _call("POST", "/api/access/enroll", {"name": name})
    if cookie:
        os.makedirs(os.path.dirname(config.DEVICE_FILE), exist_ok=True)
        with open(config.DEVICE_FILE, "w", encoding="utf-8") as f:
            json.dump({"name": name, "cookie": cookie}, f)
    return data


def ensure_device_access():
    """Make sure this machine is a known ScaleX device. Returns "" when it has access, otherwise a
    short message for the operator (enrolled just now / waiting for approval / revoked); None when
    ScaleX can't be reached right now."""
    try:
        me = access_status()
        if not me.get("enabled"):
            return ""
        device = me.get("device")
        if device and device.get("sections"):
            return ""
        if device and device.get("role") == "revoked":
            return "ScaleX отозвал доступ этого компьютера. Обратитесь к администратору."
        if device:
            return "Устройство «%s» ждёт одобрения администратором ScaleX." % device.get("name", "")
        enroll()
        logmsg("=== ScaleX device access: enrolled this machine, waiting for admin approval ===")
        return "Заявка на доступ отправлена в ScaleX. Администратору нужно одобрить устройство и выдать разделы «Принтеры» и «Склад»."
    except Exception as e:
        logmsg("=== ScaleX device access check failed: %s ===", e)
        return None
