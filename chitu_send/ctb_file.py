import base64
import re
import struct

from .logs import logmsg


try:
    from Crypto.Cipher import AES  # pip install pycryptodome - see extract_ctb_machine_name
except ImportError:
    AES = None


# ---------------------------------------------------------------------------
# CTB header sniffing - so the picker can show/filter to only the printers a
# file was actually sliced for.
#
# Primary method: parse the real "Chitubox CTB (Encrypted)" structure
# (magic 0x12FD0107) - a 48-byte unencrypted FileHeader points at a 288-byte
# SlicerSettings block, AES-256-CBC-encrypted with a fixed key/IV that's
# baked into the format itself (obfuscation, not a real secret - the same
# key/IV work for every file of this format). That block has
# MachineNameOffset/MachineNameSize fields pointing at the exact plain-ASCII
# machine name elsewhere in the file - byte-exact, no guessing. Courtesy of
# a ready-made parser the user already had (ctb_header_tool.py) confirmed
# against every real captured file on 2026-08-20.
#
# Fallback: a plain text scan for CHITUBOX's copyright notice, which the
# machine name sits right before - used if the precise parse fails (e.g. a
# different/newer CTB version, or pycryptodome isn't installed). Offset of
# that anchor isn't fixed/near the start (seen anywhere from ~6KB to ~5MB
# in), so it scans forward in chunks rather than assuming a small header.
# ---------------------------------------------------------------------------
CTB_ENCRYPTED_MAGIC = 0x12FD0107


_CTB_AES_KEY_B64 = "hQ36XB6yTk+zO02ysyiowt8yC1buK+nbLWyfY40EXoU="


_CTB_AES_IV_B64 = "Wld+ampndVJecmVjYH5cWQ=="


_CTB_XOR_PASSPHRASE = "UVtools"  # format constant, not a real secret


# Transcribed verbatim (name, struct-type) from ctb_header_tool.py's
# FILE_HEADER_FIELDS/SETTINGS_FIELDS - kept as explicit (name, type) pairs
# rather than a hand-flattened format string, so it's easy to check against
# the source instead of trusting a manual character count.
_CTB_HEADER_FIELDS = [
    ("Magic", "I"), ("SettingsSize", "I"), ("SettingsOffset", "I"), ("Unknown1", "I"),
    ("Version", "I"), ("SignatureSize", "I"), ("SignatureOffset", "I"), ("Unknown", "I"),
    ("Unknown4", "H"), ("Unknown5", "H"), ("Unknown6", "I"), ("Unknown7", "I"), ("Unknown8", "I"),
]


_CTB_SETTINGS_FIELDS = [
    ("ChecksumValue", "Q"), ("LayerPointersOffset", "I"), ("DisplayWidth", "f"),
    ("DisplayHeight", "f"), ("MachineZ", "f"), ("Unknown1", "I"), ("Unknown2", "I"),
    ("TotalHeightMillimeter", "f"), ("LayerHeight", "f"), ("ExposureTime", "f"),
    ("BottomExposureTime", "f"), ("LightOffDelay", "f"), ("BottomLayerCount", "I"),
    ("ResolutionX", "I"), ("ResolutionY", "I"), ("LayerCount", "I"),
    ("LargePreviewOffset", "I"), ("SmallPreviewOffset", "I"), ("PrintTime", "I"),
    ("ProjectorType", "I"), ("BottomLiftHeight", "f"), ("BottomLiftSpeed", "f"),
    ("LiftHeight", "f"), ("LiftSpeed", "f"), ("RetractSpeed", "f"),
    ("MaterialMilliliters", "f"), ("MaterialGrams", "f"), ("MaterialCost", "f"),
    ("BottomLightOffDelay", "f"), ("Unknown3", "I"), ("LightPWM", "H"), ("BottomLightPWM", "H"),
    ("LayerXorKey", "I"), ("BottomLiftHeight2", "f"), ("BottomLiftSpeed2", "f"),
    ("LiftHeight2", "f"), ("LiftSpeed2", "f"), ("RetractHeight2", "f"), ("RetractSpeed2", "f"),
    ("RestTimeAfterLift", "f"), ("MachineNameOffset", "I"), ("MachineNameSize", "I"),
    ("AntiAliasFlag", "B"), ("Padding", "H"), ("PerLayerSettings", "B"),
    ("ModifiedTimestampMinutes", "I"), ("AntiAliasLevel", "I"), ("RestTimeAfterRetract", "f"),
    ("RestTimeAfterLift2", "f"), ("TransitionLayerCount", "I"), ("BottomRetractSpeed", "f"),
    ("BottomRetractSpeed2", "f"), ("Padding1", "I"), ("Four1", "f"), ("Padding2", "I"),
    ("Four2", "f"), ("RestTimeAfterRetract2", "f"), ("RestTimeAfterLift3", "f"),
    ("RestTimeBeforeLift", "f"), ("BottomRetractHeight2", "f"), ("Unknown6", "I"),
    ("Unknown7", "I"), ("Unknown8", "I"), ("LastLayerIndex", "I"), ("Padding3", "I"),
    ("Padding4", "I"), ("Padding5", "I"), ("Padding6", "I"), ("DisclaimerOffset", "I"),
    ("DisclaimerSize", "I"), ("Padding7", "I"), ("ResinParametersAddress", "I"),
    ("Padding8", "I"), ("Padding9", "I"),
]


_CTB_HEADER_FMT = "<" + "".join(t for _, t in _CTB_HEADER_FIELDS)


_CTB_SETTINGS_FMT = "<" + "".join(t for _, t in _CTB_SETTINGS_FIELDS)


_CTB_SETTINGS_INDEX = {name: i for i, (name, _) in enumerate(_CTB_SETTINGS_FIELDS)}


def _ctb_xor(data, key):
    kb = key.encode("utf-8")
    return bytes(b ^ kb[i % len(kb)] for i, b in enumerate(data))


def _extract_ctb_machine_name_precise(file_path):
    """Byte-exact via the real struct - returns None (never raises) if this
    isn't a "CTB Encrypted" file, the struct doesn't line up, or
    pycryptodome isn't installed, so the caller can fall back cleanly."""
    if AES is None:
        return None
    try:
        with open(file_path, "rb") as f:
            header_size = struct.calcsize(_CTB_HEADER_FMT)
            header_raw = f.read(header_size)
            if len(header_raw) < header_size:
                return None
            header = dict(zip((n for n, _ in _CTB_HEADER_FIELDS), struct.unpack(_CTB_HEADER_FMT, header_raw)))
            if header["Magic"] != CTB_ENCRYPTED_MAGIC:
                return None

            settings_size = struct.calcsize(_CTB_SETTINGS_FMT)
            if settings_size != header["SettingsSize"]:
                return None  # different format version than this struct - don't guess, fall back

            f.seek(header["SettingsOffset"])
            encrypted = f.read(settings_size)
            if len(encrypted) != settings_size:
                return None

            key = _ctb_xor(base64.b64decode(_CTB_AES_KEY_B64), _CTB_XOR_PASSPHRASE)
            iv = _ctb_xor(base64.b64decode(_CTB_AES_IV_B64), _CTB_XOR_PASSPHRASE)
            decrypted = AES.new(key, AES.MODE_CBC, iv).decrypt(encrypted)

            settings_vals = struct.unpack(_CTB_SETTINGS_FMT, decrypted)
            name_offset = settings_vals[_CTB_SETTINGS_INDEX["MachineNameOffset"]]
            name_size = settings_vals[_CTB_SETTINGS_INDEX["MachineNameSize"]]
            if not (0 < name_size <= 128):
                return None

            f.seek(name_offset)
            name_raw = f.read(name_size)
            if len(name_raw) != name_size:
                return None
            return name_raw.decode("ascii", "replace").strip() or None
    except Exception as e:
        logmsg("=== _extract_ctb_machine_name_precise FAILED for %s (%s) ===", file_path, e)
        return None


CTB_MACHINE_NAME_ANCHOR = b"Layout and record format for the ctb and cbddlp file types"


CTB_SCAN_CHUNK = 4 * 1024 * 1024


CTB_SCAN_MAX = 24 * 1024 * 1024  # give up past this - picker just shows every printer, same as before


def _extract_ctb_machine_name_fallback(file_path):
    """Text-scan fallback - see module notes above. A couple of stray
    binary bytes sometimes end up glued to the *front* of the captured
    string (harmless noise from whatever field precedes it - never the
    back), trimmed off by starting at the first run that actually looks
    like the start of a real word."""
    try:
        with open(file_path, "rb") as f:
            prev_tail = b""
            scanned = 0
            while scanned < CTB_SCAN_MAX:
                chunk = f.read(CTB_SCAN_CHUNK)
                if not chunk:
                    break
                buf = prev_tail + chunk
                idx = buf.find(CTB_MACHINE_NAME_ANCHOR)
                if idx >= 0:
                    before = buf[max(0, idx - 64):idx]
                    m = re.search(rb"[ -~]+$", before)
                    if not m:
                        return None
                    raw = m.group(0)
                    start = re.search(rb"[A-Z][A-Za-z0-9]{2,}", raw)
                    clean = raw[start.start():] if start else raw
                    return clean.decode("ascii", "replace").strip()
                prev_tail = buf[-len(CTB_MACHINE_NAME_ANCHOR):]
                scanned += len(chunk)
    except Exception as e:
        logmsg("=== _extract_ctb_machine_name_fallback FAILED for %s (%s) ===", file_path, e)
    return None


def extract_ctb_machine_name(file_path):
    """Best-effort: returns the file's embedded target-machine name (e.g.
    "ELEGOO Saturn 4 Ultra 16K"), or None if it can't be determined."""
    # 2026-09-08: goo_hook.dll's own custom-built V5.1 output (only ever
    # produced for ELEGOO Jupiter 2 - see goo_hook.c's resolution gate in
    # convert_v3_to_v5) isn't a real CTB file at all, so neither
    # CTB-specific extractor below can find anything in it (different
    # magic, no embedded "Layout and record format..." anchor text) - the
    # "Нарезано под" label was coming back blank for every Jupiter-2
    # capture even though it's fully known. The magic byte alone already
    # identifies it unambiguously.
    try:
        with open(file_path, "rb") as f:
            if f.read(4) == b"V5.1":
                return "ELEGOO Jupiter 2"
    except OSError:
        pass
    name = _extract_ctb_machine_name_precise(file_path)
    if name:
        return name
    return _extract_ctb_machine_name_fallback(file_path)
