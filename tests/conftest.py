"""Shared pytest fixtures for the slm_chitu_send test suite.

slm_chitu_send.py is a single-file script, not a package, so it's imported
directly by adding the project root to sys.path (see pytest.ini's
`pythonpath = .`, mirrored here as a fallback for anyone running pytest
from a different working directory).

Importing it never touches the network, the filesystem outside of
function calls, or creates a QApplication at import time (only main()
does that, guarded by `if __name__ == "__main__"`) - EXCEPT one real
side effect: `_logf = open(LOG_PATH, "a", ...)` at module level opens the
real production log (C:\\slm_chitu_send\\slm_chitu_send.log) in append mode
immediately on import, and logmsg() writes every test's log lines into
it. The autouse fixture below redirects that to a throwaway buffer for
the whole test session so running this suite never pollutes the real
log (caught while writing this suite, 2026-08-31 - test output showed
real UPLOAD STATUS lines going into the actual log file).
"""
import base64
import io
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import slm_chitu_send


@pytest.fixture(autouse=True)
def _isolate_logmsg(monkeypatch):
    monkeypatch.setattr(slm_chitu_send, "_logf", io.StringIO())


@pytest.fixture
def make_ctb_file(tmp_path):
    """Builds a real, byte-valid "CTB Encrypted" file exercising the exact
    format slm_chitu_send._extract_ctb_machine_name_precise() parses: a
    plaintext FileHeader pointing at an AES-256-CBC-encrypted
    SlicerSettings block (encrypted with the format's own fixed,
    XOR-obfuscated key/IV - same derivation the real code uses), whose
    decrypted MachineNameOffset/MachineNameSize fields point at a plain
    ASCII machine name placed right after the settings block.

    Returns a function(machine_name=..., **overrides) -> Path so
    individual tests can build variants (e.g. a corrupt/undersized file)
    without duplicating the struct-packing logic.
    """
    from Crypto.Cipher import AES

    def _build(machine_name="ELEGOO Saturn 4 Ultra 16K", filename="synthetic.ctb",
               truncate_header=False, wrong_magic=False, mismatched_settings_size=False):
        header_size = struct.calcsize(slm_chitu_send._CTB_HEADER_FMT)
        settings_size = struct.calcsize(slm_chitu_send._CTB_SETTINGS_FMT)
        name_bytes = machine_name.encode("ascii")
        name_offset = header_size + settings_size

        settings_vals = [0] * len(slm_chitu_send._CTB_SETTINGS_FIELDS)
        settings_vals[slm_chitu_send._CTB_SETTINGS_INDEX["MachineNameOffset"]] = name_offset
        settings_vals[slm_chitu_send._CTB_SETTINGS_INDEX["MachineNameSize"]] = len(name_bytes)
        settings_plain = struct.pack(slm_chitu_send._CTB_SETTINGS_FMT, *settings_vals)

        key = slm_chitu_send._ctb_xor(base64.b64decode(slm_chitu_send._CTB_AES_KEY_B64), slm_chitu_send._CTB_XOR_PASSPHRASE)
        iv = slm_chitu_send._ctb_xor(base64.b64decode(slm_chitu_send._CTB_AES_IV_B64), slm_chitu_send._CTB_XOR_PASSPHRASE)
        settings_encrypted = AES.new(key, AES.MODE_CBC, iv).encrypt(settings_plain)

        header_vals = [0] * len(slm_chitu_send._CTB_HEADER_FIELDS)
        header_vals[0] = 0xBADBEEF if wrong_magic else slm_chitu_send.CTB_ENCRYPTED_MAGIC  # Magic
        header_vals[1] = settings_size + (1 if mismatched_settings_size else 0)  # SettingsSize
        header_vals[2] = header_size  # SettingsOffset
        header_bytes = struct.pack(slm_chitu_send._CTB_HEADER_FMT, *header_vals)
        if truncate_header:
            header_bytes = header_bytes[:-4]

        path = tmp_path / filename
        with open(path, "wb") as f:
            f.write(header_bytes)
            f.write(settings_encrypted)
            f.write(name_bytes)
        return path

    return _build
