"""Tests for slm_chitu_send's CTB machine-name extraction: the byte-exact
AES-decrypt path (_extract_ctb_machine_name_precise), the text-scan
fallback (_extract_ctb_machine_name_fallback), and the public dispatcher
(extract_ctb_machine_name) that picks between them."""
from chitu_send import ctb_file


class TestCtbXor:
    def test_round_trip(self):
        data = bytes([1, 2, 3, 4, 5, 250, 251, 252])
        key = "some-key"
        encoded = ctb_file._ctb_xor(data, key)
        assert encoded != data
        assert ctb_file._ctb_xor(encoded, key) == data

    def test_deterministic(self):
        data = b"hello world"
        assert ctb_file._ctb_xor(data, "k") == ctb_file._ctb_xor(data, "k")

    def test_empty_data(self):
        assert ctb_file._ctb_xor(b"", "key") == b""

    def test_key_repeats_for_longer_data(self):
        # key shorter than data - key bytes must wrap around (i % len(kb))
        data = bytes(range(20))
        key = "ab"
        result = ctb_file._ctb_xor(data, key)
        kb = key.encode("utf-8")
        expected = bytes(b ^ kb[i % len(kb)] for i, b in enumerate(data))
        assert result == expected


class TestExtractPrecise:
    def test_valid_file_returns_exact_machine_name(self, make_ctb_file):
        path = make_ctb_file(machine_name="ELEGOO Saturn 4 Ultra 16K")
        assert ctb_file._extract_ctb_machine_name_precise(str(path)) == "ELEGOO Saturn 4 Ultra 16K"

    def test_different_machine_name(self, make_ctb_file):
        path = make_ctb_file(machine_name="Phrozen Sonic Mighty 8K")
        assert ctb_file._extract_ctb_machine_name_precise(str(path)) == "Phrozen Sonic Mighty 8K"

    def test_wrong_magic_returns_none(self, make_ctb_file):
        path = make_ctb_file(wrong_magic=True)
        assert ctb_file._extract_ctb_machine_name_precise(str(path)) is None

    def test_truncated_header_returns_none(self, make_ctb_file):
        path = make_ctb_file(truncate_header=True)
        assert ctb_file._extract_ctb_machine_name_precise(str(path)) is None

    def test_mismatched_settings_size_returns_none(self, make_ctb_file):
        # A different format version than this struct - must not guess.
        path = make_ctb_file(mismatched_settings_size=True)
        assert ctb_file._extract_ctb_machine_name_precise(str(path)) is None

    def test_nonexistent_file_returns_none_not_raise(self):
        assert ctb_file._extract_ctb_machine_name_precise(r"C:\does\not\exist.ctb") is None

    def test_empty_file_returns_none(self, tmp_path):
        path = tmp_path / "empty.ctb"
        path.write_bytes(b"")
        assert ctb_file._extract_ctb_machine_name_precise(str(path)) is None

    def test_no_pycryptodome_returns_none(self, make_ctb_file, monkeypatch):
        path = make_ctb_file()
        monkeypatch.setattr(ctb_file, "AES", None)
        assert ctb_file._extract_ctb_machine_name_precise(str(path)) is None


class TestExtractFallback:
    def test_finds_name_before_anchor(self, tmp_path):
        path = tmp_path / "fallback.ctb"
        junk_before = b"\x00" * 100
        content = junk_before + b"ELEGOOSaturn4Ultra" + ctb_file.CTB_MACHINE_NAME_ANCHOR + b"\x00" * 50
        path.write_bytes(content)
        name = ctb_file._extract_ctb_machine_name_fallback(str(path))
        assert name == "ELEGOOSaturn4Ultra"

    def test_strips_leading_stray_bytes(self, tmp_path):
        # "A couple of stray binary bytes sometimes end up glued to the
        # *front*" - the fallback should start at the first run that looks
        # like a real word (starts with an uppercase letter), trimming any
        # printable-but-not-word-shaped junk immediately before it.
        path = tmp_path / "stray.ctb"
        content = b"\x01\x02##ElegooSaturn" + ctb_file.CTB_MACHINE_NAME_ANCHOR
        path.write_bytes(content)
        name = ctb_file._extract_ctb_machine_name_fallback(str(path))
        assert name == "ElegooSaturn"

    def test_no_anchor_returns_none(self, tmp_path):
        path = tmp_path / "no_anchor.ctb"
        path.write_bytes(b"just some random bytes with no anchor at all" * 100)
        assert ctb_file._extract_ctb_machine_name_fallback(str(path)) is None

    def test_anchor_split_across_chunk_boundary(self, tmp_path, monkeypatch):
        # The anchor could straddle two read() chunks - prev_tail carries
        # the boundary-crossing bytes forward so it's still found.
        monkeypatch.setattr(ctb_file, "CTB_SCAN_CHUNK", 32)
        path = tmp_path / "boundary.ctb"
        padding = b"x" * 20
        content = padding + b"TestMachine" + ctb_file.CTB_MACHINE_NAME_ANCHOR
        path.write_bytes(content)
        name = ctb_file._extract_ctb_machine_name_fallback(str(path))
        assert name == "TestMachine"

    def test_nonexistent_file_returns_none_not_raise(self):
        assert ctb_file._extract_ctb_machine_name_fallback(r"C:\does\not\exist.ctb") is None


class TestExtractCtbMachineName:
    def test_prefers_precise_over_fallback(self, make_ctb_file):
        path = make_ctb_file(machine_name="Precise Machine")
        assert ctb_file.extract_ctb_machine_name(str(path)) == "Precise Machine"

    def test_falls_back_when_precise_fails(self, tmp_path):
        path = tmp_path / "not_encrypted_ctb.ctb"
        content = b"\x00" * 20 + b"FallbackMachine" + ctb_file.CTB_MACHINE_NAME_ANCHOR
        path.write_bytes(content)
        assert ctb_file.extract_ctb_machine_name(str(path)) == "FallbackMachine"

    def test_neither_method_returns_none(self, tmp_path):
        path = tmp_path / "garbage.ctb"
        path.write_bytes(b"\x00" * 500)
        assert ctb_file.extract_ctb_machine_name(str(path)) is None
