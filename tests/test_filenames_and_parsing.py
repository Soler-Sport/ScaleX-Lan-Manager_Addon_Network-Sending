"""Tests for own_manager's small string-parsing helpers: filename display
cleanup (_clean_display_filename), the CHITUBOX TCP protocol's raw field
extractor (extract_field), and ScaleX upload-status shape normalization
(_progress_from_status)."""
import own_manager


class TestCleanDisplayFilename:
    def test_strips_trailing_hex_suffix(self):
        assert own_manager._clean_display_filename("MyRealJobName_607a0575.ctb") == "MyRealJobName.ctb"

    def test_case_insensitive_hex(self):
        assert own_manager._clean_display_filename("Job_ABCDEF12.ctb") == "Job.ctb"

    def test_leaves_name_without_suffix_alone(self):
        assert own_manager._clean_display_filename("plain_name.ctb") == "plain_name.ctb"

    def test_requires_exactly_8_hex_chars(self):
        # 7 chars - not a match, left alone.
        assert own_manager._clean_display_filename("Job_abcdef1.ctb") == "Job_abcdef1.ctb"

    def test_requires_underscore_separator(self):
        assert own_manager._clean_display_filename("Job-607a0575.ctb") == "Job-607a0575.ctb"

    def test_only_strips_trailing_suffix_not_mid_string(self):
        assert own_manager._clean_display_filename("607a0575_Job.ctb") == "607a0575_Job.ctb"

    def test_preserves_extension(self):
        assert own_manager._clean_display_filename("network_send_c374f38c.goo") == "network_send.goo"

    def test_no_extension(self):
        assert own_manager._clean_display_filename("bare_607a0575") == "bare"

    def test_empty_stem_after_stripping_falls_back_to_original(self):
        # If the whole stem IS the hex suffix (no real label prefix), don't
        # collapse to an empty/ugly name like ".ctb".
        result = own_manager._clean_display_filename("_607a0575.ctb")
        assert result != ".ctb"
        assert "607a0575" in result

    def test_spaces_in_label_preserved(self):
        assert own_manager._clean_display_filename("WM-35041Ch_R_B_7326c0b3.ctb") == "WM-35041Ch_R_B.ctb"


class TestExtractField:
    def test_finds_field_value(self):
        buf = '{"MsgType": "SaveFile", "Data": {"SavePath": "C:/foo/bar.ctb"}}'
        assert own_manager.extract_field(buf, '"SavePath": "') == "C:/foo/bar.ctb"

    def test_marker_not_found_returns_none(self):
        buf = '{"MsgType": "LoadWindow"}'
        assert own_manager.extract_field(buf, '"SavePath": "') is None

    def test_unterminated_value_returns_none(self):
        buf = '{"SavePath": "no closing quote here'
        assert own_manager.extract_field(buf, '"SavePath": "') is None

    def test_extracts_first_occurrence(self):
        buf = '"SliceFileName": "first.ctb"} {"SliceFileName": "second.ctb"}'
        assert own_manager.extract_field(buf, '"SliceFileName": "') == "first.ctb"

    def test_empty_value(self):
        buf = '{"SavePath": ""}'
        assert own_manager.extract_field(buf, '"SavePath": "') == ""


class TestProgressFromStatus:
    def test_flat_uploads_shape(self):
        status = {"percent": 42.5, "stage": "uploading"}
        percent, message = own_manager._progress_from_status(status)
        assert percent == 42.5
        assert message == "uploading"

    def test_falls_back_to_state_when_no_stage(self):
        status = {"percent": 10.0, "state": "queued"}
        percent, message = own_manager._progress_from_status(status)
        assert percent == 10.0
        assert message == "queued"

    def test_bulk_targets_shape_averages_percent(self):
        status = {"targets": [{"percent": 20, "state": "uploading"}, {"percent": 60, "state": "uploading"}]}
        percent, message = own_manager._progress_from_status(status)
        assert percent == 40.0
        assert message == "uploading"

    def test_bulk_targets_shape_joins_distinct_states(self):
        status = {"targets": [{"percent": 20, "state": "uploading"}, {"percent": 100, "state": "done"}]}
        percent, message = own_manager._progress_from_status(status)
        assert "done" in message and "uploading" in message

    def test_no_percent_or_targets_returns_none_percent(self):
        status = {"state": "queued"}
        percent, message = own_manager._progress_from_status(status)
        assert percent is None
        assert message == "queued"

    def test_completely_empty_status(self):
        percent, message = own_manager._progress_from_status({})
        assert percent is None
        assert message == ""

    def test_non_numeric_percent_does_not_raise(self):
        status = {"percent": "not-a-number"}
        percent, message = own_manager._progress_from_status(status)
        assert percent is None

    def test_empty_targets_list_falls_through_to_flat_shape(self):
        status = {"targets": [], "percent": 55.0, "state": "sending"}
        percent, message = own_manager._progress_from_status(status)
        assert percent == 55.0
