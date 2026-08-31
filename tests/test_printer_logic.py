"""Tests for own_manager's pure printer-status/decision functions - the
logic that decides what a printer card shows and whether a send should
even be attempted. These are the functions with the most real bug
history this session (printer_is_uploading, printer_memory_fit,
_clean_display_filename's siblings), so behavior here is pinned tightly."""
import pytest

import own_manager


def printer(**overrides):
    """A minimal, online, idle, non-uploading printer dict - each test
    overrides only the fields it cares about."""
    base = {
        "id": "p1",
        "displayName": "Test Printer",
        "model": "Saturn 4 Ultra 16K",
        "status": {"online": True, "currentStatus": 0, "printStatus": 8, "printStatusText": "idle"},
        "upload": None,
        "operatorPrepared": False,
    }
    base.update(overrides)
    return base


class TestPrinterIsUploading:
    def test_no_upload_field_is_false(self):
        assert own_manager.printer_is_uploading(printer(upload=None)) is False

    def test_active_upload_is_true(self):
        assert own_manager.printer_is_uploading(printer(upload={"done": False, "cancelled": False})) is True

    def test_done_upload_is_false(self):
        assert own_manager.printer_is_uploading(printer(upload={"done": True, "cancelled": False})) is False

    def test_cancelled_upload_is_false(self):
        assert own_manager.printer_is_uploading(printer(upload={"done": False, "cancelled": True})) is False

    def test_idle_printstatus_does_not_hide_an_active_upload(self):
        # The real bug this fixed: printStatus can read "idle" for the
        # whole transfer, so printer_is_busy() must catch this via the
        # upload field, not via printStatus.
        p = printer(status={"online": True, "currentStatus": 0, "printStatus": 8, "printStatusText": "idle"},
                    upload={"done": False, "cancelled": False})
        assert own_manager.printer_is_uploading(p) is True
        assert own_manager.printer_is_busy(p) is True


class TestPrinterIsBusy:
    def test_idle_is_not_busy(self):
        assert own_manager.printer_is_busy(printer()) is False

    def test_current_status_1_is_busy(self):
        assert own_manager.printer_is_busy(printer(status={"currentStatus": 1})) is True

    @pytest.mark.parametrize("print_status", [1, 2, 3, 4, 5, 6, 7])
    def test_busy_print_status_codes(self, print_status):
        assert own_manager.printer_is_busy(printer(status={"currentStatus": 1, "printStatus": print_status})) is True

    @pytest.mark.parametrize("print_status", [8, 9])
    def test_idle_print_status_codes_override_busy(self, print_status):
        # current_status==0 already short-circuits to False, so force
        # current_status truthy to isolate the print_status/text check.
        assert own_manager.printer_is_busy(printer(status={"currentStatus": 0, "printStatus": print_status})) is False

    @pytest.mark.parametrize("text", ["preparing", "homing", "lifting", "exposing", "printing", "pausing", "paused", "stopping"])
    def test_busy_text(self, text):
        assert own_manager.printer_is_busy(printer(status={"currentStatus": 1, "printStatusText": text})) is True

    @pytest.mark.parametrize("text", ["idle", "stopped", "complete", "completed"])
    def test_idle_text(self, text):
        assert own_manager.printer_is_busy(printer(status={"currentStatus": 0, "printStatusText": text})) is False

    def test_missing_status_dict_is_not_busy(self):
        assert own_manager.printer_is_busy({"id": "p1", "upload": None}) is False

    def test_non_numeric_status_does_not_raise(self):
        p = printer(status={"currentStatus": "not-a-number", "printStatus": "also-not"})
        assert own_manager.printer_is_busy(p) is False

    def test_uploading_wins_over_idle_print_status(self):
        p = printer(status={"currentStatus": 0, "printStatus": 8}, upload={"done": False})
        assert own_manager.printer_is_busy(p) is True


class TestPrinterIsOnline:
    def test_online_true(self):
        assert own_manager.printer_is_online(printer(status={"online": True})) is True

    def test_online_false(self):
        assert own_manager.printer_is_online(printer(status={"online": False})) is False

    def test_missing_status(self):
        assert own_manager.printer_is_online({"id": "p1"}) is False

    def test_online_not_exactly_true(self):
        # Must be `is True`, not just truthy - e.g. a stringly-typed API
        # response should not be treated as online.
        assert own_manager.printer_is_online(printer(status={"online": "yes"})) is False


class TestPrinterMatchesMachine:
    def test_no_detected_machine_matches_everything(self):
        assert own_manager.printer_matches_machine(printer(model="Anything"), None) is True
        assert own_manager.printer_matches_machine(printer(model="Anything"), "") is True

    def test_no_model_on_printer_matches_everything(self):
        assert own_manager.printer_matches_machine(printer(model=""), "ELEGOO Saturn 4 Ultra 16K") is True

    def test_exact_match(self):
        p = printer(model="Saturn 4 Ultra 16K")
        assert own_manager.printer_matches_machine(p, "ELEGOO Saturn 4 Ultra 16K") is True

    def test_case_insensitive(self):
        p = printer(model="saturn 4 ultra 16k")
        assert own_manager.printer_matches_machine(p, "ELEGOO SATURN 4 ULTRA 16K") is True

    def test_suffix_not_substring_shorter_model_does_not_match_longer_detected(self):
        # "Saturn 4 Ultra" (no 16K) must NOT match a file sliced for the
        # 16K variant - a plain substring check would incorrectly match
        # both directions.
        p = printer(model="Saturn 4 Ultra")
        assert own_manager.printer_matches_machine(p, "ELEGOO Saturn 4 Ultra 16K") is False

    def test_suffix_not_substring_longer_model_does_not_match_shorter_detected(self):
        p = printer(model="Saturn 4 Ultra 16K")
        assert own_manager.printer_matches_machine(p, "ELEGOO Saturn 4 Ultra") is False

    def test_machineModel_used_when_model_absent(self):
        p = printer()
        del p["model"]
        p["machineModel"] = "Saturn 4 Ultra 16K"
        assert own_manager.printer_matches_machine(p, "ELEGOO Saturn 4 Ultra 16K") is True

    def test_unrelated_model_does_not_match(self):
        p = printer(model="Mars 5 Ultra")
        assert own_manager.printer_matches_machine(p, "ELEGOO Saturn 4 Ultra 16K") is False


class TestHasRecommendations:
    def test_none_present(self):
        assert own_manager.has_recommendations(printer()) is False

    def test_empty_string_does_not_count(self):
        assert own_manager.has_recommendations(printer(recommendedNormalExposure="")) is False

    def test_normal_exposure_present(self):
        assert own_manager.has_recommendations(printer(recommendedNormalExposure=2.8)) is True

    def test_bottom_exposure_present(self):
        assert own_manager.has_recommendations(printer(recommendedBottomExposure=38.0)) is True

    def test_bottom_layers_present(self):
        assert own_manager.has_recommendations(printer(recommendedBottomLayers=4)) is True

    def test_zero_value_still_counts(self):
        # 0 is a valid (falsy but real) recommendation value - only None/""
        # should be treated as "not set".
        assert own_manager.has_recommendations(printer(recommendedBottomLayers=0)) is True


class TestBuildRecommendationPatch:
    def test_empty_when_no_recommendations(self):
        assert own_manager.build_recommendation_patch(printer()) == {}

    def test_maps_all_three_fields(self):
        p = printer(recommendedNormalExposure=2.8, recommendedBottomExposure=38.0, recommendedBottomLayers=4)
        assert own_manager.build_recommendation_patch(p) == {
            "normalExposure": 2.8, "bottomExposure": 38.0, "bottomLayers": 4,
        }

    def test_only_includes_set_fields(self):
        p = printer(recommendedNormalExposure=2.8)
        assert own_manager.build_recommendation_patch(p) == {"normalExposure": 2.8}


class TestPrinterRecSummary:
    def test_empty_when_none_set(self):
        assert own_manager.printer_rec_summary(printer()) == ""

    def test_single_field(self):
        assert own_manager.printer_rec_summary(printer(recommendedNormalExposure=2.8)) == "обычная 2.8s"

    def test_all_fields_joined_with_comma(self):
        p = printer(recommendedNormalExposure=2.8, recommendedBottomExposure=38.0, recommendedBottomLayers=4)
        assert own_manager.printer_rec_summary(p) == "обычная 2.8s, нижняя 38.0s, 4 нижних слоёв"


class TestFormatBytes:
    def test_megabytes(self):
        assert own_manager._format_bytes(5 * 1024 * 1024) == "5 МБ"

    def test_gigabytes_uses_one_decimal(self):
        assert own_manager._format_bytes(int(5.7 * 1024 ** 3)) == "5.7 ГБ"

    def test_boundary_exactly_one_gb(self):
        assert own_manager._format_bytes(1024 ** 3) == "1.0 ГБ"

    def test_just_under_one_gb_is_megabytes(self):
        result = own_manager._format_bytes(1024 ** 3 - 1)
        assert result.endswith("МБ")


class TestPrinterMemoryFit:
    def test_none_file_size_returns_none(self):
        assert own_manager.printer_memory_fit(printer(status={"remainingMemory": 1000}), None) is None

    def test_missing_remaining_memory_returns_none(self):
        assert own_manager.printer_memory_fit(printer(status={}), 1000) is None

    def test_fits(self):
        p = printer(status={"remainingMemory": 500 * 1024 * 1024})
        fits, text = own_manager.printer_memory_fit(p, 100 * 1024 * 1024)
        assert fits is True
        assert "Поместится" in text

    def test_does_not_fit(self):
        p = printer(status={"remainingMemory": 50 * 1024 * 1024})
        fits, text = own_manager.printer_memory_fit(p, 100 * 1024 * 1024)
        assert fits is False
        assert "Не хватит места" in text

    def test_exactly_equal_size_fits(self):
        p = printer(status={"remainingMemory": 1000})
        fits, _ = own_manager.printer_memory_fit(p, 1000)
        assert fits is True

    def test_zero_remaining_never_fits_a_real_file(self):
        # The real scenario this caught live: a printer at 0 bytes free.
        p = printer(status={"remainingMemory": 0})
        fits, _ = own_manager.printer_memory_fit(p, 3409665)
        assert fits is False

    def test_non_numeric_remaining_memory_returns_none(self):
        p = printer(status={"remainingMemory": "not-a-number"})
        assert own_manager.printer_memory_fit(p, 1000) is None
