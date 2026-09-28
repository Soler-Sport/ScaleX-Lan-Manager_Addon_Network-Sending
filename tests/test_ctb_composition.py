"""Tests for the ChituHook -> ScaleX "состав CTB" composition feature
(read_chitu_hook_model_names, match_composition_components,
fetch_warehouse_components, save_ctb_composition) - see slm_chitu_send.py's
own module-level comment above fetch_warehouse_components for the design.
http.client.HTTPConnection is mocked throughout, matching test_network.py's
own pattern, so these never touch a real network."""
import json
from unittest.mock import MagicMock, patch

import slm_chitu_send


def _mock_conn(status=200, body=b'{"ok": true}'):
    conn = MagicMock()
    resp = MagicMock()
    resp.status = status
    resp.read.return_value = body
    conn.getresponse.return_value = resp
    return conn


class TestReadChituHookModelNames:
    def test_reads_sidecar_json_array(self, tmp_path):
        ctb = tmp_path / "Box F x8.ctb"
        ctb.write_bytes(b"fake ctb bytes")
        (tmp_path / "Box F x8.json").write_text(
            json.dumps(["133_SOPLI_KRAN_7.stl", "134_SOPLI_KRAN_8.stl"]), encoding="utf-8")

        names = slm_chitu_send.read_chitu_hook_model_names(str(ctb))

        assert names == ["133_SOPLI_KRAN_7.stl", "134_SOPLI_KRAN_8.stl"]

    def test_missing_sidecar_returns_none(self, tmp_path):
        ctb = tmp_path / "no_sidecar.ctb"
        ctb.write_bytes(b"x")

        assert slm_chitu_send.read_chitu_hook_model_names(str(ctb)) is None

    def test_malformed_sidecar_returns_none(self, tmp_path):
        ctb = tmp_path / "bad.ctb"
        ctb.write_bytes(b"x")
        (tmp_path / "bad.json").write_text("not valid json{", encoding="utf-8")

        assert slm_chitu_send.read_chitu_hook_model_names(str(ctb)) is None

    def test_non_list_json_returns_none(self, tmp_path):
        ctb = tmp_path / "obj.ctb"
        ctb.write_bytes(b"x")
        (tmp_path / "obj.json").write_text(json.dumps({"not": "a list"}), encoding="utf-8")

        assert slm_chitu_send.read_chitu_hook_model_names(str(ctb)) is None


class TestMatchCompositionComponents:
    COMPONENTS = [
        {"id": "comp-1", "code": "WM-24001W:LA", "name": "WM-24001W L A"},
        {"id": "comp-2", "code": "WM-24001W:RA", "name": "WM-24001W R A"},
    ]

    # Two different articles that happen to share one name - the case this
    # class's ambiguous-match tests exercise (see match_composition_components'
    # own docstring, and PickerWindow._rebuild_composition_ambiguous_rows).
    SAME_NAME_COMPONENTS = [
        {"id": "comp-a1", "code": "ART-001", "name": "Кронштейн универсальный"},
        {"id": "comp-a2", "code": "ART-002", "name": "Кронштейн универсальный"},
    ]

    def test_exact_match_is_case_insensitive_and_extension_stripped(self):
        matched, ambiguous, unmatched = slm_chitu_send.match_composition_components(
            ["wm-24001w:la.stl"], self.COMPONENTS)

        assert matched == [(self.COMPONENTS[0], 1)]
        assert ambiguous == []
        assert unmatched == []

    def test_counts_repeated_models_as_quantity(self):
        matched, ambiguous, unmatched = slm_chitu_send.match_composition_components(
            ["WM-24001W:LA.stl", "WM-24001W:LA.stl", "WM-24001W:LA.stl"], self.COMPONENTS)

        assert matched == [(self.COMPONENTS[0], 3)]
        assert ambiguous == []
        assert unmatched == []

    def test_no_substring_matching(self):
        # "WM-24001W.stl" is not an exact match for either code above (each
        # has a ":LA"/":RA" suffix it lacks) - a model name that only
        # partially overlaps a code must NOT match. This is the whole point
        # of not reusing ScaleX's own fuzzy browser-side logic.
        matched, ambiguous, unmatched = slm_chitu_send.match_composition_components(
            ["WM-24001W.stl"], self.COMPONENTS)

        assert matched == []
        assert ambiguous == []
        assert unmatched == ["WM-24001W.stl"]

    def test_unrecognized_model_goes_to_unmatched(self):
        matched, ambiguous, unmatched = slm_chitu_send.match_composition_components(
            ["some_unrelated_part.stl"], self.COMPONENTS)

        assert matched == []
        assert ambiguous == []
        assert unmatched == ["some_unrelated_part.stl"]

    def test_mixed_matched_and_unmatched(self):
        matched, ambiguous, unmatched = slm_chitu_send.match_composition_components(
            ["WM-24001W:LA.stl", "mystery_part.stl", "WM-24001W:RA.stl"], self.COMPONENTS)

        assert sorted(matched, key=lambda pair: pair[0]["id"]) == [
            (self.COMPONENTS[0], 1), (self.COMPONENTS[1], 1)]
        assert ambiguous == []
        assert unmatched == ["mystery_part.stl"]

    def test_same_name_different_article_is_ambiguous_not_silently_picked(self):
        matched, ambiguous, unmatched = slm_chitu_send.match_composition_components(
            ["Кронштейн универсальный.stl"], self.SAME_NAME_COMPONENTS)

        assert matched == []
        assert unmatched == []
        assert len(ambiguous) == 1
        model_name, candidates, quantity = ambiguous[0]
        assert model_name == "Кронштейн универсальный.stl"
        assert quantity == 1
        assert sorted(candidates, key=lambda c: c["id"]) == self.SAME_NAME_COMPONENTS

    def test_ambiguous_match_counts_repeats_as_one_group(self):
        matched, ambiguous, unmatched = slm_chitu_send.match_composition_components(
            ["Кронштейн универсальный.stl", "Кронштейн универсальный.stl"], self.SAME_NAME_COMPONENTS)

        assert matched == []
        assert unmatched == []
        assert len(ambiguous) == 1
        _, candidates, quantity = ambiguous[0]
        assert quantity == 2
        assert len(candidates) == 2

    def test_ambiguous_and_unambiguous_matches_stay_independent(self):
        components = self.COMPONENTS + self.SAME_NAME_COMPONENTS
        matched, ambiguous, unmatched = slm_chitu_send.match_composition_components(
            ["WM-24001W:LA.stl", "Кронштейн универсальный.stl"], components)

        assert matched == [(self.COMPONENTS[0], 1)]
        assert len(ambiguous) == 1
        assert unmatched == []


class TestFetchWarehouseComponents:
    def test_gets_components_from_warehouse_payload(self):
        conn = _mock_conn(body=json.dumps({
            "components": [{"id": "c1", "code": "X:Y", "name": "n"}],
            "articles": [],
        }).encode("utf-8"))
        with patch("slm_chitu_send.http.client.HTTPConnection", return_value=conn):
            components = slm_chitu_send.fetch_warehouse_components()

        assert components == [{"id": "c1", "code": "X:Y", "name": "n"}]
        assert conn.request.call_args[0] == ("GET", "/api/warehouse")

    def test_missing_components_key_returns_empty_list(self):
        conn = _mock_conn(body=b'{"articles": []}')
        with patch("slm_chitu_send.http.client.HTTPConnection", return_value=conn):
            assert slm_chitu_send.fetch_warehouse_components() == []

    def test_non_200_raises(self):
        conn = _mock_conn(status=500, body=b'{}')
        with patch("slm_chitu_send.http.client.HTTPConnection", return_value=conn):
            try:
                slm_chitu_send.fetch_warehouse_components()
                assert False, "expected RuntimeError"
            except RuntimeError:
                pass


class TestSaveCtbComposition:
    def test_puts_correct_path_and_body(self):
        conn = _mock_conn(status=200)
        with patch("slm_chitu_send.http.client.HTTPConnection", return_value=conn):
            slm_chitu_send.save_ctb_composition("Box F x8.ctb", [("comp-1", 3), ("comp-2", 1)])

        call_args = conn.request.call_args
        assert call_args[0][0] == "PUT"
        assert call_args[0][1] == "/api/warehouse/ctb-mappings"
        body = json.loads(call_args[1]["body"])
        assert body["file_name"] == "Box F x8.ctb"
        assert body["component_quantities"] == [
            {"component_id": "comp-1", "quantity": 3},
            {"component_id": "comp-2", "quantity": 1},
        ]
        assert call_args[1]["headers"]["Content-Type"] == "application/json"

    def test_non_2xx_raises(self):
        conn = _mock_conn(status=400, body=b'{"error": "bad request"}')
        with patch("slm_chitu_send.http.client.HTTPConnection", return_value=conn):
            try:
                slm_chitu_send.save_ctb_composition("f.ctb", [("comp-1", 1)])
                assert False, "expected RuntimeError"
            except RuntimeError:
                pass
