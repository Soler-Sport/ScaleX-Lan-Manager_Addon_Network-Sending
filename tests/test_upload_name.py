"""ScaleX answers HTTP 500 to a file name with characters Windows forbids (2026-10-19:
"WW-35001* x5.ctb" failed on every printer); the picker cleans the name before sending."""
import pytest

from chitu_send.sender import sanitize_upload_name


@pytest.mark.parametrize("raw, expected", [
    ("WW-35001* x5.ctb", "WW-35001_ x5.ctb"),
    ("WW-35001? x5.ctb", "WW-35001_ x5.ctb"),
    ('a<b>c:d"e/f|g.ctb', "a_b_c_d_e_f_g.ctb"),
    ("a" + chr(92) + "b.ctb", "a_b.ctb"),
    ("tab\there.ctb", "tab_here.ctb"),
])
def test_forbidden_characters_become_underscores(raw, expected):
    assert sanitize_upload_name(raw) == expected


@pytest.mark.parametrize("name", ["Box E x5.ctb", "WW-35042.ctb", "Box(21,22) x9.ctb", "Колесо №1.ctb"])
def test_ordinary_names_are_left_alone(name):
    assert sanitize_upload_name(name) == name


def test_surrounding_whitespace_is_trimmed():
    assert sanitize_upload_name("  Box.ctb ") == "Box.ctb"


def test_empty_name_stays_empty():
    assert sanitize_upload_name("") == ""
    assert sanitize_upload_name(None) == ""
