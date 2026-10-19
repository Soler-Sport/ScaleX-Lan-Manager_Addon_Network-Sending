"""CHITUBOX announces the manager window with Title "Network Sending" and hides a window
carrying exactly that title (2026-10-16/19: the picker stayed invisible and the keyboard
focus went to it). The host window's title must never equal it, in any state."""
import pytest

from chitu_send.picker import _host_title

CHITUBOX_TITLE = "network sending"


@pytest.mark.parametrize("names", [[], ["Box.ctb"], ["Box.ctb", "Wheel.ctb"], ["a"] * 12])
def test_title_is_never_the_bare_chitubox_title(names):
    assert _host_title(names).strip().lower() != CHITUBOX_TITLE


def test_single_tab_title_names_the_file():
    assert _host_title(["Box(21,22).ctb"]) == "Network sending — Box(21,22).ctb"


def test_several_tabs_title_counts_them():
    assert "3" in _host_title(["a.ctb", "b.ctb", "c.ctb"])
