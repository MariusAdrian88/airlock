"""WinMTR Redux v1.00 (MSVC, MFC, 64-bit), source: github White-Tiger/WinMTR tag v1.0, WinMTRDialog.cpp.

Facts: BEGIN_MESSAGE_MAP(WinMTRDialog, CDialog) with 17 entries (WM_PAINT, WM_SIZE, WM_SIZING,
WM_QUERYDRAGICON, ID_RESTART=1002 OnRestart, ID_OPTIONS=1003, ID_CTTC=1004, ID_CHTC=1005, ID_EXPT=1006,
ID_EXPH=1007, the list notify, 3 combo notifications, WM_TIMER, WM_CLOSE, IDCANCEL); OnEXPT / OnEXPH open
a CFileDialog with the filters "Text Files (*.txt)|..." and "HTML Files (*.htm, *.html)|...".
"""

from __future__ import annotations

import re

import pytest

from airlock.server.tools import core, cpp

pytestmark = pytest.mark.realdata
TARGET = "winmtr"


def _map(ctx):
    out = cpp.mfc_message_maps(ctx, "WinMTRDialog")
    assert out.startswith("WinMTRDialog map 0x"), out
    return out


def test_message_map_of_the_dialog(target_world):
    """The map has 17 entries on dialog 102 with the system messages and the handlers named by id."""
    ctx, _, _ = target_world
    out = _map(ctx)
    assert re.search(r"entries 17 dialog 102", out), out.splitlines()[0]
    for msg in ("WM_PAINT", "WM_SIZE", "WM_SIZING", "WM_QUERYDRAGICON", "WM_TIMER", "WM_CLOSE"):
        assert re.search(rf"^{msg} -> 0x", out, re.M), msg
    for ident in (1002, 1003, 1004, 1005, 1006, 1007):          # ID_RESTART .. ID_EXPH
        assert re.search(rf"^WM_COMMAND id {ident} -> 0x[0-9a-f]+ ", out, re.M), ident
