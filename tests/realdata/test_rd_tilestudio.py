"""Tile Studio 2.55 (Delphi 32-bit), source: github Wiering/Tile-Studio, Main.pas.

Facts: ReadConfigFile reads `ts.tsc`; WriteConfigFile (called from FormClose) writes it back and has no
Ghidra function after the first analysis. Round 10 checks (T2) on this program: on-demand creation at a
string address, an interior address, direct call targets of the fix pass. Tests run in file order: the
creation tests must come before anything that creates the writer function.
"""

from __future__ import annotations

import re

import pytest

from airlock.server.tools import core

pytestmark = pytest.mark.realdata
TARGET = "tilestudio"
WRITER = 0x004C1984         # TMainForm.WriteConfigFile (Main.pas); no function in the first index
STRING_IN_WRITER = 0x004C1DF8   # the string "[Settings]" inside the writer's code


def _store(ctx):
    st = ctx.indexer.store("tilestudio")
    return st, st.list_binaries()[0].id


def test_config_file_string_is_read_by_one_function(target_world):
    """Source: CONFIG_FILE = 'ts.tsc', used by ReadConfigFile (round 10 n5)."""
    ctx, _, _ = target_world
    out = core.strings(ctx, "ts.tsc")
    line = next(x for x in out.splitlines() if x.startswith("0x004c1924"))
    assert '"ts.tsc"' in line and "<- " in line and "(no refs)" not in line, out


def test_on_demand_at_a_string_gives_the_string_line_and_no_function(target_world):
    """R2: the address holds the string "[Settings]" (code bytes of WriteConfigFile): the answer names
    the string and its reader, and no function is made there."""
    ctx, _, _ = target_world
    st, bid = _store(ctx)
    out = core.function(ctx, f"0x{STRING_IN_WRITER:08x}")
    assert out.startswith(f'error not_found: no function at 0x{STRING_IN_WRITER:08x}; it is the string "[Settings]"'), out
    assert st.function_at(bid, STRING_IN_WRITER) is None
