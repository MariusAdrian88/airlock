"""KeePass 2.60 (.NET Framework WinForms, managed only: no Ghidra), source: KeePass 2.60 source tree.

Facts come from the .NET evaluation ground truth (kp_menu, kp_iface, kp_struct): MainForm.Designer.cs,
MainForm.cs, NativeMethods.Structs.cs, SendInputExt.cs.
"""

from __future__ import annotations

import re

import pytest

from airlock.server.tools import core, dotnet

pytestmark = pytest.mark.realdata
TARGET = "keepass"


def test_menu_event_handler(target_world):
    """Designer: m_menuToolsGeneratePwList (Text 'Generate Password &List...').Click += OnToolsGeneratePasswordList."""
    ctx, _, _ = target_world
    out = dotnet.dotnet_events(ctx, "", "Generate Password List")
    assert re.search(r'm_menuToolsGeneratePwList ToolStripMenuItem "Generate Password &List\.\.\." '
                     r"Click -> OnToolsGeneratePasswordList 0x[0-9a-f]+", out), out


def test_handler_decompile_holds_the_known_calls(target_world):
    """OnToolsGeneratePasswordList: generator dialog, count dialog, uint.TryParse, entropy, new entries."""
    ctx, _, _ = target_world
    out = dotnet.dotnet_decompile(ctx, "KeePass.Forms.MainForm", "OnToolsGeneratePasswordList")
    assert not out.startswith("error"), out[:200]
    for text in ("PwGeneratorForm", "SingleLineEditForm", "uint.TryParse", "CollectEntropyIfEnabled",
                 "GenerateAcceptable"):
        assert text in out, text
