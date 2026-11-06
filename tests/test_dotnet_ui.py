"""dotnet_events and managed resources (dotnet_ui): WinForms IL wiring, XAML events, .resources entries.

The test assembly is built with the .NET Framework C# compiler (skipped when it is missing); the
form code needs System.Windows.Forms, which csc finds in the Framework folder.
"""

from __future__ import annotations

import struct
import subprocess
from pathlib import Path

import pytest

from airlock.server import dotnet_ui as ui
from airlock.server.tools import dotnet as dt
from airlock.server.tools import resources as rt
from test_dotnet import CSC, add_managed, make_dn_ctx

SOURCE = """
using System;
using System.Windows.Forms;
namespace Demo.UI {
  public class MainForm : Form {
    private Button btnOk;
    private ToolStripMenuItem mnuGen;
    private Label lbl;
    private Button btnLocal;
    public MainForm() { InitializeComponent(); }
    private void InitializeComponent() {
      this.btnOk = new Button();
      this.mnuGen = new ToolStripMenuItem();
      this.lbl = new Label();
      this.btnOk.Text = "OK";
      this.btnOk.Click += new EventHandler(this.OnOk);
      this.mnuGen.Text = "&Generate List...";
      this.mnuGen.Click += new EventHandler(this.OnGenerate);
      this.lbl.Text = "Name";
      Button b = new Button();
      b.Text = "Local";
      b.MouseDown += new MouseEventHandler(this.OnLocalDown);
      this.btnLocal = b;
      this.Text = "Main window";
      this.Load += new EventHandler(this.OnFormLoad);
    }
    private void OnOk(object s, EventArgs e) { }
    private void OnGenerate(object s, EventArgs e) { }
    private void OnLocalDown(object s, MouseEventArgs e) { }
    private void OnFormLoad(object s, EventArgs e) { }
  }
  public class Plain { public void Run() { } }
}
"""

XAML = """<Window x:Class="Demo.UI.MainForm" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" xmlns:local="clr-namespace:Demo.UI" Title="App" Drop="OnFormLoad">
  <UIElement.CommandBindings>
    <CommandBinding Command="Open" Executed="OnGenerate" />
    <CommandBinding Command="local:MainForm.Props" Executed="OnOk" />
  </UIElement.CommandBindings>
  <Menu><MenuItem Name="OpenItem" Header="_Open" Command="Open" />
    <MenuItem Name="PropsItem" Header="_Properties" Command="local:MainForm.Props" />
    <MenuItem Header="Other" Command="{Binding DoIt}" /></Menu>
  <Button Name="Ok" Content="OK" Click="OnOk" Width="30" />
  <Button Content="Plain" Tag="OnOk" />
</Window>
"""


def res_stream(entries: dict[str, str]) -> bytes:
    """A version 2 .resources stream with string entries."""
    def r7(n: int) -> bytes:
        out = bytearray()
        while True:
            b = n & 0x7F
            n >>= 7
            out.append(b | (0x80 if n else 0))
            if not n:
                return bytes(out)
    rd = b"System.Resources.ResourceReader, mscorlib"
    rs = b"System.Resources.RuntimeResourceSet"
    head = struct.pack("<I", 1) + r7(len(rd)) + rd + r7(len(rs)) + rs
    out = bytearray(struct.pack("<II", 0xBEEFCACE, 1) + struct.pack("<I", len(head)) + head)
    out += struct.pack("<III", 2, len(entries), 0)
    while len(out) % 8:
        out += b"P"
    out += b"\0" * (4 * len(entries))
    names = bytearray()
    data = bytearray()
    offs = []
    for k, v in entries.items():
        nb = k.encode("utf-16le")
        offs.append(len(names))
        names += r7(len(nb)) + nb + struct.pack("<I", len(data))
        vb = v.encode("utf-8")
        data += r7(1) + r7(len(vb)) + vb
    out += b"".join(struct.pack("<I", o) for o in offs)
    out += struct.pack("<I", len(out) + 4 + len(names))
    out += names + data
    return bytes(out)


@pytest.fixture(scope="session")
def ui_dll(tmp_path_factory) -> Path:
    if not CSC.is_file():
        pytest.skip("needs the .NET Framework C# compiler")
    d = tmp_path_factory.mktemp("ui")
    (d / "t.cs").write_text(SOURCE, encoding="utf-8")
    (d / "f.resources").write_bytes(res_stream({"btnOk.ToolTip": "Press <ok>", "greeting": "Hello"}))
    r = subprocess.run([str(CSC), "/nologo", "/target:library", "/r:System.Windows.Forms.dll",
                        "/resource:f.resources,Demo.UI.MainForm.resources", "/out:ui.dll", "t.cs"],
                       cwd=d, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    return d / "ui.dll"


def test_resources_reader():
    ents = ui.read_resources(res_stream({"a.Text": "Alpha", "b": "x" * 100}))
    assert [(e.name, e.is_string) for e in ents] == [("a.Text", True), ("b", True)]
    assert ents[0].preview == '"Alpha"' and ents[1].preview.endswith('…"')
    assert ui.read_resources(b"not a resource stream at all, 24 bytes+") is None


def test_winforms_events_from_il(ui_dll):
    rows = ui.winforms_rows(ui_dll)
    got = {(r.control, r.event): (r.handler, r.caption, r.ctype) for r in rows}
    assert got[("btnOk", "Click")] == ("OnOk", "OK", "Button")
    assert got[("mnuGen", "Click")] == ("OnGenerate", "&Generate List...", "ToolStripMenuItem")
    assert got[("btnLocal", "MouseDown")][0] == "OnLocalDown"       # local stored into a field later
    assert got[("form", "Load")] == ("OnFormLoad", "Main window", "")
    assert all(r.token >> 24 == 0x06 for r in rows)
    assert not any(r.form == "Demo.UI.Plain" for r in rows)


def test_select_rows_tiers(ui_dll):
    rows = ui.winforms_rows(ui_dll)
    sel, facts, err = ui.select_rows(rows, component="Generate List")        # caption, & ignored
    assert [r.control for r in sel] == ["mnuGen"] and not facts and not err
    sel, facts, _ = ui.select_rows(rows, component="btn")
    assert {r.control for r in sel} == {"btnOk", "btnLocal"} and "prefix match" in facts[0]
    sel, facts, _ = ui.select_rows(rows, component="Gener", event="click")
    assert [r.control for r in sel] == ["mnuGen"] and "prefix match" in facts[0]
    sel, _, _ = ui.select_rows(rows, component="OnOk")                       # by handler
    assert [r.control for r in sel] == ["btnOk"]
    _, _, err = ui.select_rows(rows, form="Missing")
    assert err.startswith("error not_found:") and "Demo.UI.MainForm" in err
    _, _, err = ui.select_rows(rows, component="zzz")
    assert err.startswith("error not_found:")


def test_xaml_events_and_commands(ui_dll):
    asm = ui._Asm(ui_dll)
    rows = ui.xaml_rows(XAML, "mainform.baml", asm)
    lines = [ui.row_line(r, False) for r in rows]
    assert 'Ok Button "OK" Click -> OnOk 0x' in " ".join(lines)
    assert any(ln.startswith('OpenItem MenuItem "_Open" Command Open -> OnGenerate 0x') for ln in lines)
    assert any(ln.startswith('PropsItem MenuItem "_Properties" Command local:MainForm.Props -> OnOk 0x')
               for ln in lines)
    assert any("Command {Binding DoIt} -> no CommandBinding in the XAML" in ln for ln in lines)
    assert any(r.event == "Executed" and r.ctype == "CommandBinding" and r.handler == "OnGenerate" for r in rows)
    assert any(r.control == "" and r.event == "Drop" and r.handler == "OnFormLoad" for r in rows)
    assert not any(r.caption == "Plain" for r in rows)            # Tag="OnOk" is not an event
    assert ui.xaml_rows("<not xml", "x", None) == []


def test_managed_resources_lines(ui_dll):
    lines = ui.managed_resources(ui_dll, "")
    assert lines == ["managed Demo.UI.MainForm.resources " + lines[0].split()[2] + " B embedded public 2 entries"]
    full = ui.managed_resources(ui_dll, "resources")
    assert any("MainForm.resources/btnOk.ToolTip " in ln and ln.endswith('"Press <ok>"') for ln in full)
    assert any(ln.startswith("  Demo.UI.MainForm.resources/greeting ") and ln.endswith('"Hello"') for ln in full)
    assert ui.managed_resources(ui_dll, "baml") == []


def test_dotnet_events_tool(tmp_path, ui_dll):
    ctx = make_dn_ctx(tmp_path)
    add_managed(ctx, ui_dll, "ui.dll")
    out = dt.dotnet_events(ctx).splitlines()
    assert out[0] == "Demo.UI.MainForm events 4"
    one = dt.dotnet_events(ctx, form="MainForm", component="OK")
    assert "Demo.UI.MainForm events 1 of 4" in one
    assert 'btnOk Button "OK" Click -> OnOk 0x06' in one
    assert dt.dotnet_events(ctx, form="Nope").startswith("error not_found:")


def test_pe_resources_lists_managed(tmp_path, ui_dll):
    ctx = make_dn_ctx(tmp_path)
    add_managed(ctx, ui_dll, "ui.dll")
    out = rt.pe_resources(ctx)
    assert "managed Demo.UI.MainForm.resources" in out and "embedded public 2 entries" in out
    assert "Hello" in rt.pe_resources(ctx, type="managed")
    assert "managed" not in rt.pe_resources(ctx, type="ICON")


def test_dotnet_events_registered_in_catalog():
    from airlock.config.catalog import CATALOG
    from airlock.server import registry
    registry.load_tool_modules()
    assert "dotnet_events" in registry.IMPLEMENTED
    assert CATALOG["dotnet_events"].set == "dotnet"
