"""Agent-evaluation fixes: forgiving binary names, Ghidra default names as targets, kind forms."""

from __future__ import annotations

import pytest

from airlock.server import registry
from airlock.server.selectors import default_name_address
from airlock.server.tools import common, core
from test_tools import fill, make_ctx


def run(ctx, name, **kw):
    """The registered (note-adding) implementation, without the role gate."""
    return registry.IMPLEMENTED[name].fn(ctx, **kw)


@pytest.fixture
def one(tmp_path):
    c = make_ctx(tmp_path)
    fill(c)
    return c


def test_binary_that_is_the_project_name_uses_the_only_binary(one):
    out = run(one, "strings", pattern="open", binary="proj")
    assert out.splitlines()[0] == "(binary: app.exe)"
    assert out.splitlines()[1].startswith("strings matching")
    assert "(binary:" not in run(one, "strings", pattern="open", binary="app.exe")
    assert "(binary:" not in run(one, "strings", pattern="open")


def test_binary_without_extension_or_other_case(tmp_path):
    c = make_ctx(tmp_path)
    fill(c)
    st = c.indexer.store("proj")
    b2 = st.upsert_binary("cd" * 32, "other.dll", pointer_size=4)
    c.indexer.set_status(st, b2, "ready")
    out = run(c, "strings", pattern="open", binary="APP")
    assert out.splitlines()[0] == "(binary: app.exe)"
    assert run(c, "strings", pattern="open", binary="zzz").startswith("error not_found:")
    assert "app.exe, other.dll" in run(c, "strings", pattern="open", binary="zzz")
    assert run(c, "strings", pattern="open", binary="proj").startswith("error not_found:")


@pytest.mark.parametrize("name,addr", [
    ("DAT_14026ebc8", 0x14026EBC8), ("DAT_00402000", 0x402000), ("PTR_FUN_00401000", 0x401000),
    ("LAB_0040102c", 0x40102C), ("UNK_140001000", 0x140001000), ("FUN_140001000", 0x140001000),
    ("s_Hello_world_00402abc", 0x402ABC), ("u_Hello_14000a000", 0x14000A000),
    ("PTR_s_text_1400b0000", 0x1400B0000),
])
def test_default_name_address(name, addr):
    assert default_name_address(name) == addr


@pytest.mark.parametrize("name", ["DAT_", "DAT_xyz", "main", "DATA_00402000", "s_hello", "OnFoo"])
def test_default_name_address_rejects(name):
    assert default_name_address(name) is None


def test_xrefs_accepts_default_data_name_32bit(one):
    a = run(one, "xrefs", target="0x00402000")
    b = run(one, "xrefs", target="DAT_00402000")
    assert not b.startswith("error")
    assert a == b


def test_xrefs_accepts_default_data_name_64bit(tmp_path):
    c = make_ctx(tmp_path)
    st = c.indexer.store("proj")
    bid = st.upsert_binary("ef" * 32, "w.exe", format="pe64", arch="x86", pointer_size=8,
                           image_base=0x140000000, toolchain="msvc", analysis_profile="p")
    c.indexer.set_status(st, bid, "ready")
    c.indexer.current = "proj"
    a = run(c, "xrefs", target="0x14026ebc8")
    b = run(c, "xrefs", target="DAT_14026ebc8")
    assert not b.startswith("error"), b
    assert a == b


@pytest.mark.parametrize("kind,want", [("methods", "method"), ("Method", "method"), ("PInvokes", "pinvoke"),
                                        ("p-invoke", "pinvoke"), ("types", "type"), ("COM", "com"),
                                        ("method", "method")])
def test_normalize_kind(kind, want):
    v, note = common.normalize_kind(kind, ("type", "method", "pinvoke", "com"))
    assert v == want
    assert (note is None) == (kind == want)


def test_normalize_kind_unknown_and_plural_targets():
    assert common.normalize_kind("zzz", ("type", "method")) == ("", None)
    assert common.normalize_kind("strings", ("string", "import"))[0] == "string"
    assert common.normalize_kind("class", ("function", "class"))[0] == "class"
    assert common.normalize_kind("notes", ("note", "any"))[0] == "note"
    assert common.normalize_kind("calls", ("call", "jump"))[1] == "(kind: calls read as call)"


def test_search_and_xrefs_kind_forms(one):
    out = run(one, "search", query="open", kind="Strings")
    assert out.splitlines()[0] == "(kind: Strings read as string)"
    assert run(one, "xrefs", target="0x00402000", kind="Reads").splitlines()[0] \
        == "(kind: Reads read as read)"
    assert run(one, "xrefs", target="0x00402000", kind="zzz").startswith("error bad_args")
