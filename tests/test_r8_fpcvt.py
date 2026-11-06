"""Round 8 (N9): Free Pascal VMT origins. The linker puts one shared empty stub into the VMT of the classes whose
virtual methods nothing calls (TObject among them); a class that really inherits the RTL's empty method carries the
address of that method. A shared stub is no method of any class: no borrowed names, no false overrides."""

from __future__ import annotations

import pytest

from airlock.server import delphi
from airlock.server.tools import cpp as cpp_tools
from test_delphi import TEXT_VA
from test_fpc import START, FpcPe
from test_tools import make_ctx


def build_pe(path, psize: int):
    pe = FpcPe(psize)
    pe.fclass("TObject", None, "System", psize, virtuals=13)
    pe.fclass("TAnimal", "TObject", "t1", 2 * psize, virtuals=15)        # + Speak (abstract), Show
    for i in range(3):
        pe.fclass(f"EPruned{i}", "TObject", "SysUtils", 3 * psize, virtuals=13)
    pe.fclass("TEnc", "TObject", "SysUtils", 2 * psize, virtuals=15)
    shared, abstract = pe.stub("shared"), pe.stub("abstract")
    pe.text[abstract - pe.base - TEXT_VA] = 0x90                      # the error stub is a real function, not a bare RET
    ps = psize
    def set_slot(cls: str, slot: int, addr: int) -> None:
        pe.put(pe.vmts[cls] + (START + slot) * ps, pe.p(addr))
    for cls in ("TObject", "EPruned0", "EPruned1", "EPruned2"):
        for k in (4, 5, 6, 7):
            set_slot(cls, k, shared)                                    # emptied by the linker
    for cls, slots in (("TAnimal", (13,)), ("TEnc", (13, 14))):
        for k in slots:
            set_slot(cls, k, abstract)                                  # FPC_ABSTRACTERROR
    pe.write(path)
    return pe


@pytest.mark.parametrize("psize", [4, 8])
def test_shared_empty_stub_is_not_an_override(tmp_path, psize):
    pe = build_pe(tmp_path / "a.exe", psize)
    classes, _ = delphi.parse_file(tmp_path / "a.exe", {"TEnc": {13: "GETBYTECOUNT", 14: "getBytes"}})
    by = {c.name: c for c in classes}
    animal = {m.slot: m for m in by["TAnimal"].methods if m.kind == "virtual"}
    assert [animal[k].name for k in (4, 5, 6, 7)] == ["", "", "", ""]      # inherited: no name of its own
    assert animal[0].name == "Destroy"                                    # its own code in slot 0: an override
    kinds = {(m.kind, m.slot) for m in by["TObject"].methods}
    assert ("empty-stub", 4) in kinds and ("empty-shared", 4) in kinds


@pytest.fixture
def store(tmp_path):
    ctx = make_ctx(tmp_path)
    ix = ctx.indexer
    st = ix.store("proj")
    ix.current = "proj"
    art = ix.paths("proj", create=True).artifacts
    art.mkdir(parents=True, exist_ok=True)
    sha = "cf" * 32
    pe = build_pe(art / sha, 4)
    bid = st.upsert_binary(sha, "t1.exe", format="pe32", arch="x86", pointer_size=4, image_base=0x400000,
                           toolchain="fpc", toolchain_ver="3.2.2", analysis_profile="p")
    ix.set_status(st, bid, "ready")
    classes, forms = delphi.parse_file(art / sha, {"TEnc": {13: "GETBYTECOUNT", 14: "getBytes"}})
    delphi.store_rows(st, bid, classes, forms)
    return ctx, st, bid, pe


def test_vtable_origins_and_stub_labels(store):
    ctx, st, bid, pe = store
    out = cpp_tools.vtable(ctx, "TAnimal").splitlines()
    by = {int(ln[1:ln.index("]")]): ln for ln in out if ln.startswith("[")}
    for k in (4, 5, 6, 7):
        assert by[k].endswith("; inherited from TObject")                # was: override, introduced by TObject
    assert by[0].endswith("; override, introduced by TObject")           # a real bare-RET override of its own stays one
    assert " abstract; new" in by[13]
    tobj = {int(ln[1:ln.index("]")]): ln for ln in cpp_tools.vtable(ctx, "TObject").splitlines() if ln.startswith("[")}
    assert all(" empty; new" in tobj[k] for k in (4, 5, 6, 7))
    enc = {int(ln[1:ln.index("]")]): ln for ln in cpp_tools.vtable(ctx, "TEnc").splitlines() if ln.startswith("[")}
    assert " abstract; new" in enc[13] and " abstract; new" in enc[14]


def test_hints_for_shared_stub_has_no_borrowed_name(store):
    ctx, st, bid, pe = store
    assert {r[0] for r in st.db.execute("SELECT name FROM dl_method WHERE binary_id=? AND slot IN (13, 14) AND "
                                        "kind='virtual' AND name<>''", (bid,))} == {"GETBYTECOUNT", "getBytes"}
    got = delphi.hints_for(st, bid, pe.code["abstract"])
    assert not any("GETBYTECOUNT" in h or "getBytes" in h for h in got)
    assert any(h.startswith("shared stub of virtual slots 13, 14") for h in got)
    assert any(h.startswith("TAnimal::vslot 13") for h in got) and not any("(" in h and "vslot" in h and "classes" not in h
                                                                          for h in got if h.startswith("TAnimal"))
    shared = delphi.hints_for(st, bid, pe.code["shared"])
    assert any(h.startswith("shared stub of virtual slots 4, 5, 6, 7") for h in shared)
    assert not any("DefaultHandler" in h or "AfterConstruction" in h for h in shared)
    assert "TObject::vslot 0 (Destroy)" in delphi.hints_for(st, bid, pe.code["TObject.v0"])    # a method keeps its name
