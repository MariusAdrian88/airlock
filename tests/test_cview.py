"""Noise reduction and outline of decompiled C (synthetic Ghidra-like text)."""

from __future__ import annotations

from airlock.server.cview import compress_cases, outline_lines, reduce_c, strip_warnings
from airlock.server.tools.core import annotate_calls


def _fn(decls: list[str], body: list[str]) -> str:
    return "\n".join(["void f(int a)", "", "{"] + decls + [""] + body + ["}"])


def test_warning_strip_with_blank_and_multiline():
    t = _fn(["  int a;"], ["  /* WARNING: bad */", "", "  x = 1;",
                          "  /* WARNING: two", "     lines */", "  y = 2;"])
    out = reduce_c(t)
    assert "WARNING" not in out and "lines */" not in out
    assert out.split("\n")[-3:] == ["  x = 1;", "  y = 2;", "}"]
    assert strip_warnings(["a", "/* WARNING: z */", "", "b"]) == ["a", "b"]


def test_locals_threshold():
    d6 = [f"  int iVar{i};" for i in range(6)]
    d7 = [f"  int iVar{i};" for i in range(7)]
    assert reduce_c(_fn(d6, ["  x = 1;"])) == _fn(d6, ["  x = 1;"])
    out = reduce_c(_fn(d7, ["  x = 1;"]))
    assert "  // 7 locals: iVar0, iVar1, iVar2, iVar3, iVar4, iVar5, iVar6 (detail=full shows types)" in out
    assert "int iVar0;" not in out and out.endswith("\n\n  x = 1;\n}")


def test_locals_formats_and_cap():
    d = ["  char *pcVar1;", "  undefined1 local_28 [16];", "  struct foo_s local_40;",
         "  code *pcVar2;", "  undefined4 *puVar3;", "  uint auStack_60 [4] [2];",
         "  ulonglong uVar4;"]
    out = reduce_c(_fn(d, ["  x = 1;"]))
    assert ("// 7 locals: pcVar1, local_28, local_40, pcVar2, puVar3, auStack_60, uVar4"
            in out)
    many = [f"  undefined4 local_{i:04x};" for i in range(300)]
    line = [x for x in reduce_c(_fn(many, [])).split("\n") if "locals:" in x][0]
    assert line.startswith("  // 300 locals: ") and "+" in line and "more (detail=full" in line
    assert len(line) < 260
    # initialised statements end the run
    mixed = [f"  int v{i};" for i in range(8)] + ["  int w = 3;"]
    out = reduce_c(_fn(mixed, []))
    assert "// 8 locals:" in out and "  int w = 3;" in out


def test_full_is_identity():
    t = _fn([f"  int v{i};" for i in range(9)], ["  /* WARNING: x */", "  y;"])
    assert reduce_c(t, "full") == t


def test_call_annotations_survive_reduction():
    raw = _fn([f"  int v{i};" for i in range(9)],
              ["  /* WARNING: x */", "", "  Helper(a);", "  FUN_00401234();"])
    i = raw.index("Helper")
    nodes = [{"kind": "call", "start_off": i, "end_off": i + 6, "target": 0x401500, "text": "Helper"}]
    ann = annotate_calls(raw, nodes, 4)
    out = reduce_c(ann)
    assert "Helper/*0x00401500*/(a);" in out and "WARNING" not in out and "locals:" in out


BIG = "\n".join(
    ["int f(int a)", "", "{", "  int x;", "", "  if (a == 0x1234567812345678123456781234567812345678123456781234567890) {",
     '    Log("start");', "    while (x < 3) {", "      Deep();", "      if (x) {", "        Deeper();", "      }", "    }",
     "  }", "  switch(a) {"] +
    [f"  case {i}:" for i in range(0, 0x21)] +
    ["    Log(\"case\");", "    break;", "  case 0x100:", "  case 0x200:", "  default:", "    break;", "  }",
     "  do {", "    Log(\"loop\");", "  } while (x < 9);", "  return x;", "}"])


def test_outline_structure():
    ls = BIG.split("\n")
    out = outline_lines(ls, "// H")
    assert out[0] == "// H" and out[1] == "int f(int a)"
    ctl = out[out.index("control:") + 1: out.index("calls:")]
    first_if = ls.index(next(x for x in ls if x.startswith("  if (a ==")))
    assert ctl[0].startswith(f"  L{first_if + 1}-L{first_if + 9} if (a == ") and ctl[0].endswith("...")
    assert any("while (x < 3)" in x and x.startswith(f"  L{first_if + 3}-") for x in ctl)
    assert not any("Deeper" in x or "if (x)" in x for x in ctl)           # level 2 hidden
    assert any("case 0..32,0x100,0x200,default (37 cases)" in x or "case 0..0x20,0x100,0x200,default" in x
               for x in ctl)
    assert any("do {" in x or x.strip().endswith("do") for x in ctl)
    calls = out[out.index("calls:") + 1: out.index("strings:")]
    assert calls[0] == f"  Log x3 L{first_if + 2}"
    strs = out[out.index("strings:") + 1:]
    assert strs[0] == f'  L{first_if + 2} "start"'


def test_compress_cases():
    assert compress_cases(["0", "1", "2", "3", "5", "0x20", "default"]) == "0..3,5,0x20,default"
    assert compress_cases(["A", "B"]) == "A,B"
