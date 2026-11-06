# Real-data suite

Checks airlock on real open-source programs with real Ghidra. Every target is downloaded
from a pinned URL, checked by sha256, and then known facts (from the program source or from
earlier evaluations) are asserted through the tool functions.

## Run

    pytest -q -m realdata --realdata

Add `--realdata-cache=<folder>` to choose the download folder. Default:
`<airlock data dir>/realdata` (`%LOCALAPPDATA%\airlock\realdata`). One target:
`pytest -q --realdata tests/realdata/test_rd_keepass.py`.

The option makes pytest run serially (no xdist). Without `--realdata` all these tests
skip: no download, no Ghidra. Ghidra paths come from `config.jsonc`, as for the other tests.
Do not run two real-Ghidra runs at the same time.

## Targets (3)

`targets.json`: name, url, sha256 (of the archive), file, members, toolchain, license,
version, source. The fixture `target_world` (conftest.py) downloads, checks the hash
(a mismatch fails, never skips), extracts the listed members, runs `project_create` and
waits for the index in a temp folder.

| target | what | toolchain | license | asserted facts |
|---|---|---|---|---|
| winmtr | WinMTR Redux v1.00 `WinMTR64.exe` | MSVC, MFC, x64 | GPL-2.0 | message map of `WinMTRDialog`: 17 entries, ids 1002-1007 (source `WinMTRDialog.cpp`) |
| tilestudio | Tile Studio 2.55 `TS.exe` | Delphi, x86 | MIT | string `ts.tsc` has a reader; round 10: a string address gives the string line and no function |
| keepass | KeePass 2.60 `KeePass.exe` | .NET WinForms (no Ghidra) | GPL-2.0 | menu event `OnToolsGeneratePasswordList`; its decompile holds the known calls |

## Time

One full run: 5 min 43 s (measured while other agents used the machine). Ghidra analysis dominates (TS.exe and WinMTR64.exe
about 2.5 min each); KeePass takes about 30 s. The run is serial.

## Known gaps found by the suite

- Fix pass R4: a fresh index of Tile Studio still has about 97 direct call targets without
  a function (for example `0x00402cbc`, a real FPU routine that on-demand creation makes).
  No test asserts it now (cut from the suite); `fnfix._call_targets(store, id)` counts them.
- .NET race (`UNIQUE constraint failed: dn_field`) was found here on code before 0.1.0;
  0.1.0 fixes it (one writer per managed binary). The fixture has no retry.
