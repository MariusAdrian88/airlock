# Third-party notices

airlock is MIT-licensed. It depends on, or adapts ideas and code from, the
projects below. Code copied or adapted from a project keeps that project's
copyright notice and license, reproduced here when the code lands.

## Runtime dependencies (not redistributed)

| Project | License | Use |
|---|---|---|
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) and its bundled PyGhidra | Apache-2.0 | analysis engine, loaded from the user's installation |
| [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) | MIT | MCP server |
| [json5](https://github.com/dpranke/pyjson5) | Apache-2.0 | JSONC config parsing |
| [capstone](https://github.com/capstone-engine/capstone) | BSD-3-Clause | x86 decoder for `airlock delphi-sigs build` only (optional extra `sigs`) |

## Planned sources (not yet included)

| Project | License | Planned use |
|---|---|---|
| [DelphiReSym](https://github.com/WenzWenzWenz/DelphiReSym) | BSD-3-Clause | format reference for the Delphi metadata parser (M6); no code copied |
| [JCL](https://github.com/project-jedi/jcl) (`.jdbg` debug info) | MPL-1.1 | format reference only; the layout of the files next to the Delphi packages was studied for a reader that is not part of airlock; no code copied |
| Itanium C++ ABI | public specification | format reference for `server/itanium.py` (written from the description) |
| [IDR](https://github.com/crypto2011/IDR) and [IDR64](https://github.com/crypto2011/IDR64) | MIT | optional knowledge bases (`kb*.bin`) that name Delphi RTL / VCL functions; file format reference only, the files are supplied by the user and never committed |
| [WARP](https://github.com/Vector35/warp) and [delphinja](https://github.com/psifertex/delphinja) | Apache-2.0 / MIT | `.warp` file format and function GUID rules (spec and reference code read, no code copied); the Delphi `.warp` libraries are supplied by the user and never committed |
| [delphinja](https://github.com/psifertex/delphinja) (`tools/RTTI.md`, `rttikb.py`) | MIT | the "extended RTTI consensus" method behind `server/delphirtti.py`: read the method names that a Delphi 2010+ binary states about its own RTL code, keep a code shape to name pair only where independent programs agree. Idea only: the code is new and masks bytes with `delphisigs`; no delphinja code is copied. The databases are derived from the user's programs and never committed |
| [REA](https://github.com/morluto/rea) | MIT | design ideas: selectors, artifact identity, analysis profiles, bounded output |
| [IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) | MIT | MSVC RTTI / vtable / xref handler logic (M2) |
| pefile, dnfile, olefile | MIT / BSD | PE, .NET metadata and OLE parsing |
| [ILSpy / ilspycmd](https://github.com/icsharpcode/ILSpy) | MIT | optional external C# decompiler (M7), not redistributed |
