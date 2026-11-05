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

## Planned sources (not yet included)

| Project | License | Planned use |
|---|---|---|
| [DelphiReSym](https://github.com/WenzWenzWenz/DelphiReSym) | BSD-3-Clause | format reference for the Delphi metadata parser (M6); no code copied |
| [REA](https://github.com/morluto/rea) | MIT | design ideas: selectors, artifact identity, analysis profiles, bounded output |
| [IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) | MIT | MSVC RTTI / vtable / xref handler logic (M2) |
| pefile, dnfile, olefile | MIT / BSD | PE, .NET metadata and OLE parsing |
| [ILSpy / ilspycmd](https://github.com/icsharpcode/ILSpy) | MIT | optional external C# decompiler (M7), not redistributed |
