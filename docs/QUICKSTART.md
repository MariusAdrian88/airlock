# Quickstart

This page takes you from nothing to a working project in about 15 minutes.
Other install ways (uvx, uv tool, wheel file) are in the [INSTALL.md](INSTALL.md).
All tools are in [TOOLS.md](TOOLS.md). Error messages are in [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## 1. What you need

- Windows x64.
- Python 3.13.
- [Ghidra 12.1.4](https://github.com/NationalSecurityAgency/ghidra/releases). Unpack it to a folder, for example `C:/Tools/ghidra_12.1.4_PUBLIC`.
- A JDK 21 or newer, for example Eclipse Temurin 21.
- An MCP client, for example Claude Code.

`airlock doctor --fix` gets 3 things for you:

- PyGhidra, from the wheels inside your Ghidra folder (no internet needed).
- `ilspycmd`, the .NET decompiler (a download).
- An upgrade of an old `config.jsonc`.

## 2. Install

Run these commands in PowerShell:

```powershell
git clone https://github.com/MariusAdrian88/airlock
cd airlock
py -3.13 -m venv .venv
.venv\Scripts\activate
pip install -e .
airlock init --ghidra C:/Tools/ghidra_12.1.4_PUBLIC
airlock doctor --fix
airlock doctor --start
```

`airlock init` writes `%APPDATA%\airlock\config.jsonc`. All settings are in this file.
If `java` is not on your PATH, set `"jdk_dir"` in the file.
Go on when each line of `airlock doctor --start` shows `[OK   ]`.

## 3. Connect Claude Code

```powershell
claude mcp add airlock -- C:\path\to\airlock\.venv\Scripts\airlock.exe serve --profile dirty
```

Start a new Claude Code session. The tools of airlock are now available.
For OpenCode and for the other install ways, see [Register with an MCP client](INSTALL.md#register-with-an-mcp-client).

The sets `delphi` and `dotnet` are off by default. To turn them on, run this command and restart the client:

```powershell
airlock config --set disabled_sets "[]"
```

## 4. Make your first project

1. Put the program that you want to analyse in a folder, for example `C:\work\target`.
2. Tell the agent: `Reverse engineer the program in C:\work\target.`
3. The agent calls `program_scan`. It shows the files and 4 analysis options (A to D) with a time estimate.
4. The agent asks you for a project name and an option. Answer it.
5. The agent calls `project_create`. Ghidra analyses the files in a queue and decompiles them in the background.
6. Ask `Is the analysis ready?`. The agent calls `index_status`. You can work on a binary when it is ready.

In a later session, tell the agent to open the project by name. The agent calls `projects`, then `project_open`
with the role `dirty`.

## 5. Five typical tasks

Each task shows the prompt that you give the agent and the tools that the agent uses.

**Find a function by a string.**
Prompt: `Find the function that shows the text "License expired".`
Tools: `strings`, `function`

**Read a function.**
Prompt: `Show me the function CMainFrame::OnFileOpen as C.`
Tools: `function`

**Follow the callers.**
Prompt: `Who calls LoadDocument? Show the callers 2 levels up.`
Tools: `callgraph`, `xrefs`

**Delphi form events** (set `delphi` on).
Prompt: `List the forms of this Delphi program. For TMainForm, show which handler runs on each button click.`
Tools: `delphi_forms`, `delphi_events`, `function`

**A .NET method** (set `dotnet` on).
Prompt: `Find the types that have "License" in the name. Show the C# of the method Check.`
Tools: `dotnet_types`, `dotnet_decompile`

A long answer ends with `… N more lines. cursor=<id>`. The agent continues with that cursor.

## 6. Clean-room work

Write what you learn as specifications with `spec_write`, and publish them with `spec_export`.
Then register a second server with `--profile clean` and use it in a separate session.
That session sees specifications only, never code, addresses or bytes.
