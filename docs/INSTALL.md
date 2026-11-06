# Install

This page holds every install way. For the short path, use the [Quickstart](QUICKSTART.md).

## Requirements

- Windows x64 (Linux/macOS can work but are not the primary target)
- Python **3.13** (3.10–3.13 work; Ghidra bundles JPype wheels only up to 3.13)
- [Ghidra 12.1.4](https://github.com/NationalSecurityAgency/ghidra/releases)
- JDK 21+ (e.g. Eclipse Temurin 21)

## Install

There are 4 ways to install airlock. All of them need Ghidra, a JDK and the
config file. Pick one:

| Way | Use it when |
|---|---|
| [A. From a clone](#a-from-a-clone) | You want to change the airlock code. |
| [B. uvx, no install](#b-uvx-no-install) | You want no install step. The MCP client starts airlock directly from GitHub. |
| [C. uv tool install](#c-uv-tool-install) | You want a fixed `airlock.exe` on the PATH. The MCP command is then only `airlock serve`. |
| [D. Wheel file](#d-wheel-file) | You install on a machine with no internet, or you give a file to other people. |

**PyGhidra.** PyGhidra is not a dependency of airlock, because its version must
match your Ghidra install. Ghidra bundles the correct wheels (PyGhidra and JPype)
in this folder:

```
<ghidra>/Ghidra/Features/PyGhidra/pypkg/dist
```

Ghidra 12.1.4 has `pyghidra-3.1.0`. If your Ghidra has another version, use that
version in the commands below. Method A and the venv form of method D install
PyGhidra with `airlock doctor --fix`. A uv environment has no `pip`. Methods B and C,
and the uv form of method D, give PyGhidra with `--with` and `--find-links` instead.

**Python.** Use Python 3.13. Ghidra bundles JPype wheels only for Python 3.9 to 3.13.
uv downloads Python 3.13 itself if it is not installed.

The examples use these 2 PowerShell variables:

```powershell
$ghidra = "C:/Tools/ghidra_12.1.4_PUBLIC"
$dist   = "$ghidra/Ghidra/Features/PyGhidra/pypkg/dist"
```

### A. From a clone

```powershell
git clone https://github.com/MariusAdrian88/airlock
cd airlock
py -3.13 -m venv .venv
.venv\Scripts\activate
pip install -e .            # for the tests: pip install -e .[dev]

airlock init --ghidra $ghidra
airlock doctor --fix        # installs PyGhidra from Ghidra's bundled wheels (offline)
airlock doctor --start      # also starts the worker and Ghidra once
```

To update, run `git pull` in the clone. The MCP command is
`C:\path\to\airlock\.venv\Scripts\airlock.exe serve`.

### B. uvx, no install

[uv](https://docs.astral.sh/uv/) runs airlock in a cached environment that it
builds from GitHub. You need no clone and no venv.

```powershell
$src = "git+https://github.com/MariusAdrian88/airlock"

uvx --from $src airlock init --ghidra $ghidra
uvx --python 3.13 --from $src --find-links $dist --with pyghidra==3.1.0 airlock doctor --start
```

The MCP command is the same `uvx` line with `serve` in place of `doctor --start`
(see [Register with an MCP client](#register-with-an-mcp-client)).

- The first start takes about 1 minute, because uv builds the environment. Later starts use the cache.
- Without a commit or tag, uvx uses the newest `main`. To keep one version, add a tag
  or commit to the URL: `git+https://github.com/MariusAdrian88/airlock@v0.1.0`.
- To get the newest `main` again, add `--refresh` to the command one time.

### C. uv tool install

`uv tool install` makes a permanent environment for airlock. It puts `airlock.exe`
in `%USERPROFILE%\.local\bin`. If that folder is not on your PATH, run
`uv tool update-shell` one time.

```powershell
$src = "git+https://github.com/MariusAdrian88/airlock"    # or a wheel file, see D

uv tool install --python 3.13 --find-links $dist --with pyghidra==3.1.0 $src
airlock init --ghidra $ghidra
airlock doctor --start
```

uv remembers the `--with` and `--find-links` options for this tool.

| Task | Command |
|---|---|
| Update to the newest `main` | `uv tool upgrade airlock` |
| Install one fixed version | `uv tool install --force --python 3.13 --find-links $dist --with pyghidra==3.1.0 "$src@v0.1.0"` |
| Also install capstone (for `airlock delphi-sigs build`) | add `--with capstone` to the install command |
| Remove | `uv tool uninstall airlock` |

The MCP command is `airlock serve`. Your configuration and projects stay when you
remove the tool. They are in `%APPDATA%\airlock` and `%LOCALAPPDATA%\airlock`.

### D. Wheel file

A wheel (`airlock-<version>-py3-none-any.whl`) is one file that holds airlock.
It holds no Ghidra and no PyGhidra.

**Get the wheel.** Use one of these sources:

- **From a GitHub release.** Open the [Releases](https://github.com/MariusAdrian88/airlock/releases)
  page and download the `.whl` file. You can also install directly from its URL:
  `https://github.com/MariusAdrian88/airlock/releases/download/v<version>/airlock-<version>-py3-none-any.whl`.
- **Build it yourself** from a clone. The wheel and the source archive (`.tar.gz`) go to `dist\`:

  ```powershell
  uv build              # or: pip install build; python -m build
  ```

**Install it with uv:**

```powershell
uv tool install --python 3.13 --find-links $dist --with pyghidra==3.1.0 .\airlock-0.1.0-py3-none-any.whl
airlock init --ghidra $ghidra
airlock doctor --start
```

**Install it with pip in a venv:**

```powershell
py -3.13 -m venv C:\Tools\airlock-venv
C:\Tools\airlock-venv\Scripts\activate
pip install .\airlock-0.1.0-py3-none-any.whl
airlock init --ghidra $ghidra
airlock doctor --fix
airlock doctor --start
```

The MCP command is then `C:\Tools\airlock-venv\Scripts\airlock.exe serve`.

**Machine with no internet.** airlock needs some packages from PyPI: `mcp`, `json5`,
`pefile`, `olefile`, `dnfile`, and their dependencies. On a machine with internet,
download them all to one folder with the same Python version:

```powershell
pip download --only-binary=:all: -d .\wheels .\airlock-0.1.0-py3-none-any.whl
```

Copy the `wheels` folder and the airlock wheel to the other machine. Then install
with no index:

```powershell
pip install --no-index --find-links .\wheels .\airlock-0.1.0-py3-none-any.whl
airlock doctor --fix        # PyGhidra comes from the Ghidra folder, also offline
```

### After the install

`airlock init` writes `%APPDATA%\airlock\config.jsonc`. If `java` is not on your
PATH, set `"jdk_dir"` in that file (for example `"C:/Program Files/Eclipse
Adoptium/jdk-21..."`). Before you register airlock with a client, make sure that
each line of `airlock doctor --start` shows `[OK   ]`.

### Releases

The GitHub workflow `.github/workflows/release.yml` builds the wheel and the
source archive. To publish a release:

1. Change `__version__` in `src/airlock/__init__.py` (for example `0.1.0`) and commit.
2. Create a tag with the same version and a `v` in front: `git tag v0.1.0`.
3. Push the tag: `git push origin v0.1.0`.

The workflow checks that the tag and `__version__` agree. It runs the tests on
Windows, builds the wheel, and starts `airlock --version` from that wheel. Then
it makes a GitHub release with the 2 files. To build the files without a release,
start the workflow by hand (Actions > release > Run workflow). The workflow then
attaches the files to the run as an artifact.

## Register with an MCP client

Claude Code, from a clone (method A):

```powershell
claude mcp add airlock -- C:\path\to\airlock\.venv\Scripts\airlock.exe serve --profile dirty
```

Claude Code, after `uv tool install` (method C):

```powershell
claude mcp add airlock -- airlock serve --profile dirty
```

OpenCode (`opencode.json`), with uvx (method B):

```jsonc
"mcp": {
  "airlock": {
    "type": "local",
    "command": ["uvx", "--python", "3.13",
                "--from", "git+https://github.com/MariusAdrian88/airlock",
                "--find-links", "C:/Tools/ghidra_12.1.4_PUBLIC/Ghidra/Features/PyGhidra/pypkg/dist",
                "--with", "pyghidra==3.1.0",
                "airlock", "serve", "--profile", "dirty"],
    "enabled": true
  }
}
```

After `uv tool install` (method C), the OpenCode command is only
`["airlock", "serve", "--profile", "dirty"]`.

`--profile` picks the role: `dirty` (the default) or `clean`. For clean-room work,
register a second server with `--profile clean` in a **separate** session. The clean
side only ever sees specifications.

