"""Feature index derivation (DESIGN 4 "Project map and feature index"). Server side, no Ghidra.

A fixed table maps API names to feature keys; string patterns add more. Functions that call
those imports or reference matching strings are the seeds of a feature; its entry points are
the seeds plus their callers up to depth 2 inside the project's own binaries (runtime
libraries excluded). Rows live in the index (``feature``, ``feature_entry``); features defined
by the agent (source 'agent') survive every re-derivation. Feature keys never change.
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any

from airlock.index.store import Store
from airlock.projects import ProjectPaths, read_manifest

log = logging.getLogger("airlock")

FEATURES: dict[str, str] = {
    "file-io": "File input/output",
    "config": "Configuration and settings",
    "ui": "User interface",
    "network": "Network and serial communication",
    "hardware": "Hardware and drivers",
    "plugins": "Plugins and dynamic loading",
    "scripting": "Scripting and automation",
    "graphics": "Graphics and imaging",
    "licensing": "Licensing, crypto and time checks",
}
DATA_FORMAT = "data-format:"
MAX_DEPTH = 2
MAX_FANIN = 40        # a function with more callers is a utility: its callers are not followed
MAX_ENTRIES = 3000    # per feature
MAX_EVIDENCE = 4
_CHUNK = 400

_API: dict[str, tuple[str, ...]] = {
    "file-io": (
        "CreateFile CreateFile2 ReadFile ReadFileEx WriteFile WriteFileEx SetFilePointer SetFilePointerEx "
        "GetFileSize GetFileSizeEx GetFileAttributes GetFileAttributesEx SetFileAttributes DeleteFile "
        "MoveFile MoveFileEx CopyFile CopyFileEx FindFirstFile FindFirstFileEx FindNextFile FindClose "
        "CreateFileMapping MapViewOfFile MapViewOfFileEx UnmapViewOfFile FlushFileBuffers SetEndOfFile "
        "GetOpenFileName GetSaveFileName GetOpenFileNameEx SHBrowseForFolder SHGetFileInfo "
        "CreateDirectory RemoveDirectory GetTempPath GetTempFileName GetCurrentDirectory "
        "SetCurrentDirectory GetFullPathName PathFileExists PathFindExtension LockFile UnlockFile "
        "fopen fopen_s _wfopen _wfopen_s fread fwrite fgets fputs fgetc fputc fprintf fscanf fclose fseek "
        "ftell fflush freopen _open _wopen _read _write _close _lseek _sopen _sopen_s _fsopen _wfsopen "
        "_stat _wstat remove _unlink _wremove rename _wrename OpenFile _lopen _lcreat _lread _lwrite "
        "_hread _hwrite ReadDirectoryChangesW"
    ).split(),
    "config": (
        "RegOpenKey RegOpenKeyEx RegCreateKey RegCreateKeyEx RegQueryValue RegQueryValueEx RegSetValue "
        "RegSetValueEx RegDeleteKey RegDeleteValue RegEnumKey RegEnumKeyEx RegEnumValue RegCloseKey "
        "RegGetValue RegSaveKey RegLoadKey RegQueryInfoKey SHGetValue SHSetValue SHDeleteKey "
        "GetPrivateProfileString GetPrivateProfileInt GetPrivateProfileSection GetPrivateProfileStruct "
        "GetPrivateProfileSectionNames WritePrivateProfileString WritePrivateProfileSection "
        "WritePrivateProfileStruct GetProfileInt GetProfileString WriteProfileString "
        "SHGetFolderPath SHGetKnownFolderPath SHGetSpecialFolderPath GetEnvironmentVariable "
        "SetEnvironmentVariable ExpandEnvironmentStrings GetModuleFileName GetUserName GetComputerName "
        "CoCreateInstance_MSXML"
    ).split(),
    "ui": (
        "CreateWindow CreateWindowEx RegisterClass RegisterClassEx DefWindowProc DialogBox DialogBoxParam "
        "DialogBoxIndirect DialogBoxIndirectParam CreateDialog CreateDialogParam CreateDialogIndirect "
        "CreateDialogIndirectParam EndDialog GetMessage PeekMessage DispatchMessage TranslateMessage "
        "PostQuitMessage SendMessage PostMessage SendDlgItemMessage GetDlgItem SetDlgItemText "
        "GetDlgItemText LoadMenu LoadMenuIndirect CreateMenu CreatePopupMenu TrackPopupMenu TrackPopupMenuEx "
        "AppendMenu InsertMenu ModifyMenu EnableMenuItem CheckMenuItem SetMenu GetMenu DestroyMenu "
        "LoadAccelerators TranslateAccelerator LoadIcon LoadCursor LoadString LoadImage MessageBox "
        "MessageBoxEx MessageBoxIndirect ShowWindow UpdateWindow SetWindowText GetWindowText "
        "SetWindowLong SetWindowLongPtr GetWindowLong GetWindowLongPtr CreateToolbarEx InitCommonControls "
        "InitCommonControlsEx CreateStatusWindow SetTimer KillTimer DrawText DrawTextEx TextOut "
        "BeginPaint EndPaint InvalidateRect RedrawWindow SetFocus SetCapture ReleaseCapture "
        "GetCursorPos SetCursorPos ChooseColor ChooseFont PropertySheet CreatePropertySheetPage"
    ).split(),
    "network": (
        "socket connect bind listen accept send recv sendto recvfrom select closesocket shutdown "
        "gethostbyname gethostbyaddr getaddrinfo freeaddrinfo getpeername getsockname getsockopt setsockopt "
        "ioctlsocket inet_addr inet_ntoa htons htonl ntohs ntohl WSAStartup WSACleanup WSASocket "
        "WSAConnect WSASend WSARecv WSAEventSelect WSAAsyncSelect WSAGetLastError WSAIoctl "
        "InternetOpen InternetOpenUrl InternetConnect InternetReadFile InternetWriteFile "
        "InternetCloseHandle HttpOpenRequest HttpSendRequest HttpQueryInfo InternetSetOption "
        "InternetCrackUrl FtpOpenFile FtpGetFile FtpPutFile URLDownloadToFile URLDownloadToCacheFile "
        "WinHttpOpen WinHttpConnect WinHttpOpenRequest WinHttpSendRequest WinHttpReceiveResponse "
        "WinHttpReadData WinHttpQueryHeaders WinHttpCloseHandle "
        "GetCommState SetCommState GetCommTimeouts SetCommTimeouts SetupComm PurgeComm EscapeCommFunction "
        "WaitCommEvent GetCommModemStatus ClearCommError BuildCommDCB"
    ).split(),
    "hardware": (
        "DeviceIoControl SetupDiGetClassDevs SetupDiEnumDeviceInterfaces SetupDiGetDeviceInterfaceDetail "
        "SetupDiEnumDeviceInfo SetupDiGetDeviceRegistryProperty SetupDiDestroyDeviceInfoList "
        "SetupDiOpenDevRegKey HidD_GetHidGuid HidD_GetAttributes HidD_GetFeature HidD_SetFeature "
        "HidD_GetPreparsedData HidD_FreePreparsedData HidD_GetProductString HidD_GetManufacturerString "
        "HidD_GetSerialNumberString HidD_GetInputReport HidD_SetOutputReport HidP_GetCaps "
        "OpenSCManager OpenService CreateService StartService ControlService DeleteService "
        "QueryServiceStatus _inp _outp _inpw _outpw _inpd _outpd inp outp "
        "NtLoadDriver ZwLoadDriver CM_Get_Device_ID CM_Locate_DevNode GetRawInputData "
        "RegisterRawInputDevices GetRawInputDeviceList WinUsb_Initialize WinUsb_ReadPipe WinUsb_WritePipe "
        "WinUsb_ControlTransfer QueryDosDevice GetLogicalDrives GetDriveType GetDiskFreeSpace "
        "GetDiskFreeSpaceEx midiOutOpen midiInOpen waveOutOpen waveInOpen joyGetPos joyGetPosEx"
    ).split(),
    "plugins": (
        "LoadLibrary LoadLibraryEx GetProcAddress FreeLibrary GetModuleHandle GetModuleHandleEx "
        "CoCreateInstance CoCreateInstanceEx CoGetClassObject CoInitialize CoInitializeEx DllGetClassObject "
        "DllRegisterServer DllCanUnloadNow CLSIDFromProgID CLSIDFromString ProgIDFromCLSID "
        "OleCreate OleLoadFromStream LdrLoadDll LdrGetProcedureAddress SetDllDirectory AddDllDirectory "
        "SearchPath"
    ).split(),
    "scripting": (
        "CreateObject GetObject VariantInit VariantClear SysAllocString SysFreeString "
        "OleInitialize OleRun OleUninitialize DispInvoke DispGetIDsOfNames LoadTypeLib LoadTypeLibEx "
        "LoadRegTypeLib CreateStdDispatch GetActiveObject Py_Initialize Py_Finalize PyRun_SimpleString "
        "PyRun_String PyImport_ImportModule lua_newstate luaL_newstate luaL_loadfile luaL_loadstring "
        "luaL_openlibs lua_pcall lua_pcallk JS_NewRuntime JS_NewContext duk_create_heap_default"
    ).split(),
    "graphics": (
        "BitBlt StretchBlt StretchDIBits SetDIBitsToDevice SetDIBits GetDIBits CreateCompatibleDC "
        "CreateCompatibleBitmap CreateDIBSection CreateBitmap CreateBitmapIndirect CreatePalette "
        "RealizePalette SelectPalette SelectObject DeleteObject DeleteDC GetDC ReleaseDC CreateDC "
        "CreateFontIndirect CreateFont CreatePen CreateSolidBrush SetBkMode SetStretchBltMode "
        "AlphaBlend TransparentBlt MaskBlt PlgBlt PatBlt LineTo MoveToEx Polyline Polygon Rectangle "
        "Ellipse FillRect GdiFlush SwapBuffers ChoosePixelFormat SetPixelFormat DescribePixelFormat "
        "Direct3DCreate9 Direct3DCreate8 D3D11CreateDevice D3D11CreateDeviceAndSwapChain "
        "CreateDXGIFactory CreateDXGIFactory1 DirectDrawCreate DirectDrawCreateEx DirectDrawCreateClipper "
        "GdiplusStartup GdipCreateBitmapFromFile GdipLoadImageFromFile GdipDrawImageI GdipDrawImageRectI "
        "GdipSaveImageToFile OleLoadPicture OleLoadPicturePath ImageList_Create ImageList_Draw "
        "ImageList_Add DrawIcon DrawIconEx DrawDibDraw DrawDibOpen"
    ).split(),
    "licensing": (
        "CryptAcquireContext CryptCreateHash CryptHashData CryptDeriveKey CryptEncrypt CryptDecrypt "
        "CryptGenKey CryptGenRandom CryptImportKey CryptExportKey CryptSignHash CryptVerifySignature "
        "CryptDestroyKey CryptDestroyHash CryptGetHashParam CryptReleaseContext CryptStringToBinary "
        "CryptBinaryToString CryptProtectData CryptUnprotectData CertOpenStore CertFindCertificateInStore "
        "BCryptOpenAlgorithmProvider BCryptCreateHash BCryptHashData BCryptFinishHash BCryptEncrypt "
        "BCryptDecrypt BCryptGenerateSymmetricKey BCryptGenRandom BCryptDeriveKey BCryptCloseAlgorithmProvider "
        "GetSystemTime GetLocalTime GetSystemTimeAsFileTime SystemTimeToFileTime FileTimeToSystemTime "
        "GetTickCount GetTickCount64 QueryPerformanceCounter time _time64 _time32 localtime gmtime difftime "
        "GetVolumeInformation GetAdaptersInfo GetAdaptersAddresses GetComputerNameEx GetSystemFirmwareTable "
        "IsDebuggerPresent CheckRemoteDebuggerPresent GetUserDefaultLCID MD5Init MD5Update MD5Final "
        "SHA1Init A_SHAInit A_SHAUpdate A_SHAFinal"
    ).split(),
}

# Names whose A/W/Ex suffix variants are covered by the base name (see ``api_feature``).
API_FEATURE: dict[str, str] = {name: key for key, names in _API.items() for name in names}
# Ambiguous names resolved to the first listed feature (CoCreateInstance is plugins, not config).
API_FEATURE.pop("CoCreateInstance_MSXML", None)

# (prefix, feature, case-sensitive match on the cleaned name)
API_PREFIX: tuple[tuple[str, str], ...] = (
    ("wgl", "graphics"), ("glu", "graphics"), ("gl", "graphics"), ("glut", "graphics"),
    ("WSA", "network"), ("Internet", "network"), ("WinHttp", "network"), ("Http", "network"),
    ("SetupDi", "hardware"), ("HidD_", "hardware"), ("HidP_", "hardware"), ("WinUsb_", "hardware"),
    ("CM_", "hardware"), ("BCrypt", "licensing"), ("Crypt", "licensing"), ("Cert", "licensing"),
    ("Gdip", "graphics"), ("ImageList_", "graphics"), ("Direct3D", "graphics"), ("D3D", "graphics"),
    ("DirectDraw", "graphics"), ("DXGI", "graphics"),
    ("RegOpen", "config"), ("RegCreate", "config"), ("RegQuery", "config"), ("RegSet", "config"),
    ("RegDelete", "config"), ("RegEnum", "config"), ("RegClose", "config"), ("RegGet", "config"),
    ("RegSave", "config"), ("RegLoad", "config"), ("RegFlush", "config"),
    ("CFile::", "file-io"), ("CStdioFile::", "file-io"), ("CMemFile::", "file-io"),
    ("CArchive::", "file-io"), ("CFileDialog::", "file-io"), ("CFileFind::", "file-io"),
    ("CRecentFileList::", "file-io"), ("CRegKey::", "config"), ("CWinApp::GetProfile", "config"),
    ("CWinApp::WriteProfile", "config"), ("CWinApp::SetRegistryKey", "config"),
    ("CWnd::", "ui"), ("CDialog::", "ui"), ("CFrameWnd::", "ui"), ("CMenu::", "ui"),
    ("CView::", "ui"), ("CDocument::", "ui"), ("CPropertySheet::", "ui"), ("CPropertyPage::", "ui"),
    ("CSocket::", "network"), ("CAsyncSocket::", "network"), ("CInternetSession::", "network"),
    ("CHttpFile::", "network"), ("CDC::", "graphics"), ("CBitmap::", "graphics"),
    ("CBrush::", "graphics"), ("CPen::", "graphics"),
)
# gl*/glu*/glut* only when followed by an uppercase letter (glBegin, not global).
_GL_RE = re.compile(r"^(?:wgl|glu|glut|gl)[A-Z]")
_NOISE = ("__imp_", "_imp__", "imp_")


def clean_api(name: str) -> str:
    """Strip import decoration: ``__imp_ReadFile`` / ``_ReadFile@12`` -> ``ReadFile``."""
    n = name.strip()
    for p in _NOISE:
        if n.startswith(p):
            n = n[len(p):]
            break
    if n.startswith("_") and n[1:2].isupper():
        n = n[1:]
    if "@" in n and not n.startswith("@"):
        n = n.split("@", 1)[0]
    return n


def api_feature(name: str | None) -> str | None:
    """Feature key for an imported/library function name, or None."""
    if not name:
        return None
    n = clean_api(name)
    key = API_FEATURE.get(n)
    if key:
        return key
    if n and n[-1] in "AW" and (key := API_FEATURE.get(n[:-1])):
        return key
    if n.endswith(("ExA", "ExW")) and (key := API_FEATURE.get(n[:-3])):
        return key
    for pre, feat in API_PREFIX:
        if n.startswith(pre):
            if pre in ("wgl", "glu", "glut", "gl"):
                if _GL_RE.match(n):
                    return feat
                continue
            return feat
    return None


# -- strings ---------------------------------------------------------------------

_FILTER = re.compile(r"\*\.[A-Za-z0-9?*]{1,8}")
_PATH_ABS = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\[\w.?$-]+\\|%\w+%[\\/])")
_PATH_REL = re.compile(r"^[\w .-]+[\\/][\w .\\/-]*\.[A-Za-z0-9]{1,5}$")
_REGISTRY = re.compile(r"(?:^|[\\/])Software[\\/]|^HKEY_|^SOFTWARE\\|CurrentVersion", re.I)
_CONFIG_FILE = re.compile(r"\.(?:ini|cfg|conf|config|reg|inf)(?![A-Za-z0-9])", re.I)
_URL = re.compile(r"\b(?:https?|ftp|wss?|tcp|udp|smtp)://", re.I)
_COM_PORT = re.compile(r"^(?:\\\\\.\\)?COM\d{1,3}(?::.*)?$|\bCOM\d+\b", re.I)
_DEVICE = re.compile(r"^\\\\\.\\[\w$-]+|^\\\\\?\\|\\Device\\|\\DosDevices\\", re.I)
_PLUGIN = re.compile(r"(?:^|[\\/])plug-?ins?[\\/]|\.(?:dll|ocx|flt|plg|addin)(?![A-Za-z0-9])", re.I)
_SCRIPT = re.compile(r"\.(?:vbs|vbe|wsf|js|jse|py|lua|bas|cmd|bat|ps1|macro|mac)(?![A-Za-z0-9])|"
                     r"\b(?:VBScript|JScript|WScript|Scripting\.FileSystemObject)\b", re.I)
_IMAGE = re.compile(r"\.(?:bmp|png|jpe?g|gif|tiff?|ico|cur|tga|dds|pcx|wmf|emf)(?![A-Za-z0-9])", re.I)
_LICENSE = re.compile(r"licen[cs]|serial number|activation|registration key|product key|"
                      r"\btrial\b|evaluation|expire|dongle|hardware key", re.I)


def _short(value: str, n: int = 40) -> str:
    s = value.replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    return '"' + (s[: n - 1] + "…" if len(s) > n else s) + '"'


def _ext_regex(ext: str) -> re.Pattern[str]:
    return re.compile(r"\." + re.escape(ext) + r"(?![A-Za-z0-9])", re.I)


def string_features(value: str, ext_rx: dict[str, re.Pattern[str]] | None = None) -> list[str]:
    """Feature keys one string points to (possibly several, deduplicated, stable order)."""
    if len(value) < 4:
        return []
    out: list[str] = []

    def add(k: str) -> None:
        if k not in out:
            out.append(k)

    if _FILTER.search(value) or _PATH_ABS.search(value) or _PATH_REL.search(value):
        add("file-io")
    if _REGISTRY.search(value) or _CONFIG_FILE.search(value):
        add("config")
    if _URL.search(value) or _COM_PORT.search(value):
        add("network")
    if _DEVICE.search(value):
        add("hardware")
    if _PLUGIN.search(value):
        add("plugins")
    if _SCRIPT.search(value):
        add("scripting")
    if _IMAGE.search(value):
        add("graphics")
    if _LICENSE.search(value):
        add("licensing")
    for ext, rx in (ext_rx or {}).items():
        if rx.search(value):
            add(DATA_FORMAT + ext)
    return out


def feature_title(key: str) -> str:
    if key in FEATURES:
        return FEATURES[key]
    if key.startswith(DATA_FORMAT):
        return f"Data format .{key[len(DATA_FORMAT):]}"
    return key


def feature_order(key: str) -> tuple[int, str]:
    keys = list(FEATURES)
    return (keys.index(key), "") if key in keys else (len(keys), key)


# -- project inputs ----------------------------------------------------------------

def manifest_inputs(pp: ProjectPaths, store: Store,
                    man: dict[str, Any] | None = None) -> tuple[set[int], list[str]]:
    """(binary ids of runtime-group binaries, data-file extensions) from the manifest scan.
    ``man``: an already parsed manifest (parsing JSONC is slow, callers share one)."""
    if man is None:
        try:
            man = read_manifest(pp.manifest)
        except (OSError, ValueError):
            return set(), []
    files = [f for f in man.get("files") or [] if isinstance(f, dict)]
    rt_sha = {f.get("sha256") for f in files if f.get("group") == "runtime" and f.get("sha256")}
    rt_name = {PurePosixPath(str(f.get("path", "")).replace("\\", "/")).name.lower()
               for f in files if f.get("group") == "runtime"}
    runtime = {b.id for b in store.list_binaries() if b.sha256 in rt_sha or b.name.lower() in rt_name}
    exts: list[str] = []
    for f in files:
        if f.get("kind") == "data":
            e = PurePosixPath(str(f.get("path", "")).replace("\\", "/")).suffix.lower().lstrip(".")
            if 1 <= len(e) <= 8 and e.isalnum() and e not in exts:
                exts.append(e)
    return runtime, sorted(exts)


# -- derivation ------------------------------------------------------------------------

class _Bin:
    """Per-binary lookup tables used while deriving."""

    def __init__(self, store: Store, binary_id: int) -> None:
        self.id = binary_id
        self.fn: dict[int, tuple[str, int, str, bool]] = {}      # id -> (space, entry, qname, skip)
        self.at: dict[tuple[str, int], int] = {}
        self.names: dict[int, str] = {}
        for r in store.db.execute(
                "SELECT id, space, entry, name, namespace, is_thunk, is_external FROM function "
                "WHERE binary_id=?", (binary_id,)):
            q = f"{r['namespace']}::{r['name']}" if r["namespace"] else r["name"]
            self.fn[r["id"]] = (r["space"], r["entry"], q, bool(r["is_thunk"] or r["is_external"]))
            self.at[(r["space"], r["entry"])] = r["id"]
        self.callers = store.callers_of_ids(binary_id)
        self.thunk_ids = {i for i, v in self.fn.items() if v[3]}


def _edge_sources(store: Store, binary_id: int, addrs: Iterable[int],
                  kinds: tuple[str, ...]) -> dict[int, set[int]]:
    """{dst address: source function ids} for edges of these kinds into the addresses."""
    out: dict[int, set[int]] = {}
    todo = sorted(set(addrs))
    marks = ",".join("?" * len(kinds))
    for i in range(0, len(todo), _CHUNK):
        part = todo[i:i + _CHUNK]
        q = ("SELECT src_fn, dst_addr FROM edge WHERE binary_id=? AND src_fn IS NOT NULL AND "
             f"kind IN ({marks}) AND dst_addr IN ({','.join('?' * len(part))})")
        for r in store.db.execute(q, [binary_id, *kinds, *part]):
            out.setdefault(r["dst_addr"], set()).add(r["src_fn"])
    return out


def _cross_callers(store: Store, bins: dict[int, _Bin], binary_id: int, entry: int) -> set[tuple[int, int]]:
    """Functions of other (non-runtime) binaries that call this exported function through an
    import slot or thunk: {(binary id, function id)}."""
    found: set[tuple[int, int]] = set()
    for r in store.db.execute("SELECT src_binary, src_addr FROM xedge WHERE dst_binary=? AND dst_entry=?",
                              (binary_id, entry)):
        sb = bins.get(r["src_binary"])
        if sb is None:
            continue
        for fid in _edge_sources(store, sb.id, [r["src_addr"]], ("call", "call_ind", "jump")).get(
                r["src_addr"], ()):
            found.add((sb.id, fid))
        tid = sb.at.get(("ram", r["src_addr"]))
        if tid is not None:
            found.update((sb.id, c) for c in sb.callers.get(tid, ()))
    return found


def derive(store: Store, runtime_ids: Iterable[int] = (), data_exts: Iterable[str] = (),
           now: str | None = None) -> dict[str, int]:
    """Rebuild the auto features of a project index. Returns {feature key: entry points}."""
    runtime = set(runtime_ids)
    ext_rx = {e: _ext_regex(e) for e in data_exts}
    bins = {b.id: _Bin(store, b.id) for b in store.list_binaries() if b.id not in runtime}
    # seeds[key][(bid, fid)] = list of evidence labels (calls X / refs "s")
    seeds: dict[str, dict[tuple[int, int], list[str]]] = {}
    summary: dict[str, Counter[str]] = {}

    def seed(key: str, bid: int, fid: int, reason: str, label: str) -> None:
        ev = seeds.setdefault(key, {}).setdefault((bid, fid), [])
        if reason not in ev:
            ev.append(reason)
        summary.setdefault(key, Counter())[label] += 1

    for bid, bn in bins.items():
        # API seeds: callers of import slots, thunks and recognised library functions.
        targets: dict[int, tuple[str, str]] = {}      # address -> (feature, api name)
        for r in store.db.execute("SELECT name, address FROM import WHERE binary_id=? AND name IS NOT NULL "
                                  "AND address IS NOT NULL", (bid,)):
            k = api_feature(r["name"])
            if k:
                targets[r["address"]] = (k, clean_api(r["name"]))
        for fid, (space, entry, q, skip) in bn.fn.items():
            if space != "ram":
                continue
            k = api_feature(q)
            if k and (skip or "::" in q) and entry not in targets:
                targets[entry] = (k, clean_api(q))
        for addr, srcs in _edge_sources(store, bid, targets, ("call", "call_ind", "jump")).items():
            key, api = targets[addr]
            for fid in srcs:
                if fid not in bn.thunk_ids:
                    seed(key, bid, fid, f"calls {api}", api)
        # string seeds
        hits: dict[int, list[tuple[str, str]]] = {}
        for r in store.db.execute("SELECT address, value FROM string WHERE binary_id=?", (bid,)):
            for k in string_features(r["value"], ext_rx):
                hits.setdefault(r["address"], []).append((k, _short(r["value"])))
        for addr, srcs in _edge_sources(store, bid, hits, ("read", "write", "data")).items():
            for k, lab in hits[addr]:
                for fid in srcs:
                    if fid not in bn.thunk_ids:
                        seed(k, bid, fid, f"refs {lab}", lab)
        # a data-format extension that appears in strings is a feature even when no code refs it
        for addr, lst in hits.items():
            for k, lab in lst:
                if k.startswith(DATA_FORMAT):
                    seeds.setdefault(k, {})
                    summary.setdefault(k, Counter())[lab] += 0

    rows: list[tuple[str, int, str, int, str, str, int]] = []
    feats: list[tuple[str, str, str]] = []
    counts: dict[str, int] = {}
    for key in sorted(seeds, key=feature_order):
        got: dict[tuple[int, int], tuple[str, list[str], int]] = {
            ref: (ev[0], ev, 0) for ref, ev in seeds[key].items()}
        frontier = list(got)
        for depth in range(1, MAX_DEPTH + 1):
            nxt: list[tuple[int, int]] = []
            for bid, fid in frontier:
                bn = bins[bid]
                space, entry, qn, _skip = bn.fn[fid]
                cs = {(bid, c) for c in bn.callers.get(fid, ())}
                if len(cs) > MAX_FANIN:
                    continue
                cs |= _cross_callers(store, bins, bid, entry) if space == "ram" else set()
                if len(cs) > MAX_FANIN:
                    continue
                inherited = got[(bid, fid)][1][:MAX_EVIDENCE]
                for cb, cf in sorted(cs):
                    if (cb, cf) in got or cf in bins[cb].thunk_ids or len(got) >= MAX_ENTRIES:
                        continue
                    got[(cb, cf)] = (f"caller of {qn}", inherited, depth)
                    nxt.append((cb, cf))
            frontier = nxt
        for (bid, fid), (reason, ev, depth) in got.items():
            space, entry, _q, _s = bins[bid].fn[fid]
            rows.append((key, bid, space, entry, reason, " ; ".join(ev[:MAX_EVIDENCE]), depth))
        counts[key] = len(got)
        top = ", ".join(f"{lab} x{n}" if n > 1 else lab
                        for lab, n in summary.get(key, Counter()).most_common(6))
        feats.append((key, feature_title(key), top))
    store.replace_auto_features(feats, rows, now or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    return counts


def derive_project(pp: ProjectPaths, store: Store, man: dict[str, Any] | None = None) -> dict[str, int]:
    runtime, exts = manifest_inputs(pp, store, man)
    return derive(store, runtime, exts)


# -- coverage ---------------------------------------------------------------------------

def coverage(n: int, named: int) -> str:
    return f"{named}/{n}" + (f" ({100 * named // n}%)" if n else "")


def stats(store: Store) -> list[dict[str, Any]]:
    """Features in display order: key, title, source, topics, n, named."""
    rows = [dict(r) for r in store.feature_stats()]
    rows.sort(key=lambda r: feature_order(r["key"]))
    return rows
