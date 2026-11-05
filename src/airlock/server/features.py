"""Feature index derivation (DESIGN 4 "Project map and feature index"). Server side, no Ghidra.

A fixed table maps API names to feature keys; string patterns add more. Functions that call
those imports or reference matching strings are the seeds of a feature; its entry points are
the seeds plus their callers up to depth 2 inside the project's own binaries (runtime
libraries and library functions excluded: they are evidence, not entry points). Rows live in the index (``feature``, ``feature_entry``); features defined
by the agent (source 'agent') survive every re-derivation. Feature keys never change.
"""

from __future__ import annotations

import json
import logging
import re
from collections import Counter
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any

from airlock.index.store import CODE_EDGES, Store
from airlock.projects import ProjectPaths, read_manifest
from airlock.server import delphi
from airlock.server.uijoin import UiIndex

log = logging.getLogger("airlock")

FEATURES: dict[str, str] = {
    "file-io": "File input/output",
    "config": "Configuration and settings",
    "ui-window": "User interface: window lifecycle and message loop",
    "ui-controls": "User interface: control text, state and messages",
    "ui-dialog": "User interface: dialogs and message boxes",
    "ui-menu": "User interface: menus and accelerators",
    "ui-draw": "User interface: 2D drawing (GDI)",
    "ui-input": "User interface: keyboard, mouse, cursor and timers",
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
MAX_ENTRIES = 1500    # per feature; strong seeds first (strongest evidence), then callers by depth
FEATURES_VERSION = 6  # 6: Delphi DFM event handlers seed ui-menu / ui-dialog; 5: framework range / runtime message map entries no longer seed ui features; 4: ui-menu / ui-dialog seeds from message map handlers of menu items and dialog controls; 3: CRT underscore rule needs a known CRT name; meta key FEATURES_VERSION_META; a project derived by an older version is derived again on open
FEATURES_VERSION_META = "features_version"
DROPPED_META = "feature_dropped"   # JSON {feature key: entry points cut by MAX_ENTRIES}
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
    "ui-window": (
        "CreateWindow CreateWindowEx RegisterClass RegisterClassEx UnregisterClass DefWindowProc "
        "DefMDIChildProc DefFrameProc CallWindowProc DestroyWindow MoveWindow SetWindowPos FindWindow "
        "FindWindowEx SetParent GetMessage PeekMessage DispatchMessage TranslateMessage PostQuitMessage "
        "CreateToolbarEx InitCommonControls InitCommonControlsEx CreateStatusWindow "
        "PropertySheet CreatePropertySheetPage LoadString LoadIcon LoadImage SetForegroundWindow"
    ).split(),
    "ui-controls": (
        "SendMessage PostMessage SetWindowText GetWindowText ShowWindow EnableWindow SetFocus "
        "SetWindowLong SetWindowLongPtr GetWindowLong GetWindowLongPtr InvalidateRect RedrawWindow "
        "UpdateWindow GetParent GetClientRect GetWindowRect SetActiveWindow BringWindowToTop"
    ).split(),
    "ui-dialog": (
        "DialogBox DialogBoxParam DialogBoxIndirect DialogBoxIndirectParam CreateDialog CreateDialogParam "
        "CreateDialogIndirect CreateDialogIndirectParam EndDialog IsDialogMessage DefDlgProc GetDlgItem "
        "SetDlgItemText GetDlgItemText GetDlgItemInt SetDlgItemInt SendDlgItemMessage CheckDlgButton "
        "IsDlgButtonChecked CheckRadioButton MessageBox MessageBoxEx MessageBoxIndirect ChooseColor "
        "ChooseFont PrintDlg PageSetupDlg FindText ReplaceText"
    ).split(),
    "ui-menu": (
        "LoadMenu LoadMenuIndirect CreateMenu CreatePopupMenu TrackPopupMenu TrackPopupMenuEx AppendMenu "
        "InsertMenu ModifyMenu DeleteMenu RemoveMenu EnableMenuItem CheckMenuItem CheckMenuRadioItem "
        "SetMenu GetMenu GetSubMenu GetMenuItemCount GetMenuItemInfo SetMenuItemInfo InsertMenuItem "
        "DestroyMenu LoadAccelerators TranslateAccelerator CreateAcceleratorTable"
    ).split(),
    "ui-draw": (
        "DrawText DrawTextEx TextOut ExtTextOut BeginPaint EndPaint BitBlt StretchBlt StretchDIBits "
        "CreateCompatibleDC CreateCompatibleBitmap CreateBitmap CreateBitmapIndirect SelectObject "
        "DeleteObject DeleteDC GetDC GetWindowDC ReleaseDC CreateDC CreateFontIndirect CreateFont "
        "CreatePen CreatePenIndirect CreateSolidBrush CreateHatchBrush CreatePatternBrush SetBkMode "
        "SetBkColor SetTextColor SetStretchBltMode AlphaBlend TransparentBlt MaskBlt PlgBlt PatBlt "
        "LineTo MoveToEx Polyline Polygon Rectangle RoundRect Ellipse Arc Pie FillRect FrameRect "
        "InvertRect SetPixel GetPixel SetROP2 SetMapMode GetTextExtentPoint GetTextExtentPoint32 "
        "GetTextMetrics GetStockObject GdiFlush"
    ).split(),
    "ui-input": (
        "SetTimer KillTimer GetCursorPos SetCursorPos SetCursor LoadCursor ShowCursor ClipCursor "
        "SetCapture ReleaseCapture GetCapture GetKeyState GetAsyncKeyState GetKeyboardState "
        "SetKeyboardState MapVirtualKey MapVirtualKeyEx VkKeyScan ToAscii ToUnicode keybd_event "
        "mouse_event SendInput RegisterHotKey UnregisterHotKey TrackMouseEvent GetDoubleClickTime "
        "GetKeyboardLayout GetKeyNameText"
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
        "SetDIBitsToDevice SetDIBits GetDIBits CreateDIBSection CreatePalette RealizePalette "
        "SelectPalette SwapBuffers ChoosePixelFormat SetPixelFormat DescribePixelFormat "
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
    ("CWnd::", "ui-window"), ("CFrameWnd::", "ui-window"), ("CView::", "ui-window"),
    ("CDocument::", "ui-window"), ("CDialog::", "ui-dialog"), ("CPropertySheet::", "ui-dialog"),
    ("CPropertyPage::", "ui-dialog"), ("CMenu::", "ui-menu"),
    ("CSocket::", "network"), ("CAsyncSocket::", "network"), ("CInternetSession::", "network"),
    ("CHttpFile::", "network"), ("CDC::", "ui-draw"), ("CBitmap::", "ui-draw"),
    ("CBrush::", "ui-draw"), ("CPen::", "ui-draw"), ("CFont::", "ui-draw"),
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


# -- weak (ubiquitous) evidence ------------------------------------------------------------------
# A weak seed is listed as an entry point but its callers are not followed: the call says nothing
# about the function's role (every CWnd-derived destructor calls ~CWnd, every dialog handler calls
# GetDlgItem or SendMessage). Strong seeds (window creation, class registration, window procedures,
# dialog/menu/drawing calls that define the code) expand to callers as before.
WEAK_API = frozenset(
    "LoadString LoadIcon LoadImage GetDlgItem SetDlgItemText GetDlgItemText GetDlgItemInt SetDlgItemInt "
    "SendDlgItemMessage CheckDlgButton IsDlgButtonChecked CheckRadioButton GetDC GetWindowDC ReleaseDC "
    "SelectObject DeleteObject DeleteDC GetStockObject SetBkMode SetBkColor SetTextColor SetCursor "
    "LoadCursor GetCursorPos GetKeyState GetAsyncKeyState ShowCursor SetCapture ReleaseCapture "
    "GetCapture".split())
# MFC methods that are plumbing for any class (weak wherever they appear)
_WEAK_MEMBERS = frozenset(
    "FromHandle FromHandlePermanent Default Attach Detach Delete InvokeHelper SetProperty GetProperty "
    "SendChildNotifyLastMsg PrepareForHelp GetOwner SelectObject SelectGdiObject SetBkMode SetBkColor "
    "SetTextColor GetSafeHwnd AssertValid Dump GetRuntimeClass".split())
# CWnd methods that create, destroy or subclass a window: strong ui-window evidence
_CWND_STRONG = frozenset(
    "Create CreateEx PreCreateWindow DestroyWindow WindowProc DefWindowProc SubclassWindow SubclassDlgItem "
    "UnsubclassWindow CreateControl CreateDlg CreateDlgIndirect PostNcDestroy OnCreate OnDestroy OnNcDestroy "
    "OnClose MoveWindow SetWindowPos SetParent RunModalLoop ContinueModal PreSubclassWindow OnWndMsg".split())
# CWnd methods that read or change the state of a control: ui-controls (always weak)
_CWND_CONTROL = frozenset(
    "ShowWindow EnableWindow SetFocus GetFocus GetWindowText GetWindowTextLength SetWindowText GetDlgItem "
    "GetDlgCtrlID GetDlgItemText SetDlgItemText IsWindowEnabled IsWindowVisible GetWindowRect GetClientRect "
    "ScreenToClient ClientToScreen Invalidate InvalidateRect UpdateWindow RedrawWindow GetParent "
    "GetTopLevelParent GetTopLevelFrame GetExStyle GetStyle ModifyStyle ModifyStyleEx SetFont GetFont "
    "SendMessage PostMessage SendDlgItemMessage GetDescendantWindow GetWindowPlacement SetWindowPlacement "
    "IsWindow IsIconic IsZoomed CenterWindow BringWindowToTop SetActiveWindow".split())


def api_class(name: str | None) -> tuple[str, bool] | None:
    """(feature key, weak) for an imported/library function name, or None. ``weak``: ubiquitous
    evidence that lists the caller but does not expand to its callers."""
    key = api_feature(name)
    if not key or not name:
        return None
    n = clean_api(name)
    if "::" in n:
        cls, _, meth = n.rpartition("::")
        simple = cls.rsplit("::", 1)[-1]
        if meth == simple or meth == "~" + simple:      # constructor / destructor
            return key, True
        if meth not in _CWND_STRONG | _CWND_CONTROL | _WEAK_MEMBERS and meth[-1:] in ("A", "W"):
            meth = meth[:-1]                            # GetWindowTextA -> GetWindowText
        if n.startswith("CWnd::"):
            if meth in _CWND_STRONG:
                return "ui-window", False
            if meth in _CWND_CONTROL:
                return "ui-controls", True
            return key, True
        return key, meth in _WEAK_MEMBERS
    base = n
    if base not in API_FEATURE:
        base = n[:-1] if n[-1:] in ("A", "W") and n[:-1] in API_FEATURE else             n[:-3] if n.endswith(("ExA", "ExW")) and n[:-3] in API_FEATURE else n
    return key, key == "ui-controls" or base in WEAK_API


# -- library (runtime) code recognition ---------------------------------------------------------
# A function is library code when its name_state is 'library', its name/namespace matches a known
# runtime family, or (propagation) it is only called from library code and calls only library code.
# Names the user or agent set (name_state 'user') are never matched by pattern.

MFC_CLASSES = frozenset(
    "CObject CCmdTarget CWnd CFrameWnd CMDIFrameWnd CMDIChildWnd CView CScrollView CFormView CEditView "
    "CListView CTreeView CRichEditView CDocument CDocTemplate CSingleDocTemplate CMultiDocTemplate "
    "CWinApp CWinThread CDialog CPropertySheet CPropertyPage CCommonDialog CFileDialog CColorDialog "
    "CFontDialog CString CStringArray CStringList CByteArray CDWordArray CPtrArray CPtrList CObArray "
    "CObList CMapStringToPtr CMapStringToString CMapPtrToPtr CMapWordToPtr CArchive CFile CStdioFile "
    "CMemFile CFileFind CException CFileException CMemoryException CArchiveException CUserException "
    "CNotSupportedException CResourceException COleException CDC CClientDC CPaintDC CWindowDC CMetaFileDC "
    "CGdiObject CBitmap CBrush CPen CFont CPalette CRgn CMenu CImageList CToolBar CStatusBar CDialogBar "
    "CControlBar CReBar CButton CEdit CListBox CComboBox CStatic CScrollBar CListCtrl CTreeCtrl "
    "CTabCtrl CSliderCtrl CSpinButtonCtrl CProgressCtrl CToolTipCtrl CHeaderCtrl CRichEditCtrl "
    "CAnimateCtrl CDateTimeCtrl CMonthCalCtrl CComboBoxEx CSplitterWnd CTime CTimeSpan CPoint CSize "
    "CRect CCriticalSection CMutex CEvent CSemaphore CSingleLock CMultiLock CSyncObject CRuntimeClass "
    "CCmdUI CDataExchange CDocManager CRecentFileList CSocket CAsyncSocket CSocketFile "
    "CInternetSession CHttpFile CInternetFile CFtpConnection CHttpConnection CDatabase CRecordset "
    "CDaoDatabase CDaoRecordset COleDispatchDriver COleControl COleDataObject COleDataSource "
    "COleVariant COleSafeArray COleDocument COleServerDoc COleClientItem CDockState CHandleMap "
    "CPlex CDumpContext CMemoryState CWaitCursor CTypedPtrList CTypedPtrArray CTypedPtrMap "
    "CRegKey CBitmapButton CHotKeyCtrl CIPAddressCtrl CDialogEx COleControlSite COccManager COleControlContainer "
    "CDockContext CDockBar CMiniFrameWnd CMiniDockFrameWnd COleMessageFilter COleDropTarget COleDropSource "
    "COleDialog COleBusyDialog CPrintDialog CPrintingDialog CPrintInfo COleResizeBar CFindReplaceDialog "
    "COleInsertDialog COlePropertyPage COleStreamFile COleFrameHook COleIPFrameWnd CMiniDockFrameWnd "
    "CControlBarInfo CCreateContext CBasePane CFileStatus CLongBinary CArchiveStream".split())
_CRT_PLAIN = frozenset(
    "malloc free calloc realloc memcpy memmove memset memcmp memchr strlen strcpy strncpy strcat strncat "
    "strcmp strncmp strchr strrchr strstr strtok strtol strtoul strtod atoi atol atof sprintf snprintf "
    "vsprintf printf vprintf sscanf scanf puts putchar getchar qsort bsearch abs labs exit abort atexit "
    "toupper tolower isalpha isdigit isspace isalnum isupper islower isxdigit ispunct sin cos tan atan "
    "atan2 sqrt pow exp log log10 floor ceil fabs fmod rand srand setjmp longjmp signal raise getenv "
    "wcslen wcscpy wcscmp wcscat wcsncpy wcschr wcsstr swprintf vswprintf".split())
_CRT_RE = re.compile(r"^(?:__crt|__security_|__SEH_|__except|__CxxFrame|__CxxThrow|__local_unwind|"
                     r"__global_unwind|__alloca|__chkstk|__aullrem|__aulldiv|__allmul|__alldiv|__allrem|"
                     r"__ftol|__CIpow|__CI[a-z]|__unwind|__NLG|__EH|__amsg|__cinit|__initterm|"
                     r"__onexit|__dllonexit|__setargv|__mtinit|__heap|__sbh|__lock|__unlock|"
                     r"_EH|_CxxThrow|_SEH|_except_|_unwind|_security_|_purecall|_RTC_|_encode|_decode)")
_CRT_UNDERSCORE_RE = re.compile(r"^__?([a-z]\w*)$")      # _malloc, _free, __strlen_sse2, __ftol2
# Underscore-prefixed names are CRT only when the stem is a known CRT function: a program's own
# `_do_work` or `__helper` must not be taken for library code.
_CRT_US_SUFFIX = re.compile(r"(?:_(?:sse2|sse4|avx2?|s|l|nolock|impl))+$")
_CRT_US = frozenset(
    "stricmp strnicmp strdup strlwr strupr strrev strset strnset wcsicmp wcsnicmp wcsdup wcslwr wcsupr "
    "mbscmp mbsicmp mbslen mbscpy mbscat mbschr mbsstr mbsnbcpy mbsnbcmp memicmp memccpy snprintf "
    "snwprintf vsnprintf vsnwprintf vscprintf scprintf itoa ltoa ultoa i64toa ui64toa itow ltow "
    "atoi64 atodbl strtoi64 strtoui64 wtoi wtol fopen wfopen fdopen fsopen fclose fread fwrite fseek "
    "ftell fseeki64 ftelli64 fflush fgetc fputc fgets fputs getc putc getch putch getche kbhit open "
    "close read write lseek tell eof chsize commit dup dup2 pipe isatty fileno setmode sopen creat "
    "access unlink remove rename stat fstat stati64 fstati64 chdir getcwd mkdir rmdir findfirst "
    "findnext findclose beginthread beginthreadex endthread endthreadex cexit c_exit exit amsg_exit "
    "purecall invalid_parameter errno doserrno get_osfhandle open_osfhandle lock unlock initterm "
    "initterm_e onexit dllonexit setargv setenvp getmainargs wgetmainargs ftol ftol2 chkstk alloca "
    "msize expand heapchk heapmin heapwalk callnewh set_new_handler set_se_translator lrotl lrotr "
    "rotl rotr swab gcvt fcvt ecvt tzset time64 mktime64 localtime64 gmtime64 ftime fullpath "
    "splitpath makepath wsplitpath wmakepath wfullpath tempnam tmpnam mktemp putenv wgetenv wputenv "
    "lock_file unlock_file getptd freeptd mtinit mtterm ioinit ioterm cinit cfltcvt fpclass isnan "
    "finite copysign chgsign logb nextafter scalb".split())
_STL_NS = ("std", "stdext", "__gnu_cxx", "_STL")
_ATL_NS = ("ATL", "ATLSafe", "ATL7")
_MFC_CLS_RE = re.compile(r"^(C[A-Z]\w*)")


def _crt_underscore(name: str) -> bool:
    """``_malloc``, ``__strlen_sse2``, ``_beginthreadex``: a known CRT stem behind one or two
    underscores (optionally ``_sse2`` / ``_s`` / ``_nolock`` style suffixes), or a ``crt`` stem."""
    m = _CRT_UNDERSCORE_RE.match(name)
    if not m:
        return False
    base = _CRT_US_SUFFIX.sub("", m.group(1)) or m.group(1)
    if base.startswith("crt") or base in _CRT_PLAIN or base in _CRT_US:
        return True
    return base[:1] == "w" and (base[1:] in _CRT_PLAIN or base[1:] in _CRT_US)


def lib_family(name: str, namespace: str | None, state: str) -> str | None:
    """'MFC' | 'CRT' | 'ATL/STL' | 'lib' (name_state=library, family unknown) | None (not library)."""
    if state == "user":
        return None
    ns = namespace or ""
    top = ns.split("::", 1)[0] if ns else ""
    if top in _ATL_NS or top in _STL_NS or name.startswith("operator_"):
        return "ATL/STL"
    if top.startswith(("Afx", "afx", "_Afx", "AFX")) or name.startswith(("Afx", "afx", "_Afx", "AFX_")):
        return "MFC"
    if top:
        m = _MFC_CLS_RE.match(top)
        if m and m.group(1) in MFC_CLASSES:
            return "MFC"
    elif name in MFC_CLASSES:
        return "MFC"
    if name.startswith(("operator new", "operator delete", "operator_")) or (not ns and name in _CRT_PLAIN):
        return "CRT"
    if not ns and (_CRT_RE.match(name) or _crt_underscore(name)):
        return "CRT"
    return "lib" if state == "library" else None


def propagate_library(base: dict[int, str], nodes: Iterable[int], callers: dict[int, set[int]],
                      callees: dict[int, set[int]], rounds: int = 3) -> dict[int, str]:
    """Extend {node: family} with nodes that have at least one caller, all of them library, and call
    only library nodes (max ``rounds`` rounds). Propagated nodes get the family 'prop'."""
    lib = dict(base)
    order = sorted(nodes)
    for _ in range(rounds):
        new: dict[int, str] = {}
        for v in order:
            if v in lib:
                continue
            cs = callers.get(v)
            if cs and all(c in lib for c in cs) and all(c in lib for c in callees.get(v, ())):
                new[v] = "prop"
        if not new:
            break
        lib.update(new)
    return lib


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
        self.lib: dict[int, str] = {}                             # library function id -> family
        self.at: dict[tuple[str, int], int] = {}
        self.names: dict[int, str] = {}
        for r in store.db.execute(
                "SELECT id, space, entry, name, name_state, namespace, is_thunk, is_external FROM function "
                "WHERE binary_id=?", (binary_id,)):
            q = f"{r['namespace']}::{r['name']}" if r["namespace"] else r["name"]
            self.fn[r["id"]] = (r["space"], r["entry"], q, bool(r["is_thunk"] or r["is_external"]))
            self.at[(r["space"], r["entry"])] = r["id"]
            if not (r["is_thunk"] or r["is_external"]):
                fam = lib_family(r["name"], r["namespace"], r["name_state"])
                if fam:
                    self.lib[r["id"]] = fam
        self.callers = store.callers_of_ids(binary_id)
        self.thunk_ids = {i for i, v in self.fn.items() if v[3]}
        callees: dict[int, set[int]] = {}
        for callee, srcs in self.callers.items():
            if callee in self.thunk_ids:
                continue
            for c in srcs:
                callees.setdefault(c, set()).add(callee)
        self.lib = propagate_library(self.lib, [i for i in self.fn if i not in self.thunk_ids],
                                     self.callers, callees)


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
        for fid in _edge_sources(store, sb.id, [r["src_addr"]], CODE_EDGES).get(
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
    strong: dict[str, set[tuple[int, int]]] = {}      # seeds with at least one strong evidence item
    summary: dict[str, Counter[str]] = {}

    def seed(key: str, bid: int, fid: int, reason: str, label: str, weak: bool = False) -> None:
        ev = seeds.setdefault(key, {}).setdefault((bid, fid), [])
        if reason not in ev:
            ev.append(reason)
        if not weak:
            strong.setdefault(key, set()).add((bid, fid))
        summary.setdefault(key, Counter())[label] += 1

    for bid, bn in bins.items():
        # API seeds: callers of import slots, thunks and recognised library functions.
        targets: dict[int, tuple[str, str, bool]] = {}      # address -> (feature, api name, weak)
        for r in store.db.execute("SELECT name, address FROM import WHERE binary_id=? AND name IS NOT NULL "
                                  "AND address IS NOT NULL", (bid,)):
            kw = api_class(r["name"])
            if kw:
                targets[r["address"]] = (kw[0], clean_api(r["name"]), kw[1])
        for fid, (space, entry, q, skip) in bn.fn.items():
            if space != "ram":
                continue
            kw = api_class(q)
            if kw and (skip or "::" in q) and entry not in targets:
                targets[entry] = (kw[0], clean_api(q), kw[1])
        for addr, srcs in _edge_sources(store, bid, targets, CODE_EDGES).items():
            key, api, weak = targets[addr]
            for fid in srcs:
                if fid not in bn.thunk_ids and fid not in bn.lib:
                    seed(key, bid, fid, f"calls {api}", api, weak)
        # string seeds
        hits: dict[int, list[tuple[str, str]]] = {}
        for r in store.db.execute("SELECT address, value FROM string WHERE binary_id=?", (bid,)):
            for k in string_features(r["value"], ext_rx):
                hits.setdefault(r["address"], []).append((k, _short(r["value"])))
        for addr, srcs in _edge_sources(store, bid, hits, ("read", "write", "data")).items():
            for k, lab in hits[addr]:
                for fid in srcs:
                    if fid not in bn.thunk_ids and fid not in bn.lib:
                        seed(k, bid, fid, f"refs {lab}", lab)
        # a string in a command/dispatch table points at its handler function
        if hits:
            for r in store.db.execute("SELECT l.string_addr, f.id AS fid FROM string_link l "
                                      "JOIN function f ON f.binary_id=l.binary_id AND f.space='ram' "
                                      "AND f.entry=l.fn_entry WHERE l.binary_id=? ORDER BY l.slot_addr", (bid,)):
                for k, lab in hits.get(r["string_addr"], ()):
                    if r["fid"] not in bn.thunk_ids and r["fid"] not in bn.lib:
                        seed(k, bid, r["fid"], f"table string {lab}", lab)
        # MFC: a handler mapped from a menu item / dialog control (message map x resources) is a strong seed
        try:
            ui = UiIndex(store, bid)
            by_addr = ui.ui_of_handlers() if ui.has_ui else {}
        except Exception as e:  # noqa: BLE001  an extra: the other seeds stay
            log.warning("ui seeds of binary %s failed: %s", bid, e)
            by_addr = {}
        for addr, d in by_addr.items():
            fid = bn.at.get(("ram", addr))
            if fid is None or fid in bn.thunk_ids or fid in bn.lib:
                continue
            for key, ev in (("ui-menu", d["menu"]), ("ui-dialog", d["dialog"])):
                for e in ev[:MAX_EVIDENCE]:
                    seed(key, bid, fid, e, e)
        # Delphi: a handler named by a DFM event (form x published methods) is a strong seed
        try:
            for addr, key, ev in delphi.feature_seeds(store, bid):
                fid = bn.at.get(("ram", addr))
                if fid is not None and fid not in bn.thunk_ids and fid not in bn.lib:
                    seed(key, bid, fid, ev, ev)
        except Exception as e:  # noqa: BLE001  an extra: the other seeds stay
            log.warning("delphi seeds of binary %s failed: %s", bid, e)
        # a data-format extension that appears in strings is a feature even when no code refs it
        for addr, lst in hits.items():
            for k, lab in lst:
                if k.startswith(DATA_FORMAT):
                    seeds.setdefault(k, {})
                    summary.setdefault(k, Counter())[lab] += 0

    rows: list[tuple[str, int, str, int, str, str, int]] = []
    feats: list[tuple[str, str, str]] = []
    counts: dict[str, int] = {}
    dropped: dict[str, int] = {}
    for key in sorted(seeds, key=feature_order):
        strong_refs = strong.get(key, set())
        ranked = sorted(seeds[key].items(), key=lambda kv: (kv[0] not in strong_refs, -len(kv[1]), kv[0]))
        dropped_refs: set[tuple[int, int]] = {ref for ref, _ev in ranked[MAX_ENTRIES:]}
        got: dict[tuple[int, int], tuple[str, list[str], int]] = {
            ref: (ev[0], ev, 0) for ref, ev in ranked[:MAX_ENTRIES]}
        frontier = [ref for ref in got if ref in strong_refs]   # weak seeds do not expand
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
                    if (cb, cf) in got or cf in bins[cb].thunk_ids or cf in bins[cb].lib:
                        continue
                    if len(got) >= MAX_ENTRIES:
                        dropped_refs.add((cb, cf))
                        continue
                    got[(cb, cf)] = (f"caller of {qn}", inherited, depth)
                    nxt.append((cb, cf))
            frontier = nxt
        for (bid, fid), (reason, ev, depth) in got.items():
            space, entry, _q, _s = bins[bid].fn[fid]
            rows.append((key, bid, space, entry, reason, " ; ".join(ev[:MAX_EVIDENCE]), depth))
        counts[key] = len(got)
        dropped_refs -= set(got)
        if dropped_refs:
            dropped[key] = len(dropped_refs)
        top = ", ".join(f"{lab} x{n}" if n > 1 else lab
                        for lab, n in summary.get(key, Counter()).most_common(6))
        feats.append((key, feature_title(key), top))
    store.replace_auto_features(feats, rows, now or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    with store.db:
        store.set_meta(DROPPED_META, json.dumps(dropped, separators=(",", ":")))
        store.set_meta(FEATURES_VERSION_META, str(FEATURES_VERSION))
    return counts


def stale(store: Store) -> bool:
    """True when the stored features were derived by an older FEATURES_VERSION (or never)."""
    return store.get_meta(FEATURES_VERSION_META) != str(FEATURES_VERSION)


def derive_project(pp: ProjectPaths, store: Store, man: dict[str, Any] | None = None) -> dict[str, int]:
    runtime, exts = manifest_inputs(pp, store, man)
    return derive(store, runtime, exts)


# -- coverage ---------------------------------------------------------------------------

def coverage(n: int, named: int) -> str:
    return f"named {named} of {n}" + (f" ({100 * named // n}%)" if n else "")


def stats(store: Store) -> list[dict[str, Any]]:
    """Features in display order: key, title, source, topics, n, named, seeds, binaries."""
    rows = [dict(r) for r in store.feature_stats()]
    extra = {r["feature_key"]: (r["seeds"], r["bins"]) for r in store.db.execute(
        "SELECT feature_key, COALESCE(SUM(depth=0), 0) AS seeds, COUNT(DISTINCT binary_id) AS bins "
        "FROM feature_entry GROUP BY feature_key")}
    for r in rows:
        r["seeds"], r["binaries"] = extra.get(r["key"], (0, 0))
    rows.sort(key=lambda r: feature_order(r["key"]))
    return rows


def dropped(store: Store) -> dict[str, int]:
    """{feature key: entry points cut by MAX_ENTRIES at the last derivation}."""
    try:
        return {k: int(v) for k, v in json.loads(store.get_meta(DROPPED_META) or "{}").items()}
    except (ValueError, TypeError):
        return {}


def size_text(r: dict[str, Any], drop: int = 0, binaries: bool = False) -> str:
    """``seeds 41, total 688`` (+ `` in 6 binaries``). A capped list says the true total (a lower
    bound) and that the listed part is ranked: ``seeds 41, total at least 2100, ranked top 1500 listed``."""
    out = f"seeds {r['seeds']}, total {r['n']}" if not drop else         f"seeds {r['seeds']}, total at least {r['n'] + drop}, ranked top {r['n']} listed (cap {MAX_ENTRIES})"
    if binaries and r.get("binaries"):
        out += f" in {r['binaries']} binar{'y' if r['binaries'] == 1 else 'ies'}"
    return out


def rank_entries(rows: Iterable[Any]) -> list[Any]:
    """Entry-point rows ordered by depth, then evidence strength (distinct evidence items), with the
    binaries interleaved inside each (depth, strength) group so the first page spans binaries."""
    def strength(r: Any) -> int:
        ev = r["evidence"] or ""
        return len({x.strip() for x in ev.split(" ; ") if x.strip()})

    base = sorted(rows, key=lambda r: (r["depth"], -strength(r), r["binary_id"], r["space"], r["entry"]))
    seen: Counter[tuple[int, int, int]] = Counter()
    keyed = []
    for i, r in enumerate(base):
        grp = (r["depth"], strength(r), r["binary_id"])
        keyed.append(((r["depth"], -strength(r), seen[grp], r["binary_id"], i), r))
        seen[grp] += 1
    keyed.sort(key=lambda t: t[0])
    return [r for _k, r in keyed]
