"""Capability taxonomy: map imported APIs and string literals to behaviours.

Reverse engineering a binary is mostly "what does this thing *do*?". Raw call
graphs answer that poorly because the interesting verbs live in the import
table (``CreateRemoteThread``, ``connect``, ``CryptEncrypt`` ...). This module
turns those imports into **capability** concepts so the graph can be asked
"which functions touch the network / the registry / debugger detection?".

Everything here is heuristic. Every capability link is emitted as ``INFERRED``
by the ingester: an import name is evidence of *access to* a behaviour, not
proof the behaviour is exercised.

The tables are intentionally data, not code, so they are easy to extend::

    from graphify_ghidra.capabilities import register_api_rules
    register_api_rules("anti-analysis", [r"^IsDebuggerPresent$"], ...)
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = [
    "Capability",
    "CAPABILITIES",
    "register_api_rules",
    "register_string_rules",
    "classify_api",
    "classify_string",
    "normalize_api_name",
]


@dataclass(frozen=True)
class Capability:
    """A behaviour category.

    ``risk`` is a coarse triage weight (0-3), used only for ranking functions,
    never presented as a verdict.
    """

    key: str
    label: str
    description: str
    risk: int = 0


CAPABILITIES: dict[str, Capability] = {
    c.key: c
    for c in [
        Capability("file-io", "File I/O", "Reads, writes, enumerates or deletes files", 0),
        Capability("registry", "Registry access", "Reads or writes the Windows registry", 1),
        Capability("network", "Networking", "Opens sockets or speaks network protocols", 1),
        Capability("http", "HTTP / web client", "High-level HTTP/WinInet/WinHTTP usage", 1),
        Capability("dns", "DNS / name resolution", "Resolves hostnames", 1),
        Capability("process", "Process control", "Creates, opens or enumerates processes", 1),
        Capability("thread", "Threads / synchronisation", "Creates threads and sync primitives", 0),
        Capability("injection", "Code injection", "Writes into or runs code in other processes", 3),
        Capability("memory", "Memory management", "Allocates or re-protects memory", 0),
        Capability("dynamic-loading", "Dynamic API resolution", "Resolves APIs at runtime", 2),
        Capability("crypto", "Cryptography", "Uses crypto primitives or key material", 1),
        Capability("anti-analysis", "Anti-analysis", "Detects debuggers, VMs or tampering", 3),
        Capability("privilege", "Privilege / tokens", "Manipulates tokens, privileges or accounts", 2),
        Capability("service", "Services / persistence", "Installs or controls services and autoruns", 2),
        Capability("system-info", "System information", "Fingerprints the host", 0),
        Capability("ui", "User interface", "Windows, dialogs, input hooks", 0),
        Capability("input-capture", "Input capture", "Keyboard/mouse hooks or screen capture", 2),
        Capability("com", "COM / RPC", "COM, DCOM or RPC calls", 0),
        Capability("string-ops", "String operations", "Runtime string manipulation", 0),
        Capability("exec", "Command execution", "Spawns shells or external programs", 2),
        Capability("sandbox-escape", "Hardening / mitigations", "Touches exploit mitigations or DEP/ASLR", 2),
        Capability("time", "Time / timing", "Sleeps, timers, or timing checks", 0),
        Capability("posix-io", "POSIX file/socket I/O", "libc open/read/write/socket family", 0),
        Capability("posix-process", "POSIX process control", "fork/exec/ptrace/signal family", 1),
        Capability("linux-kernel", "Linux kernel interface", "ioctl, mmap, syscalls, modules", 1),
    ]
}

# (capability key, compiled patterns). Patterns match the *normalised* API name
# (see normalize_api_name): no module prefix, no A/W/Ex/Ex2 decoration.
_API_RULES: list[tuple[str, list[re.Pattern]]] = []
_STRING_RULES: list[tuple[str, list[re.Pattern]]] = []


def _compile(patterns: list[str], flags: int = re.IGNORECASE) -> list[re.Pattern]:
    return [re.compile(p, flags) for p in patterns]


def register_api_rules(key: str, patterns: list[str], *, label: str | None = None,
                       description: str = "", risk: int = 0) -> None:
    """Add API-name rules for a capability, creating the capability if new."""
    if key not in CAPABILITIES:
        CAPABILITIES[key] = Capability(key, label or key, description, risk)
    _API_RULES.append((key, _compile(patterns)))


def register_string_rules(key: str, patterns: list[str], *, label: str | None = None,
                          description: str = "", risk: int = 0) -> None:
    """Add string-literal rules for a capability, creating it if new."""
    if key not in CAPABILITIES:
        CAPABILITIES[key] = Capability(key, label or key, description, risk)
    _STRING_RULES.append((key, _compile(patterns)))


_WIDE_ANSI_SUFFIX = re.compile(r"(?:A|W|ExA|ExW|Ex2?|Ex3)$")


def normalize_api_name(name: str) -> str:
    """Reduce an import name to a stable base form for matching.

    ``KERNEL32.DLL!CreateFileW`` -> ``CreateFile``; ``_open`` -> ``open``;
    ``__imp_connect`` -> ``connect``; ordinals (``Ordinal_12``) are left as is.
    """
    n = name.strip()
    if "!" in n:
        n = n.split("!", 1)[1]
    if n.startswith("__imp_"):
        n = n[len("__imp_"):]
    if n.startswith("_imp__"):
        n = n[len("_imp__"):]
    n = n.lstrip("_")
    if n.lower().startswith("ordinal_"):
        return n
    # Strip decorations only from names that look like Win32 CamelCase, so we
    # do not mangle libc names such as "open" -> "ope".
    if n[:1].isupper() and len(n) > 4:
        stripped = _WIDE_ANSI_SUFFIX.sub("", n)
        if len(stripped) >= 3:
            n = stripped
    return n


def _seed() -> None:
    R = register_api_rules
    R("file-io", [
        r"^(Create|Open|Read|Write|Delete|Copy|Move|Replace|Flush|Set)File", r"^FindFirstFile", r"^FindNextFile",
        r"^GetFile(Attributes|Size|Type|Time|InformationByHandle)", r"^NtCreateFile$", r"^NtReadFile$",
        r"^NtWriteFile$", r"^NtDeleteFile$", r"^CreateDirectory", r"^RemoveDirectory", r"^SHFileOperation",
        r"^GetTempPath", r"^GetTempFileName", r"^CreateFileMapping", r"^MapViewOfFile", r"^fopen$", r"^fwrite$",
        r"^fread$", r"^_wfopen", r"^DeviceIoControl$", r"^LockFile", r"^SetEndOfFile$",
    ])
    R("registry", [
        r"^Reg(Open|Create|Delete|Set|Query|Enum|Close|Save|Load|Flush)", r"^NtOpenKey", r"^NtCreateKey",
        r"^NtSetValueKey", r"^NtQueryValueKey", r"^SHGetValue", r"^SHSetValue", r"^SHDeleteKey",
    ])
    R("network", [
        r"^(WSAStartup|WSASocket|WSAConnect|WSASend|WSARecv|WSAIoctl|WSACleanup|WSAAsync)", r"^socket$", r"^connect$",
        r"^bind$", r"^listen$", r"^accept$", r"^send$", r"^recv$", r"^sendto$", r"^recvfrom$", r"^closesocket$",
        r"^select$", r"^setsockopt$", r"^getsockopt$", r"^shutdown$", r"^inet_(addr|ntoa|pton|ntop)",
        r"^htons$", r"^ntohs$", r"^htonl$", r"^ntohl$", r"^GetAdaptersInfo", r"^GetAdaptersAddresses",
        r"^GetIpNetTable", r"^GetTcpTable", r"^GetUdpTable", r"^IcmpSendEcho", r"^WNet", r"^NetShare",
        r"^NetUse", r"^NetUser", r"^NetServer", r"^NetWkstaGetInfo",
    ])
    R("http", [
        r"^Internet(Open|Connect|ReadFile|WriteFile|OpenUrl|SetOption|QueryOption|CloseHandle)", r"^Http(OpenRequest|SendRequest|QueryInfo|AddRequestHeaders)",
        r"^WinHttp", r"^URLDownloadToFile", r"^URLOpenStream", r"^FtpOpenFile", r"^FtpPutFile", r"^FtpGetFile",
        r"^InternetCrackUrl", r"^curl_", r"^URLDownload",
    ])
    R("dns", [
        r"^getaddrinfo$", r"^GetAddrInfo", r"^gethostbyname$", r"^gethostbyaddr$", r"^getnameinfo$",
        r"^DnsQuery", r"^DnsFree", r"^gethostname$", r"^getservbyname$",
    ])
    R("process", [
        r"^CreateProcess", r"^OpenProcess$", r"^TerminateProcess$", r"^ExitProcess$", r"^GetCurrentProcess",
        r"^NtOpenProcess$", r"^NtTerminateProcess$", r"^NtQueryInformationProcess$", r"^NtSuspendProcess",
        r"^NtResumeProcess", r"^EnumProcesses$", r"^Process32(First|Next)", r"^Module32(First|Next)",
        r"^CreateToolhelp32Snapshot$", r"^GetProcessId$", r"^GetModuleFileName", r"^EnumProcessModules",
        r"^WinExec$", r"^ShellExecute", r"^GetExitCodeProcess$", r"^SetPriorityClass$",
    ])
    R("thread", [
        r"^CreateThread$", r"^ExitThread$", r"^SuspendThread$", r"^ResumeThread$", r"^OpenThread$",
        r"^GetThreadContext$", r"^SetThreadContext$", r"^_?beginthread", r"^WaitFor(Single|Multiple)Object",
        r"^CreateMutex", r"^OpenMutex", r"^ReleaseMutex$", r"^CreateEvent", r"^SetEvent$", r"^ResetEvent$",
        r"^(Enter|Leave|Initialize|Delete)CriticalSection", r"^TlsAlloc$", r"^TlsGetValue$", r"^TlsSetValue$",
        r"^pthread_", r"^Sleep$", r"^InitOnce", r"^(Acquire|Release)SRWLock",
    ])
    R("injection", [
        r"^CreateRemoteThread", r"^NtCreateThreadEx$", r"^RtlCreateUserThread$", r"^WriteProcessMemory$",
        r"^NtWriteVirtualMemory$", r"^VirtualAllocEx$", r"^VirtualProtectEx$", r"^NtMapViewOfSection$",
        r"^NtUnmapViewOfSection$", r"^QueueUserAPC$", r"^NtQueueApcThread", r"^SetThreadContext$",
        r"^SetWindowsHook", r"^NtAllocateVirtualMemoryEx?$", r"^ReadProcessMemory$", r"^NtReadVirtualMemory$",
        r"^LdrLoadDll$", r"^RtlRemoteCall$", r"^ptrace$", r"^process_vm_(readv|writev)$",
    ])
    R("memory", [
        r"^Virtual(Alloc|Free|Protect|Query|Lock)", r"^NtAllocateVirtualMemory", r"^NtProtectVirtualMemory",
        r"^NtFreeVirtualMemory", r"^Heap(Alloc|ReAlloc|Free|Create|Destroy|Size)", r"^(Local|Global)(Alloc|Free|Lock|Unlock)",
        r"^malloc$", r"^calloc$", r"^realloc$", r"^free$", r"^mmap$", r"^munmap$", r"^mprotect$", r"^memcpy$",
        r"^memmove$", r"^memset$", r"^RtlMoveMemory$", r"^RtlCopyMemory$", r"^RtlZeroMemory$", r"^RtlFillMemory$",
        r"^operator_new", r"^new$",
    ])
    R("dynamic-loading", [
        r"^LoadLibrary", r"^GetProcAddress$", r"^LdrGetProcedureAddress", r"^LdrLoadDll$", r"^GetModuleHandle",
        r"^LdrGetDllHandle", r"^dlopen$", r"^dlsym$", r"^dlclose$", r"^FreeLibrary$", r"^LoadModule$",
        r"^delayLoadHelper", r"^__delayLoadHelper",
    ])
    R("crypto", [
        r"^Crypt(Acquire|Create|Derive|Decrypt|Encrypt|Export|Import|Gen|Hash|Sign|Verify|Destroy|Release|Protect|Unprotect|Set|Get|Decode|Encode)",
        r"^BCrypt", r"^NCrypt", r"^CertOpen", r"^CertFind", r"^CertGetCertificateChain", r"^CertVerify",
        r"^CryptoAPI", r"^EVP_", r"^AES_", r"^RSA_", r"^SHA(1|224|256|384|512)_", r"^MD5_", r"^HMAC",
        r"^RAND_bytes$", r"^SSL_", r"^TLS_", r"^mbedtls_", r"^gcry_", r"^sodium_", r"^crypto_", r"^RtlGenRandom$",
        r"^SystemFunction0(36|3[0-9])", r"^GetUserNameEx", r"^CryptUnprotectData$", r"^X509_", r"^wolfSSL_",
    ])
    R("anti-analysis", [
        r"^IsDebuggerPresent$", r"^CheckRemoteDebuggerPresent$", r"^NtQueryInformationProcess$",
        r"^NtSetInformationThread$", r"^OutputDebugString", r"^DebugBreak$", r"^DbgBreakPoint$", r"^DbgUiRemoteBreakin$",
        r"^NtSetDebugFilterState", r"^NtQuerySystemInformation$",
        r"^FindWindow", r"^EnumWindows$", r"^NtYieldExecution$", r"^BlockInput$", r"^ptrace$",
        r"^GetSystemFirmwareTable$", r"^NtSetInformationProcess$",
        # NB: GetTickCount/QueryPerformanceCounter/CloseHandle/RaiseException are
        # ubiquitous in ordinary CRT code. They live under "time"/"memory" etc.,
        # not here, so "anti-analysis" stays a meaningful signal.
    ])
    R("privilege", [
        r"^OpenProcessToken$", r"^OpenThreadToken$", r"^AdjustTokenPrivileges$", r"^LookupPrivilegeValue", r"^LookupPrivilegeName",
        r"^LookupPrivilegeDisplayName", r"^DuplicateToken", r"^ImpersonateLoggedOnUser$", r"^LogonUser", r"^CreateProcessAsUser",
        r"^CreateProcessWithToken", r"^SetTokenInformation$", r"^GetTokenInformation$", r"^NtAdjustPrivilegesToken$",
        r"^CheckTokenMembership$", r"^IsUserAnAdmin$", r"^RevertToSelf$", r"^LookupAccountSid", r"^LookupAccountName",
        r"^ConvertSidToStringSid", r"^ConvertStringSidToSid", r"^AllocateAndInitializeSid$", r"^EqualSid$",
        r"^SetSecurityDescriptor", r"^SetNamedSecurityInfo", r"^setuid$", r"^setgid$", r"^seteuid$", r"^setresuid$",
        r"^getuid$", r"^geteuid$", r"^NetUserAdd$", r"^NetLocalGroupAddMembers$",
    ])
    R("service", [
        r"^(Open|Create|Delete|Start|Control|Query|Change|Enum)Service", r"^OpenSCManager", r"^StartServiceCtrlDispatcher",
        r"^RegisterServiceCtrlHandler", r"^SetServiceStatus$", r"^SchRpc", r"^ITaskScheduler", r"^NetScheduleJobAdd",
    ])
    R("system-info", [
        r"^GetSystemInfo$", r"^GetNativeSystemInfo$", r"^GetVersion", r"^RtlGetVersion$", r"^GetComputerName",
        r"^GetUserName", r"^GetSystemDirectory", r"^GetWindowsDirectory", r"^GetSystemTime", r"^GetLocalTime",
        r"^GetTimeZoneInformation$", r"^GetLogicalDrive", r"^GetDriveType", r"^GetVolumeInformation", r"^GlobalMemoryStatus",
        r"^GetDiskFreeSpace", r"^GetKeyboardLayout", r"^GetSystemMetrics$", r"^GetEnvironmentVariable", r"^ExpandEnvironmentStrings",
        r"^GetCommandLine", r"^GetStartupInfo", r"^uname$", r"^sysconf$", r"^getenv$", r"^gethostid$", r"^GetCurrentDirectory",
        r"^GetCurrentProcessId$", r"^GetCurrentThreadId$", r"^GetCPInfo$", r"^GetACP$", r"^GetOEMCP$", r"^GetConsole",
        r"^GetStdHandle$", r"^SetConsole", r"^NetGetJoinInformation", r"^NetWkstaGetInfo$", r"^GetNetworkParams$",
    ])
    R("ui", [
        r"^CreateWindow", r"^MessageBox", r"^DialogBox", r"^CreateDialog", r"^ShowWindow$", r"^UpdateWindow$",
        r"^GetMessage$", r"^PeekMessage$", r"^DispatchMessage$", r"^TranslateMessage$", r"^DefWindowProc", r"^RegisterClass",
        r"^SendMessage", r"^PostMessage", r"^SetWindowText", r"^GetDlgItem", r"^LoadString", r"^LoadIcon", r"^LoadCursor",
        r"^LoadImage", r"^BeginPaint$", r"^EndPaint$", r"^InvalidateRect$", r"^TrackPopupMenu", r"^DrawText",
        r"^Shell_NotifyIcon", r"^SetClipboardData$", r"^GetClipboardData$", r"^OpenClipboard$", r"^EmptyClipboard$",
    ])
    R("input-capture", [
        r"^SetWindowsHook", r"^GetAsyncKeyState$", r"^GetKeyState$", r"^GetKeyboardState$", r"^RegisterRawInputDevices$",
        r"^GetRawInputData$", r"^BitBlt$", r"^GetDC$", r"^GetWindowDC$", r"^CreateCompatibleDC$", r"^GetClipboardData$",
        r"^keybd_event$", r"^mouse_event$", r"^SendInput$", r"^MapVirtualKey", r"^AttachThreadInput$",
        r"^waveInOpen$", r"^waveInStart$", r"^capCreateCaptureWindow", r"^PrintWindow$", r"^GetCursorPos$",
    ])
    R("com", [
        r"^Co(Initialize|Uninitialize|CreateInstance|GetClassObject|TaskMem|SetProxyBlanket|InitializeSecurity|InitializeEx|Unmarshal)",
        r"^OleInitialize", r"^OleUninitialize", r"^Rpc", r"^NdrClientCall", r"^UuidCreate", r"^UuidFromString", r"^SysAllocString",
        r"^SysFreeString", r"^VariantInit$", r"^VariantClear$", r"^SafeArray", r"^StringFromCLSID", r"^CLSIDFromString",
        r"^CLSIDFromProgID", r"^IIDFromString", r"^ProgIDFromCLSID",
    ])
    R("string-ops", [
        r"^lstr(cat|cpy|len|cmp|cmpi)", r"^wcs(cat|cpy|len|cmp|chr|str|ncpy|ncat|ncmp)", r"^str(cat|cpy|len|cmp|chr|str|ncpy|ncat|ncmp|dup|tok|rchr)",
        r"^sprintf$", r"^swprintf$", r"^snprintf$", r"^vsnprintf$", r"^_snprintf", r"^_snwprintf", r"^_vsnwprintf", r"^_stricmp",
        r"^_wcsicmp", r"^MultiByteToWideChar$", r"^WideCharToMultiByte$", r"^CharUpper", r"^CharLower", r"^PathCombine", r"^PathFindFileName",
        r"^PathAppend", r"^PathRemove", r"^PathFileExists", r"^StrStr", r"^StrCmp", r"^StrChr", r"^StrToInt", r"^wsprintf", r"^atoi$", r"^atol$",
        r"^strtol$", r"^strtoul$", r"^_wtoi$", r"^_itoa", r"^_itow", r"^_ltoa", r"^std_string",
    ])
    R("exec", [
        r"^system$", r"^_wsystem$", r"^popen$", r"^_popen$", r"^execv", r"^execl", r"^execve$", r"^execvp$", r"^posix_spawn$",
        r"^ShellExecute", r"^WinExec$", r"^CreateProcess", r"^_spawn", r"^_wspawn", r"^_exec", r"^fork$", r"^vfork$",
    ])
    R("sandbox-escape", [
        r"^SetProcessDEPPolicy$", r"^SetProcessMitigationPolicy$", r"^GetProcessMitigationPolicy$", r"^NtSetInformationProcess$",
        r"^SetDllDirectory", r"^SetDefaultDllDirectories$", r"^AddDllDirectory$", r"^SetSearchPathMode$", r"^NtProtectVirtualMemory$",
        r"^VirtualProtect", r"^mprotect$", r"^personality$", r"^prctl$", r"^seccomp$",
    ])
    R("time", [
        r"^Sleep(Ex)?$", r"^NtDelayExecution$", r"^SetTimer$", r"^KillTimer$", r"^timeSetEvent$", r"^timeGetTime$", r"^GetTickCount(64)?$",
        r"^QueryPerformanceCounter$", r"^QueryPerformanceFrequency$", r"^GetSystemTimeAsFileTime$", r"^CreateWaitableTimer",
        r"^SetWaitableTimer$", r"^time$", r"^_time(32|64)$", r"^gettimeofday$", r"^clock$", r"^clock_gettime$", r"^nanosleep$", r"^usleep$",
        r"^__rdtsc$",
    ])
    R("posix-io", [
        r"^open(at)?$", r"^creat$", r"^read$", r"^write$", r"^close$", r"^lseek$", r"^pread$", r"^pwrite$", r"^unlink(at)?$",
        r"^stat(64)?$", r"^fstat(64)?$", r"^lstat(64)?$", r"^access$", r"^readdir$", r"^opendir$", r"^mkdir$", r"^rmdir$", r"^rename$",
        r"^fcntl$", r"^dup2?$", r"^pipe$", r"^poll$", r"^epoll_", r"^readlink$", r"^chmod$", r"^chown$", r"^fsync$", r"^ftruncate$",
        r"^fgets$", r"^fputs$", r"^fprintf$", r"^fclose$", r"^puts$", r"^printf$",
    ])
    R("posix-process", [
        r"^fork$", r"^vfork$", r"^clone$", r"^execve?$", r"^execv(p|pe)?$", r"^execl(p|e)?$", r"^kill$", r"^waitpid?$", r"^wait4$",
        r"^signal$", r"^sigaction$", r"^raise$", r"^abort$", r"^_?exit$", r"^getpid$", r"^getppid$", r"^daemon$", r"^setsid$", r"^ptrace$",
        r"^prctl$", r"^atexit$",
    ])
    R("linux-kernel", [
        r"^ioctl$", r"^syscall$", r"^init_module$", r"^finit_module$", r"^delete_module$", r"^mmap(64)?$", r"^munmap$", r"^mlock$",
        r"^bpf$", r"^perf_event_open$", r"^socketpair$", r"^unshare$", r"^setns$", r"^chroot$", r"^mount$", r"^umount2?$",
        r"^copy_(from|to)_user$", r"^kmalloc$", r"^kfree$", r"^printk$", r"^register_chrdev", r"^misc_register$",
    ])

    S = register_string_rules
    S("network", [r"\bhttps?://", r"\bftp://", r"\bwss?://", r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b", r"\bUser-Agent:", r"\bHost:\s", r"\bGET /", r"\bPOST /"])
    S("registry", [r"\b(HKLM|HKCU|HKEY_[A-Z_]+)\\", r"\\SOFTWARE\\", r"\\CurrentVersion\\Run", r"\\Microsoft\\Windows\\CurrentVersion"])
    S("file-io", [r"^[A-Za-z]:\\", r"%(APPDATA|TEMP|USERPROFILE|SYSTEMROOT|WINDIR)%", r"\\\\\.\\", r"/etc/(passwd|shadow|hosts)", r"/proc/\w+", r"/dev/\w+"])
    S("crypto", [r"-----BEGIN [A-Z ]+-----", r"\bAES[-_ ]?(128|192|256)\b", r"\bRSA\b", r"\bSHA-?(1|256|384|512)\b", r"\bMD5\b", r"\bbase64\b", r"\bchacha20\b"])
    S("anti-analysis", [r"\bvmware\b", r"\bvirtualbox\b", r"\bvbox\b", r"\bqemu\b", r"\bsandbox\b", r"\bwireshark\b", r"\bprocmon\b", r"\bollydbg\b", r"\bx64dbg\b", r"\bidaq?64?\b", r"\bsbiedll\b"])
    S("exec", [r"\bcmd(\.exe)?\s*/c\b", r"\bpowershell(\.exe)?\b", r"\b/bin/(ba)?sh\b", r"\bwscript\b", r"\bcscript\b", r"\brundll32\b", r"\bregsvr32\b", r"\bmshta\b"])
    S("service", [r"\bschtasks\b", r"\bsc\.exe\b", r"\\Services\\", r"\bsystemd\b", r"/etc/(init\.d|cron)", r"\bcrontab\b", r"\bLaunchAgents\b"])
    S("privilege", [r"\bSeDebugPrivilege\b", r"\bSe[A-Z][A-Za-z]+Privilege\b", r"\bNT AUTHORITY\\", r"\bAdministrators\b"])


_seed()


def classify_api(name: str | None) -> list[str]:
    """Return capability keys implicated by one imported/called API name."""
    if not name:
        return []
    base = normalize_api_name(name)
    seen: list[str] = []
    for key, patterns in _API_RULES:
        if key in seen:
            continue
        if any(p.search(base) for p in patterns):
            seen.append(key)
    return seen


def classify_string(value: str | None) -> list[str]:
    """Return capability keys implicated by a string literal."""
    if not value or len(value) < 4:
        return []
    seen: list[str] = []
    for key, patterns in _STRING_RULES:
        if key in seen:
            continue
        if any(p.search(value) for p in patterns):
            seen.append(key)
    return seen
