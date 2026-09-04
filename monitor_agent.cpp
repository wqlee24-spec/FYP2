// =============================================================================
//  monitor_agent.cpp  –  Hybrid Security Suite · File-System Monitor Agent
// =============================================================================
//
//  Monitors a target directory with ReadDirectoryChangesW (overlapped I/O) and
//  streams detected change events to a Named Pipe consumed by main.py.
//
//  Each event line written to the pipe:
//      FILEPATH|PID|SOURCE\n
//
//  SOURCE records how the PID was attributed:
//      ETW   – true originating process, from Microsoft-Windows-Kernel-File
//      HEUR  – legacy GetLikelyPid() guess (ETW unavailable or no recent match)
//
//  Consumers must tolerate the older two-field form (FILEPATH|PID) as well.
//
//  Compile with MSVC (Developer Command Prompt):
//      cl /EHsc /W4 /O2 monitor_agent.cpp /Fe:monitor_agent.exe
//
//  Compile with MinGW-w64:
//      g++ -std=c++17 -O2 -o monitor_agent.exe monitor_agent.cpp -lpsapi -ltdh -ladvapi32
//
// =============================================================================

#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstdlib>

#include "etw_attribution.h"

#pragma comment(lib, "psapi.lib")

// ---------------------------------------------------------------------------
// Configuration – edit these constants to change behaviour
// ---------------------------------------------------------------------------
static const wchar_t* DEFAULT_WATCH_DIR = L"C:\\Users\\Public\\Documents";
static const wchar_t* PIPE_NAME     = L"\\\\.\\pipe\\SecurityPipe";
static const DWORD    CONNECT_WAIT  = NMPWAIT_WAIT_FOREVER;
static const DWORD    BUF_SIZE      = 65536;   // RDCW notification buffer

// ETW real-time events arrive a beat after the RDCW notification (buffer-flush
// latency), so an immediate PID lookup usually misses. Retry the lookup a few
// times, briefly, before falling back to the heuristic. Bounded so it can never
// stall the agent. Only runs when ETW is active (elevated).
static const int      ETW_RESOLVE_TRIES   = 20;   // up to ETW_RESOLVE_TRIES ...
static const DWORD    ETW_RESOLVE_STEP_MS = 15;   // ... x 15 ms  = ~300 ms max

// ---------------------------------------------------------------------------
// WideToUtf8 – convert a UTF-16 wstring to a UTF-8 std::string
// ---------------------------------------------------------------------------
static std::string WideToUtf8(const std::wstring& w)
{
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0,
                                w.c_str(), static_cast<int>(w.size()),
                                nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0,
                        w.c_str(), static_cast<int>(w.size()),
                        &s[0], n, nullptr, nullptr);
    return s;
}

// ---------------------------------------------------------------------------
// GetLikelyPid – best-effort: return the PID of the most recently spawned
//                non-system user process. Used only when ETW attribution is
//                unavailable.
//
//  PERFORMANCE: a full CreateToolhelp32Snapshot + per-process OpenProcess costs
//  ~29 ms on a typical desktop, and this is called once per file event. Left
//  uncached it added ~1.4 s of latency to a 50-file burst and dominated the
//  detection pipeline. The answer ("most recently spawned process") cannot
//  meaningfully change within a few milliseconds, so the result is cached for
//  GLP_CACHE_MS. A ransomware burst completes well inside that window, so every
//  event in one burst resolves to the same PID — which is also the correct
//  answer for a single-process attack.
// ---------------------------------------------------------------------------
static const ULONGLONG GLP_CACHE_MS = 100;

static DWORD GetLikelyPidUncached();

static DWORD GetLikelyPid()
{
    static DWORD     cachedPid  = 0;
    static ULONGLONG cachedTick = 0;

    const ULONGLONG now = GetTickCount64();
    if (cachedPid != 0 && (now - cachedTick) < GLP_CACHE_MS)
        return cachedPid;

    cachedPid  = GetLikelyPidUncached();
    cachedTick = now;
    return cachedPid;
}

static DWORD GetLikelyPidUncached()
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return GetCurrentProcessId();

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    DWORD   candidatePid = 0;
    ULONGLONG latestTime = 0;

    if (Process32FirstW(snap, &pe))
    {
        do
        {
            if (pe.th32ProcessID <= 4) continue;   // skip System / Idle

            HANDLE hProc = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (!hProc) continue;

            FILETIME ftCreate{}, ftExit{}, ftKernel{}, ftUser{};
            if (GetProcessTimes(hProc, &ftCreate, &ftExit, &ftKernel, &ftUser))
            {
                // Get full image path to filter out system processes
                wchar_t img[MAX_PATH] = {};
                DWORD   sz  = MAX_PATH;
                QueryFullProcessImageNameW(hProc, 0, img, &sz);
                std::wstring imgPath(img);

                bool sysProc =
                    imgPath.find(L"\\Windows\\System32\\") != std::wstring::npos ||
                    imgPath.find(L"\\Windows\\SysWOW64\\") != std::wstring::npos ||
                    imgPath.empty();

                if (!sysProc)
                {
                    ULARGE_INTEGER t;
                    t.LowPart  = ftCreate.dwLowDateTime;
                    t.HighPart = ftCreate.dwHighDateTime;
                    if (t.QuadPart > latestTime)
                    {
                        latestTime   = t.QuadPart;
                        candidatePid = pe.th32ProcessID;
                    }
                }
            }
            CloseHandle(hProc);
        }
        while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return candidatePid ? candidatePid : GetCurrentProcessId();
}

// ---------------------------------------------------------------------------
// WriteLineToPipe – write one UTF-8 line (+ newline) to an open pipe handle.
//                   Returns false if the client disconnected.
// ---------------------------------------------------------------------------
static bool WriteLineToPipe(HANDLE hPipe, const std::string& line)
{
    std::string msg = line + "\n";
    DWORD written   = 0;
    BOOL  ok        = WriteFile(hPipe,
                                msg.c_str(),
                                static_cast<DWORD>(msg.size()),
                                &written,
                                nullptr);
    return ok && written == static_cast<DWORD>(msg.size());
}

// ---------------------------------------------------------------------------
// WaitForClient – (re-)connect a Named Pipe instance, blocking until a client
//                 connects. Returns true on success.
// ---------------------------------------------------------------------------
static bool WaitForClient(HANDLE hPipe)
{
    std::cout << "[Agent] Waiting for Python client on pipe...\n";
    BOOL ok = ConnectNamedPipe(hPipe, nullptr);
    if (!ok)
    {
        DWORD err = GetLastError();
        if (err == ERROR_PIPE_CONNECTED) return true;   // client was already there
        std::cerr << "[Agent] ConnectNamedPipe failed: " << err << "\n";
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// wmain
// ---------------------------------------------------------------------------
int wmain(int argc, wchar_t* argv[])
{
    // Diagnostics go through the NARROW stream deliberately. std::wcout enters a
    // permanent fail state the first time it meets a non-ASCII character under
    // the default C locale, which silently swallows every message after it.
    SetConsoleOutputCP(CP_UTF8);

    // ── Command line ──────────────────────────────────────────────────────
    //   --watch-dir <path>   directory to monitor (default: Public\Documents)
    //   --no-etw             force the legacy heuristic (A/B benchmarking)
    std::wstring watchDir = DEFAULT_WATCH_DIR;
    bool useEtw = true;

    for (int i = 1; i < argc; ++i)
    {
        std::wstring a = argv[i];
        if (a == L"--no-etw")
        {
            useEtw = false;
        }
        else if (a == L"--watch-dir" && i + 1 < argc)
        {
            watchDir = argv[++i];
        }
        else if (a == L"--help" || a == L"-h")
        {
            std::cout << "Usage: monitor_agent.exe [--watch-dir <path>] [--no-etw]\n";
            return 0;
        }
        else
        {
            std::cerr << "[Agent] Unknown argument: " << WideToUtf8(a) << "\n";
            return 2;
        }
    }
    const wchar_t* WATCH_DIR = watchDir.c_str();

    std::cout << "+------------------------------------------+\n";
    std::cout << "|  Hybrid Security Suite - Monitor Agent   |\n";
    std::cout << "+------------------------------------------+\n\n";
    std::cout << "[Agent] Watch directory : " << WideToUtf8(WATCH_DIR) << "\n";
    std::cout << "[Agent] Named Pipe      : " << WideToUtf8(PIPE_NAME) << "\n";

    // ── 0. Start ETW process attribution (degrades gracefully) ────────────
    // Set HSS_ETW_DEBUG=1 to print per-event ETW diagnostics (parsed/cached
    // counts + a sample cached path) so attribution failures can be pinpointed.
    const bool etwDebug = (std::getenv("HSS_ETW_DEBUG") != nullptr);
    etw::Attributor attributor;
    if (!useEtw)
    {
        std::cout << "[Agent] PID attribution : HEURISTIC (forced via --no-etw)\n\n";
    }
    else if (attributor.Start())
    {
        std::cout << "[Agent] PID attribution : ETW (Microsoft-Windows-Kernel-File)\n\n";
    }
    else
    {
        std::cout << "[Agent] PID attribution : HEURISTIC fallback\n"
                  << "[Agent]   reason        : "
                  << WideToUtf8(attributor.status()) << "\n\n";
    }
    std::cout.flush();

    // ── 1. Open the directory ─────────────────────────────────────────────
    HANDLE hDir = CreateFileW(
        WATCH_DIR,
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        nullptr);

    if (hDir == INVALID_HANDLE_VALUE)
    {
        std::cerr << "[Agent] FATAL: Cannot open watch directory ("
                  << GetLastError() << ").\n"
                  << "       Make sure '" << WideToUtf8(WATCH_DIR) << "' exists.\n";
        return 1;
    }

    // ── 2. Create Named Pipe (server end, outbound) ───────────────────────
    HANDLE hPipe = CreateNamedPipeW(
        PIPE_NAME,
        PIPE_ACCESS_OUTBOUND,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        8192,   // outbound buffer
        0,      // inbound buffer (write-only pipe)
        CONNECT_WAIT,
        nullptr);

    if (hPipe == INVALID_HANDLE_VALUE)
    {
        std::cerr << "[Agent] FATAL: CreateNamedPipe failed ("
                   << GetLastError() << ").\n";
        CloseHandle(hDir);
        return 1;
    }

    if (!WaitForClient(hPipe))
    {
        CloseHandle(hPipe);
        CloseHandle(hDir);
        return 1;
    }
    std::cout << "[Agent] Python client connected – monitoring started.\n\n";

    // ── 3. Set up overlapped I/O for RDCW ─────────────────────────────────
    std::vector<BYTE> buf(BUF_SIZE, 0);
    OVERLAPPED        ov{};
    ov.hEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent)
    {
        std::cerr << "[Agent] CreateEvent failed (" << GetLastError() << ").\n";
        CloseHandle(hPipe);
        CloseHandle(hDir);
        return 1;
    }

    // ── 4. Main watch loop ────────────────────────────────────────────────
    bool running = true;
    while (running)
    {
        ResetEvent(ov.hEvent);

        BOOL issued = ReadDirectoryChangesW(
            hDir,
            buf.data(),
            BUF_SIZE,
            TRUE,   // watch subtree
            FILE_NOTIFY_CHANGE_FILE_NAME  |
            FILE_NOTIFY_CHANGE_DIR_NAME   |
            FILE_NOTIFY_CHANGE_ATTRIBUTES |
            FILE_NOTIFY_CHANGE_SIZE       |
            FILE_NOTIFY_CHANGE_LAST_WRITE |
            FILE_NOTIFY_CHANGE_CREATION,
            nullptr,    // lpBytesReturned – must be null with overlapped I/O
            &ov,
            nullptr);

        if (!issued)
        {
            std::cerr << "[Agent] ReadDirectoryChangesW failed ("
                       << GetLastError() << ").\n";
            break;
        }

        // Block until notification arrives
        DWORD bytesRet = 0;
        if (!GetOverlappedResult(hDir, &ov, &bytesRet, TRUE /*wait*/))
            break;

        if (bytesRet == 0) continue;   // overflow – retry

        // ── 5. Walk the notification records ──────────────────────────────
        BYTE* ptr = buf.data();
        for (;;)
        {
            auto* fni = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(ptr);

            // We care about creations, deletions and writes (classic ransomware signature).
            //
            // RENAMED_OLD_NAME matters as much as RENAMED_NEW_NAME: a rename is
            // reported as a pair, and only the OLD record names the file as it
            // existed before. Dropping it meant a renamed canary was never seen
            // as a canary at all — only the new, unknown name arrived — so the
            // rename family of ransomware walked straight past the decoy layer.
            if (fni->Action == FILE_ACTION_ADDED            ||
                fni->Action == FILE_ACTION_MODIFIED         ||
                fni->Action == FILE_ACTION_RENAMED_NEW_NAME ||
                fni->Action == FILE_ACTION_RENAMED_OLD_NAME ||
                fni->Action == FILE_ACTION_REMOVED)
            {
                std::wstring relName(fni->FileName,
                                     fni->FileNameLength / sizeof(wchar_t));
                std::wstring fullPath =
                    std::wstring(WATCH_DIR) + L"\\" + relName;

                // Prefer the true originating PID observed by ETW; fall back to
                // the legacy heuristic when ETW is off or has no recent record.
                // ETW delivers its kernel events a beat later than RDCW, so wait
                // briefly (bounded) for the record to arrive before giving up.
                const char* source = "ETW";
                DWORD pid = attributor.LookupPid(fullPath);
                if (pid == 0 && attributor.active())
                {
                    for (int i = 0; i < ETW_RESOLVE_TRIES && pid == 0; ++i)
                    {
                        Sleep(ETW_RESOLVE_STEP_MS);
                        pid = attributor.LookupPid(fullPath);
                    }
                }
                const bool etwHit = (pid != 0);
                if (pid == 0)
                {
                    pid    = GetLikelyPid();
                    source = "HEUR";
                }

                if (etwDebug)
                {
                    std::cout << "[ETWDBG] hit=" << (etwHit ? 1 : 0)
                              << " parsed=" << attributor.events()
                              << " cached=" << attributor.cacheSize()
                              << " look="   << WideToUtf8(fullPath)
                              << " sample=" << WideToUtf8(attributor.sampleKey())
                              << "\n";
                    std::cout.flush();
                }

                // Build the pipe message
                std::ostringstream oss;
                oss << WideToUtf8(fullPath) << "|" << pid << "|" << source;
                std::string eventLine = oss.str();

                // Echo locally for diagnostics
                std::cout << "[EVENT] " << eventLine << "\n";
                std::cout.flush();

                // Send to pipe; on failure attempt reconnect once
                if (!WriteLineToPipe(hPipe, eventLine))
                {
                    std::cout
                        << "[Agent] Pipe write failed – reconnecting...\n";
                    DisconnectNamedPipe(hPipe);
                    if (WaitForClient(hPipe))
                        WriteLineToPipe(hPipe, eventLine);  // retry
                    else
                    {
                        running = false;
                        break;
                    }
                }
            }

            if (fni->NextEntryOffset == 0) break;
            ptr += fni->NextEntryOffset;
        }
    }

    // ── 6. Clean up ───────────────────────────────────────────────────────
    std::cout << "\n[Agent] Shutting down.\n";
    if (attributor.active())
        std::cout << "[Agent] ETW events attributed: " << attributor.events() << "\n";
    attributor.Stop();
    CloseHandle(ov.hEvent);
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
    CloseHandle(hDir);
    return 0;
}
