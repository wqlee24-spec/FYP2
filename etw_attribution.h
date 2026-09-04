// =============================================================================
//  etw_attribution.h  –  Hybrid Security Suite · ETW Process Attribution
// =============================================================================
//
//  PURPOSE
//  -------
//  ReadDirectoryChangesW tells us *what* file changed but never *who* changed
//  it. The original workaround (GetLikelyPid) guessed at the most recently
//  spawned user process, which is frequently wrong — often naming the agent
//  itself. That inaccuracy is why containment had to be environmental
//  (icacls directory lockdown) rather than process-targeted.
//
//  This module closes that gap from user space. It consumes the
//  Microsoft-Windows-Kernel-File ETW provider, which reports the true
//  originating process id in each event header, and maintains a short-lived
//  cache mapping   normalised file path -> (pid, timestamp).
//
//  The RDCW loop remains the event trigger; this cache is consulted purely to
//  answer "which process touched this path just now?". When ETW is
//  unavailable (not elevated, provider blocked) every lookup simply misses and
//  the caller falls back to the old heuristic — the agent never hard-fails.
//
//  DESIGN NOTES
//  ------------
//  * No kernel driver. ETW is consumed entirely from user mode, preserving the
//    project's deployability constraint.
//  * ETW reports NT device paths (\Device\HarddiskVolume3\...). We build a
//    device -> drive-letter map at startup so paths can be compared against the
//    DOS paths RDCW produces.
//  * Write/SetInformation events carry a FileObject rather than a name, so
//    Create events are used to learn FileObject -> path first.
//  * All maps are bounded and age-pruned; this runs for the life of the agent.
//
//  Requires: -ltdh -ladvapi32   (headers ship with both MSVC and MinGW-w64)
//
// =============================================================================

#pragma once

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#include <algorithm>
#include <atomic>
#include <cwctype>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#if defined(_MSC_VER)
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")
#endif

namespace etw {

// ── Provider: Microsoft-Windows-Kernel-File ──────────────────────────────────
// {EDD08927-9CC4-4E65-B970-C2560FB5C289}
static const GUID kKernelFileProvider =
    { 0xEDD08927, 0x9CC4, 0x4E65, { 0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89 } };

// Keywords (see KERNEL_FILE_KEYWORD_* in the provider manifest)
static const ULONGLONG KW_CREATE                = 0x0080;
static const ULONGLONG KW_WRITE                 = 0x0200;
static const ULONGLONG KW_DELETE_PATH           = 0x0400;
static const ULONGLONG KW_RENAME_SETLINK_PATH   = 0x0800;
static const ULONGLONG KW_CREATE_NEW_FILE       = 0x1000;

// Event IDs we care about
enum : USHORT {
    EVT_CREATE          = 12,
    EVT_CLOSE           = 14,
    EVT_WRITE           = 16,
    EVT_SET_INFORMATION = 17,
    EVT_SET_DELETE      = 18,
    EVT_DELETE_PATH     = 26,
    EVT_RENAME_PATH     = 27,
    EVT_SET_LINK_PATH   = 28,
    EVT_RENAME_29       = 29,
    EVT_CREATE_NEW_FILE = 30,
};

static const wchar_t* kSessionName = L"HSS_KernelFile_Session";

// Cache tuning
static const size_t kMaxPathEntries   = 8192;
static const size_t kMaxObjectEntries = 8192;
static const DWORD  kDefaultMaxAgeMs  = 2000;

// ── Small helpers ────────────────────────────────────────────────────────────

inline std::wstring ToLower(std::wstring s)
{
    std::transform(s.begin(), s.end(), s.begin(),
                   [](wchar_t c) { return (wchar_t)std::towlower(c); });
    return s;
}

/// Read a UNICODE_STRING/string property out of an event via TDH.
inline bool GetPropString(PEVENT_RECORD rec, const wchar_t* name, std::wstring& out)
{
    PROPERTY_DATA_DESCRIPTOR pdd{};
    pdd.PropertyName = (ULONGLONG)(ULONG_PTR)name;
    pdd.ArrayIndex   = ULONG_MAX;

    ULONG size = 0;
    if (TdhGetPropertySize(rec, 0, nullptr, 1, &pdd, &size) != ERROR_SUCCESS || size == 0)
        return false;

    std::vector<BYTE> buf(size, 0);
    if (TdhGetProperty(rec, 0, nullptr, 1, &pdd, size, buf.data()) != ERROR_SUCCESS)
        return false;

    out.assign(reinterpret_cast<const wchar_t*>(buf.data()), size / sizeof(wchar_t));
    while (!out.empty() && out.back() == L'\0') out.pop_back();
    return !out.empty();
}

/// Read a pointer/integer property (FileObject, FileKey) via TDH.
inline bool GetPropU64(PEVENT_RECORD rec, const wchar_t* name, ULONGLONG& out)
{
    PROPERTY_DATA_DESCRIPTOR pdd{};
    pdd.PropertyName = (ULONGLONG)(ULONG_PTR)name;
    pdd.ArrayIndex   = ULONG_MAX;

    ULONG size = 0;
    if (TdhGetPropertySize(rec, 0, nullptr, 1, &pdd, &size) != ERROR_SUCCESS)
        return false;

    if (size == sizeof(ULONGLONG))
    {
        ULONGLONG v = 0;
        if (TdhGetProperty(rec, 0, nullptr, 1, &pdd, size, (PBYTE)&v) != ERROR_SUCCESS)
            return false;
        out = v;
        return true;
    }
    if (size == sizeof(ULONG))
    {
        ULONG v = 0;
        if (TdhGetProperty(rec, 0, nullptr, 1, &pdd, size, (PBYTE)&v) != ERROR_SUCCESS)
            return false;
        out = v;
        return true;
    }
    return false;
}

// =============================================================================
// Attributor
// =============================================================================
class Attributor
{
public:
    Attributor() = default;
    ~Attributor() { Stop(); }

    Attributor(const Attributor&)            = delete;
    Attributor& operator=(const Attributor&) = delete;

    /// True once the provider is enabled and events are flowing.
    bool active() const { return _active.load(); }

    /// Human-readable reason the module is inactive (for agent diagnostics).
    std::wstring status() const
    {
        std::lock_guard<std::mutex> lk(_statusMx);
        return _status;
    }

    /// Number of ETW events successfully attributed since start (diagnostics).
    unsigned long long events() const { return _eventCount.load(); }

    // Diagnostics: how many distinct paths are currently cached, and a sample
    // key, so the agent can compare ETW's path form against the RDCW path form.
    size_t cacheSize() const
    {
        std::lock_guard<std::mutex> lk(_mx);
        return _pathToPid.size();
    }
    std::wstring sampleKey() const
    {
        std::lock_guard<std::mutex> lk(_mx);
        return _pathToPid.empty() ? std::wstring() : _pathToPid.begin()->first;
    }

    // ── Lifecycle ────────────────────────────────────────────────────────────

    /// Start the trace session. Returns false (with status() set) if ETW is
    /// unavailable — the caller is expected to continue with its fallback.
    bool Start()
    {
        if (_active.load()) return true;

        _self = GetCurrentProcessId();
        BuildDeviceMap();

        if (!StartSession())  return false;
        if (!EnableProvider()) { StopSession(); return false; }
        if (!OpenConsumer())   { StopSession(); return false; }

        _running.store(true);
        _worker = std::thread([this] { ConsumeLoop(); });
        _active.store(true);
        SetStatus(L"active");
        return true;
    }

    void Stop()
    {
        if (!_running.exchange(false)) { StopSession(); return; }

        // Closing the consumer handle makes the blocking ProcessTrace return.
        if (_consumer != INVALID_PROCESSTRACE_HANDLE)
        {
            CloseTrace(_consumer);
            _consumer = INVALID_PROCESSTRACE_HANDLE;
        }
        StopSession();

        if (_worker.joinable()) _worker.join();
        _active.store(false);
    }

    // ── Query ────────────────────────────────────────────────────────────────

    /// Look up the process that recently touched `dosPath`.
    /// Returns 0 when there is no sufficiently recent ETW observation.
    DWORD LookupPid(const std::wstring& dosPath, DWORD maxAgeMs = kDefaultMaxAgeMs)
    {
        if (!_active.load()) return 0;

        const std::wstring key = ToLower(dosPath);
        const ULONGLONG now = GetTickCount64();

        std::lock_guard<std::mutex> lk(_mx);
        auto it = _pathToPid.find(key);
        if (it == _pathToPid.end()) return 0;
        if (now - it->second.tick > maxAgeMs) return 0;
        return it->second.pid;
    }

private:
    struct PidStamp { DWORD pid; ULONGLONG tick; };

    // ── Session management ───────────────────────────────────────────────────

    std::vector<BYTE> MakeProps() const
    {
        const size_t nameBytes = (wcslen(kSessionName) + 1) * sizeof(wchar_t);
        const size_t total = sizeof(EVENT_TRACE_PROPERTIES) + nameBytes + 256;

        std::vector<BYTE> blob(total, 0);
        auto* p = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(blob.data());
        p->Wnode.BufferSize    = (ULONG)total;
        p->Wnode.ClientContext = 1;                       // QPC clock
        p->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
        p->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
        p->LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);
        p->BufferSize          = 8;                       // KB per buffer — small
                                                          // so bursts flush fast
        p->MinimumBuffers      = 4;
        p->MaximumBuffers      = 16;
        p->FlushTimer          = 1;                       // 1 s — the minimum, caps
                                                          // idle real-time latency
        return blob;
    }

    bool StartSession()
    {
        auto props = MakeProps();
        auto* p = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(props.data());

        ULONG st = StartTraceW(&_session, kSessionName, p);

        if (st == ERROR_ALREADY_EXISTS)
        {
            // A previous run left the session behind — stop and retry once.
            auto stopProps = MakeProps();
            ControlTraceW(0, kSessionName,
                          reinterpret_cast<EVENT_TRACE_PROPERTIES*>(stopProps.data()),
                          EVENT_TRACE_CONTROL_STOP);

            auto retry = MakeProps();
            st = StartTraceW(&_session, kSessionName,
                             reinterpret_cast<EVENT_TRACE_PROPERTIES*>(retry.data()));
        }

        if (st != ERROR_SUCCESS)
        {
            SetStatus(st == ERROR_ACCESS_DENIED
                          ? L"unavailable: StartTrace denied (run as Administrator)"
                          : L"unavailable: StartTrace failed (" + std::to_wstring(st) + L")");
            _session = 0;
            return false;
        }
        return true;
    }

    bool EnableProvider()
    {
        const ULONGLONG keywords = KW_CREATE | KW_WRITE | KW_DELETE_PATH |
                                   KW_RENAME_SETLINK_PATH | KW_CREATE_NEW_FILE;

        ULONG st = EnableTraceEx2(
            _session, &kKernelFileProvider,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_INFORMATION,
            keywords, 0, 0, nullptr);

        if (st != ERROR_SUCCESS)
        {
            SetStatus(st == ERROR_ACCESS_DENIED
                          ? L"unavailable: kernel provider denied (run as Administrator)"
                          : L"unavailable: EnableTraceEx2 failed (" + std::to_wstring(st) + L")");
            return false;
        }
        return true;
    }

    bool OpenConsumer()
    {
        EVENT_TRACE_LOGFILEW lf{};
        lf.LoggerName          = const_cast<LPWSTR>(kSessionName);
        lf.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME |
                                 PROCESS_TRACE_MODE_EVENT_RECORD;
        lf.EventRecordCallback = &Attributor::EventCallbackThunk;
        lf.Context             = this;

        _consumer = OpenTraceW(&lf);
        if (_consumer == INVALID_PROCESSTRACE_HANDLE)
        {
            SetStatus(L"unavailable: OpenTrace failed (" +
                      std::to_wstring(GetLastError()) + L")");
            return false;
        }
        return true;
    }

    void StopSession()
    {
        if (_session)
        {
            EnableTraceEx2(_session, &kKernelFileProvider,
                           EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                           0, 0, 0, 0, nullptr);

            auto props = MakeProps();
            ControlTraceW(_session, kSessionName,
                          reinterpret_cast<EVENT_TRACE_PROPERTIES*>(props.data()),
                          EVENT_TRACE_CONTROL_STOP);
            _session = 0;
        }
    }

    void ConsumeLoop()
    {
        // Blocks until CloseTrace() is called from Stop().
        ProcessTrace(&_consumer, 1, nullptr, nullptr);
    }

    // ── Event handling ───────────────────────────────────────────────────────

    static void WINAPI EventCallbackThunk(PEVENT_RECORD rec)
    {
        if (rec && rec->UserContext)
            static_cast<Attributor*>(rec->UserContext)->OnEvent(rec);
    }

    void OnEvent(PEVENT_RECORD rec)
    {
        const DWORD pid = rec->EventHeader.ProcessId;

        // Ignore our own I/O so the agent can never be blamed for the activity
        // it is observing — the exact failure mode of the old heuristic.
        if (pid == _self || pid == 0 || pid == 4) return;

        const USHORT id = rec->EventHeader.EventDescriptor.Id;

        switch (id)
        {
        case EVT_CREATE:
        case EVT_CREATE_NEW_FILE:
        case EVT_DELETE_PATH:
        case EVT_RENAME_PATH:
        case EVT_SET_LINK_PATH:
        case EVT_RENAME_29:
        {
            std::wstring name;
            if (!GetPropString(rec, L"FileName", name)) return;

            const std::wstring dos = ToLower(NtPathToDos(name));
            ULONGLONG obj = 0;
            const bool haveObj = GetPropU64(rec, L"FileObject", obj);

            std::lock_guard<std::mutex> lk(_mx);
            Remember(dos, pid);
            if (haveObj && obj) RememberObject(obj, dos);
            break;
        }

        case EVT_WRITE:
        case EVT_SET_INFORMATION:
        case EVT_SET_DELETE:
        {
            // These carry no name — resolve via the FileObject learned at Create.
            ULONGLONG obj = 0;
            if (!GetPropU64(rec, L"FileObject", obj) || !obj) return;

            std::lock_guard<std::mutex> lk(_mx);
            auto it = _objToPath.find(obj);
            if (it == _objToPath.end()) return;
            Remember(it->second, pid);
            break;
        }

        case EVT_CLOSE:
        {
            ULONGLONG obj = 0;
            if (!GetPropU64(rec, L"FileObject", obj) || !obj) return;
            std::lock_guard<std::mutex> lk(_mx);
            _objToPath.erase(obj);
            break;
        }

        default:
            return;
        }

        _eventCount.fetch_add(1);
    }

    // Callers must hold _mx.
    void Remember(const std::wstring& dosLowerPath, DWORD pid)
    {
        if (dosLowerPath.empty()) return;
        if (_pathToPid.size() >= kMaxPathEntries) PrunePaths();
        _pathToPid[dosLowerPath] = PidStamp{ pid, GetTickCount64() };
    }

    // Callers must hold _mx.
    void RememberObject(ULONGLONG obj, const std::wstring& dosLowerPath)
    {
        if (_objToPath.size() >= kMaxObjectEntries) _objToPath.clear();
        _objToPath[obj] = dosLowerPath;
    }

    // Callers must hold _mx. Drop entries older than the lookup window.
    void PrunePaths()
    {
        const ULONGLONG now = GetTickCount64();
        for (auto it = _pathToPid.begin(); it != _pathToPid.end(); )
        {
            if (now - it->second.tick > kDefaultMaxAgeMs * 4)
                it = _pathToPid.erase(it);
            else
                ++it;
        }
        if (_pathToPid.size() >= kMaxPathEntries) _pathToPid.clear();
    }

    // ── NT device path -> DOS path ───────────────────────────────────────────

    void BuildDeviceMap()
    {
        _deviceMap.clear();
        for (wchar_t letter = L'A'; letter <= L'Z'; ++letter)
        {
            wchar_t drive[3] = { letter, L':', 0 };
            wchar_t target[MAX_PATH] = {};
            if (QueryDosDeviceW(drive, target, MAX_PATH))
                _deviceMap.emplace_back(ToLower(target), ToLower(drive));
        }
    }

    std::wstring NtPathToDos(const std::wstring& nt) const
    {
        const std::wstring low = ToLower(nt);
        for (const auto& kv : _deviceMap)
        {
            const std::wstring& dev = kv.first;
            if (low.size() > dev.size() &&
                low.compare(0, dev.size(), dev) == 0 &&
                low[dev.size()] == L'\\')
            {
                return kv.second + nt.substr(dev.size());
            }
        }
        return nt;   // already DOS-form, or an unmapped device
    }

    void SetStatus(const std::wstring& s)
    {
        std::lock_guard<std::mutex> lk(_statusMx);
        _status = s;
    }

    // ── State ────────────────────────────────────────────────────────────────

    TRACEHANDLE _session  = 0;
    TRACEHANDLE _consumer = INVALID_PROCESSTRACE_HANDLE;
    std::thread _worker;

    std::atomic<bool> _running{ false };
    std::atomic<bool> _active { false };
    std::atomic<unsigned long long> _eventCount{ 0 };
    DWORD _self = 0;

    mutable std::mutex _mx;
    std::unordered_map<std::wstring, PidStamp>    _pathToPid;
    std::unordered_map<ULONGLONG, std::wstring>   _objToPath;
    std::vector<std::pair<std::wstring, std::wstring>> _deviceMap;

    mutable std::mutex _statusMx;
    std::wstring _status = L"not started";
};

} // namespace etw
