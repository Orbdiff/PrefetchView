#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <sstream>

#ifndef ThreadQuerySetWin32StartAddress
#define ThreadQuerySetWin32StartAddress (THREADINFOCLASS)9
#endif

using NtQueryInformationThread_t =
NTSTATUS(NTAPI*)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);

struct SechostMainThreadInfo
{
    DWORD pid = 0;
    uintptr_t sechostBase = 0;
    uintptr_t sechostEnd = 0;

    DWORD targetTID = 0;
    ULONG64 initialCycles = 0;
    ULONG64 finalCycles = 0;
    ULONG64 deltaCycles = 0;
    bool isActive = false;
};

inline void SysmainThreadSechost(std::wstringstream& out)
{
    SechostMainThreadInfo info{};

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm)
    {
        out << L"[ERROR] OpenSCManager failed\n";
        return;
    }

    SC_HANDLE svc = OpenServiceW(scm, L"SysMain", SERVICE_QUERY_STATUS);
    if (!svc)
    {
        out << L"[ERROR] SysMain service not found\n";
        CloseServiceHandle(scm);
        return;
    }

    SERVICE_STATUS_PROCESS ssp{};
    DWORD needed = 0;

    if (!QueryServiceStatusEx(
        svc,
        SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&ssp),
        sizeof(ssp),
        &needed) ||
        ssp.dwCurrentState != SERVICE_RUNNING)
    {
        out << L"[ERROR] SysMain service is not running\n";
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return;
    }

    info.pid = ssp.dwProcessId;
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    HANDLE modSnap = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        info.pid);

    if (modSnap == INVALID_HANDLE_VALUE)
    {
        out << L"[ERROR] Module snapshot failed\n";
        return;
    }

    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    bool foundSechost = false;

    if (Module32FirstW(modSnap, &me))
    {
        do
        {
            if (!_wcsicmp(me.szModule, L"sechost.dll"))
            {
                info.sechostBase = reinterpret_cast<uintptr_t>(me.modBaseAddr);
                info.sechostEnd = info.sechostBase + me.modBaseSize;
                foundSechost = true;
                break;
            }
        } while (Module32NextW(modSnap, &me));
    }

    CloseHandle(modSnap);

    if (!foundSechost)
    {
        out << L"[ERROR] sechost.dll not found in SysMain process\n";
        return;
    }

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll)
    {
        out << L"[ERROR] ntdll.dll not loaded\n";
        return;
    }

    auto NtQueryInformationThread =
        reinterpret_cast<NtQueryInformationThread_t>(
            GetProcAddress(hNtdll, "NtQueryInformationThread"));

    if (!NtQueryInformationThread)
    {
        out << L"[ERROR] NtQueryInformationThread not found\n";
        return;
    }

    HANDLE thSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (thSnap == INVALID_HANDLE_VALUE)
    {
        out << L"[ERROR] Thread snapshot failed\n";
        return;
    }

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    ULONG64 maxCycles = 0;

    if (Thread32First(thSnap, &te))
    {
        do
        {
            if (te.th32OwnerProcessID != info.pid)
                continue;

            HANDLE hThread = OpenThread(
                THREAD_QUERY_INFORMATION,
                FALSE,
                te.th32ThreadID);

            if (!hThread)
                continue;

            void* startAddr = nullptr;

            if (NT_SUCCESS(
                NtQueryInformationThread(
                    hThread,
                    ThreadQuerySetWin32StartAddress,
                    &startAddr,
                    sizeof(startAddr),
                    nullptr)))
            {
                uintptr_t addr = reinterpret_cast<uintptr_t>(startAddr);

                if (addr >= info.sechostBase && addr < info.sechostEnd)
                {
                    ULONG64 cycles = 0;
                    QueryThreadCycleTime(hThread, &cycles);

                    if (cycles > maxCycles)
                    {
                        maxCycles = cycles;
                        info.targetTID = te.th32ThreadID;
                        info.initialCycles = cycles;
                    }
                }
            }

            CloseHandle(hThread);

        } while (Thread32Next(thSnap, &te));
    }

    CloseHandle(thSnap);

    if (!info.targetTID)
    {
        out << L"[ERROR] No sechost.dll threads found\n";
        return;
    }

    HANDLE hThread = OpenThread(
        THREAD_QUERY_INFORMATION,
        FALSE,
        info.targetTID);

    if (!hThread)
    {
        out << L"[ERROR] Failed to open target thread\n";
        return;
    }

    out << L"\n[+] Monitoring sechost.dll main thread\n";
    out << L"    PID             : " << info.pid << L"\n";
    out << L"    TID             : " << info.targetTID << L"\n";
    out << L"    Initial cycles  : " << info.initialCycles << L"\n";

    Sleep(10000);

    QueryThreadCycleTime(hThread, &info.finalCycles);

    info.deltaCycles = info.finalCycles - info.initialCycles;
    info.isActive = (info.deltaCycles > 0);

    out << L"    Final cycles    : " << info.finalCycles << L"\n";
    out << L"    Delta cycles    : " << info.deltaCycles << L"\n";
    out << L"    State           : "
        << (info.isActive ? L"Active" : L"Suspended") << L"\n\n";

    out << L"Note: Detection is based on thread cycle delta, for higher confidence, verify manually using System Informer.\n";

    CloseHandle(hThread);
}