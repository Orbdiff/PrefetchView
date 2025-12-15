#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <iostream>

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

inline void SysmainThreadSechost()
{
    std::cout << "\n============================\n\n";

    SechostMainThreadInfo info{};

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm)
    {
        std::cout << "[!] OpenSCManager failed\n";
        return;
    }

    SC_HANDLE svc = OpenServiceW(scm, L"SysMain", SERVICE_QUERY_STATUS);
    if (!svc)
    {
        std::cout << "[!] SysMain not found\n";
        CloseServiceHandle(scm);
        return;
    }

    SERVICE_STATUS_PROCESS ssp{};
    DWORD needed = 0;

    if (!QueryServiceStatusEx(
        svc,
        SC_STATUS_PROCESS_INFO,
        (LPBYTE)&ssp,
        sizeof(ssp),
        &needed) ||
        ssp.dwCurrentState != SERVICE_RUNNING)
    {
        std::cout << "[!] SysMain not running\n";
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return;
    }

    info.pid = ssp.dwProcessId;
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    HANDLE modSnap = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        info.pid
    );

    if (modSnap == INVALID_HANDLE_VALUE)
    {
        std::cout << "[!] Module snapshot failed\n";
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
                info.sechostBase = (uintptr_t)me.modBaseAddr;
                info.sechostEnd = info.sechostBase + me.modBaseSize;
                foundSechost = true;
                break;
            }
        } while (Module32NextW(modSnap, &me));
    }

    CloseHandle(modSnap);

    if (!foundSechost)
    {
        std::cout << "[!] sechost.dll not found\n";
        return;
    }

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll)
    {
        std::cout << "[!] ntdll.dll not loaded\n";
        return;
    }

    auto NtQueryInformationThread =
        reinterpret_cast<NtQueryInformationThread_t>(
            GetProcAddress(hNtdll, "NtQueryInformationThread")
            );

    if (!NtQueryInformationThread)
    {
        std::cout << "[!] NtQueryInformationThread not found\n";
        return;
    }

    HANDLE thSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (thSnap == INVALID_HANDLE_VALUE)
    {
        std::cout << "[!] Thread snapshot failed\n";
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
                te.th32ThreadID
            );

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
                uintptr_t addr = (uintptr_t)startAddr;

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
        std::cout << "[!] No sechost.dll threads found\n";
        return;
    }

    HANDLE hThread = OpenThread(
        THREAD_QUERY_INFORMATION,
        FALSE,
        info.targetTID
    );

    if (!hThread)
    {
        std::cout << "[!] Failed to open target thread\n";
        return;
    }

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    const WORD greenColor = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    const WORD redColor = FOREGROUND_RED | FOREGROUND_INTENSITY;
    const WORD whiteColor = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;

    SetConsoleTextAttribute(hConsole, greenColor);
    std::cout << "[+] Monitoring sechost.dll main thread\n";
    SetConsoleTextAttribute(hConsole, whiteColor);
    std::cout << "    PID: " << info.pid << "\n";
    std::cout << "    TID: " << info.targetTID << "\n";
    std::cout << "    Initial cycles: " << info.initialCycles << "\n";

    Sleep(10000);

    QueryThreadCycleTime(hThread, &info.finalCycles);

    info.deltaCycles = info.finalCycles - info.initialCycles;
    info.isActive = (info.deltaCycles > 0);

    std::cout << "    Final cycles: " << info.finalCycles << "\n";
    std::cout << "    Delta: " << info.deltaCycles << "\n";
    std::cout << "    State: " << (info.isActive ? "Active" : "Suspended") << "\n";

    SetConsoleTextAttribute(hConsole, redColor);
    std::cout << "\n[!] This detection is based on thread cycle delta, for additional assurance check manually in system informer sysmain threads\n";

    SetConsoleTextAttribute(hConsole, whiteColor);

    CloseHandle(hThread);
}