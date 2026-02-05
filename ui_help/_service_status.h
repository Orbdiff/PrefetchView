#pragma once

#include <windows.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <optional>
#include "_time_utils.h"

struct SCHandleGuard
{
    SC_HANDLE h;
    SCHandleGuard(SC_HANDLE handle) : h(handle) {}
    SCHandleGuard(const SCHandleGuard&) = delete;
    SCHandleGuard& operator=(const SCHandleGuard&) = delete;
    ~SCHandleGuard() { if (h) CloseServiceHandle(h); }
    SC_HANDLE get() const { return h; }
};

struct HandleGuard
{
    HANDLE h;
    HandleGuard(HANDLE handle) : h(handle) {}
    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
    ~HandleGuard() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    HANDLE get() const { return h; }
};

struct ServiceInfo
{
    DWORD pid = 0;
    std::string status;
    std::string uptime;
    bool delayedStart = false;
    time_t logonTime = 0;
    std::string logonTimeStr;
};

std::vector<ServiceInfo> GetSysMainInfo()
{
    std::vector<ServiceInfo> services;
    constexpr double DELAYED_START_THRESHOLD_SECONDS = 80.0;

    time_t logonTime = GetCurrentUserLogonTime();

    SCHandleGuard scm(OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm.get()) 
    {
        return services;
    }

    SCHandleGuard service(OpenService(scm.get(), L"SysMain", SERVICE_QUERY_STATUS));
    if (!service.get()) 
    {
        return services;
    }

    SERVICE_STATUS_PROCESS ssp{};
    DWORD bytesNeeded = 0;
    if (!QueryServiceStatusEx(service.get(), SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytesNeeded))
    {
        return services;
    }

    ServiceInfo info{};
    info.pid = ssp.dwProcessId;
    info.status = (ssp.dwCurrentState == SERVICE_RUNNING ? "Running" : "Stopped");
    info.delayedStart = false;
    info.logonTime = logonTime;
    info.logonTimeStr = FormatTime(logonTime);

    if (ssp.dwCurrentState == SERVICE_RUNNING && ssp.dwProcessId != 0)
    {
        HandleGuard hProcess(OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ssp.dwProcessId));
        if (hProcess.get()) 
        {
            FILETIME ftCreate{}, ftExit{}, ftKernel{}, ftUser{};
            if (GetProcessTimes(hProcess.get(), &ftCreate, &ftExit, &ftKernel, &ftUser))
            {
                time_t sysmainStart = FileTimeToTimeT(ftCreate);
                info.uptime = FormatUptime(sysmainStart);

                if (difftime(sysmainStart, logonTime) > DELAYED_START_THRESHOLD_SECONDS) 
                {
                    info.delayedStart = true;
                }
            }
        }
    }

    services.push_back(info);
    return services;
}