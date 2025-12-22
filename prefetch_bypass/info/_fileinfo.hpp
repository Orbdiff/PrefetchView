#include <windows.h>
#include <winternl.h>
#include <sstream>
#include <string>
#include <vector>

#ifndef SystemModuleInformation
#define SystemModuleInformation 11
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)
#endif

struct ServiceStatus
{
    std::wstring name;
    std::wstring status;
};

struct SYSTEM_MODULE_ENTRY
{
    PVOID  Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    CHAR   ImageName[256];
};

struct SYSTEM_MODULE_INFORMATION
{
    ULONG NumberOfModules;
    SYSTEM_MODULE_ENTRY Modules[1];
};

inline bool IsDriverLoaded(const std::string& driverName)
{
    ULONG size = 0;
    NTSTATUS status = NtQuerySystemInformation(
        (SYSTEM_INFORMATION_CLASS)SystemModuleInformation,
        nullptr, 0, &size);

    if (status != STATUS_INFO_LENGTH_MISMATCH)
        return false;

    std::vector<BYTE> buffer(size);
    auto info = reinterpret_cast<SYSTEM_MODULE_INFORMATION*>(buffer.data());

    status = NtQuerySystemInformation(
        (SYSTEM_INFORMATION_CLASS)SystemModuleInformation,
        info, size, &size);

    if (status != 0)
        return false;

    for (ULONG i = 0; i < info->NumberOfModules; ++i)
    {
        std::string modName =
            info->Modules[i].ImageName + info->Modules[i].ModuleNameOffset;

        if (_stricmp(modName.c_str(), driverName.c_str()) == 0)
            return true;
    }

    return false;
}

inline void FileInfoStatus(std::wstringstream& out)
{
    out << L"\n[/] FileInfo: Service / Driver / Events\n\n";

    const std::wstring serviceName = L"FileInfo";
    ServiceStatus svc{};
    svc.name = serviceName;

    SC_HANDLE hSCManager =
        OpenSCManager(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);

    if (!hSCManager)
    {
        out << L"[ERROR] Failed to open SC Manager. Error: "
            << GetLastError() << L"\n";
        return;
    }

    SC_HANDLE hService =
        OpenServiceW(hSCManager, serviceName.c_str(), SERVICE_QUERY_STATUS);

    if (!hService)
    {
        out << L"[ERROR] Failed to open service. Error: "
            << GetLastError() << L"\n";

        CloseServiceHandle(hSCManager);
        return;
    }

    SERVICE_STATUS_PROCESS ssp{};
    DWORD bytesNeeded = 0;

    if (QueryServiceStatusEx(
        hService,
        SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&ssp),
        sizeof(ssp),
        &bytesNeeded))
    {
        switch (ssp.dwCurrentState)
        {
        case SERVICE_STOPPED:
            svc.status = L"Stopped";
            break;
        case SERVICE_RUNNING:
            svc.status = L"Running";
            break;
        default:
            svc.status = L"Other";
            break;
        }

        out << L"[SERVICE] " << svc.name
            << L" status: " << svc.status << L"\n";
    }
    else
    {
        out << L"[ERROR] Failed to query service status. Error: "
            << GetLastError() << L"\n";
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    const std::string driver = "FileInfo.sys";
    bool loaded = IsDriverLoaded(driver);

    out << L"[DRIVER] Driver "
        << std::wstring(driver.begin(), driver.end());

    if (loaded)
        out << L" is loaded in the kernel.\n";
    else
        out << L" is NOT loaded in the kernel.\n";
}