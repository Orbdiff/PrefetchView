#include <windows.h>
#include <string>
#include <sstream>

struct PrefetchParametersData
{
    DWORD enablePrefetcher{};
    DWORD enableSuperfetch{};
    FILETIME lastWriteTime{};
};

inline std::wstring InterpretPrefetchValue(DWORD value)
{
    switch (value)
    {
    case 0: return L"0 (Disabled)";
    case 1: return L"1 (Boot Only)";
    case 2: return L"2 (Application Only)";
    case 3: return L"3 (Enabled)";
    default:
        return std::to_wstring(value) + L" (Unknown)";
    }
}

inline void RegistryPrefetchParameters(std::wstringstream& out)
{
    constexpr wchar_t REG_PATH[] =
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters";

    HKEY hKey{};
    if (RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        REG_PATH,
        0,
        KEY_READ,
        &hKey) != ERROR_SUCCESS)
    {
        out << L"[ERROR] Failed to open registry key\n";
        return;
    }

    PrefetchParametersData data{};
    DWORD size = sizeof(DWORD);

    RegQueryValueExW(
        hKey,
        L"EnablePrefetcher",
        nullptr,
        nullptr,
        reinterpret_cast<LPBYTE>(&data.enablePrefetcher),
        &size);

    size = sizeof(DWORD);
    RegQueryValueExW(
        hKey,
        L"EnableSuperfetch",
        nullptr,
        nullptr,
        reinterpret_cast<LPBYTE>(&data.enableSuperfetch),
        &size);

    RegQueryInfoKeyW(
        hKey,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        &data.lastWriteTime);

    RegCloseKey(hKey);

    SYSTEMTIME utc{}, local{};
    FileTimeToSystemTime(&data.lastWriteTime, &utc);
    SystemTimeToTzSpecificLocalTime(nullptr, &utc, &local);

    out << L"[/] Verifying Registry Prefetch Parameters\n\n";

    out << L"[+] EnablePrefetcher : " << InterpretPrefetchValue(data.enablePrefetcher) << L"\n";

    out << L"[+] EnableSuperfetch : " << InterpretPrefetchValue(data.enableSuperfetch) << L"\n";

    out << L"[#] Modified Time    : "
        << local.wYear << L"-"
        << local.wMonth << L"-"
        << local.wDay << L" "
        << local.wHour << L":"
        << local.wMinute << L":"
        << local.wSecond << L"\n\n";

    out << L"Note: The modification time belongs to the registry key, it may change whenever any value in the key is modified.\n";
}