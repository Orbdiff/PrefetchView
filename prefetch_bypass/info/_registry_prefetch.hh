#include <windows.h>
#include <iostream>
#include <string>

struct PrefetchParametersData
{
    DWORD enablePrefetcher;
    DWORD enableSuperfetch;
    FILETIME lastWriteTime;
};

inline std::wstring InterpretPrefetchValue(DWORD value)
{
    switch (value)
    {
    case 0: return L"0 (Disabled)";
    case 1: return L"1 (Boot Only)";
    case 2: return L"2 (Application Only)";
    case 3: return L"3 (Enabled)";
    default: return std::to_wstring(value) + L" (Unknown)";
    }
}

inline WORD GetColorForPrefetch(DWORD value)
{
    switch (value)
    {
    case 0: return FOREGROUND_RED | FOREGROUND_INTENSITY;
    case 1: return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    case 2: return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    case 3: return FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    default: return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    }
}

inline void RegistryPrefetchParameters()
{
    constexpr wchar_t REG_PATH[] =
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters";

    HKEY hKey{};
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_PATH, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
    {
        std::wcerr << L"[!] Failed to open registry key\n";
        return;
    }

    PrefetchParametersData data{};
    DWORD size = sizeof(DWORD);

    RegQueryValueExW(hKey, L"EnablePrefetcher", nullptr, nullptr,
        reinterpret_cast<LPBYTE>(&data.enablePrefetcher), &size);

    size = sizeof(DWORD);
    RegQueryValueExW(hKey, L"EnableSuperfetch", nullptr, nullptr,
        reinterpret_cast<LPBYTE>(&data.enableSuperfetch), &size);

    RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr, nullptr, &data.lastWriteTime);

    RegCloseKey(hKey);

    SYSTEMTIME utc{}, local{};
    FileTimeToSystemTime(&data.lastWriteTime, &utc);
    SystemTimeToTzSpecificLocalTime(nullptr, &utc, &local);

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    std::wcout << L"[/] Verifying Registry Prefetch Parameters\n";

    SetConsoleTextAttribute(hConsole, GetColorForPrefetch(data.enablePrefetcher));
    std::wcout << L"\n[+] EnablePrefetcher : " << InterpretPrefetchValue(data.enablePrefetcher) << L"\n";

    SetConsoleTextAttribute(hConsole, GetColorForPrefetch(data.enableSuperfetch));
    std::wcout << L"[+] EnableSuperfetch : " << InterpretPrefetchValue(data.enableSuperfetch) << L"\n";

    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    std::wcout << L"[#] Modified Time    : "
        << local.wYear << L"-"
        << local.wMonth << L"-"
        << local.wDay << L" "
        << local.wHour << L":"
        << local.wMinute << L":"
        << local.wSecond << L"\n";

    std::wcout << L"\nThe modification time is in the Key, it can be any value that was changed the time is modified\n\n============================\n";
}