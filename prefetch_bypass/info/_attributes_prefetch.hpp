#include <windows.h>
#include <iostream>
#include <string>
#include <vector>

struct PrefetchAttributes
{
    std::wstring fileName;
    bool isHidden;
    bool isReadOnly;

    [[nodiscard]] std::wstring ToString() const
    {
        if (isHidden && isReadOnly) return L"Hidden | ReadOnly";
        if (isHidden)              return L"Hidden";
        if (isReadOnly)            return L"ReadOnly";
        return L"";
    }
};

inline void PrefetchAttributesSpecials()
{
    constexpr wchar_t PREFETCH_PATH[] = L"C:\\Windows\\Prefetch\\*.pf";

    WIN32_FIND_DATAW findData{};
    HANDLE hFind = FindFirstFileW(PREFETCH_PATH, &findData);

    if (hFind == INVALID_HANDLE_VALUE)
    {
        std::wcerr << L"[!] Failed to open C:\\Windows\\Prefetch\n";
        return;
    }

    std::vector<PrefetchAttributes> results;

    do
    {
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;

        const bool hidden = (findData.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN);
        const bool readOnly = (findData.dwFileAttributes & FILE_ATTRIBUTE_READONLY);

        if (!hidden && !readOnly)
            continue;

        results.push_back({
            findData.cFileName,
            hidden,
            readOnly
            });

    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    const WORD blueColor = FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    const WORD purpleColor = FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    const WORD whiteColor = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;

    SetConsoleTextAttribute(hConsole, blueColor);
    std::wcout << L"\n[/] Search prefetch files with attributes\n\n";

    SetConsoleTextAttribute(hConsole, whiteColor);

    for (const auto& entry : results)
    {
        SetConsoleTextAttribute(hConsole, purpleColor);
        std::wcout << L"  " << entry.fileName;

        SetConsoleTextAttribute(hConsole, whiteColor);
        std::wcout << L"  ->  " << entry.ToString() << L"\n";
    }

    if (results.empty())
    {
        SetConsoleTextAttribute(hConsole, whiteColor);
        std::wcout << L"[!] No prefetch files with attributes found\n";
    }

    SetConsoleTextAttribute(hConsole, whiteColor);
}