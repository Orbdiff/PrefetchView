#include <windows.h>
#include <sstream>
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

inline void PrefetchAttributesSpecials(std::wstringstream& out)
{
    constexpr wchar_t PREFETCH_PATH[] = L"C:\\Windows\\Prefetch\\*.pf";

    WIN32_FIND_DATAW findData{};
    HANDLE hFind = FindFirstFileW(PREFETCH_PATH, &findData);

    if (hFind == INVALID_HANDLE_VALUE)
    {
        out << L"[ERROR] Failed to open C:\\Windows\\Prefetch\n";
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

    out << L"\n[/] Search prefetch files with attributes\n\n";

    if (results.empty())
    {
        out << L"[+] No prefetch files with attributes found\n";
        return;
    }

    for (const auto& entry : results)
    {
        out << L"  " << entry.fileName
            << L"  ->  " << entry.ToString()
            << L"\n";
    }
}