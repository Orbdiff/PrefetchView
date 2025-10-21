#pragma once

#include <windows.h>
#include <string>
#include <unordered_map>

std::wstring MapSerialToDriveLetter(DWORD targetSerial)
{
    static std::unordered_map<DWORD, std::wstring> serialToDriveCache;

    if (auto it = serialToDriveCache.find(targetSerial); it != serialToDriveCache.end())
        return it->second;

    wchar_t path[] = L"A:\\";
    for (wchar_t drive = L'A'; drive <= L'Z'; ++drive) {
        path[0] = drive;
        DWORD volumeSerial = 0;

        if (GetVolumeInformationW(path, nullptr, 0, &volumeSerial, nullptr, nullptr, nullptr, 0)) {
            serialToDriveCache[volumeSerial] = path;
            if (volumeSerial == targetSerial)
                return path;
        }
    }

    return L"";
}

std::wstring ConvertVolumePathToDrive(const std::wstring& originalPath, std::wstring& outDriveLetter)
{
    constexpr std::wstring_view volumePrefix = L"\\VOLUME{";

    size_t start = originalPath.find(volumePrefix);
    if (start == std::wstring::npos)
        return originalPath;

    size_t end = originalPath.find(L'}', start);
    if (end == std::wstring::npos)
        return originalPath;

    size_t dash = originalPath.rfind(L'-', end);
    if (dash == std::wstring::npos || dash + 1 >= end)
        return originalPath;

    std::wstring serialStr = originalPath.substr(dash + 1, end - dash - 1);
    DWORD serial = std::wcstoul(serialStr.c_str(), nullptr, 16);
    if (serial == 0)
        return originalPath;

    std::wstring driveLetter = MapSerialToDriveLetter(serial);
    if (driveLetter.empty())
        return originalPath;

    outDriveLetter = driveLetter;

    std::wstring replacedPath = originalPath;
    replacedPath.replace(start, (end - start) + 2, driveLetter);
    return replacedPath;
}