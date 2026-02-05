#pragma once

#include <windows.h>
#include <string>
#include <unordered_map>
#include <string_view>
#include <vector>
#include <algorithm>

std::wstring MapSerialToDriveLetter(DWORD targetSerial)
{
    static std::vector<std::pair<DWORD, std::wstring>> serialToDriveCache;
    static bool cacheInitialized = false;

    for (const auto& pair : serialToDriveCache)
    {
        if (pair.first == targetSerial)
        {
            return pair.second;
        }
    }

    if (!cacheInitialized) 
    {
        DWORD drives = GetLogicalDrives();
        if (drives == 0) 
        {
            cacheInitialized = true;
            return L"";
        }

        wchar_t path[] = L"A:\\";
        for (int i = 0; i < 26; ++i)
        {
            if (drives & (1 << i)) 
            {
                path[0] = L'A' + i;
                DWORD volumeSerial = 0;

                if (GetVolumeInformationW(path, nullptr, 0, &volumeSerial, nullptr, nullptr, nullptr, 0)) 
                {
                    serialToDriveCache.emplace_back(volumeSerial, path);
                }
            }
        }
        cacheInitialized = true;
    }

    for (const auto& pair : serialToDriveCache)
    {
        if (pair.first == targetSerial)
        {
            return pair.second;
        }
    }

    return L"";
}

std::wstring ConvertVolumePathToDrive(const std::wstring& originalPath, std::wstring& outDriveLetter)
{
    constexpr std::wstring_view volumePrefix = L"\\VOLUME{";

    std::wstring_view pathView(originalPath);

    size_t start = pathView.find(volumePrefix);
    if (start == std::wstring_view::npos)
        return originalPath;

    size_t end = pathView.find(L'}', start);
    if (end == std::wstring_view::npos)
        return originalPath;

    size_t dash = pathView.rfind(L'-', end);
    if (dash == std::wstring_view::npos || dash + 1 >= end)
        return originalPath;

    std::wstring_view serialStr = pathView.substr(dash + 1, end - dash - 1);
    DWORD serial = std::wcstoul(serialStr.data(), nullptr, 16);
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