#pragma once

#include <string>
#include <vector>
#include <algorithm>
#include <cwctype>
#include <iterator>

std::wstring NormalizeName(const std::wstring& name)
{
    std::wstring result;
    result.reserve(name.size());
    std::transform(name.begin(), name.end(), std::back_inserter(result), [](wchar_t c) 
        {
        return std::iswalnum(c) ? std::towlower(c) : L'\0';
        });
    result.erase(std::remove(result.begin(), result.end(), L'\0'), result.end());
    return result;
}

std::wstring ExtractExeNameFromPfFilename(const std::wstring& pfPath)
{
    const size_t lastSlash = pfPath.find_last_of(L"\\/");
    const std::wstring filename = (lastSlash != std::wstring::npos) ? pfPath.substr(lastSlash + 1) : pfPath;

    const size_t dashPos = filename.find(L'-');
    return (dashPos != std::wstring::npos) ? filename.substr(0, dashPos) : filename;
}

std::wstring FindExecutablePath(const std::wstring& exeName, const std::vector<std::wstring>& paths)
{
    if (paths.empty())
    {
        return L"No path found...";
    }

    const std::wstring exeNorm = NormalizeName(exeName);

    struct Match 
    {
        std::wstring path;
        size_t score = 0;
    };

    std::vector<Match> matches;
    matches.reserve(paths.size());

    for (const auto& fullPath : paths) 
    {
        const size_t nameStart = fullPath.find_last_of(L"\\/");
        const std::wstring fileName = (nameStart != std::wstring::npos)
            ? fullPath.substr(nameStart + 1)
            : fullPath;

        const std::wstring fileNorm = NormalizeName(fileName);

        size_t score = 0;
        size_t len = std::min(exeNorm.size(), fileNorm.size());
        for (size_t i = 0; i < len; ++i)
        {
            if (exeNorm[i] == fileNorm[i]) 
            {
                ++score;
            }
            else 
            {
                break;
            }
        }

        if (fileNorm.find(exeNorm) != std::wstring::npos)
        {
            score += 2;
        }

        matches.push_back({ fullPath, score });
    }

    auto bestIt = std::max_element(matches.begin(), matches.end(), [](const Match& a, const Match& b)
        {
        return a.score < b.score;
        });

    if (bestIt->score == 0) 
    {
        return L"No path found...";
    }

    return bestIt->path;
}