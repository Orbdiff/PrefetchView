#pragma once

#include <string>
#include <vector>
#include <algorithm>
#include <cwctype>

std::wstring NormalizeName(const std::wstring& name)
{
    std::wstring result;
    for (wchar_t c : name) {
        if (std::iswalnum(c)) {
            result += std::towlower(c);
        }
    }
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
    std::wstring bestMatch;
    size_t bestScore = 0;

    const std::wstring exeNorm = NormalizeName(exeName);

    for (const auto& fullPath : paths) {
        const size_t nameStart = fullPath.find_last_of(L"\\/");
        const std::wstring fileName = (nameStart != std::wstring::npos)
            ? fullPath.substr(nameStart + 1)
            : fullPath;

        const std::wstring fileNorm = NormalizeName(fileName);

        size_t score = 0;
        size_t len = std::min(exeNorm.size(), fileNorm.size());
        for (size_t i = 0; i < len; ++i) {
            if (exeNorm[i] == fileNorm[i]) {
                ++score;
            } else {
                break;
            }
        }

        if (fileNorm.find(exeNorm) != std::wstring::npos) {
            score += 2;
        }

        if (score > bestScore) {
            bestScore = score;
            bestMatch = fullPath;
        }
    }

    return bestMatch;
}