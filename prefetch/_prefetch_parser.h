#define _CRT_SECURE_NO_WARNINGS
#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING

#include "_prefetch.h"

#include <string>
#include <vector>
#include <filesystem>
#include <codecvt>
#include <locale>
#include <ctime>

struct PrefetchResult {
    std::string fileName;
    PrefetchInfo info;

    bool operator==(const PrefetchResult& other) const {
        return fileName == other.fileName && info == other.info;
    }

    bool operator!=(const PrefetchResult& other) const { return !(*this == other); }
};

std::vector<PrefetchResult> ScanPrefetchFolder()
{
    std::vector<PrefetchResult> results;
    const std::string prefetchFolder = "C:\\Windows\\Prefetch";

    if (!std::filesystem::exists(prefetchFolder) || !std::filesystem::is_directory(prefetchFolder))
        return results;

    for (const auto& entry : std::filesystem::directory_iterator(prefetchFolder)) {
        if (!entry.is_regular_file())
            continue;

        const auto& path = entry.path();
        if (path.extension() == ".pf" || path.extension() == ".PF") {
            std::string filePath = path.string();

            PrefetchFile pf(filePath);
            if (!pf.IsValid())
                continue;

            auto infoOpt = pf.ExtractInfo(filePath);
            if (!infoOpt)
                continue;

            results.push_back(PrefetchResult{ path.filename().string(), *infoOpt });
        }
    }

    return results;
}