#include "_prefetch.h"
#include <string>
#include <vector>
#include <filesystem>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <atomic>

struct PrefetchResult {
    std::string fileName;
    PrefetchInfo info;

    bool operator==(const PrefetchResult& other) const noexcept {
        return fileName == other.fileName && info == other.info;
    }

    bool operator!=(const PrefetchResult& other) const noexcept {
        return !(*this == other);
    }
};

void RunYaraScan(PrefetchInfo& info) {
    bool foundCheat = false;
    std::vector<std::string> tempMatches;
    std::string tempFilePath;

    for (size_t i = 0; i < info.fileNames.size(); ++i) {
        if (i >= info.fileSignatures.size() || info.fileSignatures[i] != SignatureStatus::Unsigned)
            continue;

        tempFilePath = WStringToUTF8(info.fileNames[i]);
        tempMatches.clear();

        if (FastScanFile(tempFilePath, tempMatches) && !tempMatches.empty()) {
            info.fileSignatures[i] = SignatureStatus::Cheat;
            info.matched_rules.insert(
                info.matched_rules.end(),
                std::make_move_iterator(tempMatches.begin()),
                std::make_move_iterator(tempMatches.end())
            );
            foundCheat = true;
        }
    }

    if (foundCheat) {
        info.signatureStatus = SignatureStatus::Cheat;
    }
}

std::vector<PrefetchResult> ScanPrefetchFolder() {
    std::vector<PrefetchResult> results;
    std::queue<std::filesystem::path> tasks;
    std::mutex queueMutex;
    std::mutex resultsMutex;
    std::condition_variable cv;
    std::atomic<bool> done(false);

    char windowsPath[MAX_PATH]{};
    if (const UINT len = GetWindowsDirectoryA(windowsPath, MAX_PATH); len == 0 || len >= MAX_PATH)
        return results;

    const std::filesystem::path prefetchFolder = std::filesystem::path(windowsPath) / "Prefetch";
    if (!std::filesystem::exists(prefetchFolder) || !std::filesystem::is_directory(prefetchFolder))
        return results;

    for (const auto& entry : std::filesystem::directory_iterator(prefetchFolder)) {
        if (!entry.is_regular_file()) continue;
        auto ext = entry.path().extension().string();
        if (ext != ".pf" && ext != ".PF") continue;
        tasks.push(entry.path());
    }

    const size_t threadCount = 6;
    std::vector<std::thread> pool;

    for (size_t t = 0; t < threadCount; ++t) {
        pool.emplace_back([&]() {
            while (true) {
                std::filesystem::path path;
                {
                    std::lock_guard<std::mutex> lock(queueMutex);
                    if (tasks.empty()) break;
                    path = tasks.front();
                    tasks.pop();
                }

                try {
                    PrefetchFile pf(path.string());
                    if (!pf.IsValid()) continue;

                    auto infoOpt = pf.ExtractInfo(path.string());
                    if (!infoOpt) continue;

                    RunYaraScan(*infoOpt);

                    {
                        std::lock_guard<std::mutex> lock(resultsMutex);
                        results.push_back(PrefetchResult{ path.filename().string(), std::move(*infoOpt) });
                    }
                }
                catch (...) {
                    continue;
                }
            }
            });
    }

    for (auto& th : pool) th.join();

    return results;
}