#include "_prefetch.h"
#include <string>
#include <vector>
#include <filesystem>
#include <mutex>
#include <atomic>
#include <future>
#include <algorithm>
#include <queue>
#include <unordered_set>

static std::unordered_set<std::wstring> scannedPaths;
static std::mutex scannedMutex;

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

        {
            std::lock_guard<std::mutex> lock(scannedMutex);
            if (scannedPaths.find(info.fileNames[i]) != scannedPaths.end()) {
                continue;
            }
            scannedPaths.insert(info.fileNames[i]);
        }

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
    std::mutex resultsMutex;
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

    const size_t hwThreads = std::max(1u, std::thread::hardware_concurrency());
    const size_t maxConcurrentTasks = 4;
    std::vector<std::future<void>> futures;

    while (!tasks.empty() || !futures.empty()) {

        while (futures.size() < maxConcurrentTasks && !tasks.empty()) {
            std::filesystem::path path;
            {
                std::lock_guard<std::mutex> lock(resultsMutex);
                path = tasks.front();
                tasks.pop();
            }

            futures.push_back(std::async(std::launch::async, [path, &resultsMutex, &results]() {
                try {
                    PrefetchFile pf(path.wstring());
                    if (!pf.IsValid()) return;

                    auto infoOpt = pf.ExtractInfo(path.wstring());
                    if (!infoOpt) return;

                    RunYaraScan(*infoOpt);

                    {
                        std::lock_guard<std::mutex> lock(resultsMutex);
                        results.push_back(PrefetchResult{ WStringToUTF8(path.filename().wstring()), std::move(*infoOpt) });
                    }
                }
                catch (...) {

                    return;
                }
                }));
        }

        futures.erase(
            std::remove_if(futures.begin(), futures.end(), [](std::future<void>& f) {
                return f.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
                }),
            futures.end()
        );
    }

    return results;
}