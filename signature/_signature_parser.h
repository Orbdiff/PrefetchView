#pragma once

#include <Windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <shlwapi.h>
#include <mscat.h>
#include <string>
#include <unordered_map>
#include <shared_mutex>
#include <optional>
#include <algorithm>
#include <vector>
#include <string_view>
#include <future>
#include <thread>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <functional>

#include "_filtered_signatures.hh"

enum class SignatureStatus {
    Signed,
    Unsigned,
    NotFound,
    Cheat,
    Fake
};

inline bool operator==(SignatureStatus lhs, SignatureStatus rhs) { return static_cast<int>(lhs) == static_cast<int>(rhs); }
inline bool operator!=(SignatureStatus lhs, SignatureStatus rhs) { return !(lhs == rhs); }

extern std::unordered_map<std::wstring, SignatureStatus> g_signatureCache;
extern std::shared_mutex g_signatureMutex;
extern std::unordered_map<std::string, SignatureStatus> g_winTrustCache;
extern std::shared_mutex g_winTrustMutex;

class GlobalThreadPool {
public:
    GlobalThreadPool(size_t numThreads);
    ~GlobalThreadPool();
    template<class F>
    std::future<typename std::invoke_result<F>::type> enqueue(F&& f);
private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queueMutex;
    std::condition_variable condition;
    bool stop;
};

extern GlobalThreadPool g_globalPool;

bool ReadFileHeader(const std::wstring& path, BYTE* buffer, DWORD bytesToRead, DWORD& outRead);
std::string ComputeFileHeaderHash(const BYTE* buffer, DWORD bufferSize);
bool IsPEFile(const BYTE* buffer, DWORD bufferSize);
std::optional<PCCERT_CONTEXT> GetSignerCertificate(const std::wstring& filePath);
wchar_t GetWindowsDriveLetter();
wchar_t ToUpperFast(wchar_t c);
bool IsPathForcedSigned(const std::wstring& rawPath);
SignatureStatus GetSignatureStatus(const std::wstring& path, bool checkFake = true);
SignatureStatus GetSignatureStatusWithoutFake(const std::wstring& path);
std::future<SignatureStatus> GetSignatureStatusAsync(const std::wstring& path);
const std::unordered_set<std::wstring>& GetForcedSignedPaths();