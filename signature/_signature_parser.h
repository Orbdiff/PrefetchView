#pragma once

#include <Windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <shlwapi.h>
#include <mscat.h>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <shared_mutex>
#include <optional>
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
#include <atomic>

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

extern std::unordered_map<std::string, SignatureStatus> g_headerHashCache;
extern std::shared_mutex g_headerHashMutex;

struct StoreKey {
    DWORD context;
    std::wstring name;
    bool operator==(const StoreKey& other) const {
        return context == other.context && name == other.name;
    }
};
namespace std {
    template<> struct hash<StoreKey> {
        size_t operator()(const StoreKey& key) const {
            return hash<DWORD>()(key.context) ^ hash<std::wstring>()(key.name);
        }
    };
}
extern std::unordered_map<StoreKey, std::unordered_map<std::string, PCCERT_CONTEXT>> g_certCache;
extern std::shared_mutex g_certCacheMutex;
extern std::unordered_map<std::string, bool> g_catalogSignedHashes;
extern std::shared_mutex g_catalogMutex;
extern std::unordered_map<std::wstring, std::string> g_fileHashCache;
extern std::shared_mutex g_fileHashMutex;

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

const std::unordered_map<std::string, PCCERT_CONTEXT>& GetOrLoadCertCache(DWORD context, const std::wstring& name);
void CloseAllCertCaches();
std::string ComputeFileHash(const std::wstring& filePath);
bool VerifyFileViaCatalog(LPCWSTR filePath);
SignatureStatus CheckDigitalSignature(const std::wstring& filePath);
bool ReadFileHeader(const std::wstring& path, BYTE* buffer, DWORD bytesToRead, DWORD& outRead);
std::string ComputeFileHeaderHash(const BYTE* buffer, DWORD bufferSize);
bool IsPEFile(const BYTE* buffer, DWORD bufferSize);
std::optional<PCCERT_CONTEXT> GetSignerCertificate(const std::wstring& filePath);
wchar_t GetWindowsDriveLetter();
wchar_t ToUpperFast(wchar_t c);
bool IsPathForcedSigned(const std::wstring& rawPath);
SignatureStatus GetSignatureStatus(const std::wstring& path, bool checkFake = true);
SignatureStatus GetSignatureStatusWithoutFake(const std::wstring& path);
std::vector<std::future<SignatureStatus>> GetSignatureStatusesAsync(const std::vector<std::wstring>& paths);
const std::unordered_set<std::wstring>& GetForcedSignedPaths();