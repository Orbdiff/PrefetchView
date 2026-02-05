#include "_signature_parser.h"
#include <Windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <string>
#include <unordered_map>
#include <shared_mutex>
#include <optional>
#include <algorithm>
#include <thread>
#include <future>
#include <queue>
#include <condition_variable>
#include <vector>
#include <mutex>

GlobalThreadPool::GlobalThreadPool(size_t numThreads) : stop(false)
{
    for (size_t i = 0; i < numThreads; ++i) 
    {
        workers.emplace_back([this] 
            {
            while (true) {
                std::function<void()> task;
                {
                    std::unique_lock<std::mutex> lock(queueMutex);
                    condition.wait(lock, [this] { return stop || !tasks.empty(); });
                    if (stop && tasks.empty()) return;
                    task = std::move(tasks.front());
                    tasks.pop();
                }
                task();
            }
            });
    }
}

GlobalThreadPool::~GlobalThreadPool() 
{
    {
        std::unique_lock<std::mutex> lock(queueMutex);
        stop = true;
    }
    condition.notify_all();
    for (std::thread& worker : workers) {
        if (worker.joinable()) worker.join();
    }
}

template<class F>
std::future<typename std::invoke_result<F>::type> GlobalThreadPool::enqueue(F&& f) 
{
    using ReturnType = typename std::invoke_result<F>::type;
    auto task = std::make_shared<std::packaged_task<ReturnType()>>(std::forward<F>(f));
    std::future<ReturnType> res = task->get_future();
    {
        std::unique_lock<std::mutex> lock(queueMutex);
        tasks.emplace([task]() { (*task)(); });
    }
    condition.notify_one();
    return res;
}

GlobalThreadPool g_globalPool(std::max(2u, std::thread::hardware_concurrency() / 2));

std::unordered_map<std::wstring, SignatureStatus> g_signatureCache;
std::shared_mutex g_signatureMutex;
std::unordered_map<std::string, SignatureStatus> g_winTrustCache;
std::shared_mutex g_winTrustMutex;

bool ReadFileHeader(const std::wstring& path, BYTE* buffer, DWORD bytesToRead, DWORD& outRead)
{
    outRead = 0;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (h == INVALID_HANDLE_VALUE)
        return false;

    DWORD read = 0;
    BOOL ok = ReadFile(h, buffer, bytesToRead, &read, nullptr);
    CloseHandle(h);

    if (!ok || read == 0)
        return false;

    outRead = read;
    return true;
}

std::string ComputeFileHeaderHash(const BYTE* buffer, DWORD bufferSize)
{
    if (!buffer || bufferSize == 0) return "";

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) return "";
    if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "";
    }
    if (!CryptHashData(hHash, buffer, bufferSize, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
    DWORD hashLen = 20;
    BYTE hash[20];
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    std::string hashStr;
    hashStr.reserve(40);
    for (BYTE b : hash) {
        char hex[3];
        sprintf_s(hex, "%02x", b);
        hashStr += hex;
    }
    return hashStr;
}

bool IsPEFile(const BYTE* buffer, DWORD bufferSize) {
    if (!buffer || bufferSize < 0x40)
        return false;

    if (buffer[0] != 'M' || buffer[1] != 'Z')
        return false;

    DWORD e_lfanew = *reinterpret_cast<const DWORD*>(buffer + 0x3C);
    if (e_lfanew + 0x18 + sizeof(IMAGE_FILE_HEADER) > bufferSize)
        return false;

    const BYTE* peHeader = buffer + e_lfanew;
    if (!(peHeader[0] == 'P' && peHeader[1] == 'E' && peHeader[2] == 0 && peHeader[3] == 0))
        return false;

    auto* fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(peHeader + 4);
    return fileHeader->NumberOfSections > 0 && fileHeader->NumberOfSections <= 96;
}

std::optional<PCCERT_CONTEXT> GetSignerCertificate(const std::wstring& filePath) 
{
    HCERTSTORE hStore = nullptr;
    HCRYPTMSG hMsg = nullptr;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, filePath.c_str(), CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY, 0, nullptr, nullptr, nullptr, &hStore, &hMsg, nullptr)) return std::nullopt;

    DWORD signerInfoSize = 0;
    CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize);
    std::unique_ptr<BYTE[]> buffer(new BYTE[signerInfoSize]);
    CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, buffer.get(), &signerInfoSize);
    auto* pSignerInfo = reinterpret_cast<CMSG_SIGNER_INFO*>(buffer.get());

    CERT_INFO certInfo{};
    certInfo.Issuer = pSignerInfo->Issuer;
    certInfo.SerialNumber = pSignerInfo->SerialNumber;

    PCCERT_CONTEXT pCertContext = CertFindCertificateInStore(hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_CERT, &certInfo, nullptr);

    if (pCertContext)
    {
        CertCloseStore(hStore, 0);
        CryptMsgClose(hMsg);
        return pCertContext;
    }
    CertCloseStore(hStore, 0);
    CryptMsgClose(hMsg);
    return std::nullopt;
}

wchar_t GetWindowsDriveLetter() 
{
    static wchar_t driveLetter = 0;
    if (!driveLetter) 
    {
        wchar_t windowsPath[MAX_PATH] = { 0 };
        if (GetWindowsDirectoryW(windowsPath, MAX_PATH))
            driveLetter = windowsPath[0];
    }
    return driveLetter;
}

wchar_t ToUpperFast(wchar_t c) 
{
    return (c >= L'a' && c <= L'z') ? c - 32 : c;
}

bool IsPathForcedSigned(const std::wstring& rawPath)
{
    wchar_t winDrive = GetWindowsDriveLetter();
    if (winDrive == 0)
        winDrive = L'C';

    std::wstring norm;
    norm.reserve(rawPath.size());

    size_t start = 0;
    if (rawPath.size() >= 2 && rawPath[1] == L':' && ToUpperFast(rawPath[0]) == winDrive)
        start = 2;

    for (size_t i = start; i < rawPath.size(); ++i)
    {
        wchar_t ch = rawPath[i];
        if (ch == L'/')
            ch = L'\\';
        norm.push_back(ToUpperFast(ch));
    }

    return GetForcedSignedPaths().find(norm) != GetForcedSignedPaths().end();
}

SignatureStatus GetSignatureStatus(const std::wstring& path, bool checkFake) 
{
    {
        std::shared_lock<std::shared_mutex> lock(g_signatureMutex);
        if (auto it = g_signatureCache.find(path); it != g_signatureCache.end())
            return it->second;
    }

    if (IsPathForcedSigned(path))
        return SignatureStatus::Signed;

    static std::wstring exePath;
    if (exePath.empty()) {
        wchar_t buffer[MAX_PATH] = { 0 };
        if (GetModuleFileNameW(nullptr, buffer, MAX_PATH))
            exePath = buffer;
    }
    if (_wcsicmp(path.c_str(), exePath.c_str()) == 0)
        return SignatureStatus::Signed;

    DWORD attr = GetFileAttributesW(path.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) 
    {
        std::unique_lock<std::shared_mutex> lock(g_signatureMutex);
        g_signatureCache[path] = SignatureStatus::NotFound;
        return SignatureStatus::NotFound;
    }

    BYTE headerBuf[1024] = { 0 };
    DWORD headerRead = 0;
    if (!ReadFileHeader(path, headerBuf, sizeof(headerBuf), headerRead) || headerRead == 0) 
    {
        std::unique_lock<std::shared_mutex> lock(g_signatureMutex);
        g_signatureCache[path] = SignatureStatus::NotFound;
        return SignatureStatus::NotFound;
    }

    SignatureStatus status = SignatureStatus::Signed;
    try {
        if (IsPEFile(headerBuf, headerRead))
        {
            auto signingCertOpt = GetSignerCertificate(path);
            if (signingCertOpt.has_value())
            {
                PCCERT_CONTEXT signingCert = *signingCertOpt;

                char subjectName[256];
                CertNameToStrA(signingCert->dwCertEncodingType, &signingCert->pCertInfo->Subject, CERT_X500_NAME_STR, subjectName, sizeof(subjectName));
                std::string_view subject(subjectName);
                std::string lowerSubject(subject);
                std::transform(lowerSubject.begin(), lowerSubject.end(), lowerSubject.begin(), ::tolower);
                static const std::string_view cheats[] = { "manthe industries, llc", "slinkware", "amstion limited", "newfakeco", "faked signatures inc" };
                bool isCheat = false;
                for (auto c : cheats)
                {
                    if (lowerSubject.find(c) != std::string::npos)
                    {
                        isCheat = true;
                        break;
                    }
                }

                if (isCheat) 
                {
                    status = SignatureStatus::Cheat;
                }
                else 
                {
                    status = SignatureStatus::Signed;

                    if (checkFake && status == SignatureStatus::Signed) 
                    {
                        std::string headerHash = ComputeFileHeaderHash(headerBuf, headerRead);
                        if (!headerHash.empty()) {
                            std::unique_lock<std::shared_mutex> lock(g_winTrustMutex);
                            if (auto it = g_winTrustCache.find(headerHash); it != g_winTrustCache.end())
                            {
                                status = it->second;
                            }
                            else 
                            {
                                WINTRUST_FILE_INFO fileInfo = { sizeof(WINTRUST_FILE_INFO) };
                                fileInfo.pcwszFilePath = path.c_str();

                                WINTRUST_DATA winTrustData = { sizeof(WINTRUST_DATA) };
                                winTrustData.dwUIChoice = WTD_UI_NONE;
                                winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
                                winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
                                winTrustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_SAFER_FLAG;
                                winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
                                winTrustData.pFile = &fileInfo;

                                GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                                LONG res = WinVerifyTrust(nullptr, &action, &winTrustData);

                                winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
                                WinVerifyTrust(nullptr, &action, &winTrustData);

                                if (res == ERROR_SUCCESS)
                                {
                                    status = SignatureStatus::Signed;
                                }
                                else 
                                {
                                    status = SignatureStatus::Fake;
                                }

                                g_winTrustCache[headerHash] = status;
                            }
                        }
                        else
                        {
                            status = SignatureStatus::Fake;
                        }
                    }
                }

                CertFreeCertificateContext(signingCert);
            }
            else 
            {
                status = SignatureStatus::Unsigned;
            }
        }
        else 
        {
            status = SignatureStatus::Signed;
        }
    }
    catch (...) 
    {
        status = SignatureStatus::Signed;
    }

    {
        std::unique_lock<std::shared_mutex> lock(g_signatureMutex);
        g_signatureCache[path] = status;
    }

    return status;
}

SignatureStatus GetSignatureStatusWithoutFake(const std::wstring& path) 
{
    return GetSignatureStatus(path, false);
}

std::future<SignatureStatus> GetSignatureStatusAsync(const std::wstring& path)
{
    return g_globalPool.enqueue([path]() { return GetSignatureStatus(path); });
}