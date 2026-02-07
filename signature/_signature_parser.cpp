#include "_signature_parser.h"
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
#include <thread>
#include <future>
#include <queue>
#include <condition_variable>
#include <vector>
#include <mutex>
#include <memory>
#include <atomic>

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
std::unordered_map<std::string, SignatureStatus> g_headerHashCache;
std::shared_mutex g_headerHashMutex;
std::unordered_map<StoreKey, std::unordered_map<std::string, PCCERT_CONTEXT>> g_certCache;
std::shared_mutex g_certCacheMutex;

const std::unordered_map<std::string, PCCERT_CONTEXT>& GetOrLoadCertCache(DWORD context, const std::wstring& name) {
    StoreKey key{ context, name };
    {
        std::shared_lock<std::shared_mutex> lock(g_certCacheMutex);
        auto it = g_certCache.find(key);
        if (it != g_certCache.end()) {
            return it->second;
        }
    }
    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, NULL, context, name.c_str());
    if (!store) {
        static const std::unordered_map<std::string, PCCERT_CONTEXT> emptyMap;
        return emptyMap;
    }

    std::unordered_map<std::string, PCCERT_CONTEXT> certMap;
    PCCERT_CONTEXT pCert = nullptr;
    while ((pCert = CertEnumCertificatesInStore(store, pCert)) != nullptr) {
        DWORD hashLen = 0;
        if (CertGetCertificateContextProperty(pCert, CERT_SHA1_HASH_PROP_ID, nullptr, &hashLen)) {
            std::vector<BYTE> hash(hashLen);
            if (CertGetCertificateContextProperty(pCert, CERT_SHA1_HASH_PROP_ID, hash.data(), &hashLen)) {
                std::string hashStr;
                hashStr.reserve(hashLen * 2);
                for (BYTE b : hash) {
                    char hex[3];
                    sprintf_s(hex, "%02x", b);
                    hashStr += hex;
                }
                PCCERT_CONTEXT dupCert = CertDuplicateCertificateContext(pCert);
                if (dupCert) {
                    certMap[hashStr] = dupCert;
                }
            }
        }
    }
    CertCloseStore(store, 0);

    std::unique_lock<std::shared_mutex> lock(g_certCacheMutex);
    g_certCache[key] = std::move(certMap);
    return g_certCache[key];
}

void CloseAllCertCaches() {
    std::unique_lock<std::shared_mutex> lock(g_certCacheMutex);
    for (auto& storePair : g_certCache) {
        for (auto& certPair : storePair.second) {
            CertFreeCertificateContext(certPair.second);
        }
    }
    g_certCache.clear();
}

std::unordered_map<std::string, bool> g_catalogSignedHashes;
std::shared_mutex g_catalogMutex;
std::unordered_map<std::wstring, std::string> g_fileHashCache;
std::shared_mutex g_fileHashMutex;

std::string ComputeFileHash(const std::wstring& filePath)
{
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return "";

    HANDLE hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return "";
    }

    const BYTE* pData = (const BYTE*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pData) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return "";
    }

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        UnmapViewOfFile(pData);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return "";
    }
    if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        UnmapViewOfFile(pData);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return "";
    }

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        UnmapViewOfFile(pData);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return "";
    }

    const size_t chunkSize = 64 * 1024;
    size_t offset = 0;
    bool hashSuccess = true;
    while (offset < static_cast<size_t>(fileSize.QuadPart)) {
        size_t toHash = std::min(chunkSize, static_cast<size_t>(fileSize.QuadPart - offset));
        if (!CryptHashData(hHash, pData + offset, (DWORD)toHash, 0)) {
            hashSuccess = false;
            break;
        }
        offset += toHash;
    }

    std::string hashStr;
    if (hashSuccess) {
        DWORD hashLen = 20;
        BYTE hash[20];
        if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
            hashStr.reserve(40);
            for (BYTE b : hash) {
                char hex[3];
                sprintf_s(hex, "%02x", b);
                hashStr += hex;
            }
        }
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    UnmapViewOfFile(pData);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    return hashStr;
}

bool VerifyFileViaCatalog(LPCWSTR filePath)
{
    std::string hashStr;
    {
        std::shared_lock<std::shared_mutex> lock(g_fileHashMutex);
        auto it = g_fileHashCache.find(filePath);
        if (it != g_fileHashCache.end()) {
            hashStr = it->second;
        }
    }

    if (hashStr.empty()) {
        hashStr = ComputeFileHash(filePath);
        if (hashStr.empty()) {
            std::unique_lock<std::shared_mutex> lock(g_catalogMutex);
            g_catalogSignedHashes[""] = false;
            return false;
        }
        std::unique_lock<std::shared_mutex> lock(g_fileHashMutex);
        g_fileHashCache[filePath] = hashStr;
    }

    {
        std::shared_lock<std::shared_mutex> lock(g_catalogMutex);
        auto it = g_catalogSignedHashes.find(hashStr);
        if (it != g_catalogSignedHashes.end()) {
            return it->second;
        }
    }

    HANDLE hCatAdmin = NULL;
    if (!CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0))
    {
        std::unique_lock<std::shared_mutex> lock(g_catalogMutex);
        g_catalogSignedHashes[hashStr] = false;
        return false;
    }

    std::vector<BYTE> pbHash(hashStr.size() / 2);
    for (size_t i = 0; i < hashStr.size(); i += 2) {
        char byte[3] = { hashStr[i], hashStr[i + 1], 0 };
        pbHash[i / 2] = static_cast<BYTE>(strtol(byte, nullptr, 16));
    }
    DWORD dwHashSize = static_cast<DWORD>(pbHash.size());

    std::vector<CATALOG_INFO> catalogList;
    HANDLE hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash.data(), dwHashSize, 0, NULL);
    while (hCatInfo) {
        CATALOG_INFO catInfo = { 0 };
        catInfo.cbStruct = sizeof(catInfo);
        if (CryptCATCatalogInfoFromContext(hCatInfo, &catInfo, 0)) {
            catalogList.push_back(catInfo);
        }
        hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash.data(), dwHashSize, 0, &hCatInfo);
    }

    if (catalogList.empty()) {
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        std::unique_lock<std::shared_mutex> lock(g_catalogMutex);
        g_catalogSignedHashes[hashStr] = false;
        return false;
    }

    std::atomic<bool> foundSigned(false);

    auto verifyCatalog = [&](const CATALOG_INFO& catInfo) -> bool {
        if (foundSigned.load()) return false;

        WINTRUST_CATALOG_INFO wtc = {};
        wtc.cbStruct = sizeof(wtc);
        wtc.pcwszCatalogFilePath = catInfo.wszCatalogFile;
        wtc.pbCalculatedFileHash = pbHash.data();
        wtc.cbCalculatedFileHash = dwHashSize;
        wtc.pcwszMemberFilePath = filePath;

        WINTRUST_DATA wtd = {};
        wtd.cbStruct = sizeof(wtd);
        wtd.dwUnionChoice = WTD_CHOICE_CATALOG;
        wtd.pCatalog = &wtc;
        wtd.dwUIChoice = WTD_UI_NONE;
        wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
        wtd.dwProvFlags = 0;
        wtd.dwStateAction = WTD_STATEACTION_VERIFY;

        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        LONG res = WinVerifyTrust(NULL, &action, &wtd);

        wtd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &action, &wtd);

        if (res == ERROR_SUCCESS) {
            foundSigned.store(true);
            return true;
        }
        return false;
        };

    std::vector<std::future<bool>> futures;
    for (const auto& cat : catalogList) {
        futures.emplace_back(g_globalPool.enqueue(std::bind(verifyCatalog, cat)));
    }

    bool isCatalogSigned = false;
    for (auto& fut : futures) {
        if (fut.get()) {
            isCatalogSigned = true;
            break;
        }
    }

    if (hCatInfo) CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
    CryptCATAdminReleaseContext(hCatAdmin, 0);

    {
        std::unique_lock<std::shared_mutex> lock(g_catalogMutex);
        g_catalogSignedHashes[hashStr] = isCatalogSigned;
    }

    return isCatalogSigned;
}

SignatureStatus CheckDigitalSignature(const std::wstring& filePath) {
    if (!PathFileExistsW(filePath.c_str())) {
        return SignatureStatus::NotFound;
    }
    WINTRUST_FILE_INFO fileInfo;
    ZeroMemory(&fileInfo, sizeof(fileInfo));
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = filePath.c_str();

    GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA winTrustData;
    ZeroMemory(&winTrustData, sizeof(winTrustData));
    winTrustData.cbStruct = sizeof(winTrustData);
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    winTrustData.pFile = &fileInfo;

    LONG status = WinVerifyTrust(NULL, &guidAction, &winTrustData);
    SignatureStatus result = SignatureStatus::Unsigned;
    PCCERT_CONTEXT signingCert = nullptr;

    if (status == ERROR_SUCCESS) {
        result = SignatureStatus::Signed;
        CRYPT_PROVIDER_DATA const* provData = WTHelperProvDataFromStateData(winTrustData.hWVTStateData);
        if (provData) {
            CRYPT_PROVIDER_DATA* nonConstData = const_cast<CRYPT_PROVIDER_DATA*>(provData);
            CRYPT_PROVIDER_SGNR* signer = WTHelperGetProvSignerFromChain(nonConstData, 0, FALSE, 0);
            if (signer) {
                CRYPT_PROVIDER_CERT* provCert = WTHelperGetProvCertFromChain(signer, 0);
                if (provCert && provCert->pCert) {
                    signingCert = provCert->pCert;

                    char subjectName[256];
                    CertNameToStrA(signingCert->dwCertEncodingType, &signingCert->pCertInfo->Subject, CERT_X500_NAME_STR, subjectName, sizeof(subjectName));
                    std::string subject(subjectName);
                    std::transform(subject.begin(), subject.end(), subject.begin(), ::tolower);
                    static const char* cheats[] = { "manthe industries, llc", "slinkware", "amstion limited", "newfakeco", "faked signatures inc" };
                    for (auto c : cheats) {
                        if (subject.find(c) != std::string::npos) {
                            result = SignatureStatus::Cheat;
                            break;
                        }
                    }

                    if (result == SignatureStatus::Signed) {
                        DWORD hashLen = 0;
                        if (CertGetCertificateContextProperty(signingCert, CERT_SHA1_HASH_PROP_ID, nullptr, &hashLen)) {
                            std::vector<BYTE> hash(hashLen);
                            if (CertGetCertificateContextProperty(signingCert, CERT_SHA1_HASH_PROP_ID, hash.data(), &hashLen)) {
                                std::string hashStr;
                                hashStr.reserve(hashLen * 2);
                                for (BYTE b : hash) {
                                    char hex[3];
                                    sprintf_s(hex, "%02x", b);
                                    hashStr += hex;
                                }

                                static const LPCWSTR storeNames[] = { L"MY", L"Root", L"Trust", L"CA", L"UserDS", L"TrustedPublisher", L"Disallowed", L"AuthRoot", L"TrustedPeople", L"ClientAuthIssuer", L"CertificateEnrollment", L"SmartCardRoot" };
                                const DWORD contexts[] = { CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG, CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG };
                                bool found = false;
                                for (auto ctx : contexts) {
                                    for (auto name : storeNames) {
                                        const auto& certMap = GetOrLoadCertCache(ctx, name);
                                        if (certMap.find(hashStr) != certMap.end()) {
                                            found = true;
                                            break;
                                        }
                                    }
                                    if (found) break;
                                }
                                if (found) {
                                    result = SignatureStatus::Fake;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    else {
        if (VerifyFileViaCatalog(filePath.c_str())) {
            result = SignatureStatus::Signed;
        }
    }

    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &guidAction, &winTrustData);

    return result;
}

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
    if (!buffer || bufferSize < 2)
        return false;

    if (buffer[0] != 'M' || buffer[1] != 'Z')
        return false;

    if (bufferSize < 0x40)
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

std::vector<std::future<SignatureStatus>> GetSignatureStatusesAsync(const std::vector<std::wstring>& paths)
{
    std::vector<std::future<SignatureStatus>> results;
    results.reserve(paths.size());
    for (const auto& path : paths) {
        results.emplace_back(g_globalPool.enqueue([path]() { return GetSignatureStatus(path); }));
    }
    return results;
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

    std::string headerHash = ComputeFileHeaderHash(headerBuf, headerRead);
    {
        std::shared_lock<std::shared_mutex> lock(g_headerHashMutex);
        if (auto it = g_headerHashCache.find(headerHash); it != g_headerHashCache.end())
        {
            std::unique_lock<std::shared_mutex> pathLock(g_signatureMutex);
            g_signatureCache[path] = it->second;
            return it->second;
        }
    }

    SignatureStatus status;
    if (IsPEFile(headerBuf, headerRead))
    {
        status = CheckDigitalSignature(path);
    }
    else
    {
        status = SignatureStatus::Signed;
    }

    {
        std::unique_lock<std::shared_mutex> lock(g_signatureMutex);
        g_signatureCache[path] = status;
    }
    {
        std::unique_lock<std::shared_mutex> lock(g_headerHashMutex);
        g_headerHashCache[headerHash] = status;
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