#include <Windows.h>
#include <wincrypt.h>
#include <string>
#include <unordered_map>
#include <shared_mutex>
#include <optional>
#include <algorithm>

#include "_filtered_signatures.hh"

enum class SignatureStatus {
    Signed,
    Unsigned,
    NotFound,
    Cheat
};

static std::unordered_map<std::wstring, SignatureStatus> g_signatureCache;
static std::shared_mutex g_signatureMutex;

static bool ReadFileHeader(const std::wstring& path, BYTE* buffer, DWORD bytesToRead, DWORD& outRead)
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

bool IsPEFile(const std::wstring& path)
{
    BYTE buf[0x200] = { 0 };
    DWORD read = 0;
    if (!ReadFileHeader(path, buf, sizeof(buf), read) || read < 0x40)
        return false;

    if (buf[0] != 'M' || buf[1] != 'Z')
        return false;

    DWORD e_lfanew = *reinterpret_cast<DWORD*>(buf + 0x3C);
    if (e_lfanew + 0x18 + sizeof(IMAGE_FILE_HEADER) > read)
        return false;

    BYTE* peHeader = buf + e_lfanew;
    if (!(peHeader[0] == 'P' && peHeader[1] == 'E' && peHeader[2] == 0 && peHeader[3] == 0))
        return false;

    auto* fileHeader = reinterpret_cast<IMAGE_FILE_HEADER*>(peHeader + 4);
    return fileHeader->NumberOfSections > 0 && fileHeader->NumberOfSections <= 96;
}

std::optional<std::wstring> GetSignerCommonName_CryptoAPI(const std::wstring& filePath)
{
    HCERTSTORE hStore = nullptr;
    HCRYPTMSG hMsg = nullptr;
    PCCERT_CONTEXT pCertContext = nullptr;

    if (!CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        filePath.c_str(),
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        nullptr,
        nullptr,
        nullptr,
        &hStore,
        &hMsg,
        nullptr
    )) return std::nullopt;

    DWORD signerInfoSize = 0;
    CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize);

    std::unique_ptr<BYTE[]> buffer(new BYTE[signerInfoSize]);
    CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, buffer.get(), &signerInfoSize);
    auto* pSignerInfo = reinterpret_cast<CMSG_SIGNER_INFO*>(buffer.get());

    CERT_INFO certInfo{};
    certInfo.Issuer = pSignerInfo->Issuer;
    certInfo.SerialNumber = pSignerInfo->SerialNumber;

    pCertContext = CertFindCertificateInStore(
        hStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_CERT,
        &certInfo,
        nullptr
    );

    std::wstring signerName;
    if (pCertContext) {
        DWORD nameLen = CertGetNameStringW(
            pCertContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            nullptr,
            nullptr,
            0
        );

        if (nameLen > 1) {
            signerName.resize(nameLen);
            CertGetNameStringW(
                pCertContext,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                nullptr,
                signerName.data(),
                nameLen
            );
            signerName.pop_back();
        }
        CertFreeCertificateContext(pCertContext);
    }

    CertCloseStore(hStore, 0);
    CryptMsgClose(hMsg);

    return signerName.empty() ? std::nullopt : std::make_optional(signerName);
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

    return g_forcedSignedPaths.find(norm) != g_forcedSignedPaths.end();
}

SignatureStatus GetSignatureStatus(const std::wstring& path)
{
    {
        std::shared_lock readLock(g_signatureMutex);
        if (auto it = g_signatureCache.find(path); it != g_signatureCache.end())
            return it->second;
    }

    if (IsPathForcedSigned(path))
        return SignatureStatus::Signed;

    static std::wstring exePath;
    if (exePath.empty())
    {
        wchar_t buffer[MAX_PATH] = { 0 };
        if (GetModuleFileNameW(nullptr, buffer, MAX_PATH))
            exePath = buffer;
    }
    if (_wcsicmp(path.c_str(), exePath.c_str()) == 0)
        return SignatureStatus::Signed;

    DWORD attr = GetFileAttributesW(path.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY))
    {
        std::unique_lock writeLock(g_signatureMutex);
        g_signatureCache[path] = SignatureStatus::NotFound;
        return SignatureStatus::NotFound;
    }

    SignatureStatus status = SignatureStatus::Signed;
    try
    {
        if (IsPEFile(path))
        {
            auto signer = GetSignerCommonName_CryptoAPI(path);
            if (signer.has_value())
            {
                status = SignatureStatus::Signed;

                std::wstring signerUp;
                signerUp.reserve(signer->size());
                for (wchar_t ch : *signer)
                    signerUp.push_back(::towupper(ch));

                static constexpr std::wstring_view cheatSigners[] = {
                    L"MANTHE INDUSTRIES, LLC",
                    L"AMSTION LIMITED",
                    L"SLINKWARE",
                    L"NEWFAKECO",
                    L"FAKED SIGNATURES INC"
                };

                for (const auto& bad : cheatSigners)
                {
                    if (signerUp.find(bad.data()) != std::wstring::npos)
                    {
                        status = SignatureStatus::Cheat;
                        break;
                    }
                }
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
        std::unique_lock writeLock(g_signatureMutex);
        g_signatureCache[path] = status;
    }

    return status;

}
