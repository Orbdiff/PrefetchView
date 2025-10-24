#pragma once
#include <Windows.h>
#include <wincrypt.h>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <shared_mutex>
#include <optional>
#include <algorithm>
#include <execution>
#include "_filtered_signatures.hh"

enum class SignatureStatus {
    Signed,
    Unsigned,
    NotFound,
    Cheat
};

static std::unordered_map<std::wstring, SignatureStatus> g_signatureCache;
static std::shared_mutex g_signatureMutex;

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
    std::wstring norm;
    norm.reserve(rawPath.size());

    size_t start = 0;
    if (rawPath.size() >= 2 && rawPath[1] == L':' && ToUpperFast(rawPath[0]) == winDrive)
        start = 2;

    for (size_t i = start; i < rawPath.size(); ++i)
    {
        wchar_t ch = rawPath[i];
        if (ch == L'/') ch = L'\\';
        norm.push_back(ToUpperFast(ch));
    }

    return g_forcedSignedPaths.find(norm) != g_forcedSignedPaths.end();
}

std::optional<std::wstring> GetSignerCommonName_CryptoAPI(const std::wstring& filePath)
{
    HCERTSTORE hStore = nullptr;
    HCRYPTMSG hMsg = nullptr;
    PCCERT_CONTEXT pCertContext = nullptr;

    BOOL result = CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        filePath.c_str(),
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0, nullptr, nullptr, nullptr,
        &hStore, &hMsg, nullptr
    );

    if (!result)
        return std::nullopt;

    DWORD signerCount = 0, signerCountSize = sizeof(DWORD);
    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_COUNT_PARAM, 0, &signerCount, &signerCountSize) || signerCount == 0)
    {
        CertCloseStore(hStore, 0);
        CryptMsgClose(hMsg);
        return std::nullopt;
    }

    DWORD signerInfoSize = 0;
    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize) || signerInfoSize == 0)
    {
        CertCloseStore(hStore, 0);
        CryptMsgClose(hMsg);
        return std::nullopt;
    }

    std::unique_ptr<BYTE[]> buffer(new (std::nothrow) BYTE[signerInfoSize]);
    if (!buffer)
    {
        CertCloseStore(hStore, 0);
        CryptMsgClose(hMsg);
        return std::nullopt;
    }

    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, buffer.get(), &signerInfoSize))
    {
        CertCloseStore(hStore, 0);
        CryptMsgClose(hMsg);
        return std::nullopt;
    }

    auto* pSignerInfo = reinterpret_cast<CMSG_SIGNER_INFO*>(buffer.get());
    if (!pSignerInfo)
    {
        CertCloseStore(hStore, 0);
        CryptMsgClose(hMsg);
        return std::nullopt;
    }

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
    if (pCertContext)
    {
        DWORD nameLen = CertGetNameStringW(
            pCertContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0, nullptr, nullptr, 0
        );

        if (nameLen > 1)
        {
            signerName.resize(nameLen);
            CertGetNameStringW(
                pCertContext,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0, nullptr, signerName.data(), nameLen
            );
            if (!signerName.empty() && signerName.back() == L'\0')
                signerName.pop_back();
        }
    }

    if (pCertContext) CertFreeCertificateContext(pCertContext);
    CertCloseStore(hStore, 0);
    CryptMsgClose(hMsg);

    return signerName.empty() ? std::nullopt : std::make_optional(signerName);
}

bool HasValidDigitalSignature_CryptoAPI(const std::wstring& filePath)
{
    auto signer = GetSignerCommonName_CryptoAPI(filePath);
    return signer.has_value();
}

std::wstring ToUpperCopy(const std::wstring& s)
{
    std::wstring out;
    out.resize(s.size());
    std::transform(s.begin(), s.end(), out.begin(), [](wchar_t c) {
        return (c >= L'a' && c <= L'z') ? c - 32 : c;
        });
    return out;
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

    DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY))
    {
        std::unique_lock writeLock(g_signatureMutex);
        g_signatureCache[path] = SignatureStatus::NotFound;
        return SignatureStatus::NotFound;
    }

    SignatureStatus status = SignatureStatus::Unsigned;

    if (HasValidDigitalSignature_CryptoAPI(path))
    {
        status = SignatureStatus::Signed;

        if (auto signerOpt = GetSignerCommonName_CryptoAPI(path))
        {
            std::wstring signerUp = ToUpperCopy(*signerOpt);
            static constexpr std::wstring_view cheatSigners[] = {
                L"MANTHE INDUSTRIES, LLC",
                L"AMSTION LIMITED",
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
    }

    {
        std::unique_lock writeLock(g_signatureMutex);
        g_signatureCache[path] = status;
    }

    return status;
}