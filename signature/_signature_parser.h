#pragma once
#include <Windows.h>
#include <wintrust.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <string>
#include <unordered_map>
#include <algorithm>
#include "_filtered_signatures.hh"

enum class SignatureStatus {
    Signed,
    Unsigned,
    NotFound,
    Cheat
};

static std::unordered_map<std::wstring, SignatureStatus> g_signatureCache;

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
    std::wstring_view sv(rawPath);
    std::wstring norm;
    norm.reserve(sv.size());

    size_t start = 0;
    if (sv.size() >= 2 && sv[1] == L':' && ToUpperFast(sv[0]) == winDrive)
        start = 2;

    for (size_t i = start; i < sv.size(); ++i)
    {
        wchar_t ch = sv[i];
        if (ch == L'/') ch = L'\\';
        norm.push_back(ToUpperFast(ch));
    }

    return g_forcedSignedPaths.find(norm) != g_forcedSignedPaths.end();
}

bool HasValidDigitalSignature(const std::wstring& filePath)
{
    WINTRUST_FILE_INFO fileInfo = { sizeof(WINTRUST_FILE_INFO), const_cast<LPWSTR>(filePath.c_str()), nullptr, nullptr };

    WINTRUST_DATA winTrustData = { 0 };
    winTrustData.cbStruct = sizeof(winTrustData);
    winTrustData.pPolicyCallbackData = nullptr;
    winTrustData.pSIPClientData = nullptr;
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileInfo;
    winTrustData.dwStateAction = WTD_STATEACTION_IGNORE;
    winTrustData.hWVTStateData = nullptr;
    winTrustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    static GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG result = WinVerifyTrust(nullptr, &policyGUID, &winTrustData);
    return result == ERROR_SUCCESS;
}

static std::wstring GetSignerCommonName(const std::wstring& filePath)
{
    WINTRUST_FILE_INFO fileInfo = { sizeof(WINTRUST_FILE_INFO), const_cast<LPWSTR>(filePath.c_str()), nullptr, nullptr };

    WINTRUST_DATA winTrustData = {};
    winTrustData.cbStruct = sizeof(winTrustData);
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileInfo;
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    winTrustData.hWVTStateData = nullptr;

    static GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG verifyResult = WinVerifyTrust(nullptr, &policyGUID, &winTrustData);

    std::wstring signerName;

    if (winTrustData.hWVTStateData)
    {
        PCRYPT_PROVIDER_DATA pProvData = WTHelperProvDataFromStateData(winTrustData.hWVTStateData);
        if (pProvData)
        {
            PCRYPT_PROVIDER_SGNR pSgnr = WTHelperGetProvSignerFromChain(pProvData, 0, FALSE, 0);
            if (pSgnr)
            {
                PCRYPT_PROVIDER_CERT pProvCert = WTHelperGetProvCertFromChain(pSgnr, 0);
                if (pProvCert && pProvCert->pCert)
                {
                    PCCERT_CONTEXT pCertContext = pProvCert->pCert;
                    DWORD nameLen = CertGetNameStringW(
                        pCertContext,
                        CERT_NAME_SIMPLE_DISPLAY_TYPE,
                        0, nullptr, nullptr, 0
                    );

                    if (nameLen > 1)
                    {
                        std::wstring buf;
                        buf.resize(nameLen);
                        CertGetNameStringW(
                            pCertContext,
                            CERT_NAME_SIMPLE_DISPLAY_TYPE,
                            0, nullptr, &buf[0], nameLen
                        );

                        if (!buf.empty() && buf.back() == L'\0')
                            buf.pop_back();

                        signerName = buf;
                    }
                }
            }
        }

        winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &policyGUID, &winTrustData);
    }
    else
    {
        winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &policyGUID, &winTrustData);
    }

    return signerName;
}

static std::wstring ToUpperCopy(const std::wstring& s)
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

    auto cached = g_signatureCache.find(path);
    if (cached != g_signatureCache.end())
        return cached->second;

    DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY))
    {
        g_signatureCache[path] = SignatureStatus::NotFound;
        return SignatureStatus::NotFound;
    }

    bool isSigned = HasValidDigitalSignature(path);
    SignatureStatus status = isSigned ? SignatureStatus::Signed : SignatureStatus::Unsigned;

    if (isSigned)
    {
        std::wstring signer = GetSignerCommonName(path);
        if (!signer.empty())
        {
            static const std::vector<std::wstring> cheatSigners = {
                L"MANTHE INDUSTRIES, LLC",
                L"AMSTION LIMITED",
            };

            std::wstring signerUp = ToUpperCopy(signer);
            for (const auto& targetUp : cheatSigners)
            {
                if (signerUp.find(targetUp) != std::wstring::npos)
                {
                    status = SignatureStatus::Cheat;
                    break;
                }
            }
        }
    }

    g_signatureCache[path] = status;
    return status;
}