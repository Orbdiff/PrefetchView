#pragma once

#include <Windows.h>
#include <wintrust.h>
#include <Softpub.h>
#include <string>
#include <unordered_map>

enum class SignatureStatus {
    Signed,
    Unsigned,
    NotFound
};

static std::unordered_map<std::wstring, SignatureStatus> g_signatureCache;

bool HasValidDigitalSignature(const std::wstring& filePath) 
{
    WINTRUST_FILE_INFO fileInfo = {
        sizeof(WINTRUST_FILE_INFO),        // cbStruct
        filePath.c_str(),                  // pcwszFilePath
        nullptr,                           // hFile
        nullptr                            // pgKnownSubject
    };

    WINTRUST_DATA winTrustData = {
        sizeof(WINTRUST_DATA),             // cbStruct
        nullptr,                           // pPolicyCallbackData
        nullptr,                           // pSIPClientData
        WTD_UI_NONE,                       // dwUIChoice
        WTD_REVOKE_NONE,                   // fdwRevocationChecks
        WTD_CHOICE_FILE,                   // dwUnionChoice
        &fileInfo,                         // pFile
        WTD_STATEACTION_IGNORE,            // dwStateAction
        nullptr, nullptr, 0,               // others
        WTD_CACHE_ONLY_URL_RETRIEVAL       // dwProvFlags
    };

    static GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    return WinVerifyTrust(nullptr, &policyGUID, &winTrustData) == ERROR_SUCCESS;
}

inline SignatureStatus GetSignatureStatus(const std::wstring& path)
{
    auto cached = g_signatureCache.find(path);
    if (cached != g_signatureCache.end())
        return cached->second;

    DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        g_signatureCache[path] = SignatureStatus::NotFound;
        return SignatureStatus::NotFound;
    }

    const bool isSigned = HasValidDigitalSignature(path);
    const SignatureStatus status = isSigned ? SignatureStatus::Signed : SignatureStatus::Unsigned;

    g_signatureCache[path] = status;
    return status;
}