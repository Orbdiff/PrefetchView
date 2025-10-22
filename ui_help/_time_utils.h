#pragma once

#include <windows.h>
#include <ntsecapi.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <ctime>
#include <lmcons.h>

time_t FileTimeToTimeT(const FILETIME& ft)
{
    ULARGE_INTEGER ull;
    ull.LowPart = ft.dwLowDateTime;
    ull.HighPart = ft.dwHighDateTime;
    return static_cast<time_t>((ull.QuadPart - 116444736000000000ULL) / 10000000ULL);
}

time_t GetCurrentUserLogonTime()
{
    wchar_t username[UNLEN + 1];
    DWORD size = UNLEN + 1;
    if (!GetUserNameW(username, &size))
        return 0;

    ULONG count = 0;
    PLUID sessions = nullptr;
    NTSTATUS status = LsaEnumerateLogonSessions(&count, &sessions);
    if (status != 0 || sessions == nullptr)
        return 0;

    time_t result = 0;

    for (ULONG i = 0; i < count; i++)
    {
        PSECURITY_LOGON_SESSION_DATA pData = nullptr;
        NTSTATUS statusData = LsaGetLogonSessionData(&sessions[i], &pData);
        if (statusData == 0 && pData)
        {
            if (pData->UserName.Buffer &&
                pData->LogonType == Interactive &&
                _wcsicmp(pData->UserName.Buffer, username) == 0)
            {
                FILETIME ft;
                ft.dwLowDateTime = static_cast<DWORD>(pData->LogonTime.LowPart);
                ft.dwHighDateTime = static_cast<DWORD>(pData->LogonTime.HighPart);
                result = FileTimeToTimeT(ft);

                LsaFreeReturnBuffer(pData);
                break;
            }
            LsaFreeReturnBuffer(pData);
        }
    }

    if (sessions)
        LsaFreeReturnBuffer(sessions);

    return result;
}