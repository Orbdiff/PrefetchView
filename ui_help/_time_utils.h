#pragma once

#include <windows.h>
#include <ntsecapi.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <ctime>
#include <lmcons.h>

std::string FormatUptime(time_t startTime)
{
    time_t now = time(nullptr);
    double seconds = difftime(now, startTime);

    int days = static_cast<int>(seconds / 86400);
    int hours = static_cast<int>((seconds - days * 86400) / 3600);
    int minutes = static_cast<int>((seconds - days * 86400 - hours * 3600) / 60);

    std::string result;
    if (days > 0) result += std::to_string(days) + (days > 1 ? " days " : " day ");
    if (hours > 0) result += std::to_string(hours) + (hours > 1 ? " hours " : " hour ");
    if (minutes > 0) result += std::to_string(minutes) + (minutes > 1 ? " minutes " : " minute ");
    if (days == 0 && hours == 0 && minutes == 0) result += "a few seconds ";

    char buf[64];
    struct tm localTime {};
    localtime_s(&localTime, &startTime);
    strftime(buf, sizeof(buf), "(%I:%M:%S %p %m/%d/%Y)", &localTime);
    result += buf;

    return result;
}

std::string FormatTime(time_t t)
{
    char buf[64];
    struct tm localTime {};
    localtime_s(&localTime, &t);
    strftime(buf, sizeof(buf), "%I:%M:%S %p %m/%d/%Y", &localTime);
    return std::string(buf);
}

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