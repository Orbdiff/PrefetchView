#include "_time_utils.h"

#include <windows.h>
#include <ntsecapi.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <lmcons.h>

struct LsaBufferGuard
{
    PVOID buffer;
    LsaBufferGuard(PVOID buf) : buffer(buf) {}
    LsaBufferGuard(const LsaBufferGuard&) = delete;
    LsaBufferGuard& operator=(const LsaBufferGuard&) = delete;
    ~LsaBufferGuard() { if (buffer) LsaFreeReturnBuffer(buffer); }
    PVOID get() const { return buffer; }
};

std::string FormatUptime(time_t startTime)
{
    time_t now = time(nullptr);
    double totalSeconds = difftime(now, startTime);

    int days = static_cast<int>(totalSeconds / 86400);
    int hours = static_cast<int>((totalSeconds - days * 86400) / 3600);
    int minutes = static_cast<int>((totalSeconds - days * 86400 - hours * 3600) / 60);

    std::stringstream ss;
    auto appendUnit = [&](int value, const std::string& singular, const std::string& plural) 
        {
        if (value > 0) 
        {
            ss << value << " " << (value == 1 ? singular : plural) << " ";
        }
        };

    appendUnit(days, "day", "days");
    appendUnit(hours, "hour", "hours");
    appendUnit(minutes, "minute", "minutes");
    if (days == 0 && hours == 0 && minutes == 0) 
    {
        ss << "a few seconds ";
    }

    char buf[64];
    struct tm localTime {};
    localtime_s(&localTime, &startTime);
    strftime(buf, sizeof(buf), "(%I:%M:%S %p %m/%d/%Y)", &localTime);
    ss << buf;

    return ss.str();
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
    {
        return 0;
    }

    ULONG count = 0;
    PLUID sessions = nullptr;
    NTSTATUS status = LsaEnumerateLogonSessions(&count, &sessions);
    if (status != 0 || sessions == nullptr)
    {
        return 0;
    }

    LsaBufferGuard sessionGuard(sessions);

    for (ULONG i = 0; i < count; ++i)
    {
        PSECURITY_LOGON_SESSION_DATA pData = nullptr;
        NTSTATUS statusData = LsaGetLogonSessionData(&sessions[i], &pData);
        if (statusData == 0 && pData) 
        {
            LsaBufferGuard dataGuard(pData);
            if (pData->UserName.Buffer &&
                pData->LogonType == Interactive &&
                _wcsicmp(pData->UserName.Buffer, username) == 0)
            {
                FILETIME ft;
                ft.dwLowDateTime = static_cast<DWORD>(pData->LogonTime.LowPart);
                ft.dwHighDateTime = static_cast<DWORD>(pData->LogonTime.HighPart);
                return FileTimeToTimeT(ft);
            }
        }
    }

    return 0;
}