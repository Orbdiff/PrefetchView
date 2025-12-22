#include <windows.h>
#include <winevt.h>
#include <sstream>
#include <vector>
#include <string>
#include <algorithm>
#include <ctime>
#include "../ui_help/_time_utils.h"

struct EventRecord
{
    DWORD event_id{};
    std::wstring time_created;
    std::wstring device_name;
    std::wstring message;
};

inline std::wstring get_attr_value(const std::wstring& xml,
    const std::wstring& tag,
    const std::wstring& attr)
{
    size_t tag_pos = xml.find(L"<" + tag);
    if (tag_pos == std::wstring::npos)
        return L"";

    size_t attr_pos = xml.find(attr + L"='", tag_pos);
    if (attr_pos == std::wstring::npos)
        return L"";

    attr_pos += attr.size() + 2;
    size_t end = xml.find(L"'", attr_pos);
    if (end == std::wstring::npos)
        return L"";

    return xml.substr(attr_pos, end - attr_pos);
}

inline std::wstring get_data_value(const std::wstring& xml,
    const std::wstring& name)
{
    std::wstring key = L"<Data Name='" + name + L"'>";
    size_t pos = xml.find(key);
    if (pos == std::wstring::npos)
        return L"";

    pos += key.size();
    size_t end = xml.find(L"</Data>", pos);
    if (end == std::wstring::npos)
        return L"";

    return xml.substr(pos, end - pos);
}

inline std::wstring format_time(const std::wstring& iso)
{
    if (iso.empty())
        return L"";

    size_t t_pos = iso.find(L'T');
    if (t_pos == std::wstring::npos)
        return iso;

    std::wstring date = iso.substr(0, t_pos);
    std::wstring time = iso.substr(t_pos + 1);

    if (!time.empty() && time.back() == L'Z')
        time.pop_back();

    size_t dot_pos = time.find(L'.');
    if (dot_pos != std::wstring::npos)
        time = time.substr(0, dot_pos);

    return date + L" " + time;
}

inline time_t IsoToTimeT(const std::wstring& iso)
{
    struct tm tm_time {};
    if (iso.size() < 19)
        return 0;

    swscanf_s(
        iso.c_str(),
        L"%4d-%2d-%2d %2d:%2d:%2d",
        &tm_time.tm_year,
        &tm_time.tm_mon,
        &tm_time.tm_mday,
        &tm_time.tm_hour,
        &tm_time.tm_min,
        &tm_time.tm_sec
    );

    tm_time.tm_year -= 1900;
    tm_time.tm_mon -= 1;

    return mktime(&tm_time);
}

inline EventRecord parse_event(const std::wstring& xml)
{
    EventRecord ev{};

    size_t id_pos = xml.find(L"<EventID>");
    if (id_pos != std::wstring::npos)
    {
        id_pos += 9;
        size_t end = xml.find(L"</EventID>", id_pos);
        if (end != std::wstring::npos)
            ev.event_id = std::stoul(xml.substr(id_pos, end - id_pos));
    }

    ev.time_created = get_attr_value(xml, L"TimeCreated", L"SystemTime");
    ev.device_name = get_data_value(xml, L"DeviceName");

    if (ev.event_id == 1)
        ev.message = L"The FileInfo driver has been unloaded";
    else if (ev.event_id == 6)
        ev.message = L"The FileInfo driver has been loaded into the kernel";

    return ev;
}

inline void FileInfoEvents(std::wstringstream& out)
{
    time_t logonTime = GetCurrentUserLogonTime();
    if (!logonTime)
    {
        out << L"[ERROR] Could not get current user logon time\n";
        return;
    }

    EVT_HANDLE hQuery = EvtQuery(
        nullptr,
        L"System",
        L"*[System[(EventID=1 or EventID=6)]]",
        EvtQueryReverseDirection
    );

    if (!hQuery)
    {
        out << L"[ERROR] EvtQuery failed: " << GetLastError() << L"\n";
        return;
    }

    EVT_HANDLE hEvents[8];
    DWORD returned = 0;

    while (EvtNext(hQuery, 8, hEvents, INFINITE, 0, &returned))
    {
        for (DWORD i = 0; i < returned; ++i)
        {
            EVT_HANDLE hEvent = hEvents[i];

            DWORD used = 0, count = 0;
            EvtRender(nullptr, hEvent, EvtRenderEventXml,
                0, nullptr, &used, &count);

            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
            {
                std::vector<wchar_t> buffer(used);

                if (EvtRender(nullptr, hEvent, EvtRenderEventXml,
                    used, buffer.data(), &used, &count))
                {
                    std::wstring xml(buffer.data());
                    EventRecord ev = parse_event(xml);

                    std::wstring dev = ev.device_name;
                    std::transform(dev.begin(), dev.end(),
                        dev.begin(), ::towlower);

                    if (dev.find(L"fileinfo") == std::wstring::npos)
                        continue;

                    std::wstring cleanTime = format_time(ev.time_created);
                    time_t evTime = IsoToTimeT(cleanTime);

                    if (evTime < logonTime)
                        continue;

                    out << L"\n";
                    out << L"[-] EventID    : " << ev.event_id << L"\n";
                    out << L"[-] Time       : " << cleanTime << L"\n";
                    out << L"[-] DeviceName : " << ev.device_name << L"\n";
                    out << L"[-] Message    : " << ev.message << L"\n\n";
                }
            }

            EvtClose(hEvent);
        }
    }

    EvtClose(hQuery);
}