#pragma once

#include <Windows.h>
#include <winioctl.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <cwctype>
#include "_time_utils.h"

class USNJournalReader {
public:
    struct USNEvent {
        std::string filenameOld;
        std::string filenameNew;
        std::string action;
        time_t timestamp;
        bool isPrefetchDir = false;
    };

    explicit USNJournalReader(const std::wstring& volumeLetter)
        : volumeLetter_(volumeLetter) {
    }

    std::vector<USNEvent> Run()
    {
        std::vector<USNEvent> results;
        if (Dump(results))
            return results;
        return {};
    }

private:
    struct RenameInfo
    {
        std::string oldName;
        time_t time = 0;
        bool isPf = false;
    };

    static constexpr size_t BUFFER_SIZE = 32 * 1024 * 1024;

    std::wstring volumeLetter_;
    HANDLE volumeHandle_ = INVALID_HANDLE_VALUE;
    BYTE* buffer_ = nullptr;
    USN_JOURNAL_DATA_V0 journalData_{};

    std::unordered_set<ULONGLONG> trackedPrefetchFRN_;
    std::unordered_map<ULONGLONG, RenameInfo> renameCache_;

    static bool EndsWithPf(const std::wstring& name)
    {
        if (name.size() < 3) return false;
        std::wstring ext = name.substr(name.size() - 3);
        for (auto& c : ext) c = std::towlower(c);
        return ext == L".pf";
    }

    static bool IsExactPrefetchDir(const std::wstring& name)
    {
        std::wstring lower = name;
        for (auto& c : lower) c = std::towlower(c);
        return lower == L"prefetch";
    }

    static std::string WStringToUTF8(const std::wstring& wstr)
    {
        if (wstr.empty()) return {};
        int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.size()), nullptr, 0, nullptr, nullptr);

        std::string result(sizeNeeded, 0);
        WideCharToMultiByte( CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.size()), &result[0], sizeNeeded, nullptr, nullptr);
        return result;
    }

    bool Dump(std::vector<USNEvent>& results)
    {
        if (!OpenVolume()) return false;
        if (!QueryJournal()) { CloseVolume(); return false; }
        if (!AllocateBuffer()) { CloseVolume(); return false; }

        bool ok = ReadJournal(results);
        Cleanup();
        return ok;
    }

    bool OpenVolume()
    {
        std::wstring devicePath = L"\\\\.\\" + volumeLetter_;
        volumeHandle_ = CreateFileW(
            devicePath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr
        );
        return volumeHandle_ != INVALID_HANDLE_VALUE;
    }

    bool QueryJournal()
    {
        DWORD bytesReturned = 0;
        return DeviceIoControl(
            volumeHandle_,
            FSCTL_QUERY_USN_JOURNAL,
            nullptr, 0,
            &journalData_, sizeof(journalData_),
            &bytesReturned,
            nullptr);
    }

    bool AllocateBuffer()
    {
        buffer_ = static_cast<BYTE*>(VirtualAlloc(nullptr, BUFFER_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        return buffer_ != nullptr;
    }

    bool ReadJournal(std::vector<USNEvent>& results)
    {
        READ_USN_JOURNAL_DATA_V0 readData{};
        readData.StartUsn = journalData_.FirstUsn;
        readData.ReasonMask = USN_REASON_RENAME_OLD_NAME | USN_REASON_RENAME_NEW_NAME | USN_REASON_FILE_DELETE;
        readData.UsnJournalID = journalData_.UsnJournalID;

        DWORD bytesReturned = 0;
        time_t logonTime = GetCurrentUserLogonTime();

        results.reserve(1000);

        while (DeviceIoControl(volumeHandle_, FSCTL_READ_USN_JOURNAL, &readData, sizeof(readData), buffer_, BUFFER_SIZE, &bytesReturned, nullptr))
        {
            if (bytesReturned <= sizeof(USN))
                break;

            BYTE* ptr = buffer_ + sizeof(USN);
            BYTE* end = buffer_ + bytesReturned;

            while (ptr < end)
            {
                auto* rec = reinterpret_cast<USN_RECORD_V2*>(ptr);
                if (rec->RecordLength == 0) break;

                std::wstring filename( rec->FileName, rec->FileNameLength / sizeof(WCHAR));

                FILETIME ft;
                ft.dwLowDateTime = rec->TimeStamp.LowPart;
                ft.dwHighDateTime = rec->TimeStamp.HighPart;
                time_t usnTime = FileTimeToTimeT(ft);

                if (usnTime <= logonTime)
                {
                    ptr += rec->RecordLength;
                    continue;
                }

                ULONGLONG frn = rec->FileReferenceNumber;

                if (IsExactPrefetchDir(filename))
                {
                    trackedPrefetchFRN_.insert(frn);
                }

                bool isPrefetchDir = trackedPrefetchFRN_.count(frn) != 0;
                bool isPfFile = EndsWithPf(filename);

                if (rec->Reason & USN_REASON_RENAME_OLD_NAME)
                {
                    renameCache_[frn] = { WStringToUTF8(filename), usnTime, isPfFile };
                }
                else if (rec->Reason & USN_REASON_RENAME_NEW_NAME)
                {
                    auto it = renameCache_.find(frn);
                    if (it != renameCache_.end())
                    {
                        if (isPrefetchDir)
                        {
                            results.push_back({ it->second.oldName, WStringToUTF8(filename), "Prefetch Directory Rename", usnTime, true });
                        }
                        else if (it->second.isPf)
                        {
                            results.push_back({  it->second.oldName,  WStringToUTF8(filename), "Renamed", usnTime, false });
                        }

                        renameCache_.erase(it);
                    }
                }
                else if (rec->Reason & USN_REASON_FILE_DELETE)
                {
                    if (isPrefetchDir)
                    {
                        results.push_back({  WStringToUTF8(filename),  "", "Prefetch Directory Delete", usnTime, true });
                    }
                    else if (isPfFile)
                    {
                        results.push_back({ WStringToUTF8(filename), "", "Deleted",  usnTime, false });
                    }
                }

                ptr += rec->RecordLength;
            }

            readData.StartUsn = *(USN*)buffer_;
        }

        return true;
    }

    void Cleanup()
    {
        if (buffer_)
        {
            VirtualFree(buffer_, 0, MEM_RELEASE);
            buffer_ = nullptr;
        }

        CloseVolume();
        renameCache_.clear();
        trackedPrefetchFRN_.clear();
    }

    void CloseVolume()
    {
        if (volumeHandle_ != INVALID_HANDLE_VALUE)
        {
            CloseHandle(volumeHandle_);
            volumeHandle_ = INVALID_HANDLE_VALUE;
        }
    }
};