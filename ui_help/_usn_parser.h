#pragma once

#include <Windows.h>
#include <winioctl.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <cwctype>
#include "_time_utils.h"

class USNJournalReader {
public:
    struct USNEvent {
        std::string filenameOld;
        std::string filenameNew;
        std::string action;
        time_t timestamp;
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
    struct RenameInfo {
        std::string oldName;
        time_t time = 0;
    };

    std::wstring volumeLetter_;
    HANDLE volumeHandle_ = INVALID_HANDLE_VALUE;
    BYTE* buffer_ = nullptr;
    USN_JOURNAL_DATA_V0 journalData_{};
    std::unordered_map<ULONGLONG, RenameInfo> renameCache_;

    bool Dump(std::vector<USNEvent>& results)
    {
        if (!OpenVolume()) return false;
        if (!QueryJournal()) { CloseVolume(); return false; }
        if (!AllocateBuffer()) { CloseVolume(); return false; }

        bool result = ReadJournal(results);
        Cleanup();
        return result;
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
        const DWORD bufferSize = 32 * 1024 * 1024; // 32 MB
        buffer_ = (BYTE*)VirtualAlloc(nullptr, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        return buffer_ != nullptr;
    }

    static bool EndsWithPf(const std::wstring& name)
    {
        if (name.size() < 3) return false;
        std::wstring ext = name.substr(name.size() - 3);
        for (auto& c : ext) c = std::towlower(c);
        return ext == L".pf";
    }

    bool ReadJournal(std::vector<USNEvent>& results)
    {
        READ_USN_JOURNAL_DATA_V0 readData{};
        readData.StartUsn = journalData_.FirstUsn;
        readData.ReasonMask = 0xFFFFFFFF;
        readData.UsnJournalID = journalData_.UsnJournalID;

        const DWORD bufferSize = 32 * 1024 * 1024;
        DWORD bytesReturned = 0;

        time_t logonTime = GetCurrentUserLogonTime();

        while (DeviceIoControl(
            volumeHandle_,
            FSCTL_READ_USN_JOURNAL,
            &readData, sizeof(readData),
            buffer_, bufferSize,
            &bytesReturned,
            nullptr))
        {
            if (bytesReturned <= sizeof(USN)) break;

            BYTE* ptr = buffer_ + sizeof(USN);
            BYTE* end = buffer_ + bytesReturned;

            while (ptr < end)
            {
                USN_RECORD_V2* rec = reinterpret_cast<USN_RECORD_V2*>(ptr);
                if (rec->RecordLength == 0) break;

                std::wstring filename(rec->FileName, rec->FileNameLength / sizeof(WCHAR));
                FILETIME ft;
                ft.dwLowDateTime = rec->TimeStamp.LowPart;
                ft.dwHighDateTime = rec->TimeStamp.HighPart;
                time_t usnTime = FileTimeToTimeT(ft);

                if (usnTime > logonTime)
                {
                    ULONGLONG fileRef = rec->FileReferenceNumber;

                    if (rec->Reason & USN_REASON_RENAME_OLD_NAME)
                    {
                        renameCache_[fileRef] = { WStringToUTF8(filename), usnTime };
                    }
                    else if (rec->Reason & USN_REASON_RENAME_NEW_NAME)
                    {
                        auto it = renameCache_.find(fileRef);
                        if (it != renameCache_.end())
                        {
                            if (EndsWithPf(std::wstring(it->second.oldName.begin(), it->second.oldName.end())))
                            {
                                results.push_back({
                                    it->second.oldName,
                                    WStringToUTF8(filename),
                                    "Renamed",
                                    usnTime
                                    });
                            }
                            renameCache_.erase(it);
                        }
                    }
                    else if (rec->Reason & USN_REASON_FILE_DELETE)
                    {
                        if (EndsWithPf(filename))
                        {
                            results.push_back({
                                WStringToUTF8(filename),
                                "",
                                "Deleted",
                                usnTime
                                });
                        }
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
        FreeBuffer();
        CloseVolume();
        renameCache_.clear();
    }

    void FreeBuffer()
    {
        if (buffer_)
        {
            VirtualFree(buffer_, 0, MEM_RELEASE);
            buffer_ = nullptr;
        }
    }

    void CloseVolume()
    {
        if (volumeHandle_ != INVALID_HANDLE_VALUE)
        {
            CloseHandle(volumeHandle_);
            volumeHandle_ = INVALID_HANDLE_VALUE;
        }
    }

    static std::string WStringToUTF8(const std::wstring& wstr)
    {
        if (wstr.empty()) return {};
        int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
        std::string result(sizeNeeded, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), &result[0], sizeNeeded, nullptr, nullptr);
        return result;
    }
};