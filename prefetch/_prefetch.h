#pragma once

#include "_prefetch_utils.h"
#include "../signature/_signature_parser.h"
#include "../driver_map/_drive_mapper.h"

#include <array>
#include <optional>
#include <string>
#include <vector>
#include <fstream>
#include <cstdint>
#include <cstring>
#include <memory>
#include <windows.h>
#include <type_traits>
#include <algorithm>

struct PrefetchInfo
{
    int version = 0;
    int signature = 0;
    int fileSize = 0;
    int runCount = 0;
    std::string filePath;
    std::wstring mainExecutablePath;
    std::vector<std::wstring> fileNames;
    std::vector<time_t> lastExecutionTimes;
    SignatureStatus signatureStatus = SignatureStatus::NotFound;
    std::vector<SignatureStatus> fileSignatures;
};

class PrefetchFile {
public:
    explicit PrefetchFile(const std::string& filepath) noexcept
    {
        if (!LoadBinaryFile(filepath, rawData_))
            return;

        if (rawData_.size() < 0x100)
            return;

        if (rawData_.size() >= 8 &&
            rawData_[0] == 'M' && rawData_[1] == 'A' && rawData_[2] == 'M') {
            if (auto dec = DecompressMAM(rawData_))
                rawData_ = std::move(*dec);
            else
                rawData_.clear();
        }
        else if (rawData_.size() >= 8 &&
            rawData_[4] == 'S' && rawData_[5] == 'C' && rawData_[6] == 'C' && rawData_[7] == 'A') {
        }
        else {
            rawData_.clear();
        }
    }

    bool IsValid() const noexcept { return !rawData_.empty(); }

    std::optional<PrefetchInfo> ExtractInfo(const std::string& filepath) const noexcept
    {
        if (!IsValid()) return std::nullopt;

        PrefetchInfo info;
        info.filePath = filepath;
        info.version = ReadLE<int>(0x0).value_or(0);
        info.signature = ReadLE<int>(0x4).value_or(0);
        info.fileSize = ReadLE<int>(0xC).value_or(0);
        info.fileNames = ExtractFileNames();
        info.lastExecutionTimes = ExtractExecutionTimes();

        switch (info.version) {
        case 17: info.runCount = ReadLE<int>(0x90).value_or(0); break;
        case 23: info.runCount = ReadLE<int>(0x98).value_or(0); break;
        case 26:
        case 30:
        case 31: info.runCount = ReadLE<int>(0xD0).value_or(0); break;
        default: info.runCount = 0; break;
        }
    
        std::wstring pfWPath(filepath.begin(), filepath.end());
        std::wstring exeName = ExtractExeNameFromPfFilename(pfWPath);
        info.mainExecutablePath = FindExecutablePath(exeName, info.fileNames);

        if (!info.mainExecutablePath.empty())
            info.signatureStatus = GetSignatureStatus(info.mainExecutablePath);
        else
            info.signatureStatus = SignatureStatus::NotFound;

        info.fileSignatures.reserve(info.fileNames.size());
        for (const auto& path : info.fileNames) {
            info.fileSignatures.push_back(GetSignatureStatus(path));
        }

        return info;
    }

    int GetVersion() const noexcept { return ReadLE<int>(0x0).value_or(0); }
    int GetSignature() const noexcept { return ReadLE<int>(0x4).value_or(0); }
    int GetFileSize() const noexcept { return ReadLE<int>(0xC).value_or(0); }

private:
    std::vector<char> rawData_;

    static constexpr size_t MIN_PF_SIZE = 0x100;

    static bool LoadBinaryFile(const std::string& filepath, std::vector<char>& out) noexcept
    {
        std::ifstream ifs(filepath, std::ios::binary | std::ios::ate);
        if (!ifs) return false;

        std::streamsize size = ifs.tellg();
        if (size <= 0) return false;

        out.resize(static_cast<size_t>(size));
        ifs.seekg(0, std::ios::beg);
        if (!ifs.read(out.data(), size)) return false;

        return true;
    }

    template<typename T>
    static std::optional<T> ReadLEFromBuffer(const std::vector<char>& buf, size_t offset) noexcept
    {
        static_assert(std::is_trivially_copyable<T>::value, "T must be trivially_copyable");
        if (offset + sizeof(T) > buf.size()) return std::nullopt;
        T v;
        std::memcpy(&v, buf.data() + offset, sizeof(T));
        return v;
    }

    template<typename T>
    std::optional<T> ReadLE(size_t offset) const noexcept
    {
        return ReadLEFromBuffer<T>(rawData_, offset);
    }

    static std::optional<std::vector<char>> DecompressMAM(const std::vector<char>& compressed) noexcept
    {
        if (compressed.size() < 8) return std::nullopt;

        uint32_t sig = 0;
        uint32_t decompressedSize = 0;
        std::memcpy(&sig, compressed.data(), sizeof(uint32_t));
        std::memcpy(&decompressedSize, compressed.data() + 4, sizeof(uint32_t));

        if ((sig & 0x00FFFFFFu) != 0x004D414Du)
            return std::nullopt;

        uint8_t format = static_cast<uint8_t>((sig & 0x0F000000u) >> 24);

        const char* payload = compressed.data() + 8;
        size_t payloadSize = compressed.size() - 8;

        using RtlDecompressBufferExFn = NTSTATUS(NTAPI*)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG, PVOID);
        using RtlGetCompressionWorkSpaceSizeFn = NTSTATUS(NTAPI*)(USHORT, PULONG, PULONG);

        HMODULE ntdll = ::GetModuleHandleA("ntdll.dll");
        if (!ntdll) return std::nullopt;

        auto rtlDecompress = reinterpret_cast<RtlDecompressBufferExFn>(
            ::GetProcAddress(ntdll, "RtlDecompressBufferEx"));
        auto rtlWorkspaceSize = reinterpret_cast<RtlGetCompressionWorkSpaceSizeFn>(
            ::GetProcAddress(ntdll, "RtlGetCompressionWorkSpaceSize"));

        if (!rtlDecompress || !rtlWorkspaceSize) return std::nullopt;

        ULONG ws1 = 0, ws2 = 0;
        NTSTATUS s = rtlWorkspaceSize(format, &ws1, &ws2);
        if (s != 0) return std::nullopt;

        std::vector<char> out;
        try {
            out.resize(decompressedSize);
        }
        catch (...) {
            return std::nullopt;
        }

        std::unique_ptr<std::byte[]> workspace;
        if (ws1 > 0) {
            try {
                workspace.reset(new std::byte[ws1]);
            }
            catch (...) {
                return std::nullopt;
            }
        }

        ULONG finalSize = 0;
        NTSTATUS status = rtlDecompress(
            static_cast<USHORT>(format),
            reinterpret_cast<PUCHAR>(out.data()), static_cast<ULONG>(out.size()),
            reinterpret_cast<PUCHAR>(const_cast<char*>(payload)), static_cast<ULONG>(payloadSize),
            &finalSize,
            workspace ? reinterpret_cast<PVOID>(workspace.get()) : nullptr
        );

        if (status != 0) return std::nullopt;
        if (finalSize != out.size()) {
            out.resize(finalSize);
        }

        return out;
    }

    std::vector<std::wstring> ExtractFileNames() const noexcept
    {
        std::vector<std::wstring> results;
        auto offOpt = ReadLE<int>(0x64);
        auto sizeOpt = ReadLE<int>(0x68);
        if (!offOpt || !sizeOpt) return results;

        const size_t offset = static_cast<size_t>(*offOpt);
        const size_t sizeBytes = static_cast<size_t>(*sizeOpt);

        if (offset + sizeBytes > rawData_.size()) return results;
        if (sizeBytes == 0) return results;

        results.reserve(16);

        std::wstring current;
        for (size_t pos = 0; pos + sizeof(wchar_t) <= sizeBytes; pos += sizeof(wchar_t)) {
            wchar_t ch;
            std::memcpy(&ch, rawData_.data() + offset + pos, sizeof(wchar_t));
            if (ch == L'\0') {
                if (!current.empty()) {
                    std::wstring drive;
                    results.push_back(ConvertVolumePathToDrive(current, drive));
                    current.clear();
                }
            }
            else {
                current += ch;
            }
        }
        if (!current.empty()) {
            std::wstring drive;
            results.push_back(ConvertVolumePathToDrive(current, drive));
        }
        return results;
    }

    std::vector<time_t> ExtractExecutionTimes() const noexcept
    {
        std::vector<time_t> times;
        int version = ReadLE<int>(0x0).value_or(0);
        size_t offset = 0;

        switch (version) {
        case 17: offset = 0x78; break;
        case 23:
        case 26:
        case 30:
        case 31: offset = 0x80; break;
        default: return times;
        }

        for (int i = 0; i < 8; ++i) {
            if (offset + sizeof(uint64_t) > rawData_.size()) break;
            uint64_t li = 0;
            std::memcpy(&li, rawData_.data() + offset, sizeof(uint64_t));
            if (li != 0) {
                FILETIME ft;
                ft.dwLowDateTime = static_cast<DWORD>(li & 0xFFFFFFFFu);
                ft.dwHighDateTime = static_cast<DWORD>((li >> 32) & 0xFFFFFFFFu);
                times.push_back(FileTimeToUnixTime(ft));
            }
            offset += sizeof(uint64_t);
        }
        return times;
    }

    static time_t FileTimeToUnixTime(const FILETIME& ft) noexcept
    {
        const unsigned long long filetime = (static_cast<unsigned long long>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
        constexpr unsigned long long HUNDRED_NS_PER_SEC = 10000000ULL;
        constexpr unsigned long long EPOCH_DIFF = 11644473600ULL;
        return static_cast<time_t>(filetime / HUNDRED_NS_PER_SEC - EPOCH_DIFF);
    }
};