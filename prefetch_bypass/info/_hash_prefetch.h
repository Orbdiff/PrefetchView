#include <windows.h>
#include <wincrypt.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <unordered_map>
#include <vector>
#include <sstream>
#include <iomanip>

inline void DetectDuplicatePrefetchByHash()
{
    const std::filesystem::path prefetchPath = L"C:\\Windows\\Prefetch";
    std::unordered_map<std::string, std::vector<std::wstring>> hashMap;
    bool duplicatesFound = false;

    for (const auto& entry : std::filesystem::directory_iterator(prefetchPath))
    {
        if (!entry.is_regular_file())
            continue;

        if (entry.path().extension() != L".pf")
            continue;

        std::ifstream file(entry.path(), std::ios::binary);
        if (!file)
            continue;

        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;

        if (!CryptAcquireContext(
            &hProv,
            nullptr,
            nullptr,
            PROV_RSA_AES,
            CRYPT_VERIFYCONTEXT))
            continue;

        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
        {
            CryptReleaseContext(hProv, 0);
            continue;
        }

        BYTE buffer[8192];
        BYTE hash[32];
        DWORD hashSize = sizeof(hash);

        bool hashError = false;

        while (file.read(reinterpret_cast<char*>(buffer), sizeof(buffer)) ||
            file.gcount() > 0)
        {
            if (!CryptHashData(
                hHash,
                buffer,
                static_cast<DWORD>(file.gcount()),
                0))
            {
                hashError = true;
                break;
            }
        }

        if (!hashError &&
            CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashSize, 0))
        {
            std::ostringstream oss;
            for (DWORD i = 0; i < hashSize; i++)
            {
                oss << std::hex << std::uppercase
                    << std::setw(2) << std::setfill('0')
                    << static_cast<int>(hash[i]);
            }

            hashMap[oss.str()].push_back(entry.path().filename().wstring());
        }

        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
    }

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    const WORD blueColor = FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    const WORD yellowColor = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    const WORD whiteColor = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;

    std::wcout << L"\n============================\n";
    SetConsoleTextAttribute(hConsole, blueColor);
    std::wcout << L"\n[/] Duplicate Hash Prefetch\n";

    for (const auto& [hash, files] : hashMap)
    {
        if (files.size() > 1)
        {
            duplicatesFound = true;

            SetConsoleTextAttribute(hConsole, yellowColor);
            std::cout << "\nHASH: " << hash << "\n\n";

            SetConsoleTextAttribute(hConsole, whiteColor);
            for (const auto& file : files)
                std::wcout << L"  " << file << L"\n";
        }
    }

    if (!duplicatesFound)
    {
        SetConsoleTextAttribute(hConsole, whiteColor);
        std::wcout << L"\n[+] No duplicated Prefetch files were found.\n\n";
    }

    SetConsoleTextAttribute(hConsole, whiteColor);
}