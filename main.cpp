#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#include "wil/resource.h"

#include "prefetch/_prefetch_parser.h"
#include "ui_help/_font.h"
#include "ui_help/_time_utils.h"
#include "ui_help/_usn_parser.h"
#include "ui_help/_service_status.h"
#include "privilege/_privilege.hpp"
#include "yara/_yara_scan.hpp"
#include "prefetch_bypass/info.h"

#include <d3d11.h>
#include <tchar.h>
#include <windows.h>
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <ctime>
#include <filesystem>
#include <Shlwapi.h>
#include <algorithm>
#include <cctype>
#include <ntsecapi.h>
#include <Lmcons.h>
#include <wrl/client.h>
#include <cstdlib>

ID3D11Device*           g_pd3dDevice           = nullptr;
ID3D11DeviceContext*    g_pd3dDeviceContext    = nullptr;
IDXGISwapChain*         g_pSwapChain           = nullptr;
ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;

extern LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);
extern ID3D11Device* g_pd3dDevice;

std::vector<PrefetchResult> prefetchData;
std::atomic<bool> isLoading{ true };
std::atomic<bool> analysisDone{ false };
std::mutex dataMutex;
std::atomic<int> activeThreads{ 0 };
float fadeIn = 0.0f;

struct IconDataDX11 
{
    Microsoft::WRL::ComPtr<ID3D11ShaderResourceView> TextureView;
    int Width  = 0;
    int Height = 0;
    bool IsLoaded = false;
};

static std::unordered_map<std::wstring, IconDataDX11> g_iconsCache;
static std::unordered_set<std::wstring> g_pendingIcons;
static std::queue<std::wstring> g_iconQueue;
static std::mutex g_iconMutex;
static std::condition_variable g_iconCv;
static bool g_iconThreadExit = false;
static IconDataDX11 g_genericIcon;
static std::vector<std::string> prefetchFiles;
static bool isInitialized = false;
static float exampleProgressTimer = 0.0f;
static float timer = 0.0f;

void CreateRenderTarget()
{
    ID3D11Texture2D* pBackBuffer = nullptr;
    HRESULT hr = g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    if (FAILED(hr) || !pBackBuffer)
    {
        MessageBox(nullptr, L"Failed to get back buffer", L"Error", MB_OK);
        return;
    }
    hr = g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    if (FAILED(hr))
    {
        pBackBuffer->Release();
        MessageBox(nullptr, L"Failed to create render target view", L"Error", MB_OK);
        return;
    }
    pBackBuffer->Release();
}

void CleanupRenderTarget()
{
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

bool CreateDeviceD3D(HWND hWnd)
{
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    const D3D_FEATURE_LEVEL levels[] = { D3D_FEATURE_LEVEL_11_0 };
    D3D_FEATURE_LEVEL createdLevel;
    HRESULT res = D3D11CreateDeviceAndSwapChain(
        NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, 0,
        levels, 1, D3D11_SDK_VERSION,
        &sd, &g_pSwapChain, &g_pd3dDevice,
        &createdLevel, &g_pd3dDeviceContext);

    if (FAILED(res))
        return false;

    CreateRenderTarget();
    return true;
}

void CleanupDeviceD3D()
{
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

bool LoadFileIconDX11(ID3D11Device* device, const std::wstring& filePath, IconDataDX11& outIcon)
{
    if (!device || filePath.empty())
        return false;

    SHFILEINFO shfi{};
    if (!SHGetFileInfoW(filePath.c_str(), FILE_ATTRIBUTE_NORMAL, &shfi, sizeof(shfi),
        SHGFI_ICON | SHGFI_LARGEICON) || !shfi.hIcon)
        return false;

    wil::unique_hicon hIcon{ shfi.hIcon };

    ICONINFO iconInfo{};
    if (!GetIconInfo(hIcon.get(), &iconInfo))
        return false;

    wil::unique_hbitmap hbmColor{ iconInfo.hbmColor };
    wil::unique_hbitmap hbmMask{ iconInfo.hbmMask };

    BITMAP bm{};
    if (!GetObject(hbmColor.get(), sizeof(BITMAP), &bm))
        return false;

    const int width = bm.bmWidth;
    const int height = bm.bmHeight;

    wil::unique_hdc hdc{ CreateCompatibleDC(nullptr) };
    if (!hdc)
        return false;

    BITMAPINFO bmi{};
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = width;
    bmi.bmiHeader.biHeight = -height;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;

    std::vector<BYTE> pixels(width * height * 4);
    if (!GetDIBits(hdc.get(), hbmColor.get(), 0, height, pixels.data(), &bmi, DIB_RGB_COLORS))
        return false;

    D3D11_TEXTURE2D_DESC desc{};
    desc.Width = width;
    desc.Height = height;
    desc.MipLevels = 1;
    desc.ArraySize = 1;
    desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

    D3D11_SUBRESOURCE_DATA initData{};
    initData.pSysMem = pixels.data();
    initData.SysMemPitch = width * 4;

    Microsoft::WRL::ComPtr<ID3D11Texture2D> texture;
    HRESULT hr = device->CreateTexture2D(&desc, &initData, &texture);
    if (FAILED(hr))
        return false;

    hr = device->CreateShaderResourceView(texture.Get(), nullptr, &outIcon.TextureView);
    if (FAILED(hr))
        return false;

    outIcon.Width = width;
    outIcon.Height = height;
    outIcon.IsLoaded = true;
    return true;
}

void IconWorkerThread(ID3D11Device* device)
{
    while (true)
    {
        std::wstring path;

        {
            std::unique_lock<std::mutex> lock(g_iconMutex);
            g_iconCv.wait(lock, [] { return !g_iconQueue.empty() || g_iconThreadExit; });
            if (g_iconThreadExit && g_iconQueue.empty()) break;

            path = g_iconQueue.front();
            g_iconQueue.pop();
        }

        IconDataDX11 icon;
        if (!LoadFileIconDX11(device, path, icon))
            icon = g_genericIcon;

        {
            std::lock_guard<std::mutex> lock(g_iconMutex);
            g_iconsCache[path] = std::move(icon);
            g_pendingIcons.erase(path);
        }
    }
}

void EnsureIconLoadedAsync(ID3D11Device* device, const std::wstring& path)
{
    if (path.empty() || !device) return;

    std::lock_guard<std::mutex> lock(g_iconMutex);
    if (g_iconsCache.contains(path) || g_pendingIcons.contains(path))
        return;

    g_pendingIcons.insert(path);
    g_iconQueue.push(path);
    g_iconCv.notify_one();

    static bool threadStarted = false;
    if (!threadStarted)
    {
        threadStarted = true;
        std::thread(IconWorkerThread, device).detach();
    }
}

IconDataDX11* GetOrQueueIcon(ID3D11Device* device, const std::wstring& path)
{
    {
        std::lock_guard<std::mutex> lock(g_iconMutex);
        auto it = g_iconsCache.find(path);
        if (it != g_iconsCache.end())
            return &it->second;
    }

    EnsureIconLoadedAsync(device, path);
    return &g_genericIcon;
}


void CopyToClipboard(const std::wstring& text)
{
    if (OpenClipboard(nullptr))
    {
        EmptyClipboard();

        size_t sizeInBytes = (text.size() + 1) * sizeof(wchar_t);
        HGLOBAL hGlob = GlobalAlloc(GMEM_MOVEABLE, sizeInBytes);

        if (hGlob)
        {
            void* pGlob = GlobalLock(hGlob);
            if (pGlob)
            {
                memcpy(pGlob, text.c_str(), sizeInBytes);
                GlobalUnlock(hGlob);
                SetClipboardData(CF_UNICODETEXT, hGlob);
            }
            else
            {
                GlobalFree(hGlob);
            }
        }

        CloseClipboard();
    }
}

std::string FileTimeToString(const FILETIME& ft)
{
    SYSTEMTIME stUTC, stLocal;
    if (!FileTimeToSystemTime(&ft, &stUTC))
        return "N/A";
    if (!SystemTimeToTzSpecificLocalTime(nullptr, &stUTC, &stLocal))
        return "N/A";

    std::stringstream ss;
    ss << std::setfill('0')
        << std::setw(4) << stLocal.wYear << "-"
        << std::setw(2) << stLocal.wMonth << "-"
        << std::setw(2) << stLocal.wDay << " "
        << std::setw(2) << stLocal.wHour << ":"
        << std::setw(2) << stLocal.wMinute << ":"
        << std::setw(2) << stLocal.wSecond;
    return ss.str();
}

static ImVec4 GetLineColor(const std::wstring& line)
{
    if (line.find(L"[SERVICE]") != std::wstring::npos)
    {
        if (line.find(L"Running") != std::wstring::npos)
            return ImVec4(0.3f, 1.0f, 0.3f, 1.0f);

        if (line.find(L"Stopped") != std::wstring::npos)
            return ImVec4(1.0f, 0.2f, 0.2f, 1.0f);
    }

    if (line.find(L"[DRIVER]") != std::wstring::npos)
    {
        if (line.find(L"loaded") != std::wstring::npos &&
            line.find(L"NOT") == std::wstring::npos)
        {
            return ImVec4(0.3f, 1.0f, 0.3f, 1.0f);
        }

        if (line.find(L"NOT loaded") != std::wstring::npos)
            return ImVec4(1.0f, 0.2f, 0.2f, 1.0f);
    }

    if (line.find(L"[ERROR]") != std::wstring::npos)
        return ImVec4(1.0f, 0.2f, 0.2f, 1.0f);

    if (line.find(L"[+]") != std::wstring::npos)
        return ImVec4(0.3f, 1.0f, 0.3f, 1.0f);

    if (line.find(L"[/]") != std::wstring::npos)
        return ImVec4(0.4f, 0.6f, 1.0f, 1.0f);

    if (line.find(L"[#]") != std::wstring::npos)
        return ImVec4(1.0f, 0.85f, 0.2f, 1.0f);

    if (line.find(L"[-]") != std::wstring::npos)
        return ImVec4(1.0f, 1.0f, 1.0f, 1.0f);

    return ImVec4(0.85f, 0.85f, 0.85f, 1.0f);
}

static ImVec4 GetReasonColor(const USNJournalReader::USNEvent& e)
{
    if (e.isPrefetchDir)
        return ImVec4(0.65f, 0.45f, 0.85f, 1.0f);

    if (e.action.find("Delete") != std::string::npos)
        return ImVec4(0.85f, 0.35f, 0.35f, 1.0f);

    if (e.action.find("Rename") != std::string::npos)
        return ImVec4(0.85f, 0.75f, 0.35f, 1.0f);

    return ImVec4(0.75f, 0.75f, 0.75f, 1.0f);
}

void InitializePrefetchFiles() {
    if (isInitialized) return;
    prefetchFiles.clear();

    std::wstring prefetchDir = L"C:\\Windows\\Prefetch\\";
    WIN32_FIND_DATAW findFileData;
    HANDLE hFind = FindFirstFileW((prefetchDir + L"*.pf").c_str(), &findFileData);

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            char buffer[260];
            WideCharToMultiByte(CP_UTF8, 0, findFileData.cFileName, -1, buffer, sizeof(buffer), NULL, NULL);

            for (size_t i = 0; i < strlen(buffer); ++i) {
                buffer[i] = static_cast<char>(::toupper(static_cast<unsigned char>(buffer[i])));
            }

            prefetchFiles.push_back(std::string(buffer));
        } while (FindNextFileW(hFind, &findFileData) != 0);
        FindClose(hFind);
    }
    isInitialized = true;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg) {
    case WM_SIZE:
        if (g_pd3dDevice && wParam != SIZE_MINIMIZED) {
            if (g_mainRenderTargetView) CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, LOWORD(lParam), HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
            CreateRenderTarget();
        }
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

int WINAPI WinMain
(
    _In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPSTR     lpCmdLine,
    _In_ int       nCmdShow
) {
    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(NULL), NULL, NULL, NULL, NULL, _T("PrefetchView++"), NULL };
    RegisterClassEx(&wc);

    HWND hwnd = CreateWindow(wc.lpszClassName, _T("PrefetchView++"), WS_OVERLAPPEDWINDOW, 100, 100, 1280, 800, NULL, NULL, wc.hInstance, NULL);

    if (!CreateDeviceD3D(hwnd))
    {
        CleanupDeviceD3D();
        UnregisterClass(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    ShowWindow(hwnd, SW_SHOWMAXIMIZED);
    UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    (void)io;

    ImFontConfig CustomFont;
    CustomFont.FontDataOwnedByAtlas = false;

    ImFont* font = io.Fonts->AddFontFromMemoryTTF((void*)Custom, static_cast<int>(Custom_len), 17.0f, &CustomFont);

    io.FontDefault = font;

    ImGuiStyle& style = ImGui::GetStyle();
    ImVec4* colors = style.Colors;

    colors[ImGuiCol_Text]                 = ImVec4(0.95f, 0.95f, 0.95f, 1.00f);
    colors[ImGuiCol_TextDisabled]         = ImVec4(0.50f, 0.50f, 0.50f, 1.00f);
    colors[ImGuiCol_WindowBg]             = ImVec4(0.09f, 0.09f, 0.09f, 1.00f);
    colors[ImGuiCol_ChildBg]              = ImVec4(0.10f, 0.10f, 0.10f, 1.00f);
    colors[ImGuiCol_PopupBg]              = ImVec4(0.11f, 0.11f, 0.11f, 0.94f);
    colors[ImGuiCol_Border]               = ImVec4(0.19f, 0.19f, 0.19f, 1.00f);
    colors[ImGuiCol_BorderShadow]         = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_FrameBg]              = ImVec4(0.15f, 0.15f, 0.15f, 1.00f);
    colors[ImGuiCol_FrameBgHovered]       = ImVec4(0.20f, 0.20f, 0.20f, 1.00f);
    colors[ImGuiCol_FrameBgActive]        = ImVec4(0.25f, 0.25f, 0.25f, 1.00f);
    colors[ImGuiCol_TitleBg]              = ImVec4(0.08f, 0.08f, 0.08f, 1.00f);
    colors[ImGuiCol_TitleBgActive]        = ImVec4(0.10f, 0.10f, 0.10f, 1.00f);
    colors[ImGuiCol_TitleBgCollapsed]     = ImVec4(0.08f, 0.08f, 0.08f, 0.75f);
    colors[ImGuiCol_MenuBarBg]            = ImVec4(0.11f, 0.11f, 0.11f, 1.00f);
    colors[ImGuiCol_ScrollbarBg]          = ImVec4(0.08f, 0.08f, 0.08f, 1.00f);
    colors[ImGuiCol_ScrollbarGrab]        = ImVec4(0.25f, 0.25f, 0.25f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.30f, 0.30f, 0.30f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabActive]  = ImVec4(0.35f, 0.35f, 0.35f, 1.00f);
    colors[ImGuiCol_Separator]            = ImVec4(0.20f, 0.20f, 0.20f, 1.00f);
    colors[ImGuiCol_SeparatorHovered]     = ImVec4(0.25f, 0.25f, 0.25f, 1.00f);
    colors[ImGuiCol_SeparatorActive]      = ImVec4(0.30f, 0.30f, 0.30f, 1.00f);
    colors[ImGuiCol_Tab]                  = ImVec4(0.12f, 0.12f, 0.12f, 1.00f);
    colors[ImGuiCol_TabHovered]           = ImVec4(0.18f, 0.18f, 0.18f, 1.00f);
    colors[ImGuiCol_TabActive]            = ImVec4(0.15f, 0.15f, 0.15f, 1.00f);
    colors[ImGuiCol_TabUnfocused]         = ImVec4(0.10f, 0.10f, 0.10f, 1.00f);
    colors[ImGuiCol_TabUnfocusedActive]   = ImVec4(0.13f, 0.13f, 0.13f, 1.00f);
    colors[ImGuiCol_TableHeaderBg]        = ImVec4(0.12f, 0.12f, 0.12f, 1.00f);
    colors[ImGuiCol_TableBorderStrong]    = ImVec4(0.18f, 0.18f, 0.18f, 1.00f);
    colors[ImGuiCol_TableBorderLight]     = ImVec4(0.14f, 0.14f, 0.14f, 1.00f);
    colors[ImGuiCol_TableRowBg]           = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_TableRowBgAlt]        = ImVec4(0.11f, 0.11f, 0.11f, 1.00f);
    colors[ImGuiCol_ResizeGrip]           = ImVec4(0.25f, 0.25f, 0.25f, 1.00f);
    colors[ImGuiCol_ResizeGripHovered]    = ImVec4(0.30f, 0.30f, 0.30f, 1.00f);
    colors[ImGuiCol_ResizeGripActive]     = ImVec4(0.35f, 0.35f, 0.35f, 1.00f);
    colors[ImGuiCol_Button]               = ImVec4(0.18f, 0.18f, 0.18f, 1.00f);
    colors[ImGuiCol_ButtonHovered]        = ImVec4(0.22f, 0.36f, 0.55f, 1.00f);
    colors[ImGuiCol_ButtonActive]         = ImVec4(0.25f, 0.40f, 0.65f, 1.00f);
    colors[ImGuiCol_CheckMark]            = ImVec4(0.35f, 0.55f, 0.80f, 1.00f);
    colors[ImGuiCol_SliderGrab]           = ImVec4(0.25f, 0.40f, 0.65f, 1.00f);
    colors[ImGuiCol_SliderGrabActive]     = ImVec4(0.30f, 0.50f, 0.75f, 1.00f);
    colors[ImGuiCol_Header]               = ImVec4(0.20f, 0.20f, 0.20f, 0.80f);
    colors[ImGuiCol_HeaderHovered]        = ImVec4(0.22f, 0.36f, 0.55f, 0.90f);
    colors[ImGuiCol_HeaderActive]         = ImVec4(0.25f, 0.40f, 0.65f, 0.90f);

    style.WindowRounding    = 6.0f;
    style.FrameRounding     = 4.0f;
    style.GrabRounding      = 4.0f;
    style.ScrollbarRounding = 6.0f;
    style.TabRounding       = 5.0f;
    style.WindowBorderSize  = 1.0f;
    style.FrameBorderSize   = 1.0f;
    style.ScrollbarSize     = 14.0f;
    style.ItemSpacing       = ImVec2(8, 6);
    style.ItemInnerSpacing  = ImVec2(6, 4);
    style.CellPadding       = ImVec2(6, 4);
    style.WindowPadding     = ImVec2(14, 14);
    style.FramePadding      = ImVec2(8, 5);

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    if (!EnableDebugPrivilege()) 
    {
        MessageBoxA(nullptr, "Failed to enable SeDebugPrivilege. Please run PrefetchView++ with perms Administrator.", "Warning", MB_OK);
        return 1;
    }

    InitGenericRules();
    InitYara();

    std::thread([&]() 
        {
        activeThreads++;
        std::vector<PrefetchResult> temp = ScanPrefetchFolder();
        {
            std::lock_guard<std::mutex> lock(dataMutex);
            prefetchData = std::move(temp);
        }
        isLoading = false;
        analysisDone = true;
        activeThreads--;
        }).detach();

    static int selectedIndex      = -1;
    static int lastSelected = -1;
    static float panelHeight      = 0.0f;
    const float targetPanelHeight = 320.0f;
    const float animationSpeed    = 6.0f;

    MSG msg;
    ZeroMemory(&msg, sizeof(msg));

    while (msg.message != WM_QUIT)
    {
        if (PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE)) 
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            continue;
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        RECT rect;
        GetClientRect(hwnd, &rect);
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImVec2((float)(rect.right - rect.left), (float)(rect.bottom - rect.top)));

        ImGui::Begin("Prefetch Viewer", nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse);

        ImGuiIO& io = ImGui::GetIO();

        if (analysisDone && fadeIn < 1.0f)
            fadeIn += io.DeltaTime * 0.8f;

        InitializePrefetchFiles();

        if (isLoading)
        {
            ImVec2 pos = ImGui::GetWindowPos();
            ImVec2 size = ImGui::GetWindowSize();
            ImVec2 center = ImVec2(pos.x + size.x * 0.5f, pos.y + size.y * 0.5f - 20.0f);

            ImDrawList* draw_list = ImGui::GetWindowDrawList();
            float t = (float)ImGui::GetTime();

            int currentItem = GetProcessedFiles();
            int totalItems = GetTotalFiles();

            std::string subText1 = GetCurrentProcessingFile();
            if (subText1.empty()) subText1 = "Scanning system...";

            char progressBuf[32];
            sprintf_s(progressBuf, "%d/%d", currentItem, totalItems);
            std::string subText2 = progressBuf;

            std::transform(subText1.begin(), subText1.end(), subText1.begin(), ::toupper);
            std::transform(subText2.begin(), subText2.end(), subText2.begin(), ::toupper);

            float radius = 20.0f;
            float thickness = 4.0f;
            ImVec2 spinnerCenter = ImVec2(center.x, center.y - 48.0f);

            int num_segments = 25;
            float start = abs(sinf(t * 1.8f) * (num_segments - 5));

            float a_min = 3.14159265358979323846f * 2.0f * ((float)start) / (float)num_segments;
            float a_max = 3.14159265358979323846f * 2.0f * ((float)num_segments - 3) / (float)num_segments;

            ImU32 accentCol = IM_COL32(255, 120, 200, 220);

            for (int i = 0; i < num_segments; i++) {
                const float a = a_min + ((float)i / (float)num_segments) * (a_max - a_min);
                draw_list->PathLineTo(ImVec2(spinnerCenter.x + cosf(a + t * -8) * radius, spinnerCenter.y + sinf(a + t * -8) * radius));
            }
            draw_list->PathStroke(accentCol, false, thickness);

            const char* loadingText = "Parsing Prefetch";
            ImVec2 textSize = ImGui::CalcTextSize(loadingText);
            ImVec2 textPos = ImVec2(center.x - textSize.x * 0.5f, center.y - 20.0f);
            ImU32 textCol = IM_COL32(255, 255, 255, 255);
            draw_list->AddText(textPos, textCol, loadingText);

            ImVec2 sub1Size = ImGui::CalcTextSize(subText1.c_str());
            ImVec2 sub1Pos = ImVec2(center.x - sub1Size.x * 0.5f, textPos.y + textSize.y + 15.0f);
            ImU32 subTextCol = IM_COL32(153, 153, 153, 255);
            draw_list->AddText(sub1Pos, subTextCol, subText1.c_str());

            ImVec2 sub2Size = ImGui::CalcTextSize(subText2.c_str());
            ImVec2 sub2Pos = ImVec2(center.x - sub2Size.x * 0.5f, sub1Pos.y + sub1Size.y + 5.0f);
            draw_list->AddText(sub2Pos, subTextCol, subText2.c_str());

            if (!IsScanInProgress() && currentItem >= totalItems) {
                isLoading = false;
            }
        }
        else if (analysisDone)
        {
            static float fadeAlpha = 0.0f;
            static float fadeSpeed = 2.0f;

            static char searchBuffer[128] = "";
            static bool showOnlyUnsigned  = false;
            static bool showAfterLogon    = false;
            static bool showNotFound      = false;

            ImGui::PushItemWidth(300);
            ImGui::InputTextWithHint("##SearchPrefetch", "Search...", searchBuffer, IM_ARRAYSIZE(searchBuffer));
            ImGui::PopItemWidth();

            ImGui::SameLine(0, 20);
            bool checkboxChanged = false;
            checkboxChanged |= ImGui::Checkbox("Show Untrusted", &showOnlyUnsigned);
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Show paths without a signature, cheat signature, fake signature and yara rules");

            ImGui::SameLine(0, 20);
            checkboxChanged |= ImGui::Checkbox("Show in Instance", &showAfterLogon);
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Show all paths after logon-time");

            ImGui::SameLine(0, 20);
            checkboxChanged |= ImGui::Checkbox("Show Not Found", &showNotFound);
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Show paths with signature status NotFound");

            ImGui::SameLine();

            float buttonWidth = 160.0f;
            float windowRight = ImGui::GetWindowContentRegionMax().x + ImGui::GetWindowPos().x;

            static bool showPrefetchPopup       = false;
            static bool showPrefetchInfoPopup   = false;
            static bool isReadingPrefetch       = false;
            static float prefetchPopupInfoAlpha = 0.0f;
            static std::wstring prefetchOutput;

            ImGui::SetCursorPosX(windowRight - 3 * buttonWidth - ImGui::GetStyle().ItemSpacing.x * 3);
            if (ImGui::Button("Prefetch Info", ImVec2(buttonWidth, 0)))
            {
                showPrefetchInfoPopup = true;
                isReadingPrefetch = true;
                prefetchPopupInfoAlpha = 0.0f;
                prefetchOutput.clear();

                std::thread([]()
                    {
                        std::wstring result = InfoCmd_UIPREFETCHVIEW();
                        ImGui::GetIO().UserData = new std::wstring(std::move(result));
                    }).detach();
            }
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Analyze Prefetch, SysMain, FileInfo and Registry state");

            if (showPrefetchInfoPopup) ImGui::OpenPopup("Prefetch Info");
            if (prefetchPopupInfoAlpha < 1.0f) prefetchPopupInfoAlpha += ImGui::GetIO().DeltaTime * 4.0f;
            prefetchPopupInfoAlpha = std::min(prefetchPopupInfoAlpha, 1.0f);

            ImGui::PushStyleVar(ImGuiStyleVar_Alpha, prefetchPopupInfoAlpha);
            if (ImGui::BeginPopupModal("Prefetch Info", &showPrefetchInfoPopup, ImGuiWindowFlags_NoCollapse))
            {
                ImVec2 popupSize(950, 600);
                ImGui::SetWindowSize(popupSize, ImGuiCond_Once);

                if (isReadingPrefetch)
                {
                    auto ptr = static_cast<std::wstring*>(ImGui::GetIO().UserData);
                    if (ptr)
                    {
                        prefetchOutput = std::move(*ptr);
                        delete ptr;
                        ImGui::GetIO().UserData = nullptr;
                        isReadingPrefetch = false;
                    }
                }

                ImVec2 winSize = ImGui::GetWindowSize();

                if (isReadingPrefetch)
                {
                    ImGui::Dummy(ImVec2(0, winSize.y * 0.4f));
                    ImGui::SetCursorPosX((winSize.x - ImGui::CalcTextSize("Analyzing Prefetch Info...").x) * 0.5f);
                    ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Analyzing Prefetch Info...");
                }
                else if (prefetchOutput.empty())
                {
                    ImGui::Dummy(ImVec2(0, winSize.y * 0.4f));
                    ImGui::SetCursorPosX((winSize.x - ImGui::CalcTextSize("No information available.").x) * 0.5f);
                    ImGui::TextColored(ImVec4(0.8f, 0.5f, 0.5f, 1.0f), "No information available.");
                }
                else
                {
                    ImGui::BeginChild("PrefetchInfoScroll", ImVec2(0, 0), true);
                    std::wstringstream ss(prefetchOutput);
                    std::wstring line;
                    while (std::getline(ss, line))
                    {
                        ImVec4 color = GetLineColor(line);
                        ImGui::TextColored(color, "%ls", line.c_str());
                    }
                    ImGui::EndChild();
                }

                ImGui::EndPopup();
            }
            ImGui::PopStyleVar();
            ImGui::SameLine();

            static bool showSysMainPopup   = false;
            static bool isReadingSysMain   = false;
            static float sysmainPopupAlpha = 0.0f;
            static std::vector<ServiceInfo> sysmainResults;

            ImGui::SetCursorPosX(windowRight - 2 * buttonWidth - ImGui::GetStyle().ItemSpacing.x * 2);
            if (ImGui::Button("Sysmain Info", ImVec2(buttonWidth, 0)))
            {
                showSysMainPopup = true;
                isReadingSysMain = true;
                sysmainPopupAlpha = 0.0f;
                sysmainResults.clear();

                std::thread([]()
                    {
                    auto results = GetSysMainInfo();
                    ImGui::GetIO().UserData = new std::vector<ServiceInfo>(std::move(results));
                    }).detach();
            }
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Information about Sysmain Service");

            if (showSysMainPopup) ImGui::OpenPopup("SysMain Info");

            if (sysmainPopupAlpha < 1.0f) sysmainPopupAlpha += ImGui::GetIO().DeltaTime * 4.0f;
            sysmainPopupAlpha = std::min(sysmainPopupAlpha, 1.0f);

            ImGui::PushStyleVar(ImGuiStyleVar_Alpha, sysmainPopupAlpha);
            if (ImGui::BeginPopupModal("SysMain Info", &showSysMainPopup, ImGuiWindowFlags_NoCollapse))
            {
                ImVec2 popupSizeSysMain(400, 200);
                ImGui::SetWindowSize(popupSizeSysMain, ImGuiCond_Once);

                if (isReadingSysMain)
                {
                    auto ptr = static_cast<std::vector<ServiceInfo>*>(ImGui::GetIO().UserData);
                    if (ptr)
                    {
                        sysmainResults = std::move(*ptr);
                        delete ptr;
                        ImGui::GetIO().UserData = nullptr;
                        isReadingSysMain = false;
                    }
                }

                ImVec2 winSize = ImGui::GetWindowSize();

                if (isReadingSysMain)
                {
                    ImGui::Dummy(ImVec2(0, winSize.y * 0.35f));
                    ImGui::SetCursorPosX((winSize.x - ImGui::CalcTextSize("Reading SysMain...").x) * 0.5f);
                    ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Reading SysMain...");
                }
                else if (sysmainResults.empty())
                {
                    ImGui::Dummy(ImVec2(0, winSize.y * 0.35f));
                    ImGui::SetCursorPosX((winSize.x - ImGui::CalcTextSize("SysMain not found or stopped.").x) * 0.5f);
                    ImGui::TextColored(ImVec4(0.8f, 0.5f, 0.5f, 1.0f), "SysMain not found or stopped.");
                }
                else
                {
                    const auto& svc = sysmainResults[0];
                    ImGui::Text("PID: %u", svc.pid);
                    ImGui::Text("Status: %s", svc.status.c_str());
                    if (svc.status == "Running")
                    {
                        ImGui::Text("Uptime: %s", svc.uptime.c_str());
                        ImGui::Text("Logon Time: %s", svc.logonTimeStr.c_str());
                        if (svc.delayedStart)
                            ImGui::TextColored(ImVec4(1, 0, 0, 1), "[!] Sysmain started after logon-time...");
                    }
                }

                ImGui::EndPopup();
            }
            ImGui::PopStyleVar();
            ImGui::SameLine();

            static bool showUSNPopup = false;
            static bool isReadingUSN = false;
            static std::vector<USNJournalReader::USNEvent> usnResults;
            static float usnPopupAlpha = 0.0f;

            ImGui::SetCursorPosX(windowRight - 1 * buttonWidth - ImGui::GetStyle().ItemSpacing.x * 1);
            if (ImGui::Button("USNJournal", ImVec2(buttonWidth, 0)))
            {
                showUSNPopup = true;
                isReadingUSN = true;
                usnPopupAlpha = 0.0f;
                usnResults.clear();

                std::thread([]() {
                    wchar_t windowsPath[MAX_PATH] = {};
                    if (GetWindowsDirectoryW(windowsPath, MAX_PATH) != 0)
                    {
                        wchar_t driveLetter[3] = { windowsPath[0], L':', L'\0' };
                        USNJournalReader reader(driveLetter);
                        auto results = reader.Run();
                        ImGui::GetIO().UserData = new std::vector<USNJournalReader::USNEvent>(std::move(results));
                    }
                    }).detach();
            }
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Displays deleted or renamed entries of pfs files");

            if (showUSNPopup) ImGui::OpenPopup("USN Journal Results");
            if (usnPopupAlpha < 1.0f) usnPopupAlpha += ImGui::GetIO().DeltaTime * 4.0f;
            usnPopupAlpha = std::min(usnPopupAlpha, 1.0f);

            ImGui::PushStyleVar(ImGuiStyleVar_Alpha, usnPopupAlpha);
            if (ImGui::BeginPopupModal("USN Journal Results", &showUSNPopup, ImGuiWindowFlags_NoCollapse))
            {
                ImVec2 popupSizeUSN(900, 500);
                ImGui::SetWindowSize(popupSizeUSN, ImGuiCond_Once);

                if (isReadingUSN)
                {
                    auto ptr = static_cast<std::vector<USNJournalReader::USNEvent>*>(ImGui::GetIO().UserData);
                    if (ptr)
                    {
                        usnResults = std::move(*ptr);
                        delete ptr;
                        ImGui::GetIO().UserData = nullptr;
                        isReadingUSN = false;
                    }
                }

                ImVec2 winSize = ImGui::GetWindowSize();

                if (isReadingUSN)
                {
                    ImGui::Dummy(ImVec2(0, winSize.y * 0.40f));
                    ImGui::SetCursorPosX((winSize.x - ImGui::CalcTextSize("Reading USN Journal...").x) * 0.5f);
                    ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Reading USN Journal...");
                }
                else if (usnResults.empty())
                {
                    ImGui::Dummy(ImVec2(0, winSize.y * 0.38f));
                    ImGui::SetCursorPosX((winSize.x - ImGui::CalcTextSize("No Prefetch or .pf activity detected after logon.").x) * 0.5f);
                    ImGui::TextColored(ImVec4(0.75f, 0.45f, 0.45f, 1.0f), "No Prefetch or .pf activity detected after logon.");
                }
                else
                {
                    if (ImGui::BeginTable("USNTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable, ImVec2(0, -1)))
                    {
                        ImGui::TableSetupScrollFreeze(0, 1);
                        ImGui::TableSetupColumn("Old Name", ImGuiTableColumnFlags_WidthStretch);
                        ImGui::TableSetupColumn("New Name", ImGuiTableColumnFlags_WidthStretch);
                        ImGui::TableSetupColumn("Reason", ImGuiTableColumnFlags_WidthFixed, 160.0f);
                        ImGui::TableSetupColumn("Timestamp", ImGuiTableColumnFlags_WidthFixed, 180.0f);
                        ImGui::TableHeadersRow();

                        for (auto it = usnResults.rbegin(); it != usnResults.rend(); ++it)
                        {
                            const auto& e = *it;
                            ImGui::TableNextRow();

                            ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(e.filenameOld.c_str());
                            ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(e.filenameNew.empty() ? "-" : e.filenameNew.c_str());
                            ImGui::TableSetColumnIndex(2); ImVec4 reasonColor = GetReasonColor(e); ImGui::TextColored(reasonColor, "%s", e.action.c_str());
                            ImGui::TableSetColumnIndex(3); std::tm* tm = std::localtime(&e.timestamp); char timeBuf[32]{}; std::strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", tm); ImGui::TextUnformatted(timeBuf);
                        }

                        ImGui::EndTable();
                    }
                }

                ImGui::EndPopup();
            }
            ImGui::PopStyleVar();
            ImGui::SameLine();

            if (checkboxChanged) fadeAlpha = 0.0f;

            ImGui::Separator();

            time_t logonTime = GetCurrentUserLogonTime();
            std::string searchLower = searchBuffer;
            std::transform(searchLower.begin(), searchLower.end(), searchLower.begin(), ::tolower);

            std::vector<PrefetchResult> filteredData;
            for (const auto& result : prefetchData)
            {
                const auto& info = result.info;

                std::string nameLower = result.fileName;
                std::string pathLower = WStringToUTF8(info.mainExecutablePath);
                std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);
                std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::tolower);

                SignatureStatus sig = info.signatureStatus;

                std::string sigText;
                switch (sig)
                {
                case SignatureStatus::Signed:   sigText = "signed";    break;
                case SignatureStatus::Unsigned: sigText = "unsigned";  break;
                case SignatureStatus::Cheat:    sigText = "cheat";     break;
                case SignatureStatus::Fake:     sigText = "fake";      break;
                case SignatureStatus::NotFound: sigText = "not found"; break;
                }

                bool matchesSearch = searchLower.empty() || nameLower.find(searchLower) != std::string::npos || pathLower.find(searchLower) != std::string::npos || sigText.find(searchLower) != std::string::npos;

                bool matchesSig = (!showOnlyUnsigned && !showNotFound) || (showOnlyUnsigned && (sig == SignatureStatus::Unsigned || sig == SignatureStatus::Cheat || sig == SignatureStatus::Fake)) || (showNotFound && sig == SignatureStatus::NotFound);

                bool matchesLogon = true;
                if (showAfterLogon && !info.lastExecutionTimes.empty())
                {
                    time_t execTime = info.lastExecutionTimes.front();
                    matchesLogon = execTime > logonTime;
                }

                if (matchesSearch && matchesSig && matchesLogon)
                    filteredData.push_back(result);
            }

            fadeAlpha += io.DeltaTime * fadeSpeed;
            fadeAlpha = std::min(fadeAlpha, 1.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_Alpha, fadeAlpha);

            static std::vector<PrefetchResult> sortedData;
            static std::vector<PrefetchResult> lastFilteredData;
            static int lastSortColumn = 0;
            static bool lastSortAscending = true;

            auto sortLambda = [](const PrefetchResult& a, const PrefetchResult& b, int column, bool ascending)
                {
                    switch (column)
                    {
                    case 0: { time_t ta = a.info.lastExecutionTimes.empty() ? 0 : a.info.lastExecutionTimes.front(); time_t tb = b.info.lastExecutionTimes.empty() ? 0 : b.info.lastExecutionTimes.front(); return ascending ? ta < tb : ta > tb; }
                    case 1: return ascending ? a.fileName < b.fileName : a.fileName > b.fileName;
                    case 2: return ascending ? a.info.mainExecutablePath < b.info.mainExecutablePath : a.info.mainExecutablePath > b.info.mainExecutablePath;
                    case 3: { auto getOrder = [](SignatureStatus s) { switch (s) { case SignatureStatus::Signed: return 0; case SignatureStatus::Unsigned: return 1; case SignatureStatus::Cheat: return 2; case SignatureStatus::Fake: return 3; case SignatureStatus::NotFound: return 4; default: return 5; } }; return ascending ? getOrder(a.info.signatureStatus) < getOrder(b.info.signatureStatus) : getOrder(a.info.signatureStatus) > getOrder(b.info.signatureStatus); }
                    default: return false;
                    }
                };

            if (filteredData.size() != lastFilteredData.size() || !std::equal(filteredData.begin(), filteredData.end(), lastFilteredData.begin()))
            {
                sortedData = filteredData;
                lastFilteredData = filteredData;
                if (!sortedData.empty())
                    std::sort(sortedData.begin(), sortedData.end(), [sortLambda](const PrefetchResult& a, const PrefetchResult& b) { return sortLambda(a, b, lastSortColumn, lastSortAscending); });
            }

            float dt = io.DeltaTime;
            float target = (selectedIndex != -1) ? targetPanelHeight : 0.0f;
            panelHeight += (target - panelHeight) * dt * animationSpeed;
            float availableHeight = ImGui::GetContentRegionAvail().y - panelHeight - 8.0f;

            if (ImGui::BeginTable("PrefetchTable", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Sortable | ImGuiTableFlags_SizingFixedFit, ImVec2(-FLT_MIN, availableHeight)))
            {
                ImGui::TableSetupScrollFreeze(0, 1);

                ImGui::TableSetupColumn("Time Executed", ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_WidthFixed);
                ImGui::TableSetupColumn("Executable Path", ImGuiTableColumnFlags_WidthFixed);
                ImGui::TableSetupColumn("Signature", ImGuiTableColumnFlags_WidthStretch | ImGuiTableColumnFlags_NoResize);
                ImGui::TableHeadersRow();

                if (ImGuiTableSortSpecs* sortSpecs = ImGui::TableGetSortSpecs())
                {
                    if (!sortedData.empty() && sortSpecs->SpecsCount > 0)
                    {
                        const auto& spec = sortSpecs->Specs[0];
                        int column = spec.ColumnIndex;
                        bool ascending = (spec.SortDirection == ImGuiSortDirection_Ascending);

                        if (column != lastSortColumn || ascending != lastSortAscending || sortSpecs->SpecsDirty)
                        {
                            std::sort(sortedData.begin(), sortedData.end(),
                                [sortLambda, column, ascending](const PrefetchResult& a, const PrefetchResult& b) 
                                {
                                    return sortLambda(a, b, column, ascending);
                                });

                            lastSortColumn = column;
                            lastSortAscending = ascending;
                            sortSpecs->SpecsDirty = false;
                        }
                    }
                }

                auto renderColumn = [](int colIndex, const char* text)
                    {
                    ImGui::TableSetColumnIndex(colIndex);
                    ImGui::TextUnformatted(text);
                    };

                auto renderSignatureColumn = [](SignatureStatus s) 
                    {
                    ImGui::TableSetColumnIndex(2);
                    ImVec4 color;
                    const char* text;
                    switch (s)
                    {
                    case SignatureStatus::Signed:   color = ImVec4(0.0f, 1.0f, 0.0f, 1.0f);     text = "Signed";              break;
                    case SignatureStatus::Unsigned: color = ImVec4(1.0f, 0.4f, 0.4f, 1.0f);     text = "Unsigned";            break;
                    case SignatureStatus::Cheat:    color = ImVec4(1.f, 0.2f, 0.2f, 1.0f);      text = "Cheat";               break;
                    case SignatureStatus::Fake:     color = ImVec4(1.0f, 0.5f, 0.0f, 1.0f);     text = "Fake Signature";      break;
                    default:                        color = ImVec4(1.0f, 0.8f, 0.4f, 1.0f);     text = "Not Found";           break;
                    }
                    ImGui::TextColored(color, text);
                    };

                ImGuiListClipper clipper;
                clipper.Begin(static_cast<int>(sortedData.size()));
                while (clipper.Step())
                {
                    for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++)
                    {
                        const auto& result = sortedData[i];
                        const auto& info = result.info;

                        ImGui::TableNextRow();

                        renderColumn(0, info.cachedExecTime.c_str());

                        ImGui::TableSetColumnIndex(1);
                        bool isSelected = (i == selectedIndex);

                        IconDataDX11* iconPtr = GetOrQueueIcon(g_pd3dDevice, info.mainExecutablePath);
                        if (iconPtr && iconPtr->IsLoaded)
                        {
                            ImGui::Image(iconPtr->TextureView.Get(), ImVec2(16, 16));
                            ImGui::SameLine(0, 5);
                        }

                        std::string uniqueID = info.cachedUTF8Path + std::to_string(i);
                        ImGui::PushID(uniqueID.c_str());

                        if (ImGui::Selectable(info.cachedUTF8Path.c_str(), isSelected, ImGuiSelectableFlags_SpanAllColumns))
                            selectedIndex = (selectedIndex != i) ? i : -1;

                        if (ImGui::IsItemHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Right))
                            ImGui::OpenPopup("popup_table_path");

                        if (ImGui::BeginPopup("popup_table_path"))
                        {
                            if (ImGui::Selectable("Copy Path")) CopyToClipboard(info.mainExecutablePath);
                            if (ImGui::Selectable("Open Path")) ShellExecuteW(NULL, L"explore", info.cachedFolderPath.c_str(), NULL, NULL, SW_SHOWNORMAL);
                            ImGui::EndPopup();
                        }

                        ImGui::PopID();

                        renderSignatureColumn(info.signatureStatus);
                    }
                }

                ImGui::EndTable();
            }

            if (selectedIndex >= 0 && panelHeight > 1.0f)
            {
                ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 4.0f);
                ImGui::Separator();
                ImGui::BeginChild("BottomPanel", ImVec2(0, panelHeight), true);

                const bool selectionChanged = (selectedIndex != lastSelected);
                if (selectionChanged)
                    lastSelected = selectedIndex;

                const auto& selected = sortedData[selectedIndex];
                const auto& info = selected.info;

                static bool showOnlyUnsigned = false;
                static bool showOnlyNotFound = false;
                static float fadeAlpha = 1.0f;
                const float fadeSpeed = 2.0f;

                bool checkboxChanged = false;

                if (ImGui::BeginTabBar("DetailsTabs"))
                {
                    ImGui::SameLine(ImGui::GetContentRegionAvail().x - 30.0f);
                    if (ImGui::Button("X"))
                    {
                        selectedIndex = -1;
                        lastSelected = -1;
                    }

                    ImGui::SameLine(ImGui::GetContentRegionAvail().x - 140.0f);
                    if (ImGui::Button("Filter Options"))
                        ImGui::OpenPopup("FilterPopup");

                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("Opens the filter options");

                    if (ImGui::IsPopupOpen("FilterPopup"))
                    {
                        ImVec2 popupPos = ImGui::GetItemRectMin();
                        popupPos.y += ImGui::GetItemRectSize().y + 4.0f;
                        ImGui::SetNextWindowPos(popupPos);
                    }

                    if (ImGui::BeginPopup("FilterPopup"))
                    {
                        ImGui::Separator();
                        checkboxChanged |= ImGui::Checkbox("Show Untrusted", &showOnlyUnsigned);
                        if (ImGui::IsItemHovered())
                            ImGui::SetTooltip("Show paths without a signature, cheat signature, fake signature and yara rules");
                        checkboxChanged |= ImGui::Checkbox("Show Not Found", &showOnlyNotFound);
                        if (ImGui::IsItemHovered())
                            ImGui::SetTooltip("Show paths that were not found");
                        ImGui::Separator();
                        ImGui::EndPopup();
                    }

                    if (checkboxChanged)
                        fadeAlpha = 0.0f;

                    if (ImGui::BeginTabItem("Referenced Files"))
                    {
                        ImGui::Separator();
                        ImGuiIO& io = ImGui::GetIO();
                        fadeAlpha += io.DeltaTime * fadeSpeed;
                        if (fadeAlpha > 1.0f) fadeAlpha = 1.0f;
                        ImGui::PushStyleVar(ImGuiStyleVar_Alpha, fadeAlpha);

                        std::vector<int> visibleIndices;
                        visibleIndices.reserve(info.fileNames.size());
                        const bool filterActive = showOnlyUnsigned || showOnlyNotFound;

                        for (int i = 0; i < static_cast<int>(info.fileNames.size()); ++i)
                        {
                            SignatureStatus status = info.fileSignatures[i];
                            bool matches = false;

                            if (!filterActive)
                            {
                                matches = true;
                            }
                            else
                            {
                                if (showOnlyUnsigned && (status == SignatureStatus::Unsigned || status == SignatureStatus::Cheat || status == SignatureStatus::Fake))
                                    matches = true;
                                if (showOnlyNotFound && status == SignatureStatus::NotFound)
                                    matches = true;
                            }

                            if (matches)
                                visibleIndices.push_back(i);
                        }

                        if (!visibleIndices.empty())
                        {
                            if (ImGui::BeginTable("RefFilesTable", 2, ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInner | ImGuiTableFlags_ScrollY))
                            {
                                ImGui::TableSetupColumn("File Path", ImGuiTableColumnFlags_WidthStretch);
                                ImGui::TableSetupColumn("Signature", ImGuiTableColumnFlags_WidthFixed, 120.0f);
                                ImGui::TableHeadersRow();

                                ImGuiListClipper clipper;
                                clipper.Begin(static_cast<int>(visibleIndices.size()));
                                while (clipper.Step())
                                {
                                    for (int v = clipper.DisplayStart; v < clipper.DisplayEnd; ++v)
                                    {
                                        int i = visibleIndices[v];
                                        if (selectionChanged && v == 0)
                                            ImGui::SetScrollHereY(0.0f);

                                        const auto& wname = info.fileNames[i];
                                        std::string utf8 = WStringToUTF8(wname);

                                        ImGui::PushID(i);
                                        ImGui::TableNextRow();

                                        ImGui::TableSetColumnIndex(0);
                                        IconDataDX11* iconPtr = GetOrQueueIcon(g_pd3dDevice, wname);
                                        if (iconPtr && iconPtr->IsLoaded)
                                        {
                                            ImGui::Image(iconPtr->TextureView.Get(), ImVec2(16, 16));
                                            ImGui::SameLine(0, 5);
                                        }
                                        ImGui::TextUnformatted(utf8.c_str());

                                        if (ImGui::IsItemHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Right))
                                            ImGui::OpenPopup("popup_ref_path");

                                        if (ImGui::BeginPopup("popup_ref_path"))
                                        {
                                            wchar_t folderPath[MAX_PATH];
                                            wcscpy_s(folderPath, wname.c_str());
                                            PathRemoveFileSpecW(folderPath);

                                            if (ImGui::Selectable("Copy Path")) CopyToClipboard(wname);
                                            if (ImGui::Selectable("Open Path")) ShellExecuteW(NULL, L"explore", folderPath, NULL, NULL, SW_SHOWNORMAL);

                                            ImGui::EndPopup();
                                        }

                                        ImGui::TableSetColumnIndex(1);
                                        SignatureStatus status = info.fileSignatures[i];
                                        ImVec4 color;
                                        const char* text;
                                        switch (status)
                                        {
                                        case SignatureStatus::Signed:   color = ImVec4(0.0f, 1.0f, 0.0f, 1.0f);     text = "Signed";              break;
                                        case SignatureStatus::Unsigned: color = ImVec4(1.0f, 0.4f, 0.4f, 1.0f);     text = "Unsigned";            break;
                                        case SignatureStatus::Cheat:    color = ImVec4(1.f, 0.2f, 0.2f, 1.0f);      text = "Cheat";               break;
                                        case SignatureStatus::Fake:     color = ImVec4(1.0f, 0.5f, 0.0f, 1.0f);     text = "Fake Signature";      break;
                                        default:                        color = ImVec4(1.0f, 0.8f, 0.4f, 1.0f);     text = "Not Found";           break;
                                        }
                                        ImGui::TextColored(color, "%s", text);

                                        ImGui::PopID();
                                    }
                                }

                                ImGui::EndTable();
                            }
                        }
                        else
                        {
                            ImGui::TextDisabled("No referenced files found.");
                        }

                        ImGui::PopStyleVar();
                        ImGui::EndTabItem();
                    }

                    if (ImGui::BeginTabItem("Details"))
                    {
                        ImGui::Text("File: %s", selected.fileName.c_str());
                        ImGui::Text("Executable Path: %s", info.cachedUTF8Path.c_str());

                        auto formatFileSize = [](uint64_t size) -> std::string {
                            constexpr const char* suffixes[] = { "B", "KB", "MB", "GB", "TB" };
                            double s = static_cast<double>(size);
                            int i = 0;
                            while (s >= 1024.0 && i < 4) { s /= 1024.0; i++; }
                            char buffer[64];
                            snprintf(buffer, sizeof(buffer), "%.2f %s", s, suffixes[i]);
                            return std::string(buffer);
                            };

                        char windowsPath[MAX_PATH] = { 0 };
                        if (GetWindowsDirectoryA(windowsPath, MAX_PATH))
                        {
                            std::string fullPfPath = std::string(windowsPath) + "\\Prefetch\\" + selected.fileName;

                            WIN32_FILE_ATTRIBUTE_DATA pfInfo;
                            if (GetFileAttributesExA(fullPfPath.c_str(), GetFileExInfoStandard, &pfInfo))
                            {
                                LARGE_INTEGER pfSize;
                                pfSize.HighPart = pfInfo.nFileSizeHigh;
                                pfSize.LowPart = pfInfo.nFileSizeLow;

                                ImGui::Separator();
                                ImGui::Text("Prefetch Size: %s", formatFileSize(pfSize.QuadPart).c_str());
                                ImGui::Text("Prefetch Creation: %s", FileTimeToString(pfInfo.ftCreationTime).c_str());
                            }
                            else
                            {
                                ImGui::Text("Prefetch Size: N/A");
                                ImGui::Text("Prefetch Creation: N/A");
                            }
                        }
                        else
                        {
                            ImGui::Text("Prefetch Size: N/A");
                            ImGui::Text("Prefetch Creation: N/A");
                        }
                        ImGui::Separator();

                        HANDLE hExe = CreateFileW(info.mainExecutablePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

                        if (hExe != INVALID_HANDLE_VALUE)
                        {
                            LARGE_INTEGER exeSize;
                            if (GetFileSizeEx(hExe, &exeSize))
                                ImGui::Text("Executable Size: %s", formatFileSize(exeSize.QuadPart).c_str());
                            else
                                ImGui::Text("Executable Size: N/A");

                            FILETIME creationTime;
                            if (GetFileTime(hExe, &creationTime, nullptr, nullptr))
                            {
                                ImGui::Text("Executable Creation: %s", FileTimeToString(creationTime).c_str());
                            }
                            else
                            {
                                ImGui::Text("Executable Creation: N/A");
                            }

                            CloseHandle(hExe);
                        }
                        else
                        {
                            ImGui::Text("Executable Size: N/A");
                            ImGui::Text("Executable Creation: N/A");
                        }

                        ImGui::EndTabItem();
                    }

                    if (ImGui::BeginTabItem("Times Executed"))
                    {
                        if (!info.lastExecutionTimes.empty())
                        {
                            int runNumber = 1;
                            for (const auto& t : info.lastExecutionTimes)
                            {
                                struct tm tmBuf;
                                localtime_s(&tmBuf, &t);
                                char buffer[64];
                                strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tmBuf);

                                ImGui::Text("%s %s", ("Run " + std::to_string(runNumber) + ":").c_str(), buffer);
                                runNumber++;
                            }
                        }
                        else
                        {
                            ImGui::TextDisabled("No execution times found.");
                        }
                        ImGui::EndTabItem();
                    }

                    ImGui::EndTabBar();
                }

                ImGui::EndChild();
            }

            ImGui::PopStyleVar();
        }

        ImGui::End();
        ImGui::Render();
        const float clear_color[4] = { 0.08f, 0.08f, 0.10f, 1.0f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, NULL);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_pSwapChain->Present(1, 0);
    }

    while (activeThreads > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    FinalizeYara();
    CleanupDeviceD3D();
    DestroyWindow(hwnd);
    UnregisterClass(wc.lpszClassName, wc.hInstance);
    return 0;
}