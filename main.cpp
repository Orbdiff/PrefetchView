#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#include "wil/resource.h"

#include "prefetch/_prefetch_parser.h"
#include "ui_help/_font.h"
#include "ui_help/_time_utils.h"
#include "ui_help/_usn_parser.h"

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
#include <shlobj.h>

ID3D11Device* g_pd3dDevice = nullptr;
ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
IDXGISwapChain* g_pSwapChain = nullptr;
ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;

extern LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
extern ID3D11Device* g_pd3dDevice;

std::atomic<bool> loading(true);
std::mutex dataMutex;
std::vector<PrefetchResult> prefetchData;
float fadeAlpha = 0.0f;

struct IconDataDX11 {
    Microsoft::WRL::ComPtr<ID3D11ShaderResourceView> TextureView;
    int Width = 0;
    int Height = 0;
    bool IsLoaded = false;
};

static std::unordered_map<std::wstring, IconDataDX11> g_iconsCache;

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

void LoadPrefetchData()
{
    std::vector<PrefetchResult> temp = ScanPrefetchFolder();
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        prefetchData = std::move(temp);
    }
    loading = false;
}

int WINAPI WinMain
(
    _In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPSTR     lpCmdLine,
    _In_ int       nCmdShow
) {
    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(NULL),
                      NULL, NULL, NULL, NULL, _T("PrefetchView++"), NULL };
    RegisterClassEx(&wc);

    HWND hwnd = CreateWindow(wc.lpszClassName, _T("PrefetchView++"),
        WS_OVERLAPPEDWINDOW, 100, 100, 1280, 800,
        NULL, NULL, wc.hInstance, NULL);

    if (!CreateDeviceD3D(hwnd)) {
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

    ImFont* font = io.Fonts->AddFontFromMemoryTTF(
        (void*)Custom,
        static_cast<int>(Custom_len),
        15.5f,
        &CustomFont
    );

    io.FontDefault = font;

    ImGuiStyle& style = ImGui::GetStyle();
    ImVec4* colors = style.Colors;

    colors[ImGuiCol_Text] = ImVec4(0.90f, 0.90f, 0.90f, 1.00f);
    colors[ImGuiCol_TextDisabled] = ImVec4(0.50f, 0.50f, 0.50f, 1.00f);
    colors[ImGuiCol_WindowBg] = ImVec4(0.07f, 0.07f, 0.07f, 1.00f);
    colors[ImGuiCol_ChildBg] = ImVec4(0.08f, 0.08f, 0.08f, 1.00f);
    colors[ImGuiCol_PopupBg] = ImVec4(0.08f, 0.08f, 0.08f, 1.00f);
    colors[ImGuiCol_FrameBg] = ImVec4(0.10f, 0.10f, 0.10f, 1.00f);
    colors[ImGuiCol_FrameBgHovered] = ImVec4(0.18f, 0.18f, 0.18f, 1.00f);
    colors[ImGuiCol_FrameBgActive] = ImVec4(0.22f, 0.22f, 0.22f, 1.00f);
    colors[ImGuiCol_Border] = ImVec4(0.25f, 0.25f, 0.25f, 1.00f);
    colors[ImGuiCol_BorderShadow] = ImVec4(0, 0, 0, 0);
    colors[ImGuiCol_TitleBg] = ImVec4(0.08f, 0.08f, 0.08f, 1.00f);
    colors[ImGuiCol_TitleBgActive] = ImVec4(0.12f, 0.12f, 0.12f, 1.00f);
    colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.07f, 0.07f, 0.07f, 0.85f);
    colors[ImGuiCol_MenuBarBg] = ImVec4(0.08f, 0.08f, 0.08f, 1.00f);
    colors[ImGuiCol_ScrollbarBg] = ImVec4(0.05f, 0.05f, 0.05f, 1.00f);
    colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.30f, 0.50f, 0.85f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.35f, 0.60f, 0.95f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.40f, 0.70f, 1.00f, 1.00f);
    colors[ImGuiCol_Button] = ImVec4(0.12f, 0.12f, 0.12f, 1.00f);
    colors[ImGuiCol_ButtonHovered] = ImVec4(0.30f, 0.50f, 0.85f, 1.00f);
    colors[ImGuiCol_ButtonActive] = ImVec4(0.35f, 0.60f, 0.95f, 1.00f);
    colors[ImGuiCol_SliderGrab] = ImVec4(0.30f, 0.50f, 0.85f, 1.00f);
    colors[ImGuiCol_SliderGrabActive] = ImVec4(0.35f, 0.60f, 1.00f, 1.00f);
    colors[ImGuiCol_CheckMark] = ImVec4(0.35f, 0.60f, 1.00f, 1.00f);
    colors[ImGuiCol_Header] = ImVec4(0.35f, 0.60f, 1.00f, 0.5f);
    colors[ImGuiCol_HeaderHovered] = ImVec4(0.30f, 0.50f, 0.85f, 1.00f);
    colors[ImGuiCol_HeaderActive] = ImVec4(0.35f, 0.60f, 1.00f, 1.00f);
    colors[ImGuiCol_Tab] = ImVec4(0.08f, 0.08f, 0.08f, 1.00f);
    colors[ImGuiCol_TabHovered] = ImVec4(0.30f, 0.50f, 0.85f, 1.00f);
    colors[ImGuiCol_TabActive] = ImVec4(0.35f, 0.60f, 1.00f, 1.00f);
    colors[ImGuiCol_TabUnfocused] = ImVec4(0.08f, 0.08f, 0.08f, 1.00f);
    colors[ImGuiCol_TabUnfocusedActive] = ImVec4(0.20f, 0.35f, 0.60f, 1.00f);
    colors[ImGuiCol_Separator] = ImVec4(0.20f, 0.20f, 0.20f, 1.00f);
    colors[ImGuiCol_SeparatorHovered] = ImVec4(0.30f, 0.50f, 0.85f, 1.00f);
    colors[ImGuiCol_SeparatorActive] = ImVec4(0.35f, 0.60f, 1.00f, 1.00f);
    colors[ImGuiCol_ResizeGrip] = ImVec4(0.20f, 0.20f, 0.20f, 1.00f);
    colors[ImGuiCol_ResizeGripHovered] = ImVec4(0.30f, 0.50f, 0.85f, 1.00f);
    colors[ImGuiCol_ResizeGripActive] = ImVec4(0.35f, 0.60f, 1.00f, 1.00f);
    colors[ImGuiCol_TableHeaderBg] = ImVec4(0.08f, 0.08f, 0.08f, 1.00f);
    colors[ImGuiCol_TableBorderStrong] = ImVec4(0.25f, 0.25f, 0.25f, 1.00f);
    colors[ImGuiCol_TableBorderLight] = ImVec4(0.15f, 0.15f, 0.15f, 1.00f);
    colors[ImGuiCol_TableRowBg] = ImVec4(0, 0, 0, 0);
    colors[ImGuiCol_TableRowBgAlt] = ImVec4(0.08f, 0.08f, 0.08f, 1.00f);

    style.WindowRounding = 6.0f;
    style.FrameRounding = 4.0f;
    style.GrabRounding = 4.0f;
    style.ScrollbarRounding = 6.0f;
    style.TabRounding = 4.0f;
    style.WindowBorderSize = 1.0f;
    style.FrameBorderSize = 0.8f;
    style.ScrollbarSize = 12.0f;
    style.ItemSpacing = ImVec2(10, 6);
    style.ItemInnerSpacing = ImVec2(6, 4);
    style.CellPadding = ImVec2(6, 4);
    style.WindowPadding = ImVec2(12, 12);
    style.FramePadding = ImVec2(8, 5);

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    std::vector<PrefetchResult> prefetchData;
    bool isLoading = true;
    bool analysisDone = false;
    float fadeIn = 0.0f;

    std::thread([&]() {
        prefetchData = ScanPrefetchFolder();
        isLoading = false;
        analysisDone = true;
        }).detach();

    static int selectedIndex = -1;
    static float panelHeight = 0.0f;
    static int lastSelected = -1;
    const float targetPanelHeight = 320.0f;
    const float animationSpeed = 6.0f;

    MSG msg;
    ZeroMemory(&msg, sizeof(msg));

    while (msg.message != WM_QUIT)
    {
        if (PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE)) {
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

        if (isLoading)
        {
            ImVec2 pos = ImGui::GetWindowPos();
            ImVec2 size = ImGui::GetWindowSize();
            ImVec2 center = ImVec2(pos.x + size.x * 0.5f, pos.y + size.y * 0.5f - 20.0f);

            ImDrawList* draw_list = ImGui::GetWindowDrawList();
            float baseRadius = 30.0f;
            float pulse = 0.8f + 0.2f * sinf(ImGui::GetTime() * 3.0f);
            float radius = baseRadius * pulse;

            for (int i = 0; i < 3; ++i)
            {
                float angle = ImGui::GetTime() * 3.0f + i * 1.0f;
                float start = angle;
                float end = angle + 1.2f;
                draw_list->PathArcTo(center, radius - i * 6.0f, start, end, 32);
                draw_list->PathStroke(IM_COL32(120 + i * 40, 180, 255 - i * 50, 255), false, 4.0f);
            }

            const char* loadingText = "Parse Prefetch...";
            ImVec2 textSize = ImGui::CalcTextSize(loadingText);
            ImVec2 textPos = ImVec2(center.x - textSize.x * 0.5f, center.y + baseRadius + 15.0f);

            float textPulse = 0.85f + 0.15f * sinf(ImGui::GetTime() * 2.0f);
            int alpha = static_cast<int>(fadeIn * textPulse * 255.0f);
            if (alpha < 220) alpha = 220;

            ImU32 cyanLight = IM_COL32(200, 255, 255, alpha);
            draw_list->AddText(textPos, cyanLight, loadingText);
        }
        else if (!prefetchData.empty())
        {
            static float fadeAlpha = 0.0f;
            static float fadeSpeed = 3.0f;
            static bool lastShowOnlyUnsigned = false;
            static bool lastShowAfterLogon = false;

            static char searchBuffer[128] = "";
            static bool showOnlyUnsigned = false;
            static bool showAfterLogon = false;

            ImGui::PushItemWidth(300);
            ImGui::InputTextWithHint("##SearchPrefetch", "Search...", searchBuffer, IM_ARRAYSIZE(searchBuffer));
            ImGui::PopItemWidth();

            ImGui::SameLine(0, 20);
            bool checkboxChanged = false;
            checkboxChanged |= ImGui::Checkbox("Only Unsigned", &showOnlyUnsigned);
            ImGui::SameLine(0, 20);
            checkboxChanged |= ImGui::Checkbox("Show in Instance", &showAfterLogon);
            ImGui::SameLine();

            float buttonWidth = 160.0f;
            float windowRight = ImGui::GetWindowContentRegionMax().x + ImGui::GetWindowPos().x;
            ImGui::SetCursorPosX(windowRight - buttonWidth - ImGui::GetStyle().ItemSpacing.x);

            static bool showUSNPopup = false;
            static bool isReadingUSN = false;
            static std::vector<USNJournalReader::USNEvent> usnResults;
            static float popupAlpha = 0.0f;

            if (ImGui::Button("Read USN Journal", ImVec2(buttonWidth, 0)))
            {
                showUSNPopup = true;
                isReadingUSN = true;
                popupAlpha = 0.0f;
                usnResults.clear();

                std::thread([]() {
                    wchar_t windowsPath[MAX_PATH];
                    GetWindowsDirectoryW(windowsPath, MAX_PATH);

                    wchar_t driveLetter[4] = { 0 };
                    wcsncpy_s(driveLetter, windowsPath, 2);
                    USNJournalReader reader(driveLetter);
                    auto results = reader.Run();

                    ImGui::GetIO().UserData = new std::vector<USNJournalReader::USNEvent>(std::move(results));
                    }).detach();
            }

            if (showUSNPopup)
                ImGui::OpenPopup("USN Journal Results");

            if (popupAlpha < 1.0f)
                popupAlpha += ImGui::GetIO().DeltaTime * 4.0f;
            popupAlpha = std::min(popupAlpha, 1.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_Alpha, popupAlpha);

            ImVec2 popupSize(900, 500);
            if (ImGui::BeginPopupModal("USN Journal Results", &showUSNPopup,
                ImGuiWindowFlags_NoCollapse))
            {
                ImGui::SetWindowSize(popupSize, ImGuiCond_Once);

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
                    ImGui::Dummy(ImVec2(0, winSize.y * 0.35f));
                    ImGui::SetCursorPosX((winSize.x - ImGui::CalcTextSize("Reading USN Journal...").x) * 0.5f);
                    ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Reading USN Journal...");
                }
                else if (usnResults.empty())
                {
                    ImGui::Dummy(ImVec2(0, winSize.y * 0.35f));
                    ImGui::SetCursorPosX((winSize.x - ImGui::CalcTextSize("No .pf deleted or renamed entries found after logon.").x) * 0.5f);
                    ImGui::TextColored(ImVec4(0.8f, 0.5f, 0.5f, 1.0f), "No .pf deleted or renamed entries found after logon.");
                }
                else
                {
                    if (ImGui::BeginTable("USNTable", 4,
                        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
                        ImVec2(-FLT_MIN, -FLT_MIN)))
                    {
                        ImGui::TableSetupScrollFreeze(0, 1);
                        ImGui::TableSetupColumn("Old Name", ImGuiTableColumnFlags_WidthStretch);
                        ImGui::TableSetupColumn("New Name", ImGuiTableColumnFlags_WidthStretch);
                        ImGui::TableSetupColumn("Reason", ImGuiTableColumnFlags_WidthFixed, 120.0f);
                        ImGui::TableSetupColumn("Timestamp", ImGuiTableColumnFlags_WidthFixed, 180.0f);
                        ImGui::TableHeadersRow();

                        for (auto it = usnResults.rbegin(); it != usnResults.rend(); ++it)
                        {
                            const auto& e = *it;
                            ImGui::TableNextRow();
                            ImGui::TableSetColumnIndex(0);
                            ImGui::TextUnformatted(e.filenameOld.c_str());
                            ImGui::TableSetColumnIndex(1);
                            ImGui::TextUnformatted(e.filenameNew.empty() ? "-" : e.filenameNew.c_str());
                            ImGui::TableSetColumnIndex(2);
                            ImGui::TextUnformatted(e.action.c_str());
                            ImGui::TableSetColumnIndex(3);

                            std::tm* tm = std::localtime(&e.timestamp);
                            char timeBuf[32];
                            std::strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", tm);
                            ImGui::TextUnformatted(timeBuf);
                        }

                        ImGui::EndTable();
                    }
                }

                ImGui::EndPopup();
            }

            ImGui::PopStyleVar();

            if (checkboxChanged)
            {
                fadeAlpha = 0.0f;
                lastShowOnlyUnsigned = showOnlyUnsigned;
                lastShowAfterLogon = showAfterLogon;
            }

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

                SignatureStatus sig = GetSignatureStatus(info.mainExecutablePath);
                std::string sigText = (sig == SignatureStatus::Signed ? "signed" :
                    sig == SignatureStatus::Unsigned ? "unsigned" : "not found");

                bool matchesSearch =
                    searchLower.empty() ||
                    nameLower.find(searchLower) != std::string::npos ||
                    pathLower.find(searchLower) != std::string::npos ||
                    sigText.find(searchLower) != std::string::npos;

                bool matchesUnsigned = !showOnlyUnsigned || sig == SignatureStatus::Unsigned;

                bool matchesLogon = true;
                if (showAfterLogon && !info.lastExecutionTimes.empty())
                {
                    time_t execTime = info.lastExecutionTimes.front();
                    matchesLogon = execTime > logonTime;
                }

                if (matchesSearch && matchesUnsigned && matchesLogon)
                    filteredData.push_back(result);
            }

            fadeAlpha += io.DeltaTime * fadeSpeed;
            if (fadeAlpha > 1.0f) fadeAlpha = 1.0f;
            ImGui::PushStyleVar(ImGuiStyleVar_Alpha, fadeAlpha);

            static std::vector<PrefetchResult> sortedData;
            sortedData = filteredData;

            float dt = io.DeltaTime;
            float target = (selectedIndex != -1) ? targetPanelHeight : 0.0f;
            panelHeight += (target - panelHeight) * dt * animationSpeed;
            float availableHeight = ImGui::GetContentRegionAvail().y - panelHeight - 8.0f;

            if (ImGui::BeginTable("PrefetchTable", 4,
                ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_Sortable,
                ImVec2(0, availableHeight)))
            {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Time Executed", ImGuiTableColumnFlags_DefaultSort);
                ImGui::TableSetupColumn("File Name");
                ImGui::TableSetupColumn("Executable Path");
                ImGui::TableSetupColumn("Signature");
                ImGui::TableHeadersRow();

                if (ImGuiTableSortSpecs* sortSpecs = ImGui::TableGetSortSpecs())
                {
                    if (!sortedData.empty())
                    {
                        const ImGuiTableColumnSortSpecs& spec = sortSpecs->Specs[0];
                        int column = spec.ColumnIndex;
                        bool ascending = (spec.SortDirection == ImGuiSortDirection_Ascending);

                        std::sort(sortedData.begin(), sortedData.end(),
                            [column, ascending](const PrefetchResult& a, const PrefetchResult& b)
                            {
                                switch (column)
                                {
                                case 0:
                                {
                                    time_t ta = a.info.lastExecutionTimes.empty() ? 0 : a.info.lastExecutionTimes.front();
                                    time_t tb = b.info.lastExecutionTimes.empty() ? 0 : b.info.lastExecutionTimes.front();
                                    return ascending ? ta < tb : ta > tb;
                                }
                                case 1: return ascending ? a.fileName < b.fileName : a.fileName > b.fileName;
                                case 2: return ascending ? a.info.mainExecutablePath < b.info.mainExecutablePath
                                    : a.info.mainExecutablePath > b.info.mainExecutablePath;
                                case 3:
                                {
                                    auto getOrder = [](SignatureStatus s) {
                                        switch (s) {
                                        case SignatureStatus::Signed: return 0;
                                        case SignatureStatus::Unsigned: return 1;
                                        case SignatureStatus::NotFound: return 2;
                                        default: return 3;
                                        }
                                        };
                                    return ascending ? getOrder(GetSignatureStatus(a.info.mainExecutablePath))
                                        < getOrder(GetSignatureStatus(b.info.mainExecutablePath))
                                        : getOrder(GetSignatureStatus(a.info.mainExecutablePath))
                                        > getOrder(GetSignatureStatus(b.info.mainExecutablePath));
                                }
                                default: return false;
                                }
                            });

                        sortSpecs->SpecsDirty = false;
                    }
                }

                ImGuiListClipper clipper;
                clipper.Begin(static_cast<int>(sortedData.size()));
                while (clipper.Step())
                {
                    for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++)
                    {
                        const auto& result = sortedData[i];
                        const auto& info = result.info;

                        ImGui::TableNextRow();

                        ImGui::TableSetColumnIndex(0);
                        std::string execTime = "N/A";
                        if (!info.lastExecutionTimes.empty()) {
                            time_t t = info.lastExecutionTimes.front();
                            struct tm tmBuf;
                            localtime_s(&tmBuf, &t);
                            char buffer[64];
                            strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tmBuf);
                            execTime = buffer;
                        }
                        ImGui::TextUnformatted(execTime.c_str());

                        ImGui::TableSetColumnIndex(1);
                        bool isSelected = (i == selectedIndex);
                        if (ImGui::Selectable(result.fileName.c_str(), isSelected, ImGuiSelectableFlags_SpanAllColumns))
                            selectedIndex = (selectedIndex != i) ? i : -1;

                        std::string popupId = "popup_table_path_" + std::to_string(i);
                        if (ImGui::IsItemHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Right))
                            ImGui::OpenPopup(popupId.c_str());

                        if (ImGui::BeginPopup(popupId.c_str()))
                        {
                            wchar_t folderPath[MAX_PATH];
                            wcscpy_s(folderPath, info.mainExecutablePath.c_str());
                            PathRemoveFileSpecW(folderPath);

                            if (ImGui::Selectable("Copy Path")) CopyToClipboard(info.mainExecutablePath);
                            if (ImGui::Selectable("Open Path")) ShellExecuteW(NULL, L"explore", folderPath, NULL, NULL, SW_SHOWNORMAL);
                            ImGui::EndPopup();
                        }

                        ImGui::TableSetColumnIndex(2);
                        IconDataDX11* iconPtr = nullptr;
                        auto it = g_iconsCache.find(info.mainExecutablePath);
                        if (it != g_iconsCache.end()) iconPtr = &it->second;
                        else {
                            IconDataDX11 icon;
                            if (LoadFileIconDX11(g_pd3dDevice, info.mainExecutablePath, icon))
                                g_iconsCache[info.mainExecutablePath] = icon;
                            iconPtr = &g_iconsCache[info.mainExecutablePath];
                        }
                        if (iconPtr && iconPtr->IsLoaded) { ImGui::Image(iconPtr->TextureView.Get(), ImVec2(16, 16)); ImGui::SameLine(0, 5); }
                        ImGui::TextUnformatted(WStringToUTF8(info.mainExecutablePath).c_str());

                        ImGui::TableSetColumnIndex(3);
                        SignatureStatus status = GetSignatureStatus(info.mainExecutablePath);
                        ImVec4 color;
                        const char* text;
                        switch (status)
                        {
                        case SignatureStatus::Signed:   color = ImVec4(0.2f, 0.8f, 0.2f, 1.0f); text = "SIGNED"; break;
                        case SignatureStatus::Unsigned: color = ImVec4(0.9f, 0.2f, 0.2f, 1.0f); text = "UNSIGNED"; break;
                        default:                        color = ImVec4(0.8f, 0.5f, 0.1f, 1.0f); text = "NOT FOUND"; break;
                        }
                        ImGui::TextColored(color, text);
                    }
                }

                ImGui::EndTable();
            }

            if (selectedIndex >= 0 && panelHeight > 1.0f)
            {
                ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 4.0f);
                ImGui::Separator();
                ImGui::BeginChild("BottomPanel", ImVec2(0, panelHeight), true);

                if (selectedIndex != lastSelected)
                {
                    ImGui::SetScrollY(0.0f);
                    lastSelected = selectedIndex;
                }

                const auto& selected = sortedData[selectedIndex];
                const auto& info = selected.info;

                if (ImGui::BeginTabBar("DetailsTabs"))
                {
                    ImGui::SameLine(ImGui::GetContentRegionAvail().x - 30.0f);
                    if (ImGui::Button("X"))
                    {
                        selectedIndex = -1;
                        lastSelected = -1;
                    }

                    if (ImGui::BeginTabItem("Referenced Files"))
                    {
                        if (!info.fileNames.empty())
                        {
                            ImGuiListClipper clipper;
                            clipper.Begin(static_cast<int>(info.fileNames.size()));
                            while (clipper.Step())
                            {
                                for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++)
                                {
                                    const auto& wname = info.fileNames[i];
                                    std::string utf8 = WStringToUTF8(wname);

                                    ImGui::PushID(i);

                                    IconDataDX11* iconPtr = nullptr;
                                    auto it = g_iconsCache.find(wname);
                                    if (it != g_iconsCache.end())
                                        iconPtr = &it->second;
                                    else
                                    {
                                        IconDataDX11 icon;
                                        if (LoadFileIconDX11(g_pd3dDevice, wname, icon))
                                            g_iconsCache[wname] = icon;
                                        iconPtr = &g_iconsCache[wname];
                                    }

                                    if (iconPtr && iconPtr->IsLoaded)
                                    {
                                        ImGui::Image(iconPtr->TextureView.Get(), ImVec2(16, 16));
                                        ImGui::SameLine(0, 5);
                                    }

                                    ImGui::TextUnformatted(utf8.c_str());

                                    if (ImGui::IsItemHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Right))
                                        ImGui::OpenPopup("popup_ref_path");

                                    ImGui::SameLine();
                                    SignatureStatus status = info.fileSignatures[i];
                                    ImVec4 color;
                                    const char* text;
                                    switch (status)
                                    {
                                    case SignatureStatus::Signed:   color = ImVec4(0.2f, 0.8f, 0.2f, 1.0f); text = "SIGNED"; break;
                                    case SignatureStatus::Unsigned: color = ImVec4(0.9f, 0.2f, 0.2f, 1.0f); text = "UNSIGNED"; break;
                                    default:                        color = ImVec4(0.8f, 0.5f, 0.1f, 1.0f); text = "NOT FOUND"; break;
                                    }
                                    ImGui::TextColored(color, "%s", text);

                                    if (ImGui::BeginPopup("popup_ref_path"))
                                    {
                                        wchar_t folderPath[MAX_PATH];
                                        wcscpy_s(folderPath, wname.c_str());
                                        PathRemoveFileSpecW(folderPath);

                                        if (ImGui::Selectable("Copy Path")) CopyToClipboard(wname);
                                        if (ImGui::Selectable("Open Path")) ShellExecuteW(NULL, L"explore", folderPath, NULL, NULL, SW_SHOWNORMAL);

                                        ImGui::EndPopup();
                                    }

                                    ImGui::PopID();
                                }
                            }
                        }
                        else
                        {
                            ImGui::TextDisabled("No referenced files found.");
                        }
                        ImGui::EndTabItem();
                    }

                    if (ImGui::BeginTabItem("Details"))
                    {
                        ImGui::Text("File: %s", selected.fileName.c_str());
                        ImGui::Text("Executable Path: %s", WStringToUTF8(info.mainExecutablePath).c_str());

                        ImGui::Text("Version: %d", info.version);
                        ImGui::Text("Signature: 0x%X", info.signature);

                        auto formatFileSize = [](uint64_t size) -> std::string {
                            constexpr const char* suffixes[] = { "B", "KB", "MB", "GB", "TB" };
                            double s = static_cast<double>(size);
                            int i = 0;
                            while (s >= 1024.0 && i < 4) { s /= 1024.0; i++; }
                            char buffer[64];
                            snprintf(buffer, sizeof(buffer), "%.2f %s", s, suffixes[i]);
                            return std::string(buffer);
                            };

                        auto showFileTime = [](const FILETIME* ft) -> std::string {
                            return ft ? FileTimeToString(*ft) : "N/A";
                            };

                        std::string fullPfPath = "C:\\Windows\\Prefetch\\" + selected.fileName;

                        WIN32_FILE_ATTRIBUTE_DATA pfInfo;
                        if (GetFileAttributesExA(fullPfPath.c_str(), GetFileExInfoStandard, &pfInfo))
                        {
                            LARGE_INTEGER pfSize;
                            pfSize.HighPart = pfInfo.nFileSizeHigh;
                            pfSize.LowPart = pfInfo.nFileSizeLow;

                            ImGui::Text("Prefetch Size: %s", formatFileSize(pfSize.QuadPart).c_str());
                            ImGui::Text("Prefetch Creation: %s", FileTimeToString(pfInfo.ftCreationTime).c_str());
                            ImGui::Text("Prefetch Modified: %s", FileTimeToString(pfInfo.ftLastWriteTime).c_str());
                        }
                        else
                        {
                            ImGui::Text("Prefetch Size: N/A");
                            ImGui::Text("Prefetch Creation: N/A");
                            ImGui::Text("Prefetch Modified: N/A");
                        }

                        HANDLE hExe = CreateFileW(info.mainExecutablePath.c_str(),
                            GENERIC_READ,
                            FILE_SHARE_READ,
                            nullptr,
                            OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL,
                            nullptr);

                        if (hExe != INVALID_HANDLE_VALUE)
                        {
                            LARGE_INTEGER exeSize;
                            if (GetFileSizeEx(hExe, &exeSize))
                                ImGui::Text("Executable Size: %s", formatFileSize(exeSize.QuadPart).c_str());
                            else
                                ImGui::Text("Executable Size: N/A");

                            FILETIME creationTime, lastAccessTime, lastWriteTime;
                            if (GetFileTime(hExe, &creationTime, &lastAccessTime, &lastWriteTime))
                            {
                                ImGui::Text("Executable Creation: %s", showFileTime(&creationTime).c_str());
                                ImGui::Text("Executable Modified: %s", showFileTime(&lastWriteTime).c_str());
                            }
                            else
                            {
                                ImGui::Text("Executable Creation: N/A");
                                ImGui::Text("Executable Modified: N/A");
                            }

                            CloseHandle(hExe);
                        }
                        else
                        {
                            ImGui::Text("Executable Size: N/A");
                            ImGui::Text("Executable Creation: N/A");
                            ImGui::Text("Executable Modified: N/A");
                        }

                        ImGui::EndTabItem();
                    }

                    if (ImGui::BeginTabItem("Times Executed"))
                    {
                        if (!info.lastExecutionTimes.empty())
                        {
                            for (const auto& t : info.lastExecutionTimes)
                            {
                                struct tm tmBuf;
                                localtime_s(&tmBuf, &t);
                                char buffer[64];
                                strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tmBuf);
                                ImGui::TextUnformatted(buffer);
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

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    DestroyWindow(hwnd);
    UnregisterClass(wc.lpszClassName, wc.hInstance);
    return 0;
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