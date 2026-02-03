#include "_filtered_signatures.hh"
#include <mutex>

static const wchar_t* g_forcedPaths[] = {
//pathsssss!!
nullptr 
};

static std::unordered_set<std::wstring> g_forcedSignedPathsInternal;
static std::once_flag g_initFlag;

const std::unordered_set<std::wstring>& GetForcedSignedPaths() {
    std::call_once(g_initFlag, []() {
        for (size_t i = 0; g_forcedPaths[i] != nullptr; ++i) {
            g_forcedSignedPathsInternal.insert(g_forcedPaths[i]);
        }
        });
    return g_forcedSignedPathsInternal;
}