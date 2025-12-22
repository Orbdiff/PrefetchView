#include "info/_events_fileinfo.hpp"
#include "info/_sechost_sysmain.h"
#include "info/_attributes_prefetch.hpp"
#include "info/_fileinfo.hpp"
#include "info/_hash_prefetch.h"
#include "info/_registry_prefetch.hh"
#include <sstream>
#include <string>

std::wstring InfoCmd_UIPREFETCHVIEW()
{
    std::wstringstream out;

    RegistryPrefetchParameters(out);
    PrefetchAttributesSpecials(out);
    DetectDuplicatePrefetchByHash(out);
    SysmainThreadSechost(out);
    FileInfoStatus(out);
    FileInfoEvents(out);

    return out.str();
}