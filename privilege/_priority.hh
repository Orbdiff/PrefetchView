#pragma once
#include <windows.h>

void ElevateProcessPriority()
{
    SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS);
}