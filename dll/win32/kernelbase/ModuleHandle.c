/*
 * PROJECT:     LiberNT KernelBase
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Module lookup by address
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include <windows.h>

BOOL
WINAPI
KernelBaseGetModuleHandleExW(
    _In_ DWORD dwFlags,
    _In_opt_ LPCWSTR lpModuleName,
    _Out_ HMODULE *phModule)
{
    PVOID Base;

    /* A program that maps a library by hand replaces this import of RtlPcToFileHeader, as on Windows 11, to give that code a module */
    if ((dwFlags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS) && lpModuleName && phModule)
    {
        if (!RtlPcToFileHeader((PVOID)lpModuleName, &Base))
        {
            *phModule = NULL;
            SetLastError(ERROR_MOD_NOT_FOUND);
            return FALSE;
        }
        lpModuleName = Base;
    }
    return GetModuleHandleExW(dwFlags, lpModuleName, phModule);
}
