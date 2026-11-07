/*
 * PROJECT:     LiberNT KernelBase
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Module handle lookup by address
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include <windows.h>

/*
 * As on Windows, KernelBase resolves GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
 * with ntdll!RtlPcToFileHeader. Loaders that map DLLs from memory, such as
 * WireGuard's, hook that import of KernelBase so that addresses inside such
 * a DLL resolve to their executable. Reference counting, pinning and the
 * lookup by name stay in kernel32.
 */
BOOL
WINAPI
KbGetModuleHandleExW(
    _In_ DWORD dwFlags,
    _In_opt_ LPCWSTR lpModuleName,
    _Out_ HMODULE *phModule)
{
    PVOID ImageBase = NULL;

    if ((dwFlags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS) && lpModuleName && phModule)
    {
        if (!RtlPcToFileHeader((PVOID)lpModuleName, &ImageBase))
        {
            *phModule = NULL;
            SetLastError(ERROR_MOD_NOT_FOUND);
            return FALSE;
        }
        lpModuleName = (LPCWSTR)ImageBase;
    }

    return GetModuleHandleExW(dwFlags, lpModuleName, phModule);
}

BOOL
WINAPI
KbGetModuleHandleExA(
    _In_ DWORD dwFlags,
    _In_opt_ LPCSTR lpModuleName,
    _Out_ HMODULE *phModule)
{
    if (dwFlags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS)
        return KbGetModuleHandleExW(dwFlags, (LPCWSTR)lpModuleName, phModule);

    return GetModuleHandleExA(dwFlags, lpModuleName, phModule);
}
