/*
 * PROJECT:     LiberNT KernelBase
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Module handle lookup by address
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include <windows.h>

/*
 * As on Windows, KernelBase resolves GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
 * with ntdll!RtlPcToFileHeader. Loaders that map DLLs from memory hook that
 * import of KernelBase so that addresses inside such a DLL resolve to their
 * executable. Reference counting, pinning and the lookup by name stay in
 * kernel32.
 */

/* Invalid flags go to kernel32 unchanged, which rejects them before any lookup */
static BOOL
KbValidModuleHandleFlags(_In_ DWORD dwFlags)
{
    const DWORD Valid = GET_MODULE_HANDLE_EX_FLAG_PIN | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT |
                        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS;
    const DWORD Exclusive = GET_MODULE_HANDLE_EX_FLAG_PIN | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;

    return !(dwFlags & ~Valid) && (dwFlags & Exclusive) != Exclusive;
}

BOOL
WINAPI
KbGetModuleHandleExW(
    _In_ DWORD dwFlags,
    _In_opt_ LPCWSTR lpModuleName,
    _Out_ HMODULE *phModule)
{
    PVOID ImageBase = NULL;

    if (KbValidModuleHandleFlags(dwFlags) && (dwFlags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS) &&
        lpModuleName && phModule)
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
