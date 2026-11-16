/*
 * PROJECT:     LiberNT KernelBase
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Module handle lookup by address
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include <windows.h>
#include <winternl.h>

NTSYSAPI NTSTATUS NTAPI LdrAddRefDll(_In_ ULONG Flags, _In_ HMODULE Module);

#define LDR_ADDREF_DLL_PIN 0x00000001

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
    DWORD Error = ERROR_SUCCESS;
    NTSTATUS Status;

    if (!KbValidModuleHandleFlags(dwFlags) || !(dwFlags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS) ||
        !lpModuleName || !phModule)
    {
        return GetModuleHandleExW(dwFlags, lpModuleName, phModule);
    }

    /* The lookup runs without the loader lock: a program may have redirected it into code that waits for a new thread */
    if (!RtlPcToFileHeader((PVOID)lpModuleName, &ImageBase))
    {
        Error = ERROR_MOD_NOT_FOUND;
    }
    else if (!(dwFlags & GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT))
    {
        Status = LdrAddRefDll((dwFlags & GET_MODULE_HANDLE_EX_FLAG_PIN) ? LDR_ADDREF_DLL_PIN : 0, (HMODULE)ImageBase);
        if (!NT_SUCCESS(Status))
            Error = RtlNtStatusToDosError(Status);
    }

    if (Error != ERROR_SUCCESS)
    {
        *phModule = NULL;
        SetLastError(Error);
        return FALSE;
    }
    *phModule = (HMODULE)ImageBase;
    return TRUE;
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
