/*
 * PROJECT:     LiberNT Spooler and Setup API
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Lock shared by the processes that stage, register and delete driver packages of the driver store
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#pragma once

#include <sddl.h>

/* Any process can create a global name first and hold it; only administrators can open this namespace */
static inline BOOL
AcquirePackageLock(PHANDLE Namespace, PHANDLE Lock)
{
    SECURITY_ATTRIBUTES Security = { sizeof(Security), NULL, FALSE };
    BYTE Admins[SECURITY_MAX_SID_SIZE];
    WCHAR Alias[40] = L"PrinterDriverPackages", LockName[48];
    DWORD Size = sizeof(Admins), Wait;
    ULONG Try, Length = 21, Shift;
    HANDLE Boundary;

    *Namespace = NULL;
    *Lock = NULL;
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, Admins, &Size) ||
        !ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;GA;;;BA)(A;;GA;;;SY)", SDDL_REVISION_1,
                                                              &Security.lpSecurityDescriptor, NULL))
    {
        return FALSE;
    }
    /* An alias belongs to the whole process, so each holder, nested or on another thread, names its own after its handle variable */
    for (Shift = sizeof(ULONG_PTR) * 8; Shift; Shift -= 4)
        Alias[Length++] = L"0123456789ABCDEF"[((ULONG_PTR)Namespace >> (Shift - 4)) & 0xF];
    Alias[Length] = L'\0';
    lstrcpyW(LockName, Alias);
    lstrcatW(LockName, L"\\Lock");
    Boundary = CreateBoundaryDescriptorW(L"PrinterDriverPackages", 0);
    if (Boundary && AddSIDToBoundaryDescriptor(&Boundary, Admins))
    {
        /* The namespace ends with its last handle, so it can be gone again once creating it found it */
        for (Try = 0; !*Namespace && Try < 3; Try++)
        {
            *Namespace = CreatePrivateNamespaceW(&Security, Boundary, Alias);
            if (!*Namespace)
                *Namespace = OpenPrivateNamespaceW(Boundary, Alias);
        }
    }
    if (Boundary)
        DeleteBoundaryDescriptor(Boundary);
    if (*Namespace)
        *Lock = CreateMutexW(&Security, FALSE, LockName);
    LocalFree(Security.lpSecurityDescriptor);

    if (*Lock)
    {
        Wait = WaitForSingleObject(*Lock, INFINITE);
        if (Wait == WAIT_OBJECT_0 || Wait == WAIT_ABANDONED)
            return TRUE;
        CloseHandle(*Lock);
    }
    if (*Namespace)
        ClosePrivateNamespace(*Namespace, 0);
    return FALSE;
}

static inline VOID
ReleasePackageLock(HANDLE Namespace, HANDLE Lock)
{
    ReleaseMutex(Lock);
    CloseHandle(Lock);
    ClosePrivateNamespace(Namespace, 0);
}
