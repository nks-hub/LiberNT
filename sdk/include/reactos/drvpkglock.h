/*
 * PROJECT:     LiberNT Spooler and Setup API
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Lock shared by the processes that stage, register and delete driver packages of the driver store
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#ifndef _LIBERNT_DRVPKGLOCK_H
#define _LIBERNT_DRVPKGLOCK_H

#include <sddl.h>

/* Any process can create a global name first and hold it; only administrators can open this namespace */
static inline BOOL
AcquirePackageLock(PHANDLE Namespace, PHANDLE Lock)
{
    SECURITY_ATTRIBUTES Security = { sizeof(Security), NULL, FALSE };
    BYTE Admins[SECURITY_MAX_SID_SIZE];
    DWORD Size = sizeof(Admins), Wait;
    HANDLE Boundary;
    ULONG Try;

    *Namespace = NULL;
    *Lock = NULL;
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, Admins, &Size) ||
        !ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;GA;;;BA)(A;;GA;;;SY)", SDDL_REVISION_1,
                                                              &Security.lpSecurityDescriptor, NULL))
    {
        return FALSE;
    }
    Boundary = CreateBoundaryDescriptorW(L"PrinterDriverPackages", 0);
    if (Boundary && AddSIDToBoundaryDescriptor(&Boundary, Admins))
    {
        /* The namespace ends with its last handle, so it can be gone again once creating it found it */
        for (Try = 0; !*Namespace && Try < 3; Try++)
        {
            *Namespace = CreatePrivateNamespaceW(&Security, Boundary, L"PrinterDriverPackages");
            if (!*Namespace)
                *Namespace = OpenPrivateNamespaceW(Boundary, L"PrinterDriverPackages");
        }
    }
    if (Boundary)
        DeleteBoundaryDescriptor(Boundary);
    if (*Namespace)
        *Lock = CreateMutexW(&Security, FALSE, L"PrinterDriverPackages\\Lock");
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

#endif
