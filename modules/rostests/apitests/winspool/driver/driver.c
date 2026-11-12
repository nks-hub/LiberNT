/*
 * PROJECT:     LiberNT Print Spooler DLL API Tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     The export by which the driver file of the DriverPackage test tells the spooler that it runs in user mode
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include <windef.h>
#include <winbase.h>
#include <wingdi.h>
#include <winddi.h>

BOOL APIENTRY
DrvQueryDriverInfo(DWORD dwMode, PVOID pBuffer, DWORD cbBuf, PDWORD pcbNeeded)
{
    if (dwMode != DRVQUERY_USERMODE)
        return FALSE;

    *pcbNeeded = sizeof(DWORD);
    if (!pBuffer || cbBuf < sizeof(DWORD))
        return FALSE;
    *(PDWORD)pBuffer = TRUE;
    return TRUE;
}
