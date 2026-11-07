/*
 * PROJECT:     LiberNT SAS Library
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Software generation of the secure attention sequence
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <sas.h>
#include <strsafe.h>
#include <winlogon_sas.h>

#define NDEBUG
#include <reactos/debug.h>

/* Values of the SoftwareSASGeneration policy */
#define SAS_GENERATION_SERVICES       0x1
#define SAS_GENERATION_EASE_OF_ACCESS 0x2

static
BOOL
IsSasGenerationAllowed(
    _In_ BOOL AsUser)
{
    DWORD Policy = 0, Size = sizeof(Policy);
    LSTATUS Status;

    Status = RegGetValueW(HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                          L"SoftwareSASGeneration",
                          RRF_RT_REG_DWORD,
                          NULL,
                          &Policy,
                          &Size);
    if (Status != ERROR_SUCCESS)
        return FALSE;

    /* shortcut: the Winlogon event admits SYSTEM only, so Ease of Access callers (uiAccess
     * processes) cannot signal it; honour SAS_GENERATION_EASE_OF_ACCESS once the event
     * grants them access */
    if (AsUser)
    {
        DPRINT1("SendSAS for Ease of Access applications is not supported\n");
        return FALSE;
    }

    return (Policy & SAS_GENERATION_SERVICES) != 0;
}

/*
 * Simulates Ctrl+Alt+Del in the session of the caller, or in the console
 * session when the caller is a service in session 0. Winlogon handles the
 * request like the keyboard sequence. The SoftwareSASGeneration policy must
 * allow it, and only SYSTEM may signal Winlogon.
 */
VOID
WINAPI
SendSAS(
    _In_ BOOL AsUser)
{
    WCHAR EventName[64];
    DWORD SessionId;
    HANDLE hEvent;

    if (!IsSasGenerationAllowed(AsUser))
    {
        DPRINT1("SAS generation is disabled by policy\n");
        return;
    }

    if (!ProcessIdToSessionId(GetCurrentProcessId(), &SessionId))
        return;
    if (SessionId == 0)
    {
        SessionId = WTSGetActiveConsoleSessionId();
        if (SessionId == 0xFFFFFFFF)
            return;
    }

    StringCchPrintfW(EventName, ARRAYSIZE(EventName), WINLOGON_SOFTWARE_SAS_EVENT, SessionId);
    hEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, EventName);
    if (!hEvent)
    {
        DPRINT1("OpenEventW(%S) failed (%lu)\n", EventName, GetLastError());
        return;
    }

    SetEvent(hEvent);
    CloseHandle(hEvent);
}
