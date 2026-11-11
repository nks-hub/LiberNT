/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Test for the access to the event through which SendSAS reaches Winlogon
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include <apitest.h>
#include <aclapi.h>
#include <strsafe.h>
#include <winlogon_sas.h>

START_TEST(SoftwareSasEvent)
{
    WCHAR EventName[64];
    HANDLE hEvent;
    PSECURITY_DESCRIPTOR SecurityDescriptor = NULL;
    PACL Dacl = NULL;
    ACCESS_ALLOWED_ACE *Ace;
    DWORD Error, i, ServiceMask = 0, SystemMask = 0;

    StringCchPrintfW(EventName, ARRAYSIZE(EventName), WINLOGON_SOFTWARE_SAS_EVENT, WTSGetActiveConsoleSessionId());
    hEvent = OpenEventW(READ_CONTROL, FALSE, EventName);
    if (!hEvent)
    {
        skip("OpenEventW(%s) failed (%lu), the test needs LocalSystem and the Winlogon of LiberNT\n",
             wine_dbgstr_w(EventName), GetLastError());
        return;
    }

    Error = GetSecurityInfo(hEvent, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &Dacl, NULL, &SecurityDescriptor);
    CloseHandle(hEvent);
    ok(Error == ERROR_SUCCESS, "GetSecurityInfo failed (%lu)\n", Error);
    if (Error != ERROR_SUCCESS)
        return;

    ok(Dacl != NULL, "The event has no DACL\n");
    for (i = 0; Dacl && i < Dacl->AceCount; i++)
    {
        if (!GetAce(Dacl, i, (PVOID *)&Ace))
        {
            ok(FALSE, "GetAce(%lu) failed (%lu)\n", i, GetLastError());
            break;
        }

        ok(Ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE, "ACE %lu has type %u\n", i, Ace->Header.AceType);
        if (IsWellKnownSid(&Ace->SidStart, WinServiceSid))
            ServiceMask |= Ace->Mask;
        else if (IsWellKnownSid(&Ace->SidStart, WinLocalSystemSid))
            SystemMask |= Ace->Mask;
        else
            ok(FALSE, "ACE %lu grants 0x%lx to an account that is neither SERVICE nor LocalSystem\n", i, Ace->Mask);
    }

    ok(ServiceMask == EVENT_MODIFY_STATE, "SERVICE is granted 0x%lx, expected 0x%x\n", ServiceMask, EVENT_MODIFY_STATE);
    ok((SystemMask & (EVENT_MODIFY_STATE | GENERIC_ALL)) != 0, "LocalSystem is granted 0x%lx\n", SystemMask);

    LocalFree(SecurityDescriptor);
}
