/*
 * PROJECT:     LiberNT SAS Library
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Software generation of the secure attention sequence
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#define _INC_WINDOWS
#define COM_NO_WINDOWS_H
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <sas.h>
#include <strsafe.h>
#include <winlogon_sas.h>
#include <wlsas_c.h>

#define NDEBUG
#include <reactos/debug.h>

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

    return (Policy & (AsUser ? SAS_GENERATION_EASE_OF_ACCESS : SAS_GENERATION_SERVICES)) != 0;
}

/* An event cannot tell Winlogon who signals it, so Winlogon reads the uiAccess of the caller from the RPC connection */
static
VOID
SendSasAsUser(
    _In_ DWORD SessionId)
{
    WCHAR Endpoint[64];
    RPC_WSTR StringBinding;
    handle_t hBinding;
    DWORD Error;

    StringCchPrintfW(Endpoint, ARRAYSIZE(Endpoint), WINLOGON_SOFTWARE_SAS_ENDPOINT, SessionId);
    if (RpcStringBindingComposeW(NULL, (RPC_WSTR)L"ncalrpc", NULL, Endpoint, NULL, &StringBinding) != RPC_S_OK)
        return;

    if (RpcBindingFromStringBindingW(StringBinding, &hBinding) == RPC_S_OK)
    {
        RpcTryExcept
        {
            Error = WlSoftwareSasAsUser(hBinding);
        }
        RpcExcept(EXCEPTION_EXECUTE_HANDLER)
        {
            Error = RpcExceptionCode();
        }
        RpcEndExcept;

        if (Error != ERROR_SUCCESS)
            DPRINT1("Winlogon refused the SAS of an Ease of Access application (%lu)\n", Error);
        RpcBindingFree(&hBinding);
    }

    RpcStringFreeW(&StringBinding);
}

void __RPC_FAR * __RPC_USER midl_user_allocate(SIZE_T len)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len);
}

void __RPC_USER midl_user_free(void __RPC_FAR * ptr)
{
    HeapFree(GetProcessHeap(), 0, ptr);
}

VOID
WINAPI
SendSAS(
    _In_ BOOL AsUser)
{
    WCHAR EventName[64];
    DWORD SessionId, Size;
    HANDLE hEvent = NULL, hThreadToken;

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_IMPERSONATE, TRUE, &hThreadToken))
    {
        if (GetLastError() != ERROR_NO_TOKEN)
            return;
        hThreadToken = NULL;
        if (!ProcessIdToSessionId(GetCurrentProcessId(), &SessionId))
            return;
    }
    else if (!GetTokenInformation(hThreadToken, TokenSessionId, &SessionId, sizeof(SessionId), &Size) ||
             !RevertToSelf())
    {
        CloseHandle(hThreadToken);
        return;
    }

    if (!IsSasGenerationAllowed(AsUser))
    {
        DPRINT1("SAS generation is disabled by policy\n");
    }
    else
    {
        if (SessionId == 0)
            SessionId = WTSGetActiveConsoleSessionId();
        if (SessionId == 0xFFFFFFFF)
        {
            DPRINT1("There is no console session\n");
        }
        else if (AsUser)
        {
            SendSasAsUser(SessionId);
        }
        else
        {
            StringCchPrintfW(EventName, ARRAYSIZE(EventName), WINLOGON_SOFTWARE_SAS_EVENT, SessionId);
            hEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, EventName);
            if (!hEvent)
                DPRINT1("OpenEventW(%S) failed (%lu)\n", EventName, GetLastError());
        }
    }

    if (hThreadToken)
    {
        if (!SetThreadToken(NULL, hThreadToken))
            DPRINT1("Restoring the impersonation failed (%lu)\n", GetLastError());
        CloseHandle(hThreadToken);
    }

    if (hEvent)
    {
        SetEvent(hEvent);
        CloseHandle(hEvent);
    }
}
