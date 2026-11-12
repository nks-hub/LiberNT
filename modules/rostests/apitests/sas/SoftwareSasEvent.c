/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Test for the callers that SendSAS lets reach Winlogon: services through an event, uiAccess tokens through RPC
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include <apitest.h>
#include <aclapi.h>
#include <winreg.h>
#include <strsafe.h>
#include <winlogon_sas.h>
#include <wlsas_c.h>

void __RPC_FAR * __RPC_USER midl_user_allocate(SIZE_T len)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len);
}

void __RPC_USER midl_user_free(void __RPC_FAR * ptr)
{
    HeapFree(GetProcessHeap(), 0, ptr);
}

static
DWORD
GetUiAccess(
    _In_ HANDLE hToken)
{
    DWORD UiAccess = 0xdeadbeef, Size;

    if (!GetTokenInformation(hToken, TokenUIAccess, &UiAccess, sizeof(UiAccess), &Size))
        return 0xdeadbeef;
    return UiAccess;
}

/* Returns an impersonation token with uiAccess, or NULL when the caller may not make one */
static
HANDLE
TestUiAccessToken(VOID)
{
    HANDLE hProcessToken, hToken = NULL, hNoTcb = NULL;
    TOKEN_PRIVILEGES Privilege;
    DWORD One = 1, Error;
    BOOL Success;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hProcessToken))
    {
        skip("OpenProcessToken failed (%lu)\n", GetLastError());
        return NULL;
    }

    Privilege.PrivilegeCount = 1;
    Privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueW(NULL, L"SeTcbPrivilege", &Privilege.Privileges[0].Luid) ||
        !DuplicateTokenEx(hProcessToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &hToken) ||
        !DuplicateTokenEx(hProcessToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &hNoTcb))
    {
        skip("Preparing the tokens failed (%lu)\n", GetLastError());
        goto Cleanup;
    }

    AdjustTokenPrivileges(hProcessToken, FALSE, &Privilege, 0, NULL, NULL);
    Privilege.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
    AdjustTokenPrivileges(hNoTcb, FALSE, &Privilege, 0, NULL, NULL);

    ok(GetUiAccess(hToken) == 0, "The copy of a token without uiAccess has uiAccess %lu\n", GetUiAccess(hToken));

    if (ImpersonateLoggedOnUser(hNoTcb))
    {
        Success = SetTokenInformation(hToken, TokenUIAccess, &One, sizeof(One));
        Error = GetLastError();
        RevertToSelf();
        ok(!Success && Error == ERROR_PRIVILEGE_NOT_HELD, "Setting uiAccess without SeTcbPrivilege returned %d (%lu)\n", Success, Error);
        ok(GetUiAccess(hToken) == 0, "A caller without SeTcbPrivilege changed uiAccess to %lu\n", GetUiAccess(hToken));
    }
    else
    {
        skip("ImpersonateLoggedOnUser failed (%lu)\n", GetLastError());
    }

    Success = SetTokenInformation(hToken, TokenUIAccess, &One, sizeof(WORD));
    Error = GetLastError();
    ok(!Success && Error == ERROR_BAD_LENGTH, "Setting uiAccess from 2 bytes returned %d (%lu)\n", Success, Error);

    Success = SetTokenInformation(hToken, TokenUIAccess, &One, sizeof(One));
    Error = GetLastError();
    if (!Success && Error == ERROR_PRIVILEGE_NOT_HELD)
    {
        skip("The test of a uiAccess caller needs SeTcbPrivilege (LocalSystem)\n");
        CloseHandle(hToken);
        hToken = NULL;
        goto Cleanup;
    }

    ok(Success, "Setting uiAccess with SeTcbPrivilege failed (%lu)\n", Error);
    ok(GetUiAccess(hToken) == 1, "uiAccess is %lu after it was set\n", GetUiAccess(hToken));

Cleanup:
    if (hNoTcb)
        CloseHandle(hNoTcb);
    CloseHandle(hProcessToken);
    return hToken;
}

/* Asks Winlogon for a SAS the way SendSAS(TRUE) does, as hToken or as the process when it is NULL */
static
DWORD
RequestSasAsUser(
    _In_opt_ HANDLE hToken)
{
    WCHAR Endpoint[64];
    RPC_WSTR StringBinding;
    handle_t hBinding;
    DWORD Error;

    StringCchPrintfW(Endpoint, ARRAYSIZE(Endpoint), WINLOGON_SOFTWARE_SAS_ENDPOINT, WTSGetActiveConsoleSessionId());
    Error = RpcStringBindingComposeW(NULL, (RPC_WSTR)L"ncalrpc", NULL, Endpoint, NULL, &StringBinding);
    if (Error != RPC_S_OK)
        return Error;

    Error = RpcBindingFromStringBindingW(StringBinding, &hBinding);
    RpcStringFreeW(&StringBinding);
    if (Error != RPC_S_OK)
        return Error;

    if (hToken && !ImpersonateLoggedOnUser(hToken))
    {
        Error = GetLastError();
        RpcBindingFree(&hBinding);
        return Error;
    }

    RpcTryExcept
    {
        Error = WlSoftwareSasAsUser(hBinding);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Error = RpcExceptionCode();
    }
    RpcEndExcept;

    if (hToken)
        RevertToSelf();

    /* Freeing the binding closes the connection, so the next request connects with its own identity */
    RpcBindingFree(&hBinding);
    return Error;
}

START_TEST(SoftwareSasEvent)
{
    WCHAR EventName[64];
    HANDLE hEvent, hUiAccessToken;
    PSECURITY_DESCRIPTOR SecurityDescriptor = NULL;
    PACL Dacl = NULL;
    ACCESS_ALLOWED_ACE *Ace;
    DWORD Error, i, ServiceMask = 0, SystemMask = 0, Policy = 0, Size = sizeof(Policy);

    hUiAccessToken = TestUiAccessToken();

    StringCchPrintfW(EventName, ARRAYSIZE(EventName), WINLOGON_SOFTWARE_SAS_EVENT, WTSGetActiveConsoleSessionId());
    hEvent = OpenEventW(READ_CONTROL, FALSE, EventName);
    if (!hEvent)
    {
        skip("OpenEventW(%s) failed (%lu), the test needs LocalSystem and the Winlogon of LiberNT\n",
             wine_dbgstr_w(EventName), GetLastError());
        goto Cleanup;
    }

    Error = GetSecurityInfo(hEvent, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &Dacl, NULL, &SecurityDescriptor);
    CloseHandle(hEvent);
    ok(Error == ERROR_SUCCESS, "GetSecurityInfo failed (%lu)\n", Error);
    if (Error != ERROR_SUCCESS)
        goto Cleanup;

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

    Error = RequestSasAsUser(NULL);
    ok(Error == ERROR_PRIVILEGE_NOT_HELD, "Winlogon answered %lu to a caller without uiAccess\n", Error);

    RegGetValueW(HKEY_LOCAL_MACHINE,
                 L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                 L"SoftwareSASGeneration",
                 RRF_RT_REG_DWORD,
                 NULL,
                 &Policy,
                 &Size);
    if (!hUiAccessToken)
    {
        skip("No uiAccess token to call Winlogon with\n");
    }
    else if (Policy & WINLOGON_SOFTWARE_SAS_EASE_OF_ACCESS)
    {
        skip("SoftwareSASGeneration is %lu, a uiAccess caller would raise a real SAS\n", Policy);
    }
    else
    {
        Error = RequestSasAsUser(hUiAccessToken);
        ok(Error == ERROR_ACCESS_DISABLED_BY_POLICY, "Winlogon answered %lu to a uiAccess caller under policy %lu\n", Error, Policy);
    }

Cleanup:
    if (hUiAccessToken)
        CloseHandle(hUiAccessToken);
}
