/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Test for SendSAS and the callers it lets reach Winlogon: services through an event, uiAccess tokens through RPC
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include <apitest.h>
#include <aclapi.h>
#include <winreg.h>
#include <strsafe.h>
#include <sas.h>
#include <winlogon_sas.h>
#include <wlsas_c.h>

#define POLICY_KEY L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
#define POLICY_VALUE L"SoftwareSASGeneration"

/* No Winlogon serves this session, so the test can listen on its endpoint and SendSAS raises no real SAS */
#define TEST_SESSION 0x5A5A

static LONG SasServerCalls;
static DWORD SasServerUiAccess, SasServerSession;

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

/* Asks Winlogon for a SAS over its RPC interface, as hToken or as the process when it is NULL */
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

/* Stands in for Winlogon on the endpoint of TEST_SESSION and records who SendSAS called as */
DWORD
__stdcall
Test_WlSoftwareSasAsUser(
    handle_t hBinding)
{
    HANDLE hToken;
    DWORD Size;

    SasServerUiAccess = SasServerSession = 0xdeadbeef;
    if (RpcImpersonateClient(hBinding) == RPC_S_OK)
    {
        if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken))
        {
            SasServerUiAccess = GetUiAccess(hToken);
            GetTokenInformation(hToken, TokenSessionId, &SasServerSession, sizeof(SasServerSession), &Size);
            CloseHandle(hToken);
        }
        RpcRevertToSelf();
    }

    InterlockedIncrement(&SasServerCalls);
    return ERROR_SUCCESS;
}

/* Runs in a process whose primary token has uiAccess: calls SendSAS(TRUE) while impersonating a token without it */
static
VOID
SendSasChild(VOID)
{
    HANDLE hProcessToken, hToken = NULL, hThreadToken;
    DWORD Zero = 0, SessionId = TEST_SESSION, Size;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &hProcessToken))
    {
        ok(FALSE, "OpenProcessToken failed (%lu)\n", GetLastError());
        return;
    }

    ok(GetUiAccess(hProcessToken) == 1, "The primary token of the child has uiAccess %lu\n", GetUiAccess(hProcessToken));

    /* Without the session of the test endpoint SendSAS would reach the real Winlogon, so it is not called then */
    if (!DuplicateTokenEx(hProcessToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &hToken) ||
        !SetTokenInformation(hToken, TokenUIAccess, &Zero, sizeof(Zero)) ||
        !SetTokenInformation(hToken, TokenSessionId, &SessionId, sizeof(SessionId)) ||
        !SetThreadToken(NULL, hToken))
    {
        ok(FALSE, "Impersonating a token of session 0x%x without uiAccess failed (%lu)\n", TEST_SESSION, GetLastError());
        goto Cleanup;
    }

    SendSAS(TRUE);

    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hThreadToken))
    {
        SessionId = 0xFFFFFFFF;
        GetTokenInformation(hThreadToken, TokenSessionId, &SessionId, sizeof(SessionId), &Size);
        ok(SessionId == TEST_SESSION && GetUiAccess(hThreadToken) == 0,
           "After SendSAS the thread impersonates a token of session 0x%lx with uiAccess %lu\n", SessionId, GetUiAccess(hThreadToken));
        CloseHandle(hThreadToken);
    }
    else
    {
        ok(FALSE, "SendSAS left the thread without its impersonation token (%lu)\n", GetLastError());
    }

    RevertToSelf();

Cleanup:
    if (hToken)
        CloseHandle(hToken);
    CloseHandle(hProcessToken);
}

/* Calls the exported SendSAS(TRUE) from a uiAccess process under a policy that allows it and one that does not */
static
VOID
TestSendSas(
    _In_ HANDLE hUiAccessToken)
{
    static const PCWSTR Privileges[] = { L"SeAssignPrimaryTokenPrivilege", L"SeIncreaseQuotaPrivilege" };
    static const DWORD Policies[] = { WINLOGON_SOFTWARE_SAS_EASE_OF_ACCESS, WINLOGON_SOFTWARE_SAS_SERVICES };
    WCHAR Endpoint[64], Path[MAX_PATH], CommandLine[MAX_PATH + 32];
    HANDLE hProcessToken, hPrimaryToken = NULL;
    TOKEN_PRIVILEGES Privilege;
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo;
    HKEY hKey = NULL;
    DWORD OldPolicy = 0, Size = sizeof(OldPolicy), SessionId = 0xFFFFFFFF, i;
    LSTATUS Error, OldPolicyError;
    RPC_STATUS Status;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hProcessToken))
    {
        Privilege.PrivilegeCount = 1;
        Privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        for (i = 0; i < ARRAYSIZE(Privileges); i++)
        {
            if (LookupPrivilegeValueW(NULL, Privileges[i], &Privilege.Privileges[0].Luid))
                AdjustTokenPrivileges(hProcessToken, FALSE, &Privilege, 0, NULL, NULL);
        }
        CloseHandle(hProcessToken);
    }

    StringCchPrintfW(Endpoint, ARRAYSIZE(Endpoint), WINLOGON_SOFTWARE_SAS_ENDPOINT, (DWORD)TEST_SESSION);
    Status = RpcServerUseProtseqEpW((RPC_WSTR)L"ncalrpc", RPC_C_PROTSEQ_MAX_REQS_DEFAULT, (RPC_WSTR)Endpoint, NULL);
    if (Status == RPC_S_OK)
        Status = RpcServerRegisterIf(Test_WinlogonSas_v1_0_s_ifspec, NULL, NULL);
    if (Status != RPC_S_OK)
    {
        ok(FALSE, "Listening on %s failed (%ld)\n", wine_dbgstr_w(Endpoint), Status);
        return;
    }

    Status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, TRUE);
    ok(Status == RPC_S_OK, "RpcServerListen failed (%ld)\n", Status);

    Error = RegCreateKeyExW(HKEY_LOCAL_MACHINE, POLICY_KEY, 0, NULL, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, NULL, &hKey, NULL);
    ok(Error == ERROR_SUCCESS, "Opening the policy key failed (%ld)\n", Error);
    if (Status != RPC_S_OK || Error != ERROR_SUCCESS)
        goto Cleanup;

    if (!DuplicateTokenEx(hUiAccessToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hPrimaryToken) ||
        !ProcessIdToSessionId(GetCurrentProcessId(), &SessionId) ||
        !GetModuleFileNameW(NULL, Path, ARRAYSIZE(Path)))
    {
        ok(FALSE, "Preparing the child process failed (%lu)\n", GetLastError());
        goto Cleanup;
    }

    StringCchPrintfW(CommandLine, ARRAYSIZE(CommandLine), L"\"%s\" SoftwareSasEvent child", Path);
    OldPolicyError = RegGetValueW(hKey, NULL, POLICY_VALUE, RRF_RT_REG_DWORD, NULL, &OldPolicy, &Size);

    for (i = 0; i < ARRAYSIZE(Policies); i++)
    {
        Error = RegSetValueExW(hKey, POLICY_VALUE, 0, REG_DWORD, (const BYTE *)&Policies[i], sizeof(Policies[i]));
        ok(Error == ERROR_SUCCESS, "Setting the policy to %lu failed (%ld)\n", Policies[i], Error);
        if (Error != ERROR_SUCCESS)
            continue;

        SasServerCalls = 0;
        if (!CreateProcessAsUserW(hPrimaryToken, NULL, CommandLine, NULL, NULL, TRUE, 0, NULL, NULL, &StartupInfo, &ProcessInfo))
        {
            ok(FALSE, "CreateProcessAsUserW failed (%lu)\n", GetLastError());
            continue;
        }

        winetest_wait_child_process(ProcessInfo.hProcess);
        CloseHandle(ProcessInfo.hThread);
        CloseHandle(ProcessInfo.hProcess);

        if (Policies[i] & WINLOGON_SOFTWARE_SAS_EASE_OF_ACCESS)
        {
            /* The session of the impersonated token picks the endpoint, the token of the process makes the call */
            ok(SasServerCalls == 1, "SendSAS(TRUE) called the endpoint of the impersonated session %ld times under policy %lu\n",
               SasServerCalls, Policies[i]);
            ok(SasServerUiAccess == 1 && SasServerSession == SessionId,
               "SendSAS(TRUE) called as a token of session %lu with uiAccess %lu, expected the process token of session %lu\n",
               SasServerSession, SasServerUiAccess, SessionId);
        }
        else
        {
            ok(SasServerCalls == 0, "SendSAS(TRUE) made %ld calls under policy %lu\n", SasServerCalls, Policies[i]);
        }
    }

    if (OldPolicyError == ERROR_SUCCESS)
        Error = RegSetValueExW(hKey, POLICY_VALUE, 0, REG_DWORD, (const BYTE *)&OldPolicy, sizeof(OldPolicy));
    else
        Error = RegDeleteValueW(hKey, POLICY_VALUE);
    ok(Error == ERROR_SUCCESS, "Restoring the policy failed (%ld)\n", Error);

Cleanup:
    if (hPrimaryToken)
        CloseHandle(hPrimaryToken);
    if (hKey)
        RegCloseKey(hKey);
    RpcServerUnregisterIf(Test_WinlogonSas_v1_0_s_ifspec, NULL, TRUE);
    RpcMgmtStopServerListening(NULL);
}

START_TEST(SoftwareSasEvent)
{
    WCHAR EventName[64];
    HANDLE hEvent, hUiAccessToken;
    PSECURITY_DESCRIPTOR SecurityDescriptor = NULL;
    PACL Dacl = NULL;
    ACCESS_ALLOWED_ACE *Ace;
    DWORD Error, i, ServiceMask = 0, SystemMask = 0, Policy = 0, Size = sizeof(Policy);
    DWORD SessionId = 0xFFFFFFFF, Expected;
    char **argv;

    if (winetest_get_mainargs(&argv) >= 3 && !strcmp(argv[2], "child"))
    {
        SendSasChild();
        return;
    }

    hUiAccessToken = TestUiAccessToken();

    StringCchPrintfW(EventName, ARRAYSIZE(EventName), WINLOGON_SOFTWARE_SAS_EVENT, WTSGetActiveConsoleSessionId());
    hEvent = OpenEventW(READ_CONTROL, FALSE, EventName);
    if (!hEvent)
    {
        skip("OpenEventW(%s) failed (%lu), the test needs LocalSystem and LiberNT: Windows 11 shows SendSAS only through a real SAS\n",
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
                 POLICY_KEY,
                 POLICY_VALUE,
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
        /* Winlogon serves the uiAccess callers of its own session only, and looks at the policy after that */
        Expected = ProcessIdToSessionId(GetCurrentProcessId(), &SessionId) && SessionId == WTSGetActiveConsoleSessionId() ?
                   ERROR_ACCESS_DISABLED_BY_POLICY : ERROR_ACCESS_DENIED;
        Error = RequestSasAsUser(hUiAccessToken);
        ok(Error == Expected, "Winlogon answered %lu to a uiAccess caller of session %lu under policy %lu, expected %lu\n",
           Error, SessionId, Policy, Expected);
    }

    if (hUiAccessToken)
        TestSendSas(hUiAccessToken);

Cleanup:
    if (hUiAccessToken)
        CloseHandle(hUiAccessToken);
}
