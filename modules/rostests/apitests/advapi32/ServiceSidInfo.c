/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     SERVICE_CONFIG_SERVICE_SID_INFO through ChangeServiceConfig2 and QueryServiceConfig2
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include "precomp.h"
#include "svchlp.h"
#include <sddl.h>

static SERVICE_STATUS_HANDLE status_handle;
static BOOL restricted_service;

static BOOL token_has_sid(PTOKEN_GROUPS groups, PSID sid)
{
    DWORD i;

    for (i = 0; i < groups->GroupCount; i++)
    {
        if (EqualSid(groups->Groups[i].Sid, sid))
            return TRUE;
    }
    return FALSE;
}

static BOOL token_has_service_sid(PTOKEN_GROUPS groups, PCWSTR name)
{
    BYTE sid[SECURITY_MAX_SID_SIZE];
    ULONG length = sizeof(sid);
    UNICODE_STRING string;

    RtlInitUnicodeString(&string, name);
    if (!NT_SUCCESS(RtlCreateServiceSid(&string, (PSID)sid, &length)))
        return FALSE;
    return token_has_sid(groups, (PSID)sid);
}

static DWORD count_logon_sids(PTOKEN_GROUPS groups, PSID *sid)
{
    DWORD i, count = 0;

    *sid = NULL;
    for (i = 0; i < groups->GroupCount; i++)
    {
        if ((groups->Groups[i].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
        {
            *sid = groups->Groups[i].Sid;
            count++;
        }
    }
    return count;
}

static PTOKEN_GROUPS query_process_groups(void)
{
    PTOKEN_GROUPS groups = NULL;
    HANDLE token;
    DWORD size = 0;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    {
        GetTokenInformation(token, TokenGroups, NULL, 0, &size);
        groups = HeapAlloc(GetProcessHeap(), 0, size);
        if (groups && !GetTokenInformation(token, TokenGroups, groups, size, &size))
        {
            HeapFree(GetProcessHeap(), 0, groups);
            groups = NULL;
        }
        CloseHandle(token);
    }
    return groups;
}

static VOID WINAPI service_handler(DWORD ctrl)
{
    UNREFERENCED_PARAMETER(ctrl);
}

static void WINAPI restricted_main(DWORD argc, LPWSTR *argv)
{
    static SID world = { SID_REVISION, 1, { SECURITY_WORLD_SID_AUTHORITY }, { SECURITY_WORLD_RID } };
    static SID write_restricted = { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { SECURITY_WRITE_RESTRICTED_CODE_RID } };
    SERVICE_STATUS status = { SERVICE_WIN32_OWN_PROCESS, SERVICE_RUNNING };
    PTOKEN_GROUPS groups = NULL, all_groups;
    PSID logon_sid = NULL;
    WCHAR key_path[150];
    HANDLE token;
    DWORD size = 0, count;
    LONG error;
    HKEY key;

    UNREFERENCED_PARAMETER(argc);

    status_handle = RegisterServiceCtrlHandlerW(argv[0], service_handler);
    service_ok(status_handle != NULL, "RegisterServiceCtrlHandlerW failed: %lu\n", GetLastError());
    if (!status_handle)
        return;
    SetServiceStatus(status_handle, &status);

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    {
        GetTokenInformation(token, TokenRestrictedSids, NULL, 0, &size);
        groups = HeapAlloc(GetProcessHeap(), 0, size);
        if (groups && !GetTokenInformation(token, TokenRestrictedSids, groups, size, &size))
        {
            HeapFree(GetProcessHeap(), 0, groups);
            groups = NULL;
        }
        CloseHandle(token);
    }
    service_ok(groups != NULL, "the restricted SIDs of the process token cannot be read: %lu\n", GetLastError());
    all_groups = query_process_groups();
    service_ok(all_groups != NULL, "the groups of the process token cannot be read: %lu\n", GetLastError());
    if (all_groups)
    {
        count = count_logon_sids(all_groups, &logon_sid);
        service_ok(count == 1, "the process token has %lu groups with SE_GROUP_LOGON_ID\n", count);
    }
    if (groups)
    {
        service_ok(groups->GroupCount == 4, "the process token has %lu restricted SIDs\n", groups->GroupCount);
        service_ok(token_has_service_sid(groups, argv[0]), "the restricted SIDs lack the service SID\n");
        service_ok(logon_sid != NULL && token_has_sid(groups, logon_sid), "the restricted SIDs lack the logon SID\n");
        service_ok(token_has_sid(groups, &world), "the restricted SIDs lack Everyone\n");
        service_ok(token_has_sid(groups, &write_restricted), "the restricted SIDs lack S-1-5-33\n");
        HeapFree(GetProcessHeap(), 0, groups);
    }
    if (all_groups)
        HeapFree(GetProcessHeap(), 0, all_groups);

    StringCbPrintfW(key_path, sizeof(key_path), L"SOFTWARE\\%ls", argv[0]);
    error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, key_path, 0, KEY_READ, &key);
    service_ok(error == ERROR_SUCCESS, "reading a key that grants access to LocalSystem only failed: %ld\n", error);
    if (error == ERROR_SUCCESS)
        RegCloseKey(key);
    error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, key_path, 0, KEY_SET_VALUE, &key);
    service_ok(error == ERROR_ACCESS_DENIED, "writing a key that grants access to LocalSystem only: %ld\n", error);
    if (error == ERROR_SUCCESS)
        RegCloseKey(key);
    error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, key_path, 0, DELETE, &key);
    service_ok(error == ERROR_ACCESS_DENIED, "opening a key that grants access to LocalSystem only for DELETE: %ld\n", error);
    if (error == ERROR_SUCCESS)
        RegCloseKey(key);
    error = RegDeleteKeyW(HKEY_LOCAL_MACHINE, key_path);
    service_ok(error == ERROR_ACCESS_DENIED, "deleting a key that grants access to LocalSystem only: %ld\n", error);

    status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(status_handle, &status);
}

static void WINAPI service_main(DWORD argc, LPWSTR *argv)
{
    SERVICE_STATUS status = { SERVICE_WIN32_SHARE_PROCESS, SERVICE_RUNNING };
    PTOKEN_GROUPS groups;
    PSID logon_sid;
    WCHAR peer[100];
    DWORD count;

    UNREFERENCED_PARAMETER(argc);

    status_handle = RegisterServiceCtrlHandlerW(argv[0], service_handler);
    service_ok(status_handle != NULL, "RegisterServiceCtrlHandlerW failed: %lu\n", GetLastError());
    if (!status_handle)
        return;
    SetServiceStatus(status_handle, &status);

    groups = query_process_groups();
    service_ok(groups != NULL, "the groups of the process token cannot be read: %lu\n", GetLastError());
    if (groups)
    {
        count = count_logon_sids(groups, &logon_sid);
        service_ok(count == 1, "the process token has %lu groups with SE_GROUP_LOGON_ID\n", count);
        StringCbPrintfW(peer, sizeof(peer), L"%lsPeer", argv[0]);
        service_ok(token_has_service_sid(groups, argv[0]), "the process token lacks the service SID of %S\n", argv[0]);
        service_ok(token_has_service_sid(groups, peer), "the process token lacks the service SID of %S, the stopped service of the same image\n", peer);
        HeapFree(GetProcessHeap(), 0, groups);
    }

    status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(status_handle, &status);
}

static BOOL start_service(PCSTR service_nameA, PCWSTR service_nameW)
{
    SERVICE_TABLE_ENTRYW table[] =
    {
        { (PWSTR)service_nameW, restricted_service ? restricted_main : service_main },
        { NULL, NULL }
    };
    BOOL res;

    UNREFERENCED_PARAMETER(service_nameA);

    res = StartServiceCtrlDispatcherW(table);
    service_ok(res, "StartServiceCtrlDispatcherW failed: %lu\n", GetLastError());
    return res;
}

static DWORD query_sid_type(SC_HANDLE service)
{
    SERVICE_SID_INFO info = { 0xdeadbeef };
    DWORD needed = 0;
    BOOL res;

    SetLastError(0xdeadbeef);
    res = QueryServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO, (LPBYTE)&info, sizeof(info), &needed);
    ok(res, "QueryServiceConfig2W failed: %lu\n", GetLastError());
    ok(needed == sizeof(info), "needed = %lu\n", needed);
    return info.dwServiceSidType;
}

static void run_service(SC_HANDLE service)
{
    SERVICE_STATUS status = { 0 };
    DWORD start;
    BOOL res;

    res = StartServiceW(service, 0, NULL);
    ok(res, "StartServiceW on a service with a service SID failed: %lu\n", GetLastError());
    if (res)
    {
        start = GetTickCount();
        do
        {
            Sleep(100);
            res = QueryServiceStatus(service, &status);
        } while (res && status.dwCurrentState != SERVICE_STOPPED && GetTickCount() - start < 30000);
        ok(res && status.dwCurrentState == SERVICE_STOPPED, "the service did not stop: %d state %lu\n", res, status.dwCurrentState);
    }
}

static void test_write_restricted(PCSTR service_nameA, PCWSTR service_nameW, void *param)
{
    SERVICE_SID_INFO info = { SERVICE_SID_TYPE_RESTRICTED };
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, FALSE };
    WCHAR key_path[150];
    SC_HANDLE scm, service;
    LONG error;
    HKEY key = NULL;
    BOOL res;

    UNREFERENCED_PARAMETER(service_nameA);
    UNREFERENCED_PARAMETER(param);

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm)
    {
        skip("OpenSCManagerW failed: %lu\n", GetLastError());
        return;
    }

    service = register_service_exW(scm, L"ServiceSidInfo", service_nameW, L"restricted", SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                   SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, NULL, NULL, NULL, NULL, NULL);
    if (!service)
    {
        CloseServiceHandle(scm);
        return;
    }

    res = ChangeServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO, &info);
    ok(res, "ChangeServiceConfig2W(RESTRICTED) failed: %lu\n", GetLastError());

    res = ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;KA;;;SY)(A;;KA;;;BA)", SDDL_REVISION_1,
                                                               &sa.lpSecurityDescriptor, NULL);
    ok(res, "ConvertStringSecurityDescriptorToSecurityDescriptorW failed: %lu\n", GetLastError());
    StringCbPrintfW(key_path, sizeof(key_path), L"SOFTWARE\\%ls", service_nameW);
    error = res ? RegCreateKeyExW(HKEY_LOCAL_MACHINE, key_path, 0, NULL, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, &sa, &key, NULL) :
                  ERROR_INVALID_SECURITY_DESCR;
    ok(error == ERROR_SUCCESS, "RegCreateKeyExW failed: %ld\n", error);
    if (error == ERROR_SUCCESS)
    {
        run_service(service);
        RegDeleteKeyW(HKEY_LOCAL_MACHINE, key_path);
        RegCloseKey(key);
    }
    if (res)
        LocalFree(sa.lpSecurityDescriptor);

    DeleteService(service);
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
}

static void test_shared_process(PCSTR service_nameA, PCWSTR service_nameW, void *param)
{
    SERVICE_SID_INFO info = { SERVICE_SID_TYPE_UNRESTRICTED };
    WCHAR path[MAX_PATH], cmd[MAX_PATH + 150], peer_name[100];
    SC_HANDLE scm, service, peer;
    BOOL res;

    UNREFERENCED_PARAMETER(service_nameA);
    UNREFERENCED_PARAMETER(param);

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm)
    {
        skip("OpenSCManagerW failed: %lu\n", GetLastError());
        return;
    }

    service = register_service_exW(scm, L"ServiceSidInfo", service_nameW, NULL, SERVICE_ALL_ACCESS, SERVICE_WIN32_SHARE_PROCESS,
                                   SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, NULL, NULL, NULL, NULL, NULL);
    if (!service)
    {
        CloseServiceHandle(scm);
        return;
    }

    res = ChangeServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO, &info);
    ok(res, "ChangeServiceConfig2W(UNRESTRICTED) on a shared process service failed: %lu\n", GetLastError());
    ok(query_sid_type(service) == SERVICE_SID_TYPE_UNRESTRICTED, "SID type of the shared process service is not UNRESTRICTED\n");

    GetModuleFileNameW(NULL, path, ARRAYSIZE(path));
    StringCbPrintfW(cmd, sizeof(cmd), L"%ls ServiceSidInfo %ls", path, service_nameW);
    StringCbPrintfW(peer_name, sizeof(peer_name), L"%lsPeer", service_nameW);
    peer = CreateServiceW(scm, peer_name, peer_name, SERVICE_ALL_ACCESS, SERVICE_WIN32_SHARE_PROCESS, SERVICE_DEMAND_START,
                          SERVICE_ERROR_IGNORE, cmd, NULL, NULL, NULL, NULL, NULL);
    ok(peer != NULL, "CreateServiceW for the second service of the image failed: %lu\n", GetLastError());
    if (peer)
    {
        res = ChangeServiceConfig2W(peer, SERVICE_CONFIG_SERVICE_SID_INFO, &info);
        ok(res, "ChangeServiceConfig2W(UNRESTRICTED) on the second service failed: %lu\n", GetLastError());
    }

    run_service(service);

    if (peer)
    {
        DeleteService(peer);
        CloseServiceHandle(peer);
    }
    DeleteService(service);
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
}

static HANDLE create_check_token(HANDLE process_token, DWORD flags, PSID first, PSID second)
{
    SID_AND_ATTRIBUTES restricting[2] = { { first, 0 }, { second, 0 } };
    HANDLE token = process_token, check_token = NULL;

    if (first && !CreateRestrictedToken(process_token, flags, 0, NULL, 0, NULL, second ? 2 : 1, restricting, &token))
        return NULL;
    DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &check_token);
    if (token != process_token)
        CloseHandle(token);
    return check_token;
}

static void test_owner_rights(void)
{
    static SID owner_rights = { SID_REVISION, 1, { SECURITY_CREATOR_SID_AUTHORITY }, { SECURITY_CREATOR_OWNER_RIGHTS_RID } };
    static SID_IDENTIFIER_AUTHORITY nt_authority = { SECURITY_NT_AUTHORITY };
    static const ACCESS_MASK desired[] = { READ_CONTROL, WRITE_DAC, MAXIMUM_ALLOWED };
    static const PCSTR token_names[] = { "unrestricted", "restricted", "write-restricted", "restricted with the owner",
                                         "write-restricted with the owner" };
    static const struct
    {
        PCSTR name;
        ACCESS_MASK granted[ARRAYSIZE(token_names)][ARRAYSIZE(desired)];
    } tests[] =
    {
        { "user: all", { { 0x20000, 0x40000, 0x1f01ff }, { 0, 0, 0 }, { 0x20000, 0, 0x1200e9 }, { 0x20000, 0x40000, 0x1f01ff },
                         { 0x20000, 0x40000, 0x1f01ff } } },
        { "empty", { { 0x20000, 0x40000, 0x60000 }, { 0, 0, 0 }, { 0, 0, 0 }, { 0x20000, 0x40000, 0x60000 }, { 0x20000, 0x40000, 0x60000 } } },
        { "owner rights: RC WD", { { 0x20000, 0x40000, 0x60000 }, { 0, 0, 0 }, { 0, 0, 0 }, { 0x20000, 0x40000, 0x60000 },
                                   { 0x20000, 0x40000, 0x60000 } } },
        { "restricting SID: all", { { 0x20000, 0x40000, 0x60000 }, { 0, 0, 0 }, { 0, 0, 0 }, { 0x20000, 0x40000, 0x60000 },
                                    { 0x20000, 0x40000, 0x60000 } } },
        { "user: read", { { 0x20000, 0x40000, 0x160089 }, { 0, 0, 0 }, { 0x20000, 0, 0x120089 }, { 0x20000, 0x40000, 0x160089 },
                          { 0x20000, 0x40000, 0x160089 } } },
    };
    GENERIC_MAPPING mapping = { FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS };
    ULONG_PTR user_buffer[(sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE) / sizeof(ULONG_PTR) + 1];
    ULONG privilege_buffer[64];
    ULONG dacl_buffer[(sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + SECURITY_MAX_SID_SIZE) / sizeof(ULONG) + 1];
    HANDLE process_token, tokens[ARRAYSIZE(token_names)];
    PSID user, service_sid = NULL, ace_sids[ARRAYSIZE(tests)];
    ACCESS_MASK ace_access[ARRAYSIZE(tests)] = { FILE_ALL_ACCESS, 0, READ_CONTROL | WRITE_DAC, FILE_ALL_ACCESS, FILE_GENERIC_READ };
    PACL dacl = (PACL)dacl_buffer;
    SECURITY_DESCRIPTOR sd;
    DWORD size, granted, i, j, k;
    BOOL res, status;

    if (!OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &process_token))
    {
        skip("OpenProcessToken failed: %lu\n", GetLastError());
        return;
    }
    res = GetTokenInformation(process_token, TokenUser, user_buffer, sizeof(user_buffer), &size);
    ok(res, "GetTokenInformation(TokenUser) failed: %lu\n", GetLastError());
    res = res && AllocateAndInitializeSid(&nt_authority, 6, SECURITY_SERVICE_ID_BASE_RID, 1, 2, 3, 4, 5, 0, 0, &service_sid);
    ok(res, "AllocateAndInitializeSid failed: %lu\n", GetLastError());
    if (!res)
    {
        CloseHandle(process_token);
        return;
    }
    user = ((PTOKEN_USER)user_buffer)->User.Sid;

    tokens[0] = create_check_token(process_token, 0, NULL, NULL);
    tokens[1] = create_check_token(process_token, 0, service_sid, NULL);
    tokens[2] = create_check_token(process_token, WRITE_RESTRICTED, service_sid, NULL);
    tokens[3] = create_check_token(process_token, 0, service_sid, user);
    tokens[4] = create_check_token(process_token, WRITE_RESTRICTED, service_sid, user);

    ace_sids[0] = user;
    ace_sids[1] = NULL;
    ace_sids[2] = &owner_rights;
    ace_sids[3] = service_sid;
    ace_sids[4] = user;

    for (i = 0; i < ARRAYSIZE(tests); i++)
    {
        InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
        InitializeAcl(dacl, sizeof(dacl_buffer), ACL_REVISION);
        res = !ace_sids[i] || AddAccessAllowedAce(dacl, ACL_REVISION, ace_access[i], ace_sids[i]);
        ok(res, "DACL %s: AddAccessAllowedAce failed: %lu\n", tests[i].name, GetLastError());
        SetSecurityDescriptorDacl(&sd, TRUE, dacl, FALSE);
        SetSecurityDescriptorOwner(&sd, user, FALSE);
        SetSecurityDescriptorGroup(&sd, user, FALSE);

        for (j = 0; j < ARRAYSIZE(tokens); j++)
        {
            if (!tokens[j])
            {
                skip("the %s token could not be created\n", token_names[j]);
                continue;
            }
            for (k = 0; k < ARRAYSIZE(desired); k++)
            {
                size = sizeof(privilege_buffer);
                granted = 0xdeadbeef;
                status = FALSE;
                res = AccessCheck(&sd, tokens[j], desired[k], &mapping, (PPRIVILEGE_SET)privilege_buffer, &size, &granted, &status);
                ok(res, "DACL %s, %s token, access 0x%lx: AccessCheck failed: %lu\n", tests[i].name, token_names[j], desired[k], GetLastError());
                if (!res)
                    continue;
                ok(status == (tests[i].granted[j][k] != 0), "DACL %s, %s token, access 0x%lx: status %d\n",
                   tests[i].name, token_names[j], desired[k], status);
                if (status)
                {
                    ok(granted == tests[i].granted[j][k], "DACL %s, %s token, access 0x%lx: granted 0x%lx, expected 0x%lx\n",
                       tests[i].name, token_names[j], desired[k], granted, tests[i].granted[j][k]);
                }
            }
        }
    }

    for (j = 0; j < ARRAYSIZE(tokens); j++)
    {
        if (tokens[j])
            CloseHandle(tokens[j]);
    }
    FreeSid(service_sid);
    CloseHandle(process_token);
}

START_TEST(ServiceSidInfo)
{
    SERVICE_SID_INFO info;
    WCHAR name[64], path[MAX_PATH];
    SC_HANDLE scm, service;
    DWORD needed;
    char **argv;
    int argc;
    BOOL res;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 3)
    {
        restricted_service = argc >= 4 && !strcmp(argv[3], "restricted");
        service_process(start_service, argc, argv);
        return;
    }

    test_owner_rights();
    test_runner(test_shared_process, NULL);
    test_runner(test_write_restricted, NULL);

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm)
    {
        skip("OpenSCManagerW failed: %lu\n", GetLastError());
        return;
    }

    GetModuleFileNameW(NULL, path, ARRAYSIZE(path));
    StringCbPrintfW(name, sizeof(name), L"LntSidInfoTest%lu", GetTickCount());
    service = CreateServiceW(scm, name, name, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
                             SERVICE_ERROR_IGNORE, path, NULL, NULL, NULL, NULL, NULL);
    ok(service != NULL, "CreateServiceW failed: %lu\n", GetLastError());
    if (!service)
    {
        CloseServiceHandle(scm);
        return;
    }

    ok(query_sid_type(service) == SERVICE_SID_TYPE_NONE, "default SID type is not NONE\n");

    needed = 0;
    SetLastError(0xdeadbeef);
    res = QueryServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO, NULL, 0, &needed);
    ok(!res && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "size query: %d error %lu\n", res, GetLastError());
    ok(needed == sizeof(SERVICE_SID_INFO), "needed = %lu\n", needed);

    info.dwServiceSidType = SERVICE_SID_TYPE_UNRESTRICTED;
    res = ChangeServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO, &info);
    ok(res, "ChangeServiceConfig2W(UNRESTRICTED) failed: %lu\n", GetLastError());
    ok(query_sid_type(service) == SERVICE_SID_TYPE_UNRESTRICTED, "SID type is not UNRESTRICTED\n");

    info.dwServiceSidType = SERVICE_SID_TYPE_RESTRICTED;
    SetLastError(0xdeadbeef);
    res = ChangeServiceConfig2A(service, SERVICE_CONFIG_SERVICE_SID_INFO, &info);
    ok(res, "ChangeServiceConfig2A(RESTRICTED) failed: %lu\n", GetLastError());
    ok(query_sid_type(service) == SERVICE_SID_TYPE_RESTRICTED, "SID type is not RESTRICTED\n");

    info.dwServiceSidType = 2;
    SetLastError(0xdeadbeef);
    res = ChangeServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO, &info);
    ok(!res && GetLastError() == ERROR_INVALID_PARAMETER, "invalid SID type: %d error %lu\n", res, GetLastError());
    ok(query_sid_type(service) == SERVICE_SID_TYPE_RESTRICTED, "invalid SID type changed the value\n");

    info.dwServiceSidType = SERVICE_SID_TYPE_NONE;
    res = ChangeServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO, &info);
    ok(res, "ChangeServiceConfig2W(NONE) failed: %lu\n", GetLastError());
    ok(query_sid_type(service) == SERVICE_SID_TYPE_NONE, "SID type is not NONE\n");

    DeleteService(service);
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
}
