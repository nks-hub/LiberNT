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

static VOID WINAPI service_handler(DWORD ctrl)
{
    UNREFERENCED_PARAMETER(ctrl);
}

static void WINAPI restricted_main(DWORD argc, LPWSTR *argv)
{
    static SID world = { SID_REVISION, 1, { SECURITY_WORLD_SID_AUTHORITY }, { SECURITY_WORLD_RID } };
    static SID write_restricted = { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { SECURITY_WRITE_RESTRICTED_CODE_RID } };
    SERVICE_STATUS status = { SERVICE_WIN32_OWN_PROCESS, SERVICE_RUNNING };
    PTOKEN_GROUPS groups = NULL;
    WCHAR key_path[150];
    HANDLE token;
    DWORD size = 0;
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
    if (groups)
    {
        service_trace("the process token has %lu restricted SIDs\n", groups->GroupCount);
        service_ok(token_has_service_sid(groups, argv[0]), "the restricted SIDs lack the service SID\n");
        service_ok(token_has_sid(groups, &world), "the restricted SIDs lack Everyone\n");
        service_ok(token_has_sid(groups, &write_restricted), "the restricted SIDs lack S-1-5-33\n");
        HeapFree(GetProcessHeap(), 0, groups);
    }

    StringCbPrintfW(key_path, sizeof(key_path), L"SOFTWARE\\%ls", argv[0]);
    error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, key_path, 0, KEY_READ, &key);
    service_ok(error == ERROR_SUCCESS, "reading a key that grants access to LocalSystem only failed: %ld\n", error);
    if (error == ERROR_SUCCESS)
        RegCloseKey(key);
    error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, key_path, 0, KEY_SET_VALUE, &key);
    service_ok(error == ERROR_ACCESS_DENIED, "writing a key that grants access to LocalSystem only: %ld\n", error);
    if (error == ERROR_SUCCESS)
        RegCloseKey(key);

    status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(status_handle, &status);
}

static void WINAPI service_main(DWORD argc, LPWSTR *argv)
{
    SERVICE_STATUS status = { SERVICE_WIN32_SHARE_PROCESS, SERVICE_RUNNING };
    PTOKEN_GROUPS groups = NULL;
    WCHAR peer[100];
    HANDLE token;
    DWORD size = 0;

    UNREFERENCED_PARAMETER(argc);

    status_handle = RegisterServiceCtrlHandlerW(argv[0], service_handler);
    service_ok(status_handle != NULL, "RegisterServiceCtrlHandlerW failed: %lu\n", GetLastError());
    if (!status_handle)
        return;
    SetServiceStatus(status_handle, &status);

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
    service_ok(groups != NULL, "the groups of the process token cannot be read: %lu\n", GetLastError());
    if (groups)
    {
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
