/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     SERVICE_CONFIG_SERVICE_SID_INFO through ChangeServiceConfig2 and QueryServiceConfig2
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include "precomp.h"

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

START_TEST(ServiceSidInfo)
{
    SERVICE_SID_INFO info;
    WCHAR name[64], path[MAX_PATH];
    SC_HANDLE scm, service;
    DWORD needed;
    BOOL res;

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
