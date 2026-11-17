/*
 * PROJECT:     LiberNT api tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Test for the Network Store Interface Service and services that depend on it
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include "precomp.h"

#include "svchlp.h"

/*** Service part of the test ***/

static SERVICE_STATUS_HANDLE status_handle;

static void
report_service_status(DWORD dwCurrentState)
{
    SERVICE_STATUS status = { 0 };

    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = dwCurrentState;
    service_ok(SetServiceStatus(status_handle, &status), "SetServiceStatus failed: %lu\n", GetLastError());
}

static VOID WINAPI
service_handler(DWORD ctrl)
{
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN)
        report_service_status(SERVICE_STOPPED);
}

static VOID WINAPI
service_main(DWORD dwArgc, LPWSTR *lpszArgv)
{
    UNREFERENCED_PARAMETER(dwArgc);

    status_handle = RegisterServiceCtrlHandlerW(lpszArgv[0], service_handler);
    service_ok(status_handle != NULL, "RegisterServiceCtrlHandlerW failed: %lu\n", GetLastError());
    if (status_handle == NULL)
        return;

    report_service_status(SERVICE_RUNNING);
    report_service_status(SERVICE_STOPPED);
}

static BOOL
start_service(PCSTR service_nameA, PCWSTR service_nameW)
{
    BOOL res;
    SERVICE_TABLE_ENTRYW servtbl[] =
    {
        { (PWSTR)service_nameW, service_main },
        { NULL, NULL }
    };

    UNREFERENCED_PARAMETER(service_nameA);

    res = StartServiceCtrlDispatcherW(servtbl);
    service_ok(res, "StartServiceCtrlDispatcherW failed: %lu\n", GetLastError());
    return res;
}

/*** Tester part of the test ***/

static void
test_nsi_service(SC_HANDLE hSC)
{
    SC_HANDLE hNsi;
    SERVICE_STATUS status;
    union
    {
        QUERY_SERVICE_CONFIGW Config;
        BYTE Buffer[8192];
    } u;
    DWORD needed;
    BOOL res;

    hNsi = OpenServiceW(hSC, L"Nsi", SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
    ok(hNsi != NULL, "OpenServiceW(Nsi) failed: %lu\n", GetLastError());
    if (hNsi == NULL)
        return;

    res = QueryServiceConfigW(hNsi, &u.Config, sizeof(u), &needed);
    ok(res, "QueryServiceConfigW failed: %lu\n", GetLastError());
    if (res)
    {
        ok(u.Config.dwServiceType == SERVICE_WIN32_SHARE_PROCESS, "dwServiceType = 0x%lx\n", u.Config.dwServiceType);
        ok(u.Config.dwStartType == SERVICE_AUTO_START, "dwStartType = %lu\n", u.Config.dwStartType);
        ok(u.Config.lpServiceStartName != NULL && _wcsicmp(u.Config.lpServiceStartName, L"NT AUTHORITY\\LocalService") == 0,
           "lpServiceStartName = %ls\n", u.Config.lpServiceStartName ? u.Config.lpServiceStartName : L"(null)");
    }

    res = QueryServiceStatus(hNsi, &status);
    ok(res, "QueryServiceStatus failed: %lu\n", GetLastError());
    ok(status.dwCurrentState == SERVICE_RUNNING, "Nsi is in state %lu\n", status.dwCurrentState);

    CloseServiceHandle(hNsi);
}

static void
my_test_server(PCSTR service_nameA, PCWSTR service_nameW, void *param)
{
    static const WCHAR Dependencies[] = L"Nsi\0TcpIp\0";
    SC_HANDLE hSC, hService;
    SERVICE_STATUS status;
    BOOL res;

    UNREFERENCED_PARAMETER(service_nameA);
    UNREFERENCED_PARAMETER(param);

    hSC = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSC == NULL)
    {
        skip("OpenSCManagerW failed with error %lu!\n", GetLastError());
        return;
    }

    test_nsi_service(hSC);

    /* The dependencies a WireGuard tunnel service is created with */
    hService = register_service_exW(hSC, L"NsiService", service_nameW, NULL, SERVICE_ALL_ACCESS,
                                    SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
                                    NULL, NULL, Dependencies, NULL, NULL);
    if (hService == NULL)
    {
        CloseServiceHandle(hSC);
        return;
    }

    res = StartServiceW(hService, 0, NULL);
    ok(res, "StartServiceW of a service that depends on Nsi failed: %lu\n", GetLastError());
    if (res)
    {
        do
        {
            Sleep(100);
            res = QueryServiceStatus(hService, &status);
        } while (res && status.dwCurrentState != SERVICE_STOPPED);
        ok(res, "QueryServiceStatus failed: %lu\n", GetLastError());
        ok(status.dwWin32ExitCode == NO_ERROR, "dwWin32ExitCode = %lu\n", status.dwWin32ExitCode);
    }

    ok(DeleteService(hService), "DeleteService failed: %lu\n", GetLastError());
    CloseServiceHandle(hService);
    CloseServiceHandle(hSC);
}

START_TEST(NsiService)
{
    int argc;
    char **argv;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 3)
    {
        service_process(start_service, argc, argv);
        return;
    }

    test_runner(my_test_server, NULL);
}
