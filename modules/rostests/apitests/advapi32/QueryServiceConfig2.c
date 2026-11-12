/*
 * PROJECT:         ReactOS api tests
 * LICENSE:         GPLv2+ - See COPYING in the top level directory
 * PURPOSE:         Test for QueryServiceConfig2A/W
 * PROGRAMMER:      Hermès BÉLUSCA - MAÏTO
 */

#include "precomp.h"

#define TESTING_SERVICEW     L"Spooler"
#define TESTING_SERVICEA      "Spooler"

/*
 * Taken from base/system/services/config.c and adapted.
 */
static DWORD
RegReadStringW(HKEY   hKey,
               LPWSTR lpValueName,
               LPWSTR *lpValue)
{
    DWORD dwError;
    DWORD dwSize;
    DWORD dwType;

    *lpValue = NULL;

    dwSize  = 0;
    dwError = RegQueryValueExW(hKey,
                               lpValueName,
                               0,
                               &dwType,
                               NULL,
                               &dwSize);
    if (dwError != ERROR_SUCCESS)
        return dwError;

    *lpValue = HeapAlloc(GetProcessHeap(), 0, dwSize);
    if (*lpValue == NULL)
        return ERROR_NOT_ENOUGH_MEMORY;

    dwError = RegQueryValueExW(hKey,
                               lpValueName,
                               0,
                               &dwType,
                               (LPBYTE)*lpValue,
                               &dwSize);
    if (dwError != ERROR_SUCCESS)
    {
        HeapFree(GetProcessHeap(), 0, *lpValue);
        *lpValue = NULL;
    }

    return dwError;
}

static DWORD
RegReadStringA(HKEY  hKey,
               LPSTR lpValueName,
               LPSTR *lpValue)
{
    DWORD dwError;
    DWORD dwSize;
    DWORD dwType;

    *lpValue = NULL;

    dwSize  = 0;
    dwError = RegQueryValueExA(hKey,
                               lpValueName,
                               0,
                               &dwType,
                               NULL,
                               &dwSize);
    if (dwError != ERROR_SUCCESS)
        return dwError;

    *lpValue = HeapAlloc(GetProcessHeap(), 0, dwSize);
    if (*lpValue == NULL)
        return ERROR_NOT_ENOUGH_MEMORY;

    dwError = RegQueryValueExA(hKey,
                               lpValueName,
                               0,
                               &dwType,
                               (LPBYTE)*lpValue,
                               &dwSize);
    if (dwError != ERROR_SUCCESS)
    {
        HeapFree(GetProcessHeap(), 0, *lpValue);
        *lpValue = NULL;
    }

    return dwError;
}


static int QueryConfig2W(SC_HANDLE hService, LPCWSTR serviceName, DWORD dwInfoLevel)
{
    int    iRet  = 0;
    LONG   lRet  = 0;
    DWORD  dwRet = 0;
    BOOL   bError = FALSE;
    DWORD  dwRequiredSize = 0;
    LPBYTE lpBuffer = NULL;

    WCHAR keyName[256];
    HKEY hKey = NULL;
    DWORD dwType = 0;

    /* Get the needed size */
    SetLastError(0xdeadbeef);
    bError = QueryServiceConfig2W(hService,
                                  dwInfoLevel,
                                  NULL,
                                  0,
                                  &dwRequiredSize);
    ok(bError == FALSE && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "(bError, GetLastError()) = (%u, 0x%08lx), expected (FALSE, 0x%08lx)\n", bError, GetLastError(), (DWORD)ERROR_INSUFFICIENT_BUFFER);
    ok(dwRequiredSize != 0, "dwRequiredSize is zero, expected non-zero\n");
    if (dwRequiredSize == 0)
    {
        skip("Required size is null; cannot proceed with QueryConfig2W --> %lu test\n", dwInfoLevel);
        return 1;
    }

    /* Allocate memory */
    lpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwRequiredSize);
    if (lpBuffer == NULL)
    {
        skip("Cannot allocate %lu bytes of memory\n", dwRequiredSize);
        return 2;
    }

    /* Get the actual value */
    SetLastError(0xdeadbeef);
    bError = QueryServiceConfig2W(hService,
                                  dwInfoLevel,
                                  lpBuffer,
                                  dwRequiredSize,
                                  &dwRequiredSize);
    ok(bError, "bError = %u, expected TRUE\n", bError);
    if (bError == FALSE)
    {
        skip("QueryServiceConfig2W returned an error; cannot proceed with QueryConfig2W --> %lu test\n", dwInfoLevel);
        HeapFree(GetProcessHeap(), 0, lpBuffer);
        return 3;
    }

    /* Now we can compare the retrieved value with what it's actually stored in the registry */
    StringCbPrintfW(keyName, sizeof(keyName), L"System\\CurrentControlSet\\Services\\%s", serviceName);
    SetLastError(0xdeadbeef);
    lRet = RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyName, 0, KEY_QUERY_VALUE, &hKey);
    ok(lRet == ERROR_SUCCESS, "RegOpenKeyExW failed with 0x%08lx\n", lRet);
    if (lRet != ERROR_SUCCESS)
    {
        skip("No regkey; cannot proceed with QueryConfig2W --> %lu test\n", dwInfoLevel);
        HeapFree(GetProcessHeap(), 0, lpBuffer);
        return 4;
    }

    switch (dwInfoLevel)
    {
        case SERVICE_CONFIG_DESCRIPTION:
        {
            LPSERVICE_DESCRIPTIONW lpDescription = (LPSERVICE_DESCRIPTIONW)lpBuffer;
            LPWSTR lpszDescription = NULL;

            /* Retrieve the description via the registry */
            dwRet = RegReadStringW(hKey, L"Description", &lpszDescription);
            ok(dwRet == ERROR_SUCCESS, "RegReadStringW returned 0x%08lx\n", dwRet);
            ok(lpszDescription != NULL, "lpszDescription is null, expected non-null\n");

            /* Compare it with the description retrieved via QueryServiceConfig2 */
            if (lpszDescription)
                iRet = wcscmp(lpDescription->lpDescription, lpszDescription);
            else
                iRet = 0;

            ok(iRet == 0, "Retrieved descriptions are different !\n");


            /* Memory cleanup */
            HeapFree(GetProcessHeap(), 0, lpszDescription);

            break;
        }

        case SERVICE_CONFIG_FAILURE_ACTIONS:
        {
            LPSERVICE_FAILURE_ACTIONSW lpFailureActions1 = (LPSERVICE_FAILURE_ACTIONSW)lpBuffer;
            LPSERVICE_FAILURE_ACTIONSW lpFailureActions2 = NULL;
            LPWSTR lpRebootMessage  = NULL;
            LPWSTR lpFailureCommand = NULL;
            DWORD  i = 0;

            /* Retrieve the failure actions via the registry */
            lRet = RegQueryValueExW(hKey,
                                    L"FailureActions",
                                    NULL,
                                    &dwType,
                                    NULL,
                                    &dwRequiredSize);
            ok(lRet == ERROR_SUCCESS, "RegQueryValueExW returned 0x%08lx\n", lRet);
            ok(dwType == REG_BINARY, "dwType = %lu, expected REG_BINARY\n", dwType);
            ok(dwRequiredSize != 0, "dwRequiredSize is zero, expected non-zero\n");

            lpFailureActions2 = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwRequiredSize);
            if (lpFailureActions2 == NULL)
            {
                skip("Cannot allocate %lu bytes of memory\n", dwRequiredSize);
                break;
            }

            lRet = RegQueryValueExW(hKey,
                                    L"FailureActions",
                                    NULL,
                                    NULL,
                                    (LPBYTE)lpFailureActions2,
                                    &dwRequiredSize);
            ok(lRet == ERROR_SUCCESS, "RegQueryValueExW returned 0x%08lx\n", lRet);
            ok(dwRequiredSize != 0, "dwRequiredSize is zero, expected non-zero\n");

            /* Get the strings */
            RegReadStringW(hKey, L"FailureCommand", &lpFailureCommand);
            RegReadStringW(hKey, L"RebootMessage" , &lpRebootMessage );

            /* Check the values */
            ok(lpFailureActions1->dwResetPeriod == lpFailureActions2->dwResetPeriod, "lpFailureActions1->dwResetPeriod != lpFailureActions2->dwResetPeriod\n");
#ifndef _WIN64 // Fails on Win 2003 x64
            ok(lpFailureActions1->cActions == lpFailureActions2->cActions, "lpFailureActions1->cActions != lpFailureActions2->cActions\n");
#endif
            /* Compare the actions */
            if (lpFailureActions1->cActions == lpFailureActions2->cActions)
            {
                lpFailureActions2->lpsaActions = (lpFailureActions2->cActions > 0 ? (LPSC_ACTION)(lpFailureActions2 + 1) : NULL);

                if (lpFailureActions1->cActions > 0 &&
                    lpFailureActions1->lpsaActions != NULL)
                {
                    for (i = 0; i < lpFailureActions1->cActions; ++i)
                    {
                        ok(lpFailureActions1->lpsaActions[i].Type  == lpFailureActions2->lpsaActions[i].Type , "lpFailureActions1->lpsaActions[%lu].Type  != lpFailureActions2->lpsaActions[%lu].Type\n" , i, i);
                        ok(lpFailureActions1->lpsaActions[i].Delay == lpFailureActions2->lpsaActions[i].Delay, "lpFailureActions1->lpsaActions[%lu].Delay != lpFailureActions2->lpsaActions[%lu].Delay\n", i, i);
                    }
                }
            }

            /* TODO: retrieve the strings if they are in MUI format */

            /* Compare RebootMsg */
            if (lpFailureActions1->lpRebootMsg && lpRebootMessage)
                iRet = wcscmp(lpFailureActions1->lpRebootMsg, lpRebootMessage);
            else
                iRet = 0;

            ok(iRet == 0, "Retrieved reboot messages are different !\n");

            /* Compare Command */
            if (lpFailureActions1->lpCommand && lpFailureCommand)
                iRet = wcscmp(lpFailureActions1->lpCommand, lpFailureCommand);
            else
                iRet = 0;

            ok(iRet == 0, "Retrieved commands are different !\n");


            /* Memory cleanup */
            if (lpRebootMessage)
                HeapFree(GetProcessHeap(), 0, lpRebootMessage);

            if (lpFailureCommand)
                HeapFree(GetProcessHeap(), 0, lpFailureCommand);

            HeapFree(GetProcessHeap(), 0, lpFailureActions2);

            break;
        }

        default:
            skip("Unknown dwInfoLevel %lu, cannot proceed with QueryConfig2W --> %lu test\n", dwInfoLevel, dwInfoLevel);
            break;
    }

    RegCloseKey(hKey);

    HeapFree(GetProcessHeap(), 0, lpBuffer);

    return 0;
}

static int QueryConfig2A(SC_HANDLE hService, LPCSTR serviceName, DWORD dwInfoLevel)
{
    int    iRet  = 0;
    LONG   lRet  = 0;
    DWORD  dwRet = 0;
    BOOL   bError = FALSE;
    DWORD  dwRequiredSize = 0;
    LPBYTE lpBuffer = NULL;

    CHAR keyName[256];
    HKEY hKey = NULL;
    DWORD dwType = 0;

    /* Get the needed size */
    SetLastError(0xdeadbeef);
    bError = QueryServiceConfig2A(hService,
                                  dwInfoLevel,
                                  NULL,
                                  0,
                                  &dwRequiredSize);
    ok(bError == FALSE && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "(bError, GetLastError()) = (%u, 0x%08lx), expected (FALSE, 0x%08lx)\n", bError, GetLastError(), (DWORD)ERROR_INSUFFICIENT_BUFFER);
    ok(dwRequiredSize != 0, "dwRequiredSize is zero, expected non-zero\n");
    if (dwRequiredSize == 0)
    {
        skip("Required size is null; cannot proceed with QueryConfig2A --> %lu test\n", dwInfoLevel);
        return 1;
    }

    /* Allocate memory */
    lpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwRequiredSize);
    if (lpBuffer == NULL)
    {
        skip("Cannot allocate %lu bytes of memory\n", dwRequiredSize);
        return 2;
    }

    /* Get the actual value */
    SetLastError(0xdeadbeef);
    bError = QueryServiceConfig2A(hService,
                                  dwInfoLevel,
                                  lpBuffer,
                                  dwRequiredSize,
                                  &dwRequiredSize);
    ok(bError, "bError = %u, expected TRUE\n", bError);
    if (bError == FALSE)
    {
        skip("QueryServiceConfig2A returned an error; cannot proceed with QueryConfig2A --> %lu test\n", dwInfoLevel);
        HeapFree(GetProcessHeap(), 0, lpBuffer);
        return 3;
    }

    /* Now we can compare the retrieved value with what it's actually stored in the registry */
    StringCbPrintfA(keyName, sizeof(keyName), "System\\CurrentControlSet\\Services\\%s", serviceName);
    SetLastError(0xdeadbeef);
    lRet = RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyName, 0, KEY_QUERY_VALUE, &hKey);
    ok(lRet == ERROR_SUCCESS, "RegOpenKeyExA failed with 0x%08lx\n", lRet);
    if (lRet != ERROR_SUCCESS)
    {
        skip("No regkey; cannot proceed with QueryConfig2A --> %lu test\n", dwInfoLevel);
        HeapFree(GetProcessHeap(), 0, lpBuffer);
        return 4;
    }

    switch (dwInfoLevel)
    {
        case SERVICE_CONFIG_DESCRIPTION:
        {
            LPSERVICE_DESCRIPTIONA lpDescription = (LPSERVICE_DESCRIPTIONA)lpBuffer;
            LPSTR lpszDescription = NULL;

            /* Retrieve the description via the registry */
            dwRet = RegReadStringA(hKey, "Description", &lpszDescription);
            ok(dwRet == ERROR_SUCCESS, "RegReadStringA returned 0x%08lx\n", dwRet);
            ok(lpszDescription != NULL, "lpszDescription is null, expected non-null\n");

            /* Compare it with the description retrieved via QueryServiceConfig2 */
            if (lpszDescription)
                iRet = strcmp(lpDescription->lpDescription, lpszDescription);
            else
                iRet = 0;

            ok(iRet == 0, "Retrieved descriptions are different !\n");


            /* Memory cleanup */
            HeapFree(GetProcessHeap(), 0, lpszDescription);

            break;
        }

        case SERVICE_CONFIG_FAILURE_ACTIONS:
        {
            LPSERVICE_FAILURE_ACTIONSA lpFailureActions1 = (LPSERVICE_FAILURE_ACTIONSA)lpBuffer;
            LPSERVICE_FAILURE_ACTIONSA lpFailureActions2 = NULL;
            LPSTR lpRebootMessage  = NULL;
            LPSTR lpFailureCommand = NULL;
            DWORD i = 0;

            /* Retrieve the failure actions via the registry */
            lRet = RegQueryValueExA(hKey,
                                    "FailureActions",
                                    NULL,
                                    &dwType,
                                    NULL,
                                    &dwRequiredSize);
            ok(lRet == ERROR_SUCCESS, "RegQueryValueExA returned 0x%08lx\n", lRet);
            ok(dwType == REG_BINARY, "dwType = %lu, expected REG_BINARY\n", dwType);
            ok(dwRequiredSize != 0, "dwRequiredSize is zero, expected non-zero\n");

            lpFailureActions2 = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwRequiredSize);
            if (lpFailureActions2 == NULL)
            {
                skip("Cannot allocate %lu bytes of memory\n", dwRequiredSize);
                break;
            }

            lRet = RegQueryValueExA(hKey,
                                    "FailureActions",
                                    NULL,
                                    NULL,
                                    (LPBYTE)lpFailureActions2,
                                    &dwRequiredSize);
            ok(lRet == ERROR_SUCCESS, "RegQueryValueExA returned 0x%08lx\n", lRet);
            ok(dwRequiredSize != 0, "dwRequiredSize is zero, expected non-zero\n");

            /* Get the strings */
            RegReadStringA(hKey, "FailureCommand", &lpFailureCommand);
            RegReadStringA(hKey, "RebootMessage" , &lpRebootMessage );

            /* Check the values */
            ok(lpFailureActions1->dwResetPeriod == lpFailureActions2->dwResetPeriod, "lpFailureActions1->dwResetPeriod != lpFailureActions2->dwResetPeriod\n");
#ifndef _WIN64 // Fails on Win 2003 x64
            ok(lpFailureActions1->cActions == lpFailureActions2->cActions, "lpFailureActions1->cActions != lpFailureActions2->cActions\n");
#endif

            /* Compare the actions */
            if (lpFailureActions1->cActions == lpFailureActions2->cActions)
            {
                lpFailureActions2->lpsaActions = (lpFailureActions2->cActions > 0 ? (LPSC_ACTION)(lpFailureActions2 + 1) : NULL);

                if (lpFailureActions1->cActions > 0 &&
                    lpFailureActions1->lpsaActions != NULL)
                {
                    for (i = 0; i < lpFailureActions1->cActions; ++i)
                    {
                        ok(lpFailureActions1->lpsaActions[i].Type  == lpFailureActions2->lpsaActions[i].Type , "lpFailureActions1->lpsaActions[%lu].Type  != lpFailureActions2->lpsaActions[%lu].Type\n" , i, i);
                        ok(lpFailureActions1->lpsaActions[i].Delay == lpFailureActions2->lpsaActions[i].Delay, "lpFailureActions1->lpsaActions[%lu].Delay != lpFailureActions2->lpsaActions[%lu].Delay\n", i, i);
                    }
                }
            }

            /* TODO: retrieve the strings if they are in MUI format */

            /* Compare RebootMsg */
            if (lpFailureActions1->lpRebootMsg && lpRebootMessage)
                iRet = strcmp(lpFailureActions1->lpRebootMsg, lpRebootMessage);
            else
                iRet = 0;

            ok(iRet == 0, "Retrieved reboot messages are different !\n");

            /* Compare Command */
            if (lpFailureActions1->lpCommand && lpFailureCommand)
                iRet = strcmp(lpFailureActions1->lpCommand, lpFailureCommand);
            else
                iRet = 0;

            ok(iRet == 0, "Retrieved commands are different !\n");


            /* Memory cleanup */
            if (lpRebootMessage)
                HeapFree(GetProcessHeap(), 0, lpRebootMessage);

            if (lpFailureCommand)
                HeapFree(GetProcessHeap(), 0, lpFailureCommand);

            HeapFree(GetProcessHeap(), 0, lpFailureActions2);

            break;
        }

        default:
            skip("Unknown dwInfoLevel %lu, cannot proceed with QueryConfig2A --> %lu test\n", dwInfoLevel, dwInfoLevel);
            break;
    }

    RegCloseKey(hKey);

    HeapFree(GetProcessHeap(), 0, lpBuffer);

    return 0;
}


static void Test_QueryServiceConfig2W(void)
{
    SC_HANDLE hScm     = NULL;
    SC_HANDLE hService = NULL;

    SetLastError(0xdeadbeef);
    hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    ok(hScm != NULL, "Failed to open service manager, error=0x%08lx\n", GetLastError());
    if (!hScm)
    {
        skip("No service control manager; cannot proceed with QueryServiceConfig2W test\n");
        goto cleanup;
    }

    ok_err(ERROR_SUCCESS);

    SetLastError(0xdeadbeef);
    hService = OpenServiceW(hScm, TESTING_SERVICEW, SERVICE_QUERY_CONFIG);
    ok(hService != NULL, "Failed to open service handle, error=0x%08lx\n", GetLastError());
    if (!hService)
    {
        skip("Service not found; cannot proceed with QueryServiceConfig2W test\n");
        goto cleanup;
    }

    ok_err(ERROR_SUCCESS);

    if (QueryConfig2W(hService, TESTING_SERVICEW, SERVICE_CONFIG_DESCRIPTION) != 0)
        goto cleanup;

    if (QueryConfig2W(hService, TESTING_SERVICEW, SERVICE_CONFIG_FAILURE_ACTIONS) != 0)
        goto cleanup;

cleanup:
    if (hService)
        CloseServiceHandle(hService);

    if (hScm)
        CloseServiceHandle(hScm);
}

static void Test_QueryServiceConfig2A(void)
{
    SC_HANDLE hScm     = NULL;
    SC_HANDLE hService = NULL;

    SetLastError(0xdeadbeef);
    hScm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    ok(hScm != NULL, "Failed to open service manager, error=0x%08lx\n", GetLastError());
    if (!hScm)
    {
        skip("No service control manager; cannot proceed with QueryServiceConfig2A test\n");
        goto cleanup;
    }

    ok_err(ERROR_SUCCESS);

    SetLastError(0xdeadbeef);
    hService = OpenServiceA(hScm, TESTING_SERVICEA, SERVICE_QUERY_CONFIG);
    ok(hService != NULL, "Failed to open service handle, error=0x%08lx\n", GetLastError());
    if (!hService)
    {
        skip("Service not found; cannot proceed with QueryServiceConfig2A test\n");
        goto cleanup;
    }

    ok_err(ERROR_SUCCESS);

    if (QueryConfig2A(hService, TESTING_SERVICEA, SERVICE_CONFIG_DESCRIPTION) != 0)
        goto cleanup;

    if (QueryConfig2A(hService, TESTING_SERVICEA, SERVICE_CONFIG_FAILURE_ACTIONS) != 0)
        goto cleanup;

cleanup:
    if (hService)
        CloseServiceHandle(hService);

    if (hScm)
        CloseServiceHandle(hScm);
}

#define PRESHUTDOWN_SERVICE L"ApitestPreshutdown"
#define PRESHUTDOWN_ABSENT  0xdeadbeef

static void CheckPreshutdownTimeout(SC_HANDLE hService, HKEY hKey, DWORD dwExpected, DWORD dwExpectedStored)
{
    SERVICE_PRESHUTDOWN_INFO Info = { 0xdeadbeef };
    DWORD dwNeeded = 0xdeadbeef, dwStored = PRESHUTDOWN_ABSENT, dwSize = sizeof(dwStored), dwType = REG_NONE;
    BOOL bRet;
    LONG lRet;

    bRet = QueryServiceConfig2W(hService, SERVICE_CONFIG_PRESHUTDOWN_INFO, (LPBYTE)&Info, sizeof(Info), &dwNeeded);
    ok(bRet, "QueryServiceConfig2W failed, error=0x%08lx\n", GetLastError());
    ok(dwNeeded == sizeof(Info), "dwNeeded = %lu\n", dwNeeded);
    ok(Info.dwPreshutdownTimeout == dwExpected, "dwPreshutdownTimeout = %lu, expected %lu\n", Info.dwPreshutdownTimeout, dwExpected);

    lRet = RegQueryValueExW(hKey, L"PreshutdownTimeout", NULL, &dwType, (LPBYTE)&dwStored, &dwSize);
    if (dwExpectedStored == PRESHUTDOWN_ABSENT)
    {
        ok(lRet == ERROR_FILE_NOT_FOUND, "RegQueryValueExW returned %ld\n", lRet);
    }
    else
    {
        ok(lRet == ERROR_SUCCESS && dwType == REG_DWORD, "RegQueryValueExW returned %ld, type %lu\n", lRet, dwType);
        ok(dwStored == dwExpectedStored, "PreshutdownTimeout = %lu, expected %lu\n", dwStored, dwExpectedStored);
    }
}

static void Test_PreshutdownTimeout(void)
{
    static const DWORD Timeouts[] = { 0, 5000, 0xffffffff };
    SERVICE_PRESHUTDOWN_INFO Info;
    SC_HANDLE hScm, hService;
    HKEY hKey = NULL;
    BOOL bRet;
    LONG lRet;
    ULONG i;

    hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hScm)
    {
        skip("Cannot create services, error=0x%08lx\n", GetLastError());
        return;
    }

    hService = CreateServiceW(hScm, PRESHUTDOWN_SERVICE, PRESHUTDOWN_SERVICE, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                              SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, L"cmd.exe", NULL, NULL, NULL, NULL, NULL);
    ok(hService != NULL, "CreateServiceW failed, error=0x%08lx\n", GetLastError());
    if (!hService)
    {
        CloseServiceHandle(hScm);
        return;
    }

    lRet = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\" PRESHUTDOWN_SERVICE, 0,
                         KEY_QUERY_VALUE | KEY_SET_VALUE, &hKey);
    ok(lRet == ERROR_SUCCESS, "RegOpenKeyExW returned %ld\n", lRet);
    if (lRet != ERROR_SUCCESS)
        goto cleanup;

    CheckPreshutdownTimeout(hService, hKey, 10000, PRESHUTDOWN_ABSENT);

    for (i = 0; i < _countof(Timeouts); i++)
    {
        Info.dwPreshutdownTimeout = Timeouts[i];
        bRet = ChangeServiceConfig2W(hService, SERVICE_CONFIG_PRESHUTDOWN_INFO, &Info);
        ok(bRet, "ChangeServiceConfig2W(%lu) failed, error=0x%08lx\n", Timeouts[i], GetLastError());
        CheckPreshutdownTimeout(hService, hKey, Timeouts[i], Timeouts[i]);
    }

    lRet = RegDeleteValueW(hKey, L"PreshutdownTimeout");
    ok(lRet == ERROR_SUCCESS, "RegDeleteValueW returned %ld\n", lRet);
    CheckPreshutdownTimeout(hService, hKey, 10000, PRESHUTDOWN_ABSENT);

cleanup:
    if (hKey)
        RegCloseKey(hKey);
    ok(DeleteService(hService), "DeleteService failed, error=0x%08lx\n", GetLastError());
    CloseServiceHandle(hService);
    CloseServiceHandle(hScm);
}


START_TEST(QueryServiceConfig2)
{
    Test_QueryServiceConfig2W();
    Test_QueryServiceConfig2A();
    Test_PreshutdownTimeout();
}
