/*
 * PROJECT:    ReactOS IF Monitor DLL
 * LICENSE:    GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:    NetSh Helper interface context functions
 * COPYRIGHT:  Copyright 2025 Eric Kohl <eric.kohl@reactos.org>
 */

#include "precomp.h"

#include <guiddef.h>

#define NDEBUG
#include <debug.h>

#include "guid.h"
#include "resource.h"

static FN_HANDLE_CMD InterfaceSetInterface;
static FN_HANDLE_CMD InterfaceShowInterface;

static
CMD_ENTRY
InterfaceSetCommands[] =
{
    {L"interface", InterfaceSetInterface, IDS_HLP_INTERFACE_SET_INTERFACE, IDS_HLP_INTERFACE_SET_INTERFACE_EX, 0}
};

static
CMD_ENTRY
InterfaceShowCommands[] = 
{
    {L"interface", InterfaceShowInterface, IDS_HLP_INTERFACE_SHOW_INTERFACE, IDS_HLP_INTERFACE_SHOW_INTERFACE_EX, 0}
};

static
CMD_GROUP_ENTRY
InterfaceGroups[] = 
{
    {L"set", IDS_HLP_INTERFACE_SET, sizeof(InterfaceSetCommands) / sizeof(CMD_ENTRY), 0, InterfaceSetCommands, NULL},
    {L"show", IDS_HLP_INTERFACE_SHOW, sizeof(InterfaceShowCommands) / sizeof(CMD_ENTRY), 0, InterfaceShowCommands, NULL},
};


static
DWORD
InterfaceRenameConnection(
    _In_ PCWSTR pszName,
    _In_ PCWSTR pszNewName)
{
    WCHAR szKeyName[MAX_PATH], szConnection[MAX_PATH], szTarget[MAX_PATH] = L"";
    WCHAR szCurrent[IF_MAX_STRING_SIZE + 1];
    DWORD dwIndex, dwSize, dwError;
    BOOL bInUse = FALSE;
    HKEY hNetworkKey, hKey;

    if ((*pszNewName == UNICODE_NULL) || (wcslen(pszNewName) > IF_MAX_STRING_SIZE))
        return ERROR_INVALID_PARAMETER;

    dwError = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}",
                            0,
                            KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE,
                            &hNetworkKey);
    if (dwError != ERROR_SUCCESS)
        return dwError;

    for (dwIndex = 0; ; dwIndex++)
    {
        dwSize = ARRAYSIZE(szKeyName);
        if (RegEnumKeyExW(hNetworkKey, dwIndex, szKeyName, &dwSize, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;

        if (FAILED(StringCchPrintfW(szConnection, ARRAYSIZE(szConnection), L"%s\\Connection", szKeyName)))
            continue;

        dwSize = sizeof(szCurrent);
        if (RegGetValueW(hNetworkKey, szConnection, L"Name", RRF_RT_REG_SZ, NULL, szCurrent, &dwSize) != ERROR_SUCCESS)
            continue;

        if ((szTarget[0] == UNICODE_NULL) && (_wcsicmp(szCurrent, pszName) == 0))
            StringCchCopyW(szTarget, ARRAYSIZE(szTarget), szConnection);
        else if (_wcsicmp(szCurrent, pszNewName) == 0)
            bInUse = TRUE;
    }

    if (szTarget[0] == UNICODE_NULL)
    {
        PrintMessageFromModule(hDllInstance, IDS_ERROR_INVALID_INTERFACE, pszName);
        dwError = ERROR_SUPPRESS_OUTPUT;
    }
    else if (bInUse)
    {
        dwError = ERROR_ALREADY_EXISTS;
    }
    else
    {
        dwError = RegOpenKeyExW(hNetworkKey, szTarget, 0, KEY_SET_VALUE, &hKey);
        if (dwError == ERROR_SUCCESS)
        {
            dwError = RegSetValueExW(hKey,
                                     L"Name",
                                     0,
                                     REG_SZ,
                                     (const BYTE *)pszNewName,
                                     (DWORD)(wcslen(pszNewName) + 1) * sizeof(WCHAR));
            RegCloseKey(hKey);
        }
    }

    RegCloseKey(hNetworkKey);

    return dwError;
}


static
DWORD
WINAPI
InterfaceSetInterface(
    LPCWSTR pwszMachine,
    LPWSTR *argv,
    DWORD dwCurrentIndex,
    DWORD dwArgCount,
    DWORD dwFlags,
    LPCVOID pvData,
    BOOL *pbDone)
{
    TAG_TYPE pttTags[] = {{L"name", NS_REQ_PRESENT, FALSE},
                          {L"admin", NS_REQ_ZERO, FALSE},
                          {L"connect", NS_REQ_ZERO, FALSE},
                          {L"newname", NS_REQ_ZERO, FALSE}};
    PDWORD pdwTagType;
    PWSTR pszName = NULL, pszNewName = NULL;
    DWORD i, dwError;

    DPRINT("InterfaceSetInterface()\n");

    pdwTagType = HeapAlloc(GetProcessHeap(),
                           0,
                           max(dwArgCount - dwCurrentIndex, 1) * sizeof(DWORD));
    if (pdwTagType == NULL)
        return ERROR_NOT_ENOUGH_MEMORY;

    dwError = MatchTagsInCmdLine(hDllInstance,
                                 argv,
                                 dwCurrentIndex,
                                 dwArgCount,
                                 pttTags,
                                 ARRAYSIZE(pttTags),
                                 pdwTagType);

    for (i = 0; (dwError == ERROR_SUCCESS) && (i < (dwArgCount - dwCurrentIndex)); i++)
    {
        switch (pdwTagType[i])
        {
            case 0:
                pszName = argv[i + dwCurrentIndex];
                break;

            case 1:
            case 2:
                /* TODO: admin= and connect= */
                dwError = ERROR_NOT_SUPPORTED;
                break;

            case 3:
                pszNewName = argv[i + dwCurrentIndex];
                break;

            default:
                dwError = ERROR_SHOW_USAGE;
                break;
        }
    }

    HeapFree(GetProcessHeap(), 0, pdwTagType);

    if (dwError != ERROR_SUCCESS)
        return dwError;

    if ((pszName == NULL) || (pszNewName == NULL))
        return ERROR_SHOW_USAGE;

    return InterfaceRenameConnection(pszName, pszNewName);
}


static
DWORD
WINAPI
InterfaceShowInterface(
    LPCWSTR pwszMachine,
    LPWSTR *argv,
    DWORD dwCurrentIndex,
    DWORD dwArgCount,
    DWORD dwFlags,
    LPCVOID pvData,
    BOOL *pbDone)
{
    PrintMessage(L"InterfaceShowInterface(): Not implemented yet!\n");

    return ERROR_SUCCESS;
}


static
DWORD
WINAPI
InterfaceDumpFn(
    _In_ LPCWSTR pwszRouter,
    _In_ LPWSTR *ppwcArguments,
    _In_ DWORD dwArgCount,
    _In_ LPCVOID pvData)
{
    DPRINT("InterfaceDumpFn(%S %p %lu %p)\n", pwszRouter, ppwcArguments, dwArgCount, pvData);

    PrintMessageFromModule(hDllInstance, IDS_DUMP_HEADERLINE);
    PrintMessage(L"# Interface Configuration\n");
    PrintMessageFromModule(hDllInstance, IDS_DUMP_HEADERLINE);
    PrintMessage(L"pushd interface\n");
    PrintMessageFromModule(hDllInstance, IDS_DUMP_NEWLINE);

    PrintMessageFromModule(hDllInstance, IDS_DUMP_NEWLINE);
    PrintMessage(L"popd\n");
    PrintMessage(L"# End of Interface Configuration\n");
    PrintMessageFromModule(hDllInstance, IDS_DUMP_NEWLINE);

    return ERROR_SUCCESS;
}


DWORD
WINAPI
InterfaceStart(
    _In_ const GUID *pguidParent,
    _In_ DWORD dwVersion)
{
    NS_CONTEXT_ATTRIBUTES ContextAttributes;

    DPRINT("InterfaceStart()\n");

    ZeroMemory(&ContextAttributes, sizeof(ContextAttributes));
    ContextAttributes.dwVersion = 1;
    ContextAttributes.pwszContext = L"interface";
    ContextAttributes.guidHelper = GUID_IFMON_INTERFACE;

    ContextAttributes.ulNumTopCmds = 0;
    ContextAttributes.pTopCmds = NULL;

    ContextAttributes.ulNumGroups = sizeof(InterfaceGroups) / sizeof(CMD_GROUP_ENTRY);
    ContextAttributes.pCmdGroups = InterfaceGroups;

    ContextAttributes.pfnDumpFn = InterfaceDumpFn;

    RegisterContext(&ContextAttributes);

    return ERROR_SUCCESS;
}


DWORD
WINAPI
RegisterInterfaceHelper(VOID)
{
    NS_HELPER_ATTRIBUTES HelperAttributes;

    DPRINT("RegisterInterfaceHelper()\n");

    ZeroMemory(&HelperAttributes, sizeof(HelperAttributes));
    HelperAttributes.dwVersion = 1;
    HelperAttributes.guidHelper = GUID_IFMON_INTERFACE;
    HelperAttributes.pfnStart = InterfaceStart;
    HelperAttributes.pfnStop = NULL;
    RegisterHelper(NULL, &HelperAttributes);

    return ERROR_SUCCESS;
}
