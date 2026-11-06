/*
 * PROJECT:     LiberNT Network Connection Interface
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Names of network connections
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include <windows.h>
#include <strsafe.h>

/* The name of a connection is the Connection\Name value of its adapter, which
 * the network folder and the NSI interface alias read as well */
#define NETWORK_CLASS_KEY L"SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define MAX_CONNECTION_NAME 256

static BOOL
FormatGuid(_In_ const GUID *Guid, _Out_writes_(39) PWSTR Text)
{
    return SUCCEEDED(StringCchPrintfW(Text, 39, L"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                                      Guid->Data1, Guid->Data2, Guid->Data3,
                                      Guid->Data4[0], Guid->Data4[1], Guid->Data4[2], Guid->Data4[3],
                                      Guid->Data4[4], Guid->Data4[5], Guid->Data4[6], Guid->Data4[7]));
}

/* TRUE when a connection other than Self already uses Name */
static BOOL
NameIsTaken(_In_ HKEY Network, _In_ PCWSTR Self, _In_ PCWSTR Name)
{
    WCHAR Connection[64], Existing[MAX_CONNECTION_NAME];
    DWORD Index, Length, Size;

    for (Index = 0; ; Index++)
    {
        Length = ARRAYSIZE(Connection);
        if (RegEnumKeyExW(Network, Index, Connection, &Length, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            return FALSE;
        if (!_wcsicmp(Connection, Self))
            continue;
        if (FAILED(StringCchCatW(Connection, ARRAYSIZE(Connection), L"\\Connection")))
            continue;
        Size = sizeof(Existing);
        if (RegGetValueW(Network, Connection, L"Name", RRF_RT_REG_SZ, NULL, Existing, &Size) == ERROR_SUCCESS &&
            !_wcsicmp(Existing, Name))
        {
            return TRUE;
        }
    }
}

DWORD
WINAPI
NciSetConnectionName(
    _In_ const GUID *Guid,
    _In_z_ LPCWSTR NewName)
{
    WCHAR Id[39], Path[64];
    HKEY Network, Connection;
    size_t Length;
    LSTATUS Error;

    if (Guid == NULL || NewName == NULL ||
        FAILED(StringCchLengthW(NewName, MAX_CONNECTION_NAME, &Length)) || Length == 0)
    {
        return ERROR_INVALID_PARAMETER;
    }
    if (!FormatGuid(Guid, Id) || FAILED(StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\Connection", Id)))
        return ERROR_INVALID_PARAMETER;

    Error = RegCreateKeyExW(HKEY_LOCAL_MACHINE, NETWORK_CLASS_KEY, 0, NULL, 0,
                            KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_CREATE_SUB_KEY, NULL, &Network, NULL);
    if (Error != ERROR_SUCCESS)
        return Error;

    if (NameIsTaken(Network, Id, NewName))
    {
        RegCloseKey(Network);
        return ERROR_DUP_NAME;
    }

    Error = RegCreateKeyExW(Network, Path, 0, NULL, 0, KEY_SET_VALUE, NULL, &Connection, NULL);
    if (Error == ERROR_SUCCESS)
    {
        Error = RegSetValueExW(Connection, L"Name", 0, REG_SZ, (const BYTE *)NewName,
                               (DWORD)((Length + 1) * sizeof(WCHAR)));
        RegCloseKey(Connection);
    }
    RegCloseKey(Network);
    return Error;
}

DWORD
WINAPI
NciGetConnectionName(
    _In_ const GUID *Guid,
    _Out_writes_bytes_opt_(InDestNameBytes) LPWSTR Name,
    _In_ DWORD InDestNameBytes,
    _Out_opt_ DWORD *OutDestNameBytes)
{
    WCHAR Id[39], Path[ARRAYSIZE(NETWORK_CLASS_KEY) + 64];
    DWORD Size = InDestNameBytes;
    LSTATUS Error;

    if (OutDestNameBytes)
        *OutDestNameBytes = 0;
    if (Guid == NULL || (Name == NULL && InDestNameBytes != 0) || !FormatGuid(Guid, Id) ||
        FAILED(StringCchPrintfW(Path, ARRAYSIZE(Path), NETWORK_CLASS_KEY L"\\%s\\Connection", Id)))
    {
        return ERROR_INVALID_PARAMETER;
    }

    Error = RegGetValueW(HKEY_LOCAL_MACHINE, Path, L"Name", RRF_RT_REG_SZ, NULL, Name, &Size);
    if (Error == ERROR_SUCCESS || Error == ERROR_MORE_DATA)
    {
        if (OutDestNameBytes)
            *OutDestNameBytes = Size;
        if (Name == NULL && Error == ERROR_SUCCESS)
            Error = ERROR_MORE_DATA;
    }
    return Error;
}
