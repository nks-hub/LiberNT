/*
 * PROJECT:     LiberNT kernel-mode tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Kernel-mode IP Helper routines of netio.sys, user-mode part
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include <kmt_test.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include "netio_iphlp.h"

#define GUID_TEXT_LENGTH 38

static
BOOL
EndsWithGuid(
    _In_ PCWSTR Text,
    _In_ PCWSTR Guid)
{
    size_t Length = wcslen(Text);

    return Length >= GUID_TEXT_LENGTH && !_wcsicmp(Text + Length - GUID_TEXT_LENGTH, Guid);
}

START_TEST(NetioIpHlp)
{
    PMIB_IF_TABLE2 Table = NULL;
    MIB_IF_ROW2 Kernel, User;
    WCHAR Guid[GUID_TEXT_LENGTH + 1];
    const GUID *Id;
    DWORD Error, Length;
    ULONG i, Tested = 0;

    Error = GetIfTable2(&Table);
    ok_eq_ulong(Error, (DWORD)NO_ERROR);
    if (Error || Table == NULL)
        return;

    Error = KmtLoadAndOpenDriver(L"NetioIpHlp", TRUE);
    ok_eq_ulong(Error, (DWORD)ERROR_SUCCESS);
    if (Error)
    {
        FreeMibTable(Table);
        return;
    }

    for (i = 0; i < Table->NumEntries; i++)
    {
        if (Table->Table[i].Type == IF_TYPE_SOFTWARE_LOOPBACK)
            continue;

        RtlZeroMemory(&User, sizeof(User));
        User.InterfaceLuid = Table->Table[i].InterfaceLuid;
        Error = GetIfEntry2(&User);
        ok_eq_ulong(Error, (DWORD)NO_ERROR);
        if (Error)
            continue;

        RtlZeroMemory(&Kernel, sizeof(Kernel));
        Kernel.InterfaceLuid = User.InterfaceLuid;
        Length = sizeof(Kernel);
        Error = KmtSendBufferToDriver(IOCTL_NETIOIPHLP_GET_IF_ENTRY2, &Kernel, sizeof(Kernel), &Length);
        ok_eq_ulong(Error, (DWORD)ERROR_SUCCESS);
        if (Error)
            continue;
        ok_eq_ulong(Length, (DWORD)sizeof(Kernel));
        Kernel.Alias[IF_MAX_STRING_SIZE] = 0;
        Kernel.Description[IF_MAX_STRING_SIZE] = 0;

        Id = &User.InterfaceGuid;
        StringCbPrintfW(Guid, sizeof(Guid), L"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                        Id->Data1, Id->Data2, Id->Data3, Id->Data4[0], Id->Data4[1], Id->Data4[2], Id->Data4[3],
                        Id->Data4[4], Id->Data4[5], Id->Data4[6], Id->Data4[7]);

        ok(Kernel.InterfaceIndex == User.InterfaceIndex, "Index %lu, expected %lu\n",
           Kernel.InterfaceIndex, User.InterfaceIndex);
        ok(Kernel.Alias[0] != 0, "Interface %lu has no alias\n", User.InterfaceIndex);
        ok(Kernel.Description[0] != 0, "Interface %lu has no description\n", User.InterfaceIndex);
        ok(!EndsWithGuid(Kernel.Alias, Guid), "Alias \"%ls\" is the device name\n", Kernel.Alias);
        ok(!EndsWithGuid(Kernel.Description, Guid), "Description \"%ls\" is the device name\n", Kernel.Description);
        ok_eq_wstr(Kernel.Alias, User.Alias);
        ok_eq_wstr(Kernel.Description, User.Description);
        Tested++;
    }

    if (Tested == 0)
        skip(FALSE, "No interface other than the loopback\n");

    KmtCloseDriver();
    KmtUnloadDriver();
    FreeMibTable(Table);
}
