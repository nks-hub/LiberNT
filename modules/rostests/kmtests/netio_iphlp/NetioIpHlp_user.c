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

#define TEST_ROUTE_NETWORK 0xC6336400UL
#define TEST_ROUTE_COUNT 200

static
ULONG
CountTestRoutes(VOID)
{
    PMIB_IPFORWARD_TABLE2 Routes = NULL;
    ULONG i, Count = 0;
    DWORD Error;

    Error = GetIpForwardTable2(AF_INET, &Routes);
    ok_eq_ulong(Error, (DWORD)NO_ERROR);
    if (Error || Routes == NULL)
        return 0;

    for (i = 0; i < Routes->NumEntries; i++)
    {
        if (Routes->Table[i].DestinationPrefix.PrefixLength == 32 &&
            (ntohl(Routes->Table[i].DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr) & 0xFFFFFF00UL) == TEST_ROUTE_NETWORK)
        {
            Count++;
        }
    }
    FreeMibTable(Routes);
    return Count;
}

static
BOOL
QueryBestRoute(
    _In_ ULONG Destination,
    _In_ PMIB_IF_TABLE2 Interfaces,
    _Out_ PMIB_IPFORWARD_ROW2 Route)
{
    NETIOIPHLP_BEST_ROUTE Request;
    DWORD Error, Length = sizeof(Request);
    ULONG i;

    RtlZeroMemory(&Request, sizeof(Request));
    Request.Destination = Destination;
    Error = KmtSendBufferToDriver(IOCTL_NETIOIPHLP_GET_BEST_ROUTE2, &Request, sizeof(Request), &Length);
    ok_eq_ulong(Error, (DWORD)ERROR_SUCCESS);
    if (Error)
        return FALSE;
    ok_eq_ulong(Length, (DWORD)sizeof(Request));

    for (i = 0; i < Interfaces->NumEntries; i++)
    {
        if (Interfaces->Table[i].InterfaceIndex == Request.Route.InterfaceIndex)
            break;
    }
    ok(i < Interfaces->NumEntries, "The route to 0x%08lx uses interface %lu, which the system does not have\n",
       Request.Destination, Request.Route.InterfaceIndex);
    if (i < Interfaces->NumEntries && Interfaces->Table[i].Type != IF_TYPE_SOFTWARE_LOOPBACK)
    {
        ok(Interfaces->Table[i].InterfaceLuid.Value == Request.Route.InterfaceLuid.Value,
           "The route to 0x%08lx has LUID 0x%I64x, expected 0x%I64x\n",
           Request.Destination, Request.Route.InterfaceLuid.Value, Interfaces->Table[i].InterfaceLuid.Value);
    }

    *Route = Request.Route;
    return TRUE;
}

static
VOID
TestGetBestRoute2(
    _In_ PMIB_IF_TABLE2 Interfaces)
{
    PMIB_IPFORWARD_TABLE2 Routes = NULL;
    MIB_IPFORWARD_ROW2 Best;
    MIB_IPFORWARDROW Route;
    ULONG i, Count, Gateway = 0, Index = 0;
    DWORD Error;

    QueryBestRoute(0, Interfaces, &Best);

    Error = GetIpForwardTable2(AF_INET, &Routes);
    ok_eq_ulong(Error, (DWORD)NO_ERROR);
    if (Error || Routes == NULL)
        return;
    for (i = 0; i < Routes->NumEntries; i++)
    {
        if (Routes->Table[i].DestinationPrefix.PrefixLength == 0 && Routes->Table[i].NextHop.Ipv4.sin_addr.s_addr != 0)
        {
            Gateway = Routes->Table[i].NextHop.Ipv4.sin_addr.s_addr;
            Index = Routes->Table[i].InterfaceIndex;
            break;
        }
    }
    FreeMibTable(Routes);

    if (skip(Gateway != 0, "No IPv4 default gateway to add routes through\n"))
        return;

    RtlZeroMemory(&Route, sizeof(Route));
    Route.dwForwardMask = 0xFFFFFFFFUL;
    Route.dwForwardNextHop = Gateway;
    Route.dwForwardIfIndex = Index;
    Route.dwForwardType = MIB_IPROUTE_TYPE_INDIRECT;
    Route.dwForwardProto = MIB_IPPROTO_NETMGMT;
    Route.dwForwardMetric1 = 1;

    for (i = 1; i <= TEST_ROUTE_COUNT; i++)
    {
        Route.dwForwardDest = htonl(TEST_ROUTE_NETWORK | i);
        CreateIpForwardEntry(&Route);
    }
    Count = CountTestRoutes();
    ok_eq_ulong(Count, (ULONG)TEST_ROUTE_COUNT);

    QueryBestRoute(0, Interfaces, &Best);
    if (QueryBestRoute(htonl(TEST_ROUTE_NETWORK | TEST_ROUTE_COUNT), Interfaces, &Best))
    {
        ok_eq_ulong((ULONG)Best.DestinationPrefix.PrefixLength, 32UL);
        ok_eq_ulong(Best.InterfaceIndex, Index);
        ok_eq_hex(Best.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr, htonl(TEST_ROUTE_NETWORK | TEST_ROUTE_COUNT));
    }

    for (i = 1; i <= TEST_ROUTE_COUNT; i++)
    {
        Route.dwForwardDest = htonl(TEST_ROUTE_NETWORK | i);
        DeleteIpForwardEntry(&Route);
    }
    Count = CountTestRoutes();
    ok_eq_ulong(Count, 0UL);
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

    TestGetBestRoute2(Table);

    KmtCloseDriver();
    KmtUnloadDriver();
    FreeMibTable(Table);
}
