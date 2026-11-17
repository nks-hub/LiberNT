/*
 * PROJECT:     LiberNT kernel-mode tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     WSK datagram receive events, user-mode part
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include <kmt_test.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include "wsk_events.h"

typedef DWORD (WINAPI *PGET_IP_ADDR_TABLE)(PMIB_IPADDRTABLE, PULONG, BOOL);
typedef DWORD (WINAPI *PIP_INTERFACE_ENTRY)(PMIB_IPINTERFACE_ROW);

static PIP_INTERFACE_ENTRY pGetIpInterfaceEntry;
static PIP_INTERFACE_ENTRY pSetIpInterfaceEntry;

static
BOOLEAN
SetWeakHostSend(
    _In_ ULONG Index,
    _In_ BOOLEAN Enable,
    _Out_opt_ PBOOLEAN Previous)
{
    MIB_IPINTERFACE_ROW Row;
    DWORD Error;

    ZeroMemory(&Row, sizeof(Row));
    Row.Family = AF_INET;
    Row.InterfaceIndex = Index;
    Error = pGetIpInterfaceEntry(&Row);
    ok(Error == NO_ERROR, "GetIpInterfaceEntry(%lu) returned %lu\n", Index, Error);
    if (Error != NO_ERROR)
        return FALSE;
    if (Previous != NULL)
        *Previous = Row.WeakHostSend;
    /* Windows 11 refuses an IPv4 row with a site prefix length other than 0, also the one it reads back */
    Row.SitePrefixLength = 0;
    Row.WeakHostSend = Enable;
    Error = pSetIpInterfaceEntry(&Row);
    ok(Error == NO_ERROR, "SetIpInterfaceEntry(%lu, WeakHostSend %u) returned %lu\n", Index, Enable, Error);
    return Error == NO_ERROR;
}

static
VOID
TestSendInterface(VOID)
{
    PGET_IP_ADDR_TABLE pGetIpAddrTable;
    WSKEVENTS_INTERFACES Interfaces;
    PMIB_IPADDRTABLE Table;
    BOOLEAN LoopbackWeak, OtherWeak;
    HMODULE IpHlp;
    ULONG Size = 0, i;
    DWORD Error, Length;

    IpHlp = LoadLibraryW(L"iphlpapi.dll");
    pGetIpAddrTable = (PGET_IP_ADDR_TABLE)GetProcAddress(IpHlp, "GetIpAddrTable");
    pGetIpInterfaceEntry = (PIP_INTERFACE_ENTRY)GetProcAddress(IpHlp, "GetIpInterfaceEntry");
    pSetIpInterfaceEntry = (PIP_INTERFACE_ENTRY)GetProcAddress(IpHlp, "SetIpInterfaceEntry");
    if (skip(pGetIpAddrTable && pGetIpInterfaceEntry && pSetIpInterfaceEntry, "iphlpapi cannot set the weak host mode\n"))
        return;

    pGetIpAddrTable(NULL, &Size, FALSE);
    Table = HeapAlloc(GetProcessHeap(), 0, Size);
    if (Table == NULL || pGetIpAddrTable(Table, &Size, FALSE) != NO_ERROR)
    {
        ok(FALSE, "GetIpAddrTable failed\n");
        HeapFree(GetProcessHeap(), 0, Table);
        return;
    }
    ZeroMemory(&Interfaces, sizeof(Interfaces));
    for (i = 0; i < Table->dwNumEntries; i++)
    {
        if (Table->table[i].dwAddr == htonl(INADDR_LOOPBACK))
            Interfaces.LoopbackIndex = Table->table[i].dwIndex;
    }
    for (i = 0; i < Table->dwNumEntries; i++)
    {
        if ((ntohl(Table->table[i].dwAddr) >> 24) != 127 && Table->table[i].dwAddr != 0 &&
            Table->table[i].dwIndex != Interfaces.LoopbackIndex && Interfaces.OtherIndex == 0)
        {
            Interfaces.OtherIndex = Table->table[i].dwIndex;
            Interfaces.OtherAddress = ntohl(Table->table[i].dwAddr);
        }
    }
    HeapFree(GetProcessHeap(), 0, Table);
    ok(Interfaces.LoopbackIndex != 0, "No interface has 127.0.0.1\n");
    if (skip(Interfaces.LoopbackIndex != 0 && Interfaces.OtherIndex != 0, "No IPv4 address outside the loopback interface\n"))
        return;

    if (!SetWeakHostSend(Interfaces.LoopbackIndex, FALSE, &LoopbackWeak))
        return;
    if (SetWeakHostSend(Interfaces.OtherIndex, FALSE, &OtherWeak))
    {
        for (Interfaces.WeakHostSend = 0; Interfaces.WeakHostSend < 2; Interfaces.WeakHostSend++)
        {
            if (Interfaces.WeakHostSend &&
                (!SetWeakHostSend(Interfaces.LoopbackIndex, TRUE, NULL) || !SetWeakHostSend(Interfaces.OtherIndex, TRUE, NULL)))
            {
                break;
            }
            Length = 0;
            Error = KmtSendBufferToDriver(IOCTL_WSKEVENTS_INTERFACES, &Interfaces, sizeof(Interfaces), &Length);
            ok_eq_int(Error, ERROR_SUCCESS);
        }
        SetWeakHostSend(Interfaces.OtherIndex, OtherWeak, NULL);
    }
    SetWeakHostSend(Interfaces.LoopbackIndex, LoopbackWeak, NULL);
}

START_TEST(WskEvents)
{
    DWORD Error;

    Error = KmtLoadAndOpenDriver(L"WskEvents", TRUE);
    ok_eq_int(Error, ERROR_SUCCESS);
    if (Error)
    {
        return;
    }

    Error = KmtSendToDriver(IOCTL_WSKEVENTS_RUN);
    ok_eq_int(Error, ERROR_SUCCESS);
    TestSendInterface();

    KmtCloseDriver();
    KmtUnloadDriver();
}
