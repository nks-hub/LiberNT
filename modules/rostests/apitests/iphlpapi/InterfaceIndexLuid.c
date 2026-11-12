/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Tests that every interface has one index and one LUID that convert into each other
 * COPYRIGHT:   Copyright 2026 LiberNT contributors
 */

#include <apitest.h>

#define WIN32_NO_STATUS
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <netioapi.h>

static VOID
CheckIdentity(NET_IFINDEX Index, NET_LUID Luid)
{
    MIB_IF_ROW2 Row;
    NET_LUID FoundLuid;
    NET_IFINDEX FoundIndex = 0;
    DWORD Error;

    FoundLuid.Value = 0;
    Error = ConvertInterfaceIndexToLuid(Index, &FoundLuid);
    ok(Error == NO_ERROR, "Index %lu: ConvertInterfaceIndexToLuid returned %lu\n", Index, Error);
    ok(FoundLuid.Value == Luid.Value, "Index %lu: LUID %I64x, expected %I64x\n", Index, FoundLuid.Value, Luid.Value);

    Error = ConvertInterfaceLuidToIndex(&Luid, &FoundIndex);
    ok(Error == NO_ERROR, "LUID %I64x: ConvertInterfaceLuidToIndex returned %lu\n", Luid.Value, Error);
    ok(FoundIndex == Index, "LUID %I64x: index %lu, expected %lu\n", Luid.Value, FoundIndex, Index);

    ZeroMemory(&Row, sizeof(Row));
    Row.InterfaceIndex = Index;
    Error = GetIfEntry2(&Row);
    ok(Error == NO_ERROR, "Index %lu: GetIfEntry2 returned %lu\n", Index, Error);
    ok(Row.InterfaceLuid.Value == Luid.Value, "Index %lu: GetIfEntry2 LUID %I64x, expected %I64x\n", Index, Row.InterfaceLuid.Value, Luid.Value);

    ZeroMemory(&Row, sizeof(Row));
    Row.InterfaceLuid = Luid;
    Error = GetIfEntry2(&Row);
    ok(Error == NO_ERROR, "LUID %I64x: GetIfEntry2 returned %lu\n", Luid.Value, Error);
    ok(Row.InterfaceIndex == Index, "LUID %I64x: GetIfEntry2 index %lu, expected %lu\n", Luid.Value, Row.InterfaceIndex, Index);
}

START_TEST(InterfaceIndexLuid)
{
    PMIB_IF_TABLE2 Table = NULL;
    PIP_ADAPTER_ADDRESSES Adapters;
    PIP_ADAPTER_ADDRESSES Adapter;
    ULONG Size = 0;
    ULONG i, j;
    DWORD Error;

    Error = GetIfTable2(&Table);
    ok(Error == NO_ERROR, "GetIfTable2 returned %lu\n", Error);
    if (Error != NO_ERROR)
        return;

    ok(Table->NumEntries != 0, "GetIfTable2 returned no interface\n");
    for (i = 0; i < Table->NumEntries; i++)
    {
        ok(Table->Table[i].InterfaceIndex != 0, "Row %lu has index 0\n", i);
        CheckIdentity(Table->Table[i].InterfaceIndex, Table->Table[i].InterfaceLuid);

        for (j = 0; j < i; j++)
        {
            ok(Table->Table[j].InterfaceIndex != Table->Table[i].InterfaceIndex,
               "Rows %lu and %lu share index %lu\n", j, i, Table->Table[i].InterfaceIndex);
            ok(Table->Table[j].InterfaceLuid.Value != Table->Table[i].InterfaceLuid.Value,
               "Rows %lu and %lu share LUID %I64x\n", j, i, Table->Table[i].InterfaceLuid.Value);
        }
    }
    FreeMibTable(Table);

    Error = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES, NULL, NULL, &Size);
    ok(Error == ERROR_BUFFER_OVERFLOW, "GetAdaptersAddresses returned %lu\n", Error);
    if (Error != ERROR_BUFFER_OVERFLOW)
        return;

    Adapters = HeapAlloc(GetProcessHeap(), 0, Size);
    if (Adapters == NULL)
    {
        skip("Out of memory\n");
        return;
    }

    Error = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES, NULL, Adapters, &Size);
    ok(Error == NO_ERROR, "GetAdaptersAddresses returned %lu\n", Error);
    if (Error == NO_ERROR)
    {
        for (Adapter = Adapters; Adapter != NULL; Adapter = Adapter->Next)
        {
            NET_IFINDEX Index = Adapter->IfIndex ? Adapter->IfIndex : Adapter->Ipv6IfIndex;

            ok(Index != 0, "Adapter %s has no index\n", Adapter->AdapterName);
            ok(Adapter->Ipv6IfIndex == 0 || Adapter->Ipv6IfIndex == Index,
               "Adapter %s: IPv6 index %lu, IPv4 index %lu\n", Adapter->AdapterName, Adapter->Ipv6IfIndex, Index);
            CheckIdentity(Index, Adapter->Luid);
        }
    }
    HeapFree(GetProcessHeap(), 0, Adapters);
}
