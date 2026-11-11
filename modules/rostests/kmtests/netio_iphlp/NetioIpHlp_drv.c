/*
 * PROJECT:     LiberNT kernel-mode tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Kernel-mode IP Helper routines of netio.sys
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include <kmt_test.h>
#include <netiodef.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <ndis.h>
#define IPHLPAPI_DLL_LINKAGE
#include <netioapi.h>

#include "netio_iphlp.h"

static KMT_MESSAGE_HANDLER TestGetIfEntry2;
static KMT_MESSAGE_HANDLER TestGetBestRoute2;

static
NTSTATUS
TestGetIfEntry2(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG ControlCode,
    _In_opt_ PVOID Buffer,
    _In_ SIZE_T InLength,
    _Inout_ PSIZE_T OutLength)
{
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(ControlCode);

    ok_irql(PASSIVE_LEVEL);
    if (Buffer == NULL || InLength != sizeof(MIB_IF_ROW2) || *OutLength < sizeof(MIB_IF_ROW2))
    {
        *OutLength = 0;
        return STATUS_INVALID_PARAMETER;
    }

    Status = GetIfEntry2(Buffer);
    ok_irql(PASSIVE_LEVEL);
    *OutLength = NT_SUCCESS(Status) ? sizeof(MIB_IF_ROW2) : 0;
    return Status;
}

static
NTSTATUS
TestGetBestRoute2(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG ControlCode,
    _In_opt_ PVOID Buffer,
    _In_ SIZE_T InLength,
    _Inout_ PSIZE_T OutLength)
{
    PNETIOIPHLP_BEST_ROUTE Request = Buffer;
    PMIB_IPFORWARD_TABLE2 Table;
    SOCKADDR_INET Destination, Source;
    MIB_IPFORWARD_ROW2 LuidRoute;
    NTSTATUS Status, LuidStatus;
    ULONG i;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(ControlCode);

    ok_irql(PASSIVE_LEVEL);
    if (Buffer == NULL || InLength != sizeof(*Request) || *OutLength < sizeof(*Request))
    {
        *OutLength = 0;
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&Destination, sizeof(Destination));
    Destination.Ipv4.sin_family = AF_INET;
    Destination.Ipv4.sin_addr.s_addr = Request->Destination;
    if (Request->Destination == 0)
    {
        Destination.Ipv4.sin_addr.s_addr = NETIOIPHLP_LOOPBACK_ADDRESS;
        Status = GetIpForwardTable2(AF_INET, &Table);
        ok_eq_hex(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status))
        {
            for (i = 0; i < Table->NumEntries; i++)
            {
                if (Table->Table[i].DestinationPrefix.PrefixLength == 0 &&
                    Table->Table[i].NextHop.Ipv4.sin_addr.s_addr != 0)
                {
                    Destination.Ipv4.sin_addr.s_addr = Table->Table[i].NextHop.Ipv4.sin_addr.s_addr;
                    break;
                }
            }
            FreeMibTable(Table);
        }
    }

    Request->Destination = Destination.Ipv4.sin_addr.s_addr;
    Status = GetBestRoute2(NULL, 0, NULL, &Destination, 0, &Request->Route, &Source);
    ok_irql(PASSIVE_LEVEL);
    if (NT_SUCCESS(Status) && Request->Route.InterfaceLuid.Value != 0)
    {
        RtlZeroMemory(&LuidRoute, sizeof(LuidRoute));
        LuidStatus = GetBestRoute2(&Request->Route.InterfaceLuid, 0xdeadbeef, NULL, &Destination, 0, &LuidRoute, &Source);
        ok_eq_hex(LuidStatus, STATUS_SUCCESS);
        ok_eq_ulong(LuidRoute.InterfaceIndex, Request->Route.InterfaceIndex);
        ok_eq_ulonglong(LuidRoute.InterfaceLuid.Value, Request->Route.InterfaceLuid.Value);
    }
    *OutLength = NT_SUCCESS(Status) ? sizeof(*Request) : 0;
    return Status;
}

NTSTATUS
TestEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PCUNICODE_STRING RegistryPath,
    _Out_ PCWSTR *DeviceName,
    _Inout_ INT *Flags)
{
    NTSTATUS Status;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    UNREFERENCED_PARAMETER(Flags);

    *DeviceName = L"NetioIpHlp";

    Status = KmtRegisterMessageHandler(IOCTL_NETIOIPHLP_GET_IF_ENTRY2, NULL, TestGetIfEntry2);
    if (!NT_SUCCESS(Status))
        return Status;
    return KmtRegisterMessageHandler(IOCTL_NETIOIPHLP_GET_BEST_ROUTE2, NULL, TestGetBestRoute2);
}

VOID
TestUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(DriverObject);
}
