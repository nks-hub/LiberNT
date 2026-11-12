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
static KMT_MESSAGE_HANDLER TestNotify;

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
VOID
TestRouteTables(
    _In_ const MIB_IPFORWARD_ROW2 *Route)
{
    PMIB_IPFORWARD_TABLE2 Table;
    MIB_IF_ROW2 Interface;
    NTSTATUS Status;
    ULONG i, Foreign = 0;

    RtlZeroMemory(&Interface, sizeof(Interface));
    Interface.InterfaceLuid = Route->InterfaceLuid;
    Status = GetIfEntry2(&Interface);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
        ok_eq_ulong(Interface.InterfaceIndex, Route->InterfaceIndex);

    Status = GetIpForwardTable2(AF_INET, &Table);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        for (i = 0; i < Table->NumEntries; i++)
        {
            if (Table->Table[i].InterfaceIndex == Route->InterfaceIndex &&
                Table->Table[i].DestinationPrefix.PrefixLength == Route->DestinationPrefix.PrefixLength &&
                Table->Table[i].DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr ==
                Route->DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr)
            {
                break;
            }
        }
        ok(i < Table->NumEntries, "The best route is not in the route table\n");
        if (i < Table->NumEntries)
        {
            ok_eq_hex(Table->Table[i].NextHop.Ipv4.sin_addr.s_addr, Route->NextHop.Ipv4.sin_addr.s_addr);
            ok_eq_ulonglong(Table->Table[i].InterfaceLuid.Value, Route->InterfaceLuid.Value);
        }
        FreeMibTable(Table);
    }

    Status = GetIpForwardTable2(AF_INET6, &Table);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        for (i = 0; i < Table->NumEntries; i++)
        {
            if (Table->Table[i].DestinationPrefix.Prefix.si_family != AF_INET6)
                Foreign++;
        }
        ok_eq_ulong(Foreign, 0UL);
        FreeMibTable(Table);
    }
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
    if (NT_SUCCESS(Status))
        TestRouteTables(&Request->Route);
    *OutLength = NT_SUCCESS(Status) ? sizeof(*Request) : 0;
    return Status;
}

typedef struct _NOTIFY_STATE
{
    LONG Initial;
    LONG InitialRows;
    LONG Changes;
    PHANDLE CancelInside;
    NTSTATUS CancelStatus;
} NOTIFY_STATE, *PNOTIFY_STATE;

static NOTIFY_STATE NotifyFirst, NotifySecond, NotifyCancelling, NotifyRouteInitial, NotifyRouteQuiet;
static HANDLE NotifyCancellingHandle;
static ULONG NotifyIndex;

static
VOID
NTAPI
TestInterfaceCallback(
    _In_ PVOID Context,
    _In_opt_ PMIB_IPINTERFACE_ROW Row,
    _In_ MIB_NOTIFICATION_TYPE Type)
{
    PNOTIFY_STATE State = Context;

    if (Type == MibInitialNotification)
    {
        InterlockedIncrement(&State->Initial);
        if (Row != NULL)
            InterlockedIncrement(&State->InitialRows);
        return;
    }
    if (Row == NULL || Type != MibParameterNotification || Row->Family != AF_INET || Row->InterfaceIndex != NotifyIndex)
        return;
    if (State->CancelInside != NULL)
        State->CancelStatus = CancelMibChangeNotify2(*State->CancelInside);
    InterlockedIncrement(&State->Changes);
}

static
VOID
NTAPI
TestRouteCallback(
    _In_ PVOID Context,
    _In_opt_ PMIB_IPFORWARD_ROW2 Row,
    _In_ MIB_NOTIFICATION_TYPE Type)
{
    PNOTIFY_STATE State = Context;

    if (Type != MibInitialNotification)
        return;
    InterlockedIncrement(&State->Initial);
    if (Row != NULL)
        InterlockedIncrement(&State->InitialRows);
}

static
VOID
TestDelay(
    _In_ ULONG Milliseconds)
{
    LARGE_INTEGER Interval;

    Interval.QuadPart = -10000LL * Milliseconds;
    KeDelayExecutionThread(KernelMode, FALSE, &Interval);
}

/* The worker of netio polls every five seconds when the stack does not report a change by itself */
static
VOID
TestWaitFor(
    _In_ const LONG *First,
    _In_opt_ const LONG *Second,
    _In_ LONG Value)
{
    ULONG i;

    for (i = 0; i < 300 && (*First < Value || (Second != NULL && *Second < Value)); i++)
        TestDelay(50);
    TestDelay(500);
}

static
NTSTATUS
TestSetMetric(
    _In_ const MIB_IPINTERFACE_ROW *Original,
    _In_ BOOLEAN Restore)
{
    MIB_IPINTERFACE_ROW Row = *Original;

    Row.SitePrefixLength = 0;
    if (!Restore)
    {
        Row.UseAutomaticMetric = FALSE;
        Row.Metric = Original->Metric + 1;
    }
    return SetIpInterfaceEntry(&Row);
}

static
NTSTATUS
TestNotify(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG ControlCode,
    _In_opt_ PVOID Buffer,
    _In_ SIZE_T InLength,
    _Inout_ PSIZE_T OutLength)
{
    HANDLE First = NULL, Second = NULL, RouteInitial = NULL, RouteQuiet = NULL;
    SOCKADDR_INET Destination, Source;
    MIB_IPFORWARD_ROW2 Route;
    MIB_IPINTERFACE_ROW Original;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(ControlCode);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(InLength);

    *OutLength = 0;
    ok_irql(PASSIVE_LEVEL);

    RtlZeroMemory(&Destination, sizeof(Destination));
    Destination.Ipv4.sin_family = AF_INET;
    Destination.Ipv4.sin_addr.s_addr = NETIOIPHLP_LOOPBACK_ADDRESS;
    Status = GetBestRoute2(NULL, 0, NULL, &Destination, 0, &Route, &Source);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return STATUS_SUCCESS;
    NotifyIndex = Route.InterfaceIndex;

    Status = NotifyIpInterfaceChange(AF_INET, TestInterfaceCallback, &NotifyFirst, TRUE, &First);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return STATUS_SUCCESS;
    TestWaitFor(&NotifyFirst.Initial, NULL, 1);
    ok_eq_long(NotifyFirst.Initial, 1L);
    ok_eq_long(NotifyFirst.InitialRows, 0L);

    Status = NotifyIpInterfaceChange(AF_INET, TestInterfaceCallback, &NotifySecond, FALSE, &Second);
    ok_eq_hex(Status, STATUS_SUCCESS);
    NotifyCancelling.CancelInside = &NotifyCancellingHandle;
    NotifyCancelling.CancelStatus = STATUS_UNSUCCESSFUL;
    Status = NotifyIpInterfaceChange(AF_INET, TestInterfaceCallback, &NotifyCancelling, FALSE, &NotifyCancellingHandle);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Status = NotifyRouteChange2(AF_INET, TestRouteCallback, &NotifyRouteInitial, TRUE, &RouteInitial);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Status = NotifyRouteChange2(AF_INET, TestRouteCallback, &NotifyRouteQuiet, FALSE, &RouteQuiet);
    ok_eq_hex(Status, STATUS_SUCCESS);
    TestWaitFor(&NotifyRouteInitial.Initial, NULL, 1);
    ok_eq_long(NotifyRouteInitial.Initial, 1L);
    ok_eq_long(NotifyRouteInitial.InitialRows, 0L);
    ok_eq_long(NotifyRouteQuiet.Initial, 0L);
    ok_eq_long(NotifyFirst.Initial, 1L);
    ok_eq_long(NotifySecond.Initial, 0L);
    ok_eq_long(NotifyCancelling.Initial, 0L);

    InitializeIpInterfaceEntry(&Original);
    Original.Family = AF_INET;
    Original.InterfaceIndex = NotifyIndex;
    Status = GetIpInterfaceEntry(&Original);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
        Status = TestSetMetric(&Original, FALSE);
    if (!skip(NT_SUCCESS(Status), "The metric of interface %lu cannot be changed, status 0x%08lx\n", NotifyIndex, Status))
    {
        TestWaitFor(&NotifyFirst.Changes, &NotifySecond.Changes, 1);
        ok_eq_long(NotifyFirst.Changes, 1L);
        ok_eq_long(NotifySecond.Changes, 1L);
        ok_eq_long(NotifyCancelling.Changes, 1L);
        ok_eq_hex(NotifyCancelling.CancelStatus, STATUS_SUCCESS);

        Status = TestSetMetric(&Original, TRUE);
        ok_eq_hex(Status, STATUS_SUCCESS);
        TestWaitFor(&NotifyFirst.Changes, &NotifySecond.Changes, 2);
        ok_eq_long(NotifyFirst.Changes, 2L);
        ok_eq_long(NotifySecond.Changes, 2L);
        ok_eq_long(NotifyCancelling.Changes, 1L);
    }
    else
    {
        Status = CancelMibChangeNotify2(NotifyCancellingHandle);
        ok_eq_hex(Status, STATUS_SUCCESS);
    }

    Status = CancelMibChangeNotify2(First);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Status = CancelMibChangeNotify2(Second);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Status = CancelMibChangeNotify2(RouteInitial);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Status = CancelMibChangeNotify2(RouteQuiet);
    ok_eq_hex(Status, STATUS_SUCCESS);

    if (NT_SUCCESS(TestSetMetric(&Original, FALSE)))
    {
        Status = TestSetMetric(&Original, TRUE);
        ok_eq_hex(Status, STATUS_SUCCESS);
        TestDelay(1000);
    }
    ok(NotifyFirst.Changes <= 2, "The cancelled registration was called %ld times\n", NotifyFirst.Changes);
    ok(NotifySecond.Changes <= 2, "The cancelled registration was called %ld times\n", NotifySecond.Changes);
    ok_eq_long(NotifyFirst.Initial, 1L);
    ok_eq_long(NotifyRouteInitial.Initial, 1L);
    ok_irql(PASSIVE_LEVEL);
    return STATUS_SUCCESS;
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
    Status = KmtRegisterMessageHandler(IOCTL_NETIOIPHLP_GET_BEST_ROUTE2, NULL, TestGetBestRoute2);
    if (!NT_SUCCESS(Status))
        return Status;
    return KmtRegisterMessageHandler(IOCTL_NETIOIPHLP_NOTIFY, NULL, TestNotify);
}

VOID
TestUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(DriverObject);
}
