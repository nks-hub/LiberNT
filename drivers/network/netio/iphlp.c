/*
 * PROJECT:     LiberNT NetIO driver
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Kernel-mode IP Helper entry points
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif.ing@outlook.com>
 */

#include <ntifs.h>
#include <netiodef.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <ndis.h>
#define IPHLPAPI_DLL_LINKAGE
#include <netioapi.h>
#include <tdiinfo.h>
#include <tcpioctl.h>
#include <tcpip_undoc.h>

#define NETIO_IPHLP_TAG 'hIeN'
#define NETIO_MAX_ENTITIES 256
#define NETIO_MAX_ROUTES 128
#define NETIO_MAX_ADDRESSES 64

static
NET_LUID
NetioInterfaceLuid(
    _In_ ULONG Index,
    _In_ ULONG Type)
{
    NET_LUID Luid;

    if (NdisIfGetNetLuidFromInterfaceIndex(Index, &Luid) == NDIS_STATUS_SUCCESS && Luid.Value)
        return Luid;
    Luid.Value = 0;
    Luid.Info.NetLuidIndex = Index;
    Luid.Info.IfType = Type;
    return Luid;
}

static
ULONG
NetioLuidIndex(
    _In_ const NET_LUID *Luid)
{
    NET_IFINDEX Index;
    NET_LUID AdapterLuid;

    if (NdisIfGetInterfaceIndexFromNetLuid(*Luid, &Index) == NDIS_STATUS_SUCCESS && Index != 0)
        return Index;

    Index = (NET_IFINDEX)Luid->Info.NetLuidIndex;
    if (NdisIfGetNetLuidFromInterfaceIndex(Index, &AdapterLuid) == NDIS_STATUS_SUCCESS && AdapterLuid.Value)
        return 0;
    return Index;
}

typedef struct _NETIO_TDI_ROUTE
{
    ULONG Dest;
    ULONG Index;
    ULONG Metric1;
    ULONG Metric2;
    ULONG Metric3;
    ULONG Metric4;
    ULONG NextHop;
    ULONG Type;
    ULONG Proto;
    ULONG Age;
    ULONG Mask;
    ULONG Metric5;
    ULONG Info;
} NETIO_TDI_ROUTE, *PNETIO_TDI_ROUTE;

C_ASSERT(sizeof(MIB_IPFORWARD_ROW2) == 0x68);
C_ASSERT(FIELD_OFFSET(MIB_IPFORWARD_ROW2, SitePrefixLength) == 0x48);
C_ASSERT(FIELD_OFFSET(MIB_IPFORWARD_ROW2, ValidLifetime) == 0x4C);
C_ASSERT(FIELD_OFFSET(MIB_IPFORWARD_ROW2, Loopback) == 0x5C);
C_ASSERT(sizeof(MIB_UNICASTIPADDRESS_ROW) == 0x50);
C_ASSERT(FIELD_OFFSET(MIB_UNICASTIPADDRESS_ROW, PrefixOrigin) == 0x2C);
C_ASSERT(FIELD_OFFSET(MIB_UNICASTIPADDRESS_ROW, OnLinkPrefixLength) == 0x3C);
C_ASSERT(sizeof(MIB_IPINTERFACE_ROW) == 0xA8);
C_ASSERT(FIELD_OFFSET(MIB_IPINTERFACE_ROW, BaseReachableTime) == 0x3C);
C_ASSERT(FIELD_OFFSET(MIB_IPINTERFACE_ROW, NlMtu) == 0x98);

VOID
NTAPI
InitializeIpForwardEntry(
    _Out_ PMIB_IPFORWARD_ROW2 Row)
{
    RtlZeroMemory(Row, sizeof(*Row));
    Row->SitePrefixLength = 0xFF;
    Row->ValidLifetime = 0xFFFFFFFF;
    Row->PreferredLifetime = 0xFFFFFFFF;
    Row->Metric = 0xFFFFFFFF;
    Row->Protocol = (NL_ROUTE_PROTOCOL)0xFFFFFFFF;
    Row->Loopback = (BOOLEAN)0xFF;
    Row->AutoconfigureAddress = (BOOLEAN)0xFF;
    Row->Publish = (BOOLEAN)0xFF;
    Row->Immortal = (BOOLEAN)0xFF;
}

VOID
NTAPI
InitializeUnicastIpAddressEntry(
    _Out_ PMIB_UNICASTIPADDRESS_ROW Row)
{
    RtlZeroMemory(Row, sizeof(*Row));
    Row->PrefixOrigin = IpPrefixOriginUnchanged;
    Row->SuffixOrigin = IpSuffixOriginUnchanged;
    Row->ValidLifetime = 0xFFFFFFFF;
    Row->PreferredLifetime = 0xFFFFFFFF;
    Row->OnLinkPrefixLength = 0xFF;
}

VOID
NTAPI
InitializeIpInterfaceEntry(
    _Inout_ PMIB_IPINTERFACE_ROW Row)
{
    RtlFillMemory(Row, sizeof(*Row), 0xFF);
    Row->Family = AF_UNSPEC;
    Row->InterfaceLuid.Value = 0;
    Row->InterfaceIndex = 0;
    Row->BaseReachableTime = 0;
    Row->RetransmitTime = 0;
    Row->PathMtuDiscoveryTimeout = 0;
    Row->NlMtu = 0;
}

VOID
NTAPI
FreeMibTable(
    _In_ PVOID Memory)
{
    if (Memory != NULL)
        ExFreePoolWithTag(Memory, NETIO_IPHLP_TAG);
}

NTSTATUS
NTAPI
GetIfTable2(
    _Outptr_ PMIB_IF_TABLE2 *Table)
{
    if (Table == NULL)
        return STATUS_INVALID_PARAMETER;
    *Table = NULL;
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
GetIpInterfaceTable(
    _In_ ADDRESS_FAMILY Family,
    _Outptr_ PMIB_IPINTERFACE_TABLE *Table)
{
    UNREFERENCED_PARAMETER(Family);

    if (Table == NULL)
        return STATUS_INVALID_PARAMETER;
    *Table = NULL;
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
GetUnicastIpAddressTable(
    _In_ ADDRESS_FAMILY Family,
    _Outptr_ PMIB_UNICASTIPADDRESS_TABLE *Table)
{
    UNREFERENCED_PARAMETER(Family);

    if (Table == NULL)
        return STATUS_INVALID_PARAMETER;
    *Table = NULL;
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
GetUnicastIpAddressEntry(
    _Inout_ PMIB_UNICASTIPADDRESS_ROW Row)
{
    if (Row == NULL)
        return STATUS_INVALID_PARAMETER;
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
CreateUnicastIpAddressEntry(
    _In_ CONST MIB_UNICASTIPADDRESS_ROW *Row)
{
    if (Row == NULL)
        return STATUS_INVALID_PARAMETER;
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
DeleteUnicastIpAddressEntry(
    _In_ CONST MIB_UNICASTIPADDRESS_ROW *Row)
{
    if (Row == NULL)
        return STATUS_INVALID_PARAMETER;
    return STATUS_NOT_SUPPORTED;
}

static
NTSTATUS
NetioTcpQuery(
    _In_ HANDLE Tcp,
    _In_ ULONG Entity,
    _In_ ULONG Instance,
    _In_ ULONG Class,
    _In_ ULONG Id,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _Out_ PULONG Returned)
{
    TCP_REQUEST_QUERY_INFORMATION_EX Request;
    IO_STATUS_BLOCK Io;
    NTSTATUS Status;

    RtlZeroMemory(&Request, sizeof(Request));
    Request.ID.toi_entity.tei_entity = Entity;
    Request.ID.toi_entity.tei_instance = Instance;
    Request.ID.toi_class = Class;
    Request.ID.toi_type = INFO_TYPE_PROVIDER;
    Request.ID.toi_id = Id;

    Status = ZwDeviceIoControlFile(Tcp, NULL, NULL, NULL, &Io, IOCTL_TCP_QUERY_INFORMATION_EX,
                                   &Request, sizeof(Request), Buffer, Length);
    *Returned = NT_SUCCESS(Status) ? (ULONG)Io.Information : 0;
    return Status;
}

static
ULONG
NetioPrefixLength(
    _In_ ULONG NetworkMask)
{
    ULONG Mask = RtlUlongByteSwap(NetworkMask), Length = 0;

    while (Length < 32 && (Mask & (0x80000000UL >> Length)))
        Length++;
    return Length;
}

static
NTSTATUS
NetioGetBestRoute6(
    _In_ NET_IFINDEX InterfaceIndex,
    _In_opt_ CONST SOCKADDR_INET *SourceAddress,
    _In_ CONST SOCKADDR_INET *DestinationAddress,
    _Out_ PMIB_IPFORWARD_ROW2 BestRoute,
    _Out_ SOCKADDR_INET *BestSourceAddress)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Device\\Ip6");
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Io;
    IP6_BEST_ROUTE Query;
    NTSTATUS Status;
    HANDLE Ip6;

    RtlZeroMemory(&Query, sizeof(Query));
    RtlCopyMemory(Query.Destination, &DestinationAddress->Ipv6.sin6_addr, sizeof(Query.Destination));
    Query.ScopeId = DestinationAddress->Ipv6.sin6_scope_id;
    Query.InterfaceIndex = InterfaceIndex;
    if (SourceAddress != NULL && SourceAddress->si_family == AF_INET6)
        RtlCopyMemory(Query.Source, &SourceAddress->Ipv6.sin6_addr, sizeof(Query.Source));

    InitializeObjectAttributes(&Attributes, &Name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = ZwCreateFile(&Ip6, GENERIC_READ | SYNCHRONIZE, &Attributes, &Io, NULL, FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(Status))
        return Status;
    Status = ZwDeviceIoControlFile(Ip6, NULL, NULL, NULL, &Io, IOCTL_IP6_GET_BEST_ROUTE,
                                   &Query, sizeof(Query), &Query, sizeof(Query));
    ZwClose(Ip6);
    if (!NT_SUCCESS(Status))
        return Status;

    InitializeIpForwardEntry(BestRoute);
    BestRoute->InterfaceIndex = Query.InterfaceIndex;
    BestRoute->InterfaceLuid = NetioInterfaceLuid(Query.InterfaceIndex, 0);
    BestRoute->DestinationPrefix.Prefix.si_family = AF_INET6;
    RtlCopyMemory(&BestRoute->DestinationPrefix.Prefix.Ipv6.sin6_addr, Query.Prefix, sizeof(Query.Prefix));
    BestRoute->DestinationPrefix.PrefixLength = (UINT8)Query.PrefixLength;
    BestRoute->NextHop.si_family = AF_INET6;
    RtlCopyMemory(&BestRoute->NextHop.Ipv6.sin6_addr, Query.NextHop, sizeof(Query.NextHop));
    BestRoute->Metric = Query.Metric;
    BestRoute->Protocol = (NL_ROUTE_PROTOCOL)Query.Protocol;
    BestRoute->Origin = (NL_ROUTE_ORIGIN)Query.Origin;
    BestRoute->Loopback = FALSE;
    BestRoute->AutoconfigureAddress = FALSE;
    BestRoute->Publish = FALSE;
    BestRoute->Immortal = FALSE;

    RtlZeroMemory(BestSourceAddress, sizeof(*BestSourceAddress));
    BestSourceAddress->Ipv6.sin6_family = AF_INET6;
    RtlCopyMemory(&BestSourceAddress->Ipv6.sin6_addr, Query.Source, sizeof(Query.Source));
    if (IN6_IS_ADDR_LINKLOCAL(&BestSourceAddress->Ipv6.sin6_addr))
        BestSourceAddress->Ipv6.sin6_scope_id = Query.InterfaceIndex;
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
GetBestRoute2(
    _In_opt_ PNET_LUID InterfaceLuid,
    _In_ NET_IFINDEX InterfaceIndex,
    _In_opt_ CONST SOCKADDR_INET *SourceAddress,
    _In_ CONST SOCKADDR_INET *DestinationAddress,
    _In_ ULONG AddressSortOptions,
    _Out_ PMIB_IPFORWARD_ROW2 BestRoute,
    _Out_ SOCKADDR_INET *BestSourceAddress)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Device\\Tcp");
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Io;
    HANDLE Tcp;
    TDIEntityID *Entities;
    PNETIO_TDI_ROUTE Routes;
    IPAddrEntry *Addresses;
    IPAddrEntry Address;
    IP_BEST_SOURCE Query;
    NETIO_TDI_ROUTE Best;
    ULONG Destination, Returned, EntityCount, RouteCount, AddressCount, i, j, k, Prefix, BestPrefix = 0;
    ULONG BestAddress = 0, BestIndex = 0;
    BOOLEAN Found = FALSE;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(AddressSortOptions);

    if (DestinationAddress == NULL || BestRoute == NULL || BestSourceAddress == NULL)
        return STATUS_INVALID_PARAMETER;
    if ((DestinationAddress->si_family != AF_INET && DestinationAddress->si_family != AF_INET6) ||
        (SourceAddress != NULL && SourceAddress->si_family != AF_UNSPEC &&
         SourceAddress->si_family != DestinationAddress->si_family))
    {
        return STATUS_NOT_SUPPORTED;
    }
    if (InterfaceLuid != NULL && InterfaceIndex == 0 && InterfaceLuid->Value != 0)
    {
        InterfaceIndex = NetioLuidIndex(InterfaceLuid);
        if (InterfaceIndex == 0)
            return STATUS_NOT_FOUND;
    }
    if (DestinationAddress->si_family == AF_INET6)
        return NetioGetBestRoute6(InterfaceIndex, SourceAddress, DestinationAddress, BestRoute, BestSourceAddress);

    Destination = DestinationAddress->Ipv4.sin_addr.s_addr;

    InitializeObjectAttributes(&Attributes, &Name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = ZwCreateFile(&Tcp, GENERIC_READ | SYNCHRONIZE, &Attributes, &Io, NULL, FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(Status))
        return Status;

    if (InterfaceIndex == 0 &&
        (SourceAddress == NULL || SourceAddress->si_family != AF_INET || SourceAddress->Ipv4.sin_addr.s_addr == 0))
    {
        RtlZeroMemory(&Query, sizeof(Query));
        Query.Destination = Destination;
        if (NT_SUCCESS(ZwDeviceIoControlFile(Tcp, NULL, NULL, NULL, &Io, IOCTL_IP_GET_BEST_SOURCE,
                                             &Query, sizeof(Query), &Query, sizeof(Query))))
        {
            InterfaceIndex = Query.InterfaceIndex;
        }
    }

    Entities = ExAllocatePoolWithTag(PagedPool, NETIO_MAX_ENTITIES * sizeof(TDIEntityID), NETIO_IPHLP_TAG);
    Routes = ExAllocatePoolWithTag(PagedPool, NETIO_MAX_ROUTES * sizeof(NETIO_TDI_ROUTE), NETIO_IPHLP_TAG);
    Addresses = ExAllocatePoolWithTag(PagedPool, NETIO_MAX_ADDRESSES * sizeof(IPAddrEntry), NETIO_IPHLP_TAG);
    if (Entities == NULL || Routes == NULL || Addresses == NULL)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Done;
    }

    Status = NetioTcpQuery(Tcp, GENERIC_ENTITY, 0, INFO_CLASS_GENERIC, ENTITY_LIST_ID,
                           Entities, NETIO_MAX_ENTITIES * sizeof(TDIEntityID), &Returned);
    if (!NT_SUCCESS(Status))
        goto Done;
    EntityCount = Returned / sizeof(TDIEntityID);

    for (i = 0; i < EntityCount; i++)
    {
        if (Entities[i].tei_entity != CL_NL_ENTITY)
            continue;

        if (!NT_SUCCESS(NetioTcpQuery(Tcp, CL_NL_ENTITY, Entities[i].tei_instance, INFO_CLASS_PROTOCOL,
                                      IP_MIB_ADDRTABLE_ENTRY_ID, Addresses,
                                      NETIO_MAX_ADDRESSES * sizeof(IPAddrEntry), &Returned)) ||
            Returned > NETIO_MAX_ADDRESSES * sizeof(IPAddrEntry))
        {
            continue;
        }
        AddressCount = Returned / sizeof(IPAddrEntry);

        for (k = 0; k < AddressCount; k++)
        {
            if (Addresses[k].iae_addr == 0)
                continue;
            if (SourceAddress != NULL && SourceAddress->si_family == AF_INET &&
                SourceAddress->Ipv4.sin_addr.s_addr != 0 &&
                SourceAddress->Ipv4.sin_addr.s_addr != Addresses[k].iae_addr)
            {
                continue;
            }
            break;
        }
        if (k == AddressCount)
            continue;
        Address = Addresses[k];
        if (InterfaceIndex != 0 && Address.iae_index != InterfaceIndex)
            continue;

        if (!NT_SUCCESS(NetioTcpQuery(Tcp, CL_NL_ENTITY, Entities[i].tei_instance, INFO_CLASS_PROTOCOL,
                                      IP_MIB_ARPTABLE_ENTRY_ID, Routes,
                                      NETIO_MAX_ROUTES * sizeof(NETIO_TDI_ROUTE), &Returned)) ||
            Returned > NETIO_MAX_ROUTES * sizeof(NETIO_TDI_ROUTE))
        {
            continue;
        }
        RouteCount = Returned / sizeof(NETIO_TDI_ROUTE);

        for (j = 0; j < RouteCount; j++)
        {
            if ((Destination & Routes[j].Mask) != (Routes[j].Dest & Routes[j].Mask))
                continue;
            Prefix = NetioPrefixLength(Routes[j].Mask);
            if (Found && (Prefix < BestPrefix || (Prefix == BestPrefix && Routes[j].Metric1 >= Best.Metric1)))
                continue;
            Best = Routes[j];
            BestPrefix = Prefix;
            BestAddress = Address.iae_addr;
            BestIndex = Address.iae_index;
            Found = TRUE;
        }
    }

    if (!Found)
    {
        Status = STATUS_NOT_FOUND;
        goto Done;
    }

    InitializeIpForwardEntry(BestRoute);
    BestRoute->InterfaceIndex = BestIndex;
    BestRoute->InterfaceLuid = NetioInterfaceLuid(BestIndex, 0);
    BestRoute->DestinationPrefix.Prefix.si_family = AF_INET;
    BestRoute->DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = Best.Dest & Best.Mask;
    BestRoute->DestinationPrefix.PrefixLength = (UINT8)BestPrefix;
    BestRoute->NextHop.si_family = AF_INET;
    BestRoute->NextHop.Ipv4.sin_addr.s_addr = Best.NextHop == BestAddress ? 0 : Best.NextHop;
    BestRoute->Metric = Best.Metric1;
    BestRoute->Protocol = MIB_IPPROTO_NETMGMT;
    BestRoute->Loopback = (Best.Dest & 0xFF) == 127;
    BestRoute->AutoconfigureAddress = FALSE;
    BestRoute->Publish = FALSE;
    BestRoute->Immortal = FALSE;

    if (SourceAddress == NULL || SourceAddress->si_family != AF_INET || SourceAddress->Ipv4.sin_addr.s_addr == 0)
    {
        RtlZeroMemory(&Query, sizeof(Query));
        Query.Destination = Destination;
        Query.InterfaceIndex = BestIndex;
        if (NT_SUCCESS(ZwDeviceIoControlFile(Tcp, NULL, NULL, NULL, &Io, IOCTL_IP_GET_BEST_SOURCE,
                                             &Query, sizeof(Query), &Query, sizeof(Query))) &&
            Query.Source != 0)
        {
            BestAddress = Query.Source;
        }
    }

    RtlZeroMemory(BestSourceAddress, sizeof(*BestSourceAddress));
    BestSourceAddress->si_family = AF_INET;
    BestSourceAddress->Ipv4.sin_addr.s_addr = BestAddress;
    Status = STATUS_SUCCESS;

Done:
    if (Addresses)
        ExFreePoolWithTag(Addresses, NETIO_IPHLP_TAG);
    if (Routes)
        ExFreePoolWithTag(Routes, NETIO_IPHLP_TAG);
    if (Entities)
        ExFreePoolWithTag(Entities, NETIO_IPHLP_TAG);
    ZwClose(Tcp);
    return Status;
}

#define NETIO_MAX_DESCRIPTION 256
#define NETIO_IF_ENTRY_SIZE FIELD_OFFSET(IFEntry, if_descr[NETIO_MAX_DESCRIPTION + 1])
#define NETIO_UNCHANGED_ULONG ((ULONG)-1)
#define NETIO_UNCHANGED_BOOLEAN ((BOOLEAN)0xFF)
#define NETIO_ROUTE_TYPE_DIRECT 3

static
NTSTATUS
NetioOpenDevice(
    _In_ PCWSTR DeviceName,
    _Out_ PHANDLE Handle)
{
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Io;

    RtlInitUnicodeString(&Name, DeviceName);
    InitializeObjectAttributes(&Attributes, &Name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    return ZwCreateFile(Handle, GENERIC_READ | SYNCHRONIZE, &Attributes, &Io, NULL, FILE_ATTRIBUTE_NORMAL,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
}

static
NTSTATUS
NetioDeviceIoControl(
    _In_ PCWSTR DeviceName,
    _In_ ULONG Code,
    _In_reads_bytes_opt_(InputLength) PVOID Input,
    _In_ ULONG InputLength,
    _Out_writes_bytes_opt_(OutputLength) PVOID Output,
    _In_ ULONG OutputLength)
{
    IO_STATUS_BLOCK Io;
    NTSTATUS Status;
    HANDLE Device;

    Status = NetioOpenDevice(DeviceName, &Device);
    if (!NT_SUCCESS(Status))
        return Status;
    Status = ZwDeviceIoControlFile(Device, NULL, NULL, NULL, &Io, Code, Input, InputLength, Output, OutputLength);
    ZwClose(Device);
    return Status;
}

static
IF_OPER_STATUS
NetioOperStatus(
    _In_ ULONG TdiStatus)
{
    if (TdiStatus == MIB_IF_OPER_STATUS_OPERATIONAL || TdiStatus == MIB_IF_OPER_STATUS_CONNECTED)
        return IfOperStatusUp;
    if (TdiStatus == MIB_IF_OPER_STATUS_CONNECTING)
        return IfOperStatusDormant;
    if (TdiStatus == MIB_IF_OPER_STATUS_NON_OPERATIONAL || TdiStatus == MIB_IF_OPER_STATUS_DISCONNECTED)
        return IfOperStatusDown;
    return IfOperStatusUnknown;
}

static
NTSTATUS
NetioQueryInterfaces(
    _Outptr_result_maybenull_ PUCHAR *Entries,
    _Out_ PULONG Count)
{
    TDIEntityID *Entities;
    IFEntry *Entry;
    PUCHAR Buffer = NULL;
    ULONG Returned, EntityCount, i, Found = 0;
    NTSTATUS Status;
    HANDLE Tcp;

    *Entries = NULL;
    *Count = 0;

    Status = NetioOpenDevice(L"\\Device\\Tcp", &Tcp);
    if (!NT_SUCCESS(Status))
        return Status;

    Entities = ExAllocatePoolWithTag(PagedPool, NETIO_MAX_ENTITIES * sizeof(TDIEntityID), NETIO_IPHLP_TAG);
    if (Entities == NULL)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Done;
    }

    Status = NetioTcpQuery(Tcp, GENERIC_ENTITY, 0, INFO_CLASS_GENERIC, ENTITY_LIST_ID,
                           Entities, NETIO_MAX_ENTITIES * sizeof(TDIEntityID), &Returned);
    if (!NT_SUCCESS(Status))
        goto Done;
    EntityCount = Returned / sizeof(TDIEntityID);

    Buffer = ExAllocatePoolWithTag(PagedPool, max(EntityCount, 1) * NETIO_IF_ENTRY_SIZE, NETIO_IPHLP_TAG);
    if (Buffer == NULL)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Done;
    }

    for (i = 0; i < EntityCount; i++)
    {
        if (Entities[i].tei_entity != IF_ENTITY)
            continue;

        Entry = (IFEntry *)(Buffer + Found * NETIO_IF_ENTRY_SIZE);
        RtlZeroMemory(Entry, NETIO_IF_ENTRY_SIZE);
        if (!NT_SUCCESS(NetioTcpQuery(Tcp, IF_ENTITY, Entities[i].tei_instance, INFO_CLASS_PROTOCOL,
                                      IF_MIB_STATS_ID, Entry, NETIO_IF_ENTRY_SIZE, &Returned)) ||
            Returned < FIELD_OFFSET(IFEntry, if_descr) || Entry->if_index == 0)
        {
            continue;
        }
        Entry->if_descrlen = min(Entry->if_descrlen, NETIO_MAX_DESCRIPTION);
        Entry->if_descr[Entry->if_descrlen] = 0;
        Found++;
    }

    *Entries = Buffer;
    *Count = Found;
    Buffer = NULL;
    Status = STATUS_SUCCESS;

Done:
    if (Buffer)
        ExFreePoolWithTag(Buffer, NETIO_IPHLP_TAG);
    if (Entities)
        ExFreePoolWithTag(Entities, NETIO_IPHLP_TAG);
    ZwClose(Tcp);
    return Status;
}

static
IFEntry *
NetioFindInterface(
    _In_ PUCHAR Entries,
    _In_ ULONG Count,
    _In_ ULONG Index)
{
    ULONG i;

    for (i = 0; i < Count; i++)
    {
        IFEntry *Entry = (IFEntry *)(Entries + i * NETIO_IF_ENTRY_SIZE);

        if (Entry->if_index == Index)
            return Entry;
    }
    return NULL;
}

static
NTSTATUS
NetioQueryIp6Table(
    _In_ ULONG TableId,
    _Outptr_ PIP6_TABLE_HEADER *Table)
{
    PIP6_TABLE_HEADER Header;
    ULONG Size = sizeof(IP6_TABLE_HEADER) + 32 * 128;
    NTSTATUS Status;

    *Table = NULL;
    for (;;)
    {
        Header = ExAllocatePoolWithTag(PagedPool, Size, NETIO_IPHLP_TAG);
        if (Header == NULL)
            return STATUS_INSUFFICIENT_RESOURCES;
        *(PULONG)Header = TableId;
        Status = NetioDeviceIoControl(L"\\Device\\Ip6", IOCTL_IP6_QUERY_TABLE, Header, sizeof(ULONG), Header, Size);
        if (NT_SUCCESS(Status) && Header->Needed <= Size)
        {
            *Table = Header;
            return STATUS_SUCCESS;
        }
        if ((NT_SUCCESS(Status) || Status == STATUS_BUFFER_OVERFLOW || Status == STATUS_BUFFER_TOO_SMALL) &&
            Header->Needed > Size)
        {
            Size = Header->Needed;
            ExFreePoolWithTag(Header, NETIO_IPHLP_TAG);
            continue;
        }
        ExFreePoolWithTag(Header, NETIO_IPHLP_TAG);
        return Status;
    }
}

static
VOID
NetioDefaultZoneIndices(
    _Out_writes_(ScopeLevelCount) PULONG Zones,
    _In_ ULONG Index,
    _In_ BOOLEAN Loopback)
{
    ULONG Level;

    for (Level = 0; Level < ScopeLevelCount; Level++)
        Zones[Level] = (Level < ScopeLevelAdmin && !Loopback) ? Index : 1;
    Zones[ScopeLevelGlobal] = 0;
}

static
VOID
NetioFillIpInterface4(
    _In_ const IFEntry *Entry,
    _In_ const IP4_INTERFACE_INFO *Info,
    _Out_ PMIB_IPINTERFACE_ROW Row)
{
    BOOLEAN Loopback = Entry->if_type == IF_TYPE_SOFTWARE_LOOPBACK;
    ULONG Level;

    RtlZeroMemory(Row, sizeof(*Row));
    Row->Family = AF_INET;
    Row->InterfaceLuid = NetioInterfaceLuid(Entry->if_index, Entry->if_type);
    Row->InterfaceIndex = Entry->if_index;
    Row->MaxReassemblySize = 0xFFFF;
    Row->ForwardingEnabled = Info->Forwarding;
    Row->WeakHostSend = Info->WeakHostSend;
    Row->WeakHostReceive = Info->WeakHostReceive;
    Row->UseAutomaticMetric = Info->UseAutomaticMetric;
    Row->UseNeighborUnreachabilityDetection = TRUE;
    Row->ManagedAddressConfigurationSupported = TRUE;
    Row->OtherStatefulConfigurationSupported = TRUE;
    Row->AdvertiseDefaultRoute = Info->AdvertiseDefaultRoute;
    Row->RouterDiscoveryBehavior = (NL_ROUTER_DISCOVERY_BEHAVIOR)Info->RouterDiscoveryBehavior;
    Row->DadTransmits = Loopback ? 0 : Info->DadTransmits;
    Row->BaseReachableTime = Info->BaseReachableTime;
    Row->RetransmitTime = Info->RetransmitTime;
    Row->PathMtuDiscoveryTimeout = Info->PathMtuDiscoveryTimeout;
    Row->LinkLocalAddressBehavior = LinkLocalDelayed;
    Row->LinkLocalAddressTimeout = Info->LinkLocalAddressTimeout;
    NetioDefaultZoneIndices(Row->ZoneIndices, Entry->if_index, Loopback);
    for (Level = 0; Level < ScopeLevelCount; Level++)
    {
        if (Info->ZoneIndices[Level])
            Row->ZoneIndices[Level] = Info->ZoneIndices[Level];
    }
    Row->SitePrefixLength = Info->SitePrefixLength;
    Row->Metric = Info->Metric;
    Row->NlMtu = Loopback ? ~0UL : Info->Mtu;
    Row->Connected = NetioOperStatus(Entry->if_operstatus) == IfOperStatusUp;
    Row->SupportsNeighborDiscovery = !Loopback;
    Row->SupportsRouterDiscovery = !Loopback;
    Row->ReachableTime = Info->ReachableTime;
    Row->DisableDefaultRoutes = Info->DisableDefaultRoutes;
}

static
VOID
NetioFillIpInterface6(
    _In_ const IP6_INTERFACE_ROW *Interface,
    _In_ ULONG Type,
    _Out_ PMIB_IPINTERFACE_ROW Row)
{
    ULONG Level;

    RtlZeroMemory(Row, sizeof(*Row));
    Row->Family = AF_INET6;
    Row->InterfaceLuid = NetioInterfaceLuid(Interface->Index, Type);
    Row->InterfaceIndex = Interface->Index;
    Row->MaxReassemblySize = 0xFFFF;
    Row->AdvertisingEnabled = Interface->Advertising;
    Row->ForwardingEnabled = Interface->Forwarding;
    Row->WeakHostSend = Interface->WeakHostSend;
    Row->WeakHostReceive = Interface->WeakHostReceive;
    Row->UseAutomaticMetric = Interface->UseAutomaticMetric;
    Row->UseNeighborUnreachabilityDetection = TRUE;
    Row->ManagedAddressConfigurationSupported = Interface->ManagedAddressConfiguration;
    Row->OtherStatefulConfigurationSupported = Interface->OtherStatefulConfiguration;
    Row->AdvertiseDefaultRoute = Interface->AdvertiseDefaultRoute;
    Row->RouterDiscoveryBehavior = (NL_ROUTER_DISCOVERY_BEHAVIOR)Interface->RouterDiscoveryBehavior;
    Row->DadTransmits = Interface->DadTransmits;
    Row->BaseReachableTime = Interface->BaseReachableTime;
    Row->RetransmitTime = Interface->RetransmitTime;
    Row->PathMtuDiscoveryTimeout = Interface->PathMtuDiscoveryTimeout;
    Row->LinkLocalAddressBehavior = LinkLocalAlwaysOn;
    Row->LinkLocalAddressTimeout = Interface->LinkLocalAddressTimeout;
    NetioDefaultZoneIndices(Row->ZoneIndices, Interface->Index, Interface->Loopback);
    for (Level = 0; Level < ScopeLevelCount; Level++)
    {
        if (Interface->ZoneIndices[Level])
            Row->ZoneIndices[Level] = Interface->ZoneIndices[Level];
    }
    Row->SitePrefixLength = Interface->SitePrefixLength;
    Row->Metric = Interface->Metric;
    Row->NlMtu = Interface->Loopback ? ~0UL : Interface->Mtu;
    Row->Connected = Interface->Connected;
    Row->SupportsNeighborDiscovery = !Interface->Loopback;
    Row->SupportsRouterDiscovery = !Interface->Loopback;
    Row->ReachableTime = Interface->ReachableTime;
    Row->DisableDefaultRoutes = Interface->DisableDefaultRoutes;
}

static
NTSTATUS
NetioQueryIpInterfaces(
    _In_ ADDRESS_FAMILY Family,
    _In_ BOOLEAN Complete,
    _Outptr_result_maybenull_ PMIB_IPINTERFACE_ROW *Rows,
    _Out_ PULONG Count)
{
    PIP6_TABLE_HEADER Table = NULL;
    PMIB_IPINTERFACE_ROW Result = NULL;
    PUCHAR Entries;
    ULONG EntryCount, i, Found = 0;
    NTSTATUS Status;

    *Rows = NULL;
    *Count = 0;

    Status = NetioQueryInterfaces(&Entries, &EntryCount);
    if (!NT_SUCCESS(Status))
        return Status;

    if (Family == AF_INET6)
    {
        Status = NetioQueryIp6Table(Ip6TableInterfaces, &Table);
        if (!NT_SUCCESS(Status))
            goto Done;
    }

    i = (Family == AF_INET6) ? Table->Count : EntryCount;
    Result = ExAllocatePoolWithTag(PagedPool, max(i, 1) * sizeof(MIB_IPINTERFACE_ROW), NETIO_IPHLP_TAG);
    if (Result == NULL)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Done;
    }

    if (Family == AF_INET6)
    {
        const IP6_INTERFACE_ROW *Interfaces = (const IP6_INTERFACE_ROW *)(Table + 1);

        for (i = 0; i < Table->Count; i++)
        {
            IFEntry *Entry = NetioFindInterface(Entries, EntryCount, Interfaces[i].Index);
            ULONG Type = Entry ? Entry->if_type :
                         (Interfaces[i].Loopback ? IF_TYPE_SOFTWARE_LOOPBACK : IF_TYPE_OTHER);

            NetioFillIpInterface6(&Interfaces[i], Type, &Result[Found++]);
        }
    }
    else
    {
        for (i = 0; i < EntryCount; i++)
        {
            IFEntry *Entry = (IFEntry *)(Entries + i * NETIO_IF_ENTRY_SIZE);
            IP4_INTERFACE_INFO Info;

            RtlZeroMemory(&Info, sizeof(Info));
            Info.Index = Entry->if_index;
            Status = NetioDeviceIoControl(L"\\Device\\Ip", IOCTL_IP_QUERY_INTERFACE,
                                          &Info, sizeof(Info), &Info, sizeof(Info));
            if (!NT_SUCCESS(Status))
            {
                /* An interface removed since the enumeration is left out */
                if (Complete)
                    goto Done;
                continue;
            }
            NetioFillIpInterface4(Entry, &Info, &Result[Found++]);
        }
    }

    *Rows = Result;
    *Count = Found;
    Result = NULL;
    Status = STATUS_SUCCESS;

Done:
    if (Result)
        ExFreePoolWithTag(Result, NETIO_IPHLP_TAG);
    if (Table)
        ExFreePoolWithTag(Table, NETIO_IPHLP_TAG);
    if (Entries)
        ExFreePoolWithTag(Entries, NETIO_IPHLP_TAG);
    return Status;
}

NTSTATUS
NTAPI
GetIfEntry2(
    _Inout_ PMIB_IF_ROW2 Row)
{
    PUCHAR Entries;
    IFEntry *Entry;
    ULONG Count, Index, Length, i;
    BOOLEAN Loopback;
    NTSTATUS Status;

    if (Row == NULL)
        return STATUS_INVALID_PARAMETER;
    Index = Row->InterfaceLuid.Value ? NetioLuidIndex(&Row->InterfaceLuid) : Row->InterfaceIndex;
    if (Index == 0)
        return Row->InterfaceLuid.Value ? STATUS_NOT_FOUND : STATUS_INVALID_PARAMETER;

    Status = NetioQueryInterfaces(&Entries, &Count);
    if (!NT_SUCCESS(Status))
        return Status;

    Entry = NetioFindInterface(Entries, Count, Index);
    if (Entry == NULL || (Row->InterfaceLuid.Value && Row->InterfaceLuid.Info.IfType != Entry->if_type))
    {
        Status = STATUS_NOT_FOUND;
        goto Done;
    }

    Loopback = Entry->if_type == IF_TYPE_SOFTWARE_LOOPBACK;
    RtlZeroMemory(Row, sizeof(*Row));
    Row->InterfaceLuid = NetioInterfaceLuid(Entry->if_index, Entry->if_type);
    Row->InterfaceIndex = Entry->if_index;
    Length = min(Entry->if_descrlen, IF_MAX_STRING_SIZE);
    for (i = 0; i < Length && Entry->if_descr[i]; i++)
        Row->Alias[i] = Row->Description[i] = Entry->if_descr[i];
    Row->PhysicalAddressLength = min(Entry->if_physaddrlen, MAX_PHYSADDR_SIZE);
    RtlCopyMemory(Row->PhysicalAddress, Entry->if_physaddr, Row->PhysicalAddressLength);
    RtlCopyMemory(Row->PermanentPhysicalAddress, Entry->if_physaddr, Row->PhysicalAddressLength);
    Row->Mtu = Entry->if_mtu;
    Row->Type = Entry->if_type;
    Row->TunnelType = TUNNEL_TYPE_NONE;
    Row->MediaType = NdisMedium802_3;
    Row->PhysicalMediumType = NdisPhysicalMediumUnspecified;
    Row->AccessType = Loopback ? NET_IF_ACCESS_LOOPBACK : NET_IF_ACCESS_BROADCAST;
    Row->DirectionType = NET_IF_DIRECTION_SENDRECEIVE;
    Row->InterfaceAndOperStatusFlags.HardwareInterface = !Loopback;
    Row->InterfaceAndOperStatusFlags.ConnectorPresent = !Loopback;
    Row->OperStatus = NetioOperStatus(Entry->if_operstatus);
    Row->InterfaceAndOperStatusFlags.NotMediaConnected = Row->OperStatus != IfOperStatusUp;
    Row->AdminStatus = (Entry->if_adminstatus == 2) ? NET_IF_ADMIN_STATUS_DOWN : NET_IF_ADMIN_STATUS_UP;
    Row->MediaConnectState = (Row->OperStatus == IfOperStatusUp) ? MediaConnectStateConnected :
                                                                   MediaConnectStateDisconnected;
    Row->ConnectionType = NET_IF_CONNECTION_DEDICATED;
    Row->TransmitLinkSpeed = Row->ReceiveLinkSpeed = Entry->if_speed;
    Row->InOctets = Row->InUcastOctets = Entry->if_inoctets;
    Row->InUcastPkts = Entry->if_inucastpkts;
    Row->InNUcastPkts = Entry->if_innucastpkts;
    Row->InDiscards = Entry->if_indiscards;
    Row->InErrors = Entry->if_inerrors;
    Row->InUnknownProtos = Entry->if_inunknownprotos;
    Row->OutOctets = Row->OutUcastOctets = Entry->if_outoctets;
    Row->OutUcastPkts = Entry->if_outucastpkts;
    Row->OutNUcastPkts = Entry->if_outnucastpkts;
    Row->OutDiscards = Entry->if_outdiscards;
    Row->OutErrors = Entry->if_outerrors;
    Row->OutQLen = Entry->if_outqlen;
    Status = STATUS_SUCCESS;

Done:
    ExFreePoolWithTag(Entries, NETIO_IPHLP_TAG);
    return Status;
}

NTSTATUS
NTAPI
GetIpInterfaceEntry(
    _Inout_ PMIB_IPINTERFACE_ROW Row)
{
    PMIB_IPINTERFACE_ROW Rows;
    ULONG Count, Index, i;
    NTSTATUS Status;

    if (Row == NULL || (Row->Family != AF_INET && Row->Family != AF_INET6))
        return STATUS_INVALID_PARAMETER;
    Index = Row->InterfaceLuid.Value ? NetioLuidIndex(&Row->InterfaceLuid) : Row->InterfaceIndex;
    if (Index == 0)
        return Row->InterfaceLuid.Value ? STATUS_NOT_FOUND : STATUS_INVALID_PARAMETER;

    Status = NetioQueryIpInterfaces(Row->Family, FALSE, &Rows, &Count);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = STATUS_NOT_FOUND;
    for (i = 0; i < Count; i++)
    {
        if (Rows[i].InterfaceIndex != Index ||
            (Row->InterfaceLuid.Value && Row->InterfaceLuid.Value != Rows[i].InterfaceLuid.Value))
        {
            continue;
        }
        *Row = Rows[i];
        Status = STATUS_SUCCESS;
        break;
    }

    ExFreePoolWithTag(Rows, NETIO_IPHLP_TAG);
    return Status;
}

static
BOOLEAN
NetioValueChanged(
    _In_ ULONG Requested,
    _In_ ULONG Current,
    _In_ BOOLEAN ZeroUnchanged)
{
    if (Requested == NETIO_UNCHANGED_ULONG || (ZeroUnchanged && Requested == 0))
        return FALSE;
    return Requested != Current;
}

static
ULONG
NetioValue(
    _In_ ULONG Requested,
    _In_ ULONG Current,
    _In_ BOOLEAN ZeroUnchanged)
{
    return NetioValueChanged(Requested, Current, ZeroUnchanged) ? Requested : Current;
}

static
BOOLEAN
NetioFlag(
    _In_ BOOLEAN Requested,
    _In_ BOOLEAN Current)
{
    return (Requested == NETIO_UNCHANGED_BOOLEAN) ? Current : !!Requested;
}

static
VOID
NetioZones(
    _In_ const MIB_IPINTERFACE_ROW *Row,
    _In_ const MIB_IPINTERFACE_ROW *Current,
    _Out_writes_(ScopeLevelCount) PULONG Zones)
{
    ULONG Level, Zone;

    for (Level = 0; Level < ScopeLevelCount; Level++)
    {
        Zone = (Row->ZoneIndices[Level] == NETIO_UNCHANGED_ULONG) ? Current->ZoneIndices[Level] :
                                                                    Row->ZoneIndices[Level];
        Zones[Level] = (Zone == Current->ZoneIndices[Level]) ? 0 : Zone;
    }
}

NTSTATUS
NTAPI
SetIpInterfaceEntry(
    _Inout_ PMIB_IPINTERFACE_ROW Row)
{
    MIB_IPINTERFACE_ROW Current;
    BOOLEAN Automatic, Advertising, Managed, Other;
    ULONG Metric;
    NTSTATUS Status;

    if (Row == NULL || (Row->Family != AF_INET && Row->Family != AF_INET6))
        return STATUS_INVALID_PARAMETER;
    if (!Row->InterfaceLuid.Value && !Row->InterfaceIndex)
        return STATUS_INVALID_PARAMETER;

    InitializeIpInterfaceEntry(&Current);
    Current.Family = Row->Family;
    Current.InterfaceLuid = Row->InterfaceLuid;
    Current.InterfaceIndex = Row->InterfaceIndex;
    Status = GetIpInterfaceEntry(&Current);
    if (!NT_SUCCESS(Status))
        return Status;

    if (Row->Family == AF_INET && Row->SitePrefixLength && Row->SitePrefixLength != NETIO_UNCHANGED_ULONG)
        return STATUS_INVALID_PARAMETER;
    if (Row->RouterDiscoveryBehavior != RouterDiscoveryUnchanged &&
        (ULONG)Row->RouterDiscoveryBehavior > RouterDiscoveryDhcp)
        return STATUS_INVALID_PARAMETER;
    if ((Row->UseNeighborUnreachabilityDetection != NETIO_UNCHANGED_BOOLEAN &&
         !Row->UseNeighborUnreachabilityDetection != !Current.UseNeighborUnreachabilityDetection) ||
        NetioValueChanged(Row->LinkLocalAddressBehavior, Current.LinkLocalAddressBehavior, FALSE))
        return STATUS_INVALID_PARAMETER;
    if (Row->NlMtu && Row->NlMtu != NETIO_UNCHANGED_ULONG &&
        Row->NlMtu < (Row->Family == AF_INET6 ? 1280UL : 576UL))
        return STATUS_INVALID_PARAMETER;

    Advertising = NetioFlag(Row->AdvertisingEnabled, Current.AdvertisingEnabled);
    Managed = NetioFlag(Row->ManagedAddressConfigurationSupported, Current.ManagedAddressConfigurationSupported);
    Other = NetioFlag(Row->OtherStatefulConfigurationSupported, Current.OtherStatefulConfigurationSupported);
    if (Row->Family == AF_INET && Advertising)
        return STATUS_INVALID_PARAMETER;
    /* FIXME: the DHCPv6 flags of an IPv4 row are not kept */
    if (Row->Family == AF_INET6 && !Advertising && !Current.AdvertisingEnabled &&
        (Managed != Current.ManagedAddressConfigurationSupported ||
         Other != Current.OtherStatefulConfigurationSupported))
        return STATUS_INVALID_PARAMETER;

    Automatic = NetioFlag(Row->UseAutomaticMetric, Current.UseAutomaticMetric);
    if (Automatic)
        Metric = 0;
    else if (Row->Metric == NETIO_UNCHANGED_ULONG ||
             (Row->UseAutomaticMetric == NETIO_UNCHANGED_BOOLEAN && Current.UseAutomaticMetric))
        Metric = Current.Metric;
    else
        Metric = Row->Metric;

    if (Row->Family == AF_INET)
    {
        IP4_INTERFACE_INFO Set;

        RtlZeroMemory(&Set, sizeof(Set));
        Set.Index = Current.InterfaceIndex;
        Set.UseAutomaticMetric = Automatic;
        Set.Metric = Metric;
        Set.Mtu = NetioValue(Row->NlMtu, Current.NlMtu, TRUE);
        Set.RetransmitTime = NetioValue(Row->RetransmitTime, Current.RetransmitTime, TRUE);
        Set.BaseReachableTime = NetioValue(Row->BaseReachableTime, Current.BaseReachableTime, TRUE);
        Set.DadTransmits = NetioValue(Row->DadTransmits, Current.DadTransmits, FALSE);
        Set.RouterDiscoveryBehavior = NetioValue(Row->RouterDiscoveryBehavior, Current.RouterDiscoveryBehavior, FALSE);
        Set.PathMtuDiscoveryTimeout = NetioValue(Row->PathMtuDiscoveryTimeout, Current.PathMtuDiscoveryTimeout, TRUE);
        Set.LinkLocalAddressTimeout = NetioValue(Row->LinkLocalAddressTimeout, Current.LinkLocalAddressTimeout, FALSE);
        Set.SitePrefixLength = (Row->SitePrefixLength == NETIO_UNCHANGED_ULONG) ? Current.SitePrefixLength : 0;
        NetioZones(Row, &Current, Set.ZoneIndices);
        Set.Forwarding = NetioFlag(Row->ForwardingEnabled, Current.ForwardingEnabled);
        Set.WeakHostSend = NetioFlag(Row->WeakHostSend, Current.WeakHostSend);
        Set.WeakHostReceive = NetioFlag(Row->WeakHostReceive, Current.WeakHostReceive);
        Set.DisableDefaultRoutes = NetioFlag(Row->DisableDefaultRoutes, Current.DisableDefaultRoutes);
        Set.AdvertiseDefaultRoute = NetioFlag(Row->AdvertiseDefaultRoute, Current.AdvertiseDefaultRoute);
        Status = NetioDeviceIoControl(L"\\Device\\Ip", IOCTL_IP_SET_INTERFACE, &Set, sizeof(Set), NULL, 0);
    }
    else
    {
        IP6_INTERFACE_SET Set;

        RtlZeroMemory(&Set, sizeof(Set));
        Set.Index = Current.InterfaceIndex;
        Set.UseAutomaticMetric = Automatic;
        Set.Metric = Metric;
        Set.Mtu = (!Row->NlMtu || Row->NlMtu == NETIO_UNCHANGED_ULONG) ? 0 : Row->NlMtu;
        Set.RouterDiscoveryBehavior = NetioValue(Row->RouterDiscoveryBehavior, Current.RouterDiscoveryBehavior, FALSE);
        Set.RouterDiscovery = Set.RouterDiscoveryBehavior != RouterDiscoveryDisabled;
        Set.DadTransmits = NetioValue(Row->DadTransmits, Current.DadTransmits, FALSE);
        Set.BaseReachableTime = NetioValue(Row->BaseReachableTime, Current.BaseReachableTime, TRUE);
        Set.RetransmitTime = NetioValue(Row->RetransmitTime, Current.RetransmitTime, TRUE);
        Set.SitePrefixLength = NetioValue(Row->SitePrefixLength, Current.SitePrefixLength, FALSE);
        Set.PathMtuDiscoveryTimeout = NetioValue(Row->PathMtuDiscoveryTimeout, Current.PathMtuDiscoveryTimeout, TRUE);
        Set.LinkLocalAddressTimeout = NetioValue(Row->LinkLocalAddressTimeout, Current.LinkLocalAddressTimeout, FALSE);
        NetioZones(Row, &Current, Set.ZoneIndices);
        Set.Forwarding = NetioFlag(Row->ForwardingEnabled, Current.ForwardingEnabled);
        Set.WeakHostSend = NetioFlag(Row->WeakHostSend, Current.WeakHostSend);
        Set.WeakHostReceive = NetioFlag(Row->WeakHostReceive, Current.WeakHostReceive);
        Set.Advertising = Advertising;
        Set.AdvertiseDefaultRoute = NetioFlag(Row->AdvertiseDefaultRoute, Current.AdvertiseDefaultRoute);
        Set.DisableDefaultRoutes = NetioFlag(Row->DisableDefaultRoutes, Current.DisableDefaultRoutes);
        Set.ManagedAddressConfiguration = Managed;
        Set.OtherStatefulConfiguration = Other;
        if (Set.SitePrefixLength > 128)
            return STATUS_INVALID_PARAMETER;
        Status = NetioDeviceIoControl(L"\\Device\\Ip6", IOCTL_IP6_SET_INTERFACE, &Set, sizeof(Set), NULL, 0);
    }

    if (NT_SUCCESS(Status))
        Row->InterfaceLuid = Current.InterfaceLuid;
    return Status;
}

static
NTSTATUS
NetioQueryRoutes4(
    _In_ PUCHAR Entries,
    _In_ ULONG EntryCount,
    _In_ BOOLEAN Complete,
    _Inout_ PMIB_IPFORWARD_ROW2 *Rows,
    _Inout_ PULONG Count,
    _Inout_ PULONG Capacity)
{
    TDIEntityID *Entities;
    PNETIO_TDI_ROUTE Routes = NULL;
    PMIB_IPFORWARD_ROW2 Grown, Row;
    IPSNMPInfo Snmp;
    IFEntry *Entry;
    ULONG Returned, EntityCount, RouteCount, Size, i, j;
    NTSTATUS Status;
    HANDLE Tcp;

    Status = NetioOpenDevice(L"\\Device\\Tcp", &Tcp);
    if (!NT_SUCCESS(Status))
        return Status;

    Entities = ExAllocatePoolWithTag(PagedPool, NETIO_MAX_ENTITIES * sizeof(TDIEntityID), NETIO_IPHLP_TAG);
    if (Entities == NULL)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Done;
    }
    Status = NetioTcpQuery(Tcp, GENERIC_ENTITY, 0, INFO_CLASS_GENERIC, ENTITY_LIST_ID,
                           Entities, NETIO_MAX_ENTITIES * sizeof(TDIEntityID), &Returned);
    if (!NT_SUCCESS(Status))
        goto Done;
    EntityCount = Returned / sizeof(TDIEntityID);

    for (i = 0; i < EntityCount; i++)
    {
        if (Entities[i].tei_entity != CL_NL_ENTITY)
            continue;

        RtlZeroMemory(&Snmp, sizeof(Snmp));
        Status = NetioTcpQuery(Tcp, CL_NL_ENTITY, Entities[i].tei_instance, INFO_CLASS_PROTOCOL,
                               IP_MIB_STATS_ID, &Snmp, sizeof(Snmp), &Returned);
        if (!NT_SUCCESS(Status))
        {
            if (Complete)
                goto Done;
            continue;
        }
        Size = (Snmp.ipsi_numroutes + 16) * sizeof(NETIO_TDI_ROUTE);
        Routes = ExAllocatePoolWithTag(PagedPool, Size, NETIO_IPHLP_TAG);
        if (Routes == NULL)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Done;
        }
        Status = NetioTcpQuery(Tcp, CL_NL_ENTITY, Entities[i].tei_instance, INFO_CLASS_PROTOCOL,
                               IP_MIB_ARPTABLE_ENTRY_ID, Routes, Size, &Returned);
        if (NT_SUCCESS(Status) && Returned > Size)
            Status = STATUS_BUFFER_OVERFLOW;
        if (!NT_SUCCESS(Status))
        {
            ExFreePoolWithTag(Routes, NETIO_IPHLP_TAG);
            Routes = NULL;
            if (Complete)
                goto Done;
            continue;
        }
        RouteCount = Returned / sizeof(NETIO_TDI_ROUTE);

        if (*Count + RouteCount > *Capacity)
        {
            Grown = ExAllocatePoolWithTag(PagedPool, (*Count + RouteCount) * sizeof(**Rows), NETIO_IPHLP_TAG);
            if (Grown == NULL)
            {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto Done;
            }
            if (*Rows)
            {
                RtlCopyMemory(Grown, *Rows, *Count * sizeof(**Rows));
                ExFreePoolWithTag(*Rows, NETIO_IPHLP_TAG);
            }
            *Rows = Grown;
            *Capacity = *Count + RouteCount;
        }

        for (j = 0; j < RouteCount; j++)
        {
            Row = &(*Rows)[(*Count)++];
            Entry = NetioFindInterface(Entries, EntryCount, Routes[j].Index);
            InitializeIpForwardEntry(Row);
            Row->InterfaceIndex = Routes[j].Index;
            Row->InterfaceLuid = NetioInterfaceLuid(Routes[j].Index, Entry ? Entry->if_type : IF_TYPE_OTHER);
            Row->DestinationPrefix.Prefix.si_family = AF_INET;
            Row->DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = Routes[j].Dest & Routes[j].Mask;
            Row->DestinationPrefix.PrefixLength = (UINT8)NetioPrefixLength(Routes[j].Mask);
            Row->NextHop.si_family = AF_INET;
            Row->NextHop.Ipv4.sin_addr.s_addr = (Routes[j].Type == NETIO_ROUTE_TYPE_DIRECT) ? 0 : Routes[j].NextHop;
            Row->SitePrefixLength = 0;
            Row->Metric = Routes[j].Metric1;
            Row->Protocol = (NL_ROUTE_PROTOCOL)Routes[j].Proto;
            Row->Loopback = (Routes[j].Dest & 0xFF) == 127;
            Row->AutoconfigureAddress = FALSE;
            Row->Publish = FALSE;
            Row->Immortal = TRUE;
            Row->Age = Routes[j].Age;
            Row->Origin = (Routes[j].Proto == MIB_IPPROTO_LOCAL) ? NlroWellKnown : NlroManual;
        }

        ExFreePoolWithTag(Routes, NETIO_IPHLP_TAG);
        Routes = NULL;
    }
    Status = STATUS_SUCCESS;

Done:
    if (Routes)
        ExFreePoolWithTag(Routes, NETIO_IPHLP_TAG);
    if (Entities)
        ExFreePoolWithTag(Entities, NETIO_IPHLP_TAG);
    ZwClose(Tcp);
    return Status;
}

static
NTSTATUS
NetioQueryRoutes6(
    _In_ PUCHAR Entries,
    _In_ ULONG EntryCount,
    _Inout_ PMIB_IPFORWARD_ROW2 *Rows,
    _Inout_ PULONG Count,
    _Inout_ PULONG Capacity)
{
    PIP6_TABLE_HEADER Table;
    const IP6_ROUTE_ROW *Routes;
    PMIB_IPFORWARD_ROW2 Grown, Row;
    IFEntry *Entry;
    NTSTATUS Status;
    ULONG i;

    Status = NetioQueryIp6Table(Ip6TableRoutes, &Table);
    if (!NT_SUCCESS(Status))
        return Status;
    Routes = (const IP6_ROUTE_ROW *)(Table + 1);

    if (*Count + Table->Count > *Capacity)
    {
        Grown = ExAllocatePoolWithTag(PagedPool, max(*Count + Table->Count, 1) * sizeof(**Rows), NETIO_IPHLP_TAG);
        if (Grown == NULL)
        {
            ExFreePoolWithTag(Table, NETIO_IPHLP_TAG);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        if (*Rows)
        {
            RtlCopyMemory(Grown, *Rows, *Count * sizeof(**Rows));
            ExFreePoolWithTag(*Rows, NETIO_IPHLP_TAG);
        }
        *Rows = Grown;
        *Capacity = *Count + Table->Count;
    }

    for (i = 0; i < Table->Count; i++)
    {
        Row = &(*Rows)[(*Count)++];
        Entry = NetioFindInterface(Entries, EntryCount, Routes[i].Index);
        InitializeIpForwardEntry(Row);
        Row->InterfaceIndex = Routes[i].Index;
        Row->InterfaceLuid = NetioInterfaceLuid(Routes[i].Index, Entry ? Entry->if_type :
                                                (Routes[i].Loopback ? IF_TYPE_SOFTWARE_LOOPBACK : IF_TYPE_OTHER));
        Row->DestinationPrefix.Prefix.si_family = AF_INET6;
        RtlCopyMemory(&Row->DestinationPrefix.Prefix.Ipv6.sin6_addr, Routes[i].Prefix, sizeof(Routes[i].Prefix));
        Row->DestinationPrefix.PrefixLength = (UINT8)Routes[i].PrefixLength;
        Row->NextHop.si_family = AF_INET6;
        RtlCopyMemory(&Row->NextHop.Ipv6.sin6_addr, Routes[i].NextHop, sizeof(Routes[i].NextHop));
        Row->SitePrefixLength = 0;
        Row->ValidLifetime = Routes[i].ValidLifetime;
        Row->PreferredLifetime = Routes[i].PreferredLifetime;
        Row->Metric = Routes[i].Metric;
        Row->Protocol = (NL_ROUTE_PROTOCOL)Routes[i].Protocol;
        Row->Loopback = Routes[i].Loopback;
        Row->AutoconfigureAddress = Routes[i].Autoconfigure;
        Row->Publish = Routes[i].Publish;
        Row->Immortal = Routes[i].Immortal;
        Row->Age = 0;
        Row->Origin = (NL_ROUTE_ORIGIN)Routes[i].Origin;
    }

    ExFreePoolWithTag(Table, NETIO_IPHLP_TAG);
    return STATUS_SUCCESS;
}

static
NTSTATUS
NetioQueryRoutes(
    _In_ ADDRESS_FAMILY Family,
    _In_ BOOLEAN Complete,
    _Outptr_result_maybenull_ PMIB_IPFORWARD_ROW2 *Rows,
    _Out_ PULONG Count)
{
    PMIB_IPFORWARD_ROW2 Result = NULL;
    ULONG Found = 0, Capacity = 0, EntryCount;
    PUCHAR Entries;
    NTSTATUS Status;

    *Rows = NULL;
    *Count = 0;

    Status = NetioQueryInterfaces(&Entries, &EntryCount);
    if (!NT_SUCCESS(Status))
        return Status;

    if (Family == AF_INET || Family == AF_UNSPEC)
        Status = NetioQueryRoutes4(Entries, EntryCount, Complete, &Result, &Found, &Capacity);
    if (NT_SUCCESS(Status) && (Family == AF_INET6 || Family == AF_UNSPEC))
    {
        Status = NetioQueryRoutes6(Entries, EntryCount, &Result, &Found, &Capacity);
        if (Status == STATUS_OBJECT_NAME_NOT_FOUND && Family == AF_UNSPEC)
            Status = STATUS_SUCCESS;
    }

    ExFreePoolWithTag(Entries, NETIO_IPHLP_TAG);
    if (!NT_SUCCESS(Status))
    {
        if (Result)
            ExFreePoolWithTag(Result, NETIO_IPHLP_TAG);
        return Status;
    }

    *Rows = Result;
    *Count = Found;
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
GetIpForwardTable2(
    _In_ ADDRESS_FAMILY Family,
    _Outptr_ PMIB_IPFORWARD_TABLE2 *Table)
{
    PMIB_IPFORWARD_TABLE2 Result;
    PMIB_IPFORWARD_ROW2 Rows;
    ULONG Count;
    NTSTATUS Status;

    if (Table == NULL)
        return STATUS_INVALID_PARAMETER;
    *Table = NULL;
    if (Family != AF_INET && Family != AF_INET6 && Family != AF_UNSPEC)
        return STATUS_INVALID_PARAMETER;

    Status = NetioQueryRoutes(Family, FALSE, &Rows, &Count);
    if (!NT_SUCCESS(Status))
        return Status;

    Result = ExAllocatePoolWithTag(PagedPool, FIELD_OFFSET(MIB_IPFORWARD_TABLE2, Table[max(Count, 1)]),
                                   NETIO_IPHLP_TAG);
    if (Result == NULL)
    {
        if (Rows)
            ExFreePoolWithTag(Rows, NETIO_IPHLP_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    Result->NumEntries = Count;
    if (Count)
        RtlCopyMemory(Result->Table, Rows, Count * sizeof(*Rows));
    if (Rows)
        ExFreePoolWithTag(Rows, NETIO_IPHLP_TAG);

    *Table = Result;
    return STATUS_SUCCESS;
}

#define NETIO_CHANGE_ROUTE      1
#define NETIO_CHANGE_INTERFACE  2

typedef struct _NETIO_CHANGE_NOTIFY
{
    LIST_ENTRY Link;
    ULONG Kind;
    ADDRESS_FAMILY Family;
    PVOID Callback;
    PVOID Context;
    LONG References;
    BOOLEAN Linked;
    BOOLEAN InitialPending;
    BOOLEAN FreeOnRelease;
    KEVENT Released;
} NETIO_CHANGE_NOTIFY, *PNETIO_CHANGE_NOTIFY;

static LIST_ENTRY NetioChangeList = { &NetioChangeList, &NetioChangeList };
static KSPIN_LOCK NetioChangeLock;
#define NETIO_CHANGE_STOPPED 0
#define NETIO_CHANGE_STARTING 1
#define NETIO_CHANGE_RUNNING 2
static volatile LONG NetioChangeState;
static KEVENT NetioChangeKick;
static PETHREAD NetioChangeThread;

static
VOID
NetioReleaseNotify(
    _In_ PNETIO_CHANGE_NOTIFY Notify)
{
    if (InterlockedDecrement(&Notify->References) != 0)
        return;
    if (Notify->FreeOnRelease)
        ExFreePoolWithTag(Notify, NETIO_IPHLP_TAG);
    else
        KeSetEvent(&Notify->Released, IO_NO_INCREMENT, FALSE);
}

static
VOID
NetioNotify(
    _In_ ULONG Kind,
    _In_ ADDRESS_FAMILY Family,
    _In_opt_ const VOID *Row,
    _In_ MIB_NOTIFICATION_TYPE Type,
    _In_ BOOLEAN InitialOnly)
{
    PNETIO_CHANGE_NOTIFY *Targets;
    PLIST_ENTRY Entry;
    ULONG Count = 0, Capacity = 0, i;
    MIB_IPFORWARD_ROW2 Route;
    MIB_IPINTERFACE_ROW Interface;
    KIRQL OldIrql;

    KeAcquireSpinLock(&NetioChangeLock, &OldIrql);
    for (Entry = NetioChangeList.Flink; Entry != &NetioChangeList; Entry = Entry->Flink)
        Capacity++;
    KeReleaseSpinLock(&NetioChangeLock, OldIrql);
    if (Capacity == 0)
        return;

    Targets = ExAllocatePoolWithTag(NonPagedPool, Capacity * sizeof(*Targets), NETIO_IPHLP_TAG);
    if (Targets == NULL)
        return;

    KeAcquireSpinLock(&NetioChangeLock, &OldIrql);
    for (Entry = NetioChangeList.Flink; Entry != &NetioChangeList && Count < Capacity; Entry = Entry->Flink)
    {
        PNETIO_CHANGE_NOTIFY Notify = CONTAINING_RECORD(Entry, NETIO_CHANGE_NOTIFY, Link);

        if (InitialOnly)
        {
            if (!Notify->InitialPending)
                continue;
            Notify->InitialPending = FALSE;
        }
        else if (Notify->Kind != Kind || (Notify->Family != AF_UNSPEC && Notify->Family != Family))
        {
            continue;
        }
        InterlockedIncrement(&Notify->References);
        Targets[Count++] = Notify;
    }
    KeReleaseSpinLock(&NetioChangeLock, OldIrql);

    for (i = 0; i < Count; i++)
    {
        if (InitialOnly)
        {
            if (Targets[i]->Kind == NETIO_CHANGE_ROUTE)
                ((PIPFORWARD_CHANGE_CALLBACK)Targets[i]->Callback)(Targets[i]->Context, NULL, MibInitialNotification);
            else
                ((PIPINTERFACE_CHANGE_CALLBACK)Targets[i]->Callback)(Targets[i]->Context, NULL, MibInitialNotification);
        }
        else if (Kind == NETIO_CHANGE_ROUTE)
        {
            Route = *(const MIB_IPFORWARD_ROW2 *)Row;
            ((PIPFORWARD_CHANGE_CALLBACK)Targets[i]->Callback)(Targets[i]->Context, &Route, Type);
        }
        else
        {
            Interface = *(const MIB_IPINTERFACE_ROW *)Row;
            ((PIPINTERFACE_CHANGE_CALLBACK)Targets[i]->Callback)(Targets[i]->Context, &Interface, Type);
        }
        NetioReleaseNotify(Targets[i]);
    }

    ExFreePoolWithTag(Targets, NETIO_IPHLP_TAG);
}

static
BOOLEAN
NetioSameRoute(
    _In_ const MIB_IPFORWARD_ROW2 *Left,
    _In_ const MIB_IPFORWARD_ROW2 *Right)
{
    return Left->InterfaceIndex == Right->InterfaceIndex &&
           Left->DestinationPrefix.PrefixLength == Right->DestinationPrefix.PrefixLength &&
           RtlEqualMemory(&Left->DestinationPrefix.Prefix, &Right->DestinationPrefix.Prefix, sizeof(SOCKADDR_INET)) &&
           RtlEqualMemory(&Left->NextHop, &Right->NextHop, sizeof(SOCKADDR_INET));
}

static
BOOLEAN
NetioRouteChanged(
    _In_ const MIB_IPFORWARD_ROW2 *Left,
    _In_ const MIB_IPFORWARD_ROW2 *Right)
{
    MIB_IPFORWARD_ROW2 A = *Left, B = *Right;

    A.Age = B.Age = 0;
    A.ValidLifetime = B.ValidLifetime = 0;
    A.PreferredLifetime = B.PreferredLifetime = 0;
    return !RtlEqualMemory(&A, &B, sizeof(A));
}

static
BOOLEAN
NetioInterfaceChanged(
    _In_ const MIB_IPINTERFACE_ROW *Left,
    _In_ const MIB_IPINTERFACE_ROW *Right)
{
    MIB_IPINTERFACE_ROW A = *Left, B = *Right;

    A.ReachableTime = B.ReachableTime = 0;
    return !RtlEqualMemory(&A, &B, sizeof(A));
}

static
VOID
NetioCompareRoutes(
    _In_reads_(OldCount) const MIB_IPFORWARD_ROW2 *Old,
    _In_ ULONG OldCount,
    _In_reads_(NewCount) const MIB_IPFORWARD_ROW2 *New,
    _In_ ULONG NewCount)
{
    ULONG i, j;

    for (i = 0; i < NewCount; i++)
    {
        for (j = 0; j < OldCount && !NetioSameRoute(&New[i], &Old[j]); j++);
        if (j == OldCount)
            NetioNotify(NETIO_CHANGE_ROUTE, New[i].DestinationPrefix.Prefix.si_family, &New[i], MibAddInstance, FALSE);
        else if (NetioRouteChanged(&New[i], &Old[j]))
            NetioNotify(NETIO_CHANGE_ROUTE, New[i].DestinationPrefix.Prefix.si_family, &New[i], MibParameterNotification, FALSE);
    }
    for (j = 0; j < OldCount; j++)
    {
        for (i = 0; i < NewCount && !NetioSameRoute(&New[i], &Old[j]); i++);
        if (i == NewCount)
            NetioNotify(NETIO_CHANGE_ROUTE, Old[j].DestinationPrefix.Prefix.si_family, &Old[j], MibDeleteInstance, FALSE);
    }
}

static
VOID
NetioCompareInterfaces(
    _In_reads_(OldCount) const MIB_IPINTERFACE_ROW *Old,
    _In_ ULONG OldCount,
    _In_reads_(NewCount) const MIB_IPINTERFACE_ROW *New,
    _In_ ULONG NewCount)
{
    ULONG i, j;

    for (i = 0; i < NewCount; i++)
    {
        for (j = 0; j < OldCount && Old[j].InterfaceIndex != New[i].InterfaceIndex; j++);
        if (j == OldCount)
            NetioNotify(NETIO_CHANGE_INTERFACE, New[i].Family, &New[i], MibAddInstance, FALSE);
        else if (NetioInterfaceChanged(&New[i], &Old[j]))
            NetioNotify(NETIO_CHANGE_INTERFACE, New[i].Family, &New[i], MibParameterNotification, FALSE);
    }
    for (j = 0; j < OldCount; j++)
    {
        for (i = 0; i < NewCount && Old[j].InterfaceIndex != New[i].InterfaceIndex; i++);
        if (i == NewCount)
            NetioNotify(NETIO_CHANGE_INTERFACE, Old[j].Family, &Old[j], MibDeleteInstance, FALSE);
    }
}

typedef struct _NETIO_SNAPSHOT
{
    PMIB_IPFORWARD_ROW2 Routes;
    ULONG RouteCount;
    PMIB_IPINTERFACE_ROW Interfaces[2];
    ULONG InterfaceCount[2];
} NETIO_SNAPSHOT, *PNETIO_SNAPSHOT;

static
VOID
NetioFreeSnapshot(
    _Inout_ PNETIO_SNAPSHOT Snapshot)
{
    ULONG i;

    if (Snapshot->Routes)
        ExFreePoolWithTag(Snapshot->Routes, NETIO_IPHLP_TAG);
    for (i = 0; i < 2; i++)
    {
        if (Snapshot->Interfaces[i])
            ExFreePoolWithTag(Snapshot->Interfaces[i], NETIO_IPHLP_TAG);
    }
    RtlZeroMemory(Snapshot, sizeof(*Snapshot));
}

static
NTSTATUS
NetioTakeSnapshot(
    _Out_ PNETIO_SNAPSHOT Snapshot)
{
    NTSTATUS Status;

    RtlZeroMemory(Snapshot, sizeof(*Snapshot));
    Status = NetioQueryRoutes(AF_UNSPEC, TRUE, &Snapshot->Routes, &Snapshot->RouteCount);
    if (NT_SUCCESS(Status))
        Status = NetioQueryIpInterfaces(AF_INET, TRUE, &Snapshot->Interfaces[0], &Snapshot->InterfaceCount[0]);
    if (NT_SUCCESS(Status))
    {
        Status = NetioQueryIpInterfaces(AF_INET6, TRUE, &Snapshot->Interfaces[1], &Snapshot->InterfaceCount[1]);
        if (Status == STATUS_OBJECT_NAME_NOT_FOUND)
            Status = STATUS_SUCCESS;
    }
    if (!NT_SUCCESS(Status))
        NetioFreeSnapshot(Snapshot);
    return Status;
}

static
VOID
NTAPI
NetioChangeWorker(
    _In_ PVOID StartContext)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Device\\Ip");
    OBJECT_ATTRIBUTES Attributes;
    NETIO_SNAPSHOT Old, New;
    IO_STATUS_BLOCK Io;
    LARGE_INTEGER Retry;
    HANDLE Ip = NULL, EventHandle = NULL;
    PKEVENT Completed = NULL;
    PVOID Objects[2];
    KWAIT_BLOCK WaitBlocks[2];
    ULONG Generation = 0, i;
    BOOLEAN Pending = FALSE, Changed, HaveOld, Stale = FALSE;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(StartContext);

    NetioChangeThread = PsGetCurrentThread();
    HaveOld = NT_SUCCESS(NetioTakeSnapshot(&Old));
    Retry.QuadPart = -50000000LL;

    for (;;)
    {
        Changed = FALSE;

        if (Completed == NULL)
        {
            if (EventHandle == NULL)
            {
                InitializeObjectAttributes(&Attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
                if (!NT_SUCCESS(ZwCreateEvent(&EventHandle, EVENT_ALL_ACCESS, &Attributes, NotificationEvent, FALSE)))
                    EventHandle = NULL;
            }
            if (EventHandle != NULL &&
                !NT_SUCCESS(ObReferenceObjectByHandle(EventHandle, EVENT_ALL_ACCESS, *ExEventObjectType,
                                                      KernelMode, (PVOID *)&Completed, NULL)))
            {
                Completed = NULL;
            }
        }

        if (!Pending && Completed != NULL)
        {
            if (Ip == NULL)
            {
                InitializeObjectAttributes(&Attributes, &Name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
                if (!NT_SUCCESS(ZwCreateFile(&Ip, GENERIC_READ, &Attributes, &Io, NULL, FILE_ATTRIBUTE_NORMAL,
                                             FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, NULL, 0)))
                    Ip = NULL;
            }
            if (Ip != NULL)
            {
                Status = ZwDeviceIoControlFile(Ip, EventHandle, NULL, NULL, &Io, IOCTL_IP_WAIT_CHANGE,
                                               &Generation, sizeof(Generation), &Generation, sizeof(Generation));
                if (Status == STATUS_PENDING)
                    Pending = TRUE;
                else if (NT_SUCCESS(Status))
                    Changed = TRUE;
            }
        }

        if (!Changed)
        {
            Objects[0] = &NetioChangeKick;
            Objects[1] = Completed;
            Status = KeWaitForMultipleObjects(Pending ? 2 : 1, Objects, WaitAny, Executive, KernelMode,
                                              FALSE, (Pending && HaveOld && !Stale) ? NULL : &Retry, WaitBlocks);
            if (Status == STATUS_WAIT_1)
            {
                Pending = FALSE;
                Changed = NT_SUCCESS(Io.Status);
            }
            else if (Status == STATUS_TIMEOUT && (Stale || !HaveOld || !Pending))
            {
                Changed = TRUE;
            }
        }

        NetioNotify(0, AF_UNSPEC, NULL, MibInitialNotification, TRUE);

        if (!Changed)
            continue;

        if (!NT_SUCCESS(NetioTakeSnapshot(&New)))
        {
            Stale = TRUE;
            continue;
        }
        Stale = FALSE;
        if (HaveOld)
        {
            NetioCompareRoutes(Old.Routes, Old.RouteCount, New.Routes, New.RouteCount);
            for (i = 0; i < 2; i++)
                NetioCompareInterfaces(Old.Interfaces[i], Old.InterfaceCount[i], New.Interfaces[i], New.InterfaceCount[i]);
            NetioFreeSnapshot(&Old);
        }
        Old = New;
        HaveOld = TRUE;
    }
}

static
NTSTATUS
NetioRegisterChange(
    _In_ ULONG Kind,
    _In_ ADDRESS_FAMILY Family,
    _In_ PVOID Callback,
    _In_opt_ PVOID CallerContext,
    _In_ BOOLEAN InitialNotification,
    _Inout_ HANDLE *NotificationHandle)
{
    PNETIO_CHANGE_NOTIFY Notify;
    LARGE_INTEGER StartWait;
    HANDLE Thread;
    KIRQL OldIrql;
    NTSTATUS Status;
    LONG State;

    StartWait.QuadPart = -10000LL;

    if (Callback == NULL || NotificationHandle == NULL ||
        (Family != AF_UNSPEC && Family != AF_INET && Family != AF_INET6))
    {
        return STATUS_INVALID_PARAMETER;
    }

    Notify = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Notify), NETIO_IPHLP_TAG);
    if (Notify == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(Notify, sizeof(*Notify));
    Notify->Kind = Kind;
    Notify->Family = Family;
    Notify->Callback = Callback;
    Notify->Context = CallerContext;
    Notify->References = 1;
    Notify->Linked = TRUE;
    Notify->InitialPending = InitialNotification;
    KeInitializeEvent(&Notify->Released, NotificationEvent, FALSE);

    for (;;)
    {
        State = InterlockedCompareExchange(&NetioChangeState, NETIO_CHANGE_STARTING, NETIO_CHANGE_STOPPED);
        if (State == NETIO_CHANGE_RUNNING)
            break;
        if (State == NETIO_CHANGE_STOPPED)
        {
            KeInitializeEvent(&NetioChangeKick, SynchronizationEvent, FALSE);
            Status = PsCreateSystemThread(&Thread, THREAD_ALL_ACCESS, NULL, NULL, NULL, NetioChangeWorker, NULL);
            if (!NT_SUCCESS(Status))
            {
                InterlockedExchange(&NetioChangeState, NETIO_CHANGE_STOPPED);
                ExFreePoolWithTag(Notify, NETIO_IPHLP_TAG);
                return Status;
            }
            ZwClose(Thread);
            InterlockedExchange(&NetioChangeState, NETIO_CHANGE_RUNNING);
            break;
        }
        KeDelayExecutionThread(KernelMode, FALSE, &StartWait);
    }

    KeAcquireSpinLock(&NetioChangeLock, &OldIrql);
    InsertTailList(&NetioChangeList, &Notify->Link);
    KeReleaseSpinLock(&NetioChangeLock, OldIrql);

    if (InitialNotification)
        KeSetEvent(&NetioChangeKick, IO_NO_INCREMENT, FALSE);

    *NotificationHandle = Notify;
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
NotifyIpInterfaceChange(
    _In_ ADDRESS_FAMILY Family,
    _In_ PIPINTERFACE_CHANGE_CALLBACK Callback,
    _In_opt_ PVOID CallerContext,
    _In_ BOOLEAN InitialNotification,
    _Inout_ HANDLE *NotificationHandle)
{
    return NetioRegisterChange(NETIO_CHANGE_INTERFACE, Family, (PVOID)Callback, CallerContext,
                               InitialNotification, NotificationHandle);
}

NTSTATUS
NTAPI
NotifyRouteChange2(
    _In_ ADDRESS_FAMILY AddressFamily,
    _In_ PIPFORWARD_CHANGE_CALLBACK Callback,
    _In_ PVOID CallerContext,
    _In_ BOOLEAN InitialNotification,
    _Inout_ HANDLE *NotificationHandle)
{
    return NetioRegisterChange(NETIO_CHANGE_ROUTE, AddressFamily, (PVOID)Callback, CallerContext,
                               InitialNotification, NotificationHandle);
}

NTSTATUS
NTAPI
CancelMibChangeNotify2(
    _In_ HANDLE NotificationHandle)
{
    PNETIO_CHANGE_NOTIFY Notify = NULL;
    PLIST_ENTRY Entry;
    KIRQL OldIrql;

    if (NotificationHandle == NULL)
        return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLock(&NetioChangeLock, &OldIrql);
    for (Entry = NetioChangeList.Flink; Entry != &NetioChangeList; Entry = Entry->Flink)
    {
        if (CONTAINING_RECORD(Entry, NETIO_CHANGE_NOTIFY, Link) != NotificationHandle)
            continue;
        Notify = NotificationHandle;
        RemoveEntryList(&Notify->Link);
        Notify->Linked = FALSE;
        break;
    }
    KeReleaseSpinLock(&NetioChangeLock, OldIrql);
    if (Notify == NULL)
        return STATUS_INVALID_HANDLE;

    if (PsGetCurrentThread() == NetioChangeThread)
    {
        Notify->FreeOnRelease = TRUE;
        if (InterlockedDecrement(&Notify->References) == 0)
            ExFreePoolWithTag(Notify, NETIO_IPHLP_TAG);
        return STATUS_SUCCESS;
    }

    if (InterlockedDecrement(&Notify->References) != 0)
        KeWaitForSingleObject(&Notify->Released, Executive, KernelMode, FALSE, NULL);
    ExFreePoolWithTag(Notify, NETIO_IPHLP_TAG);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
CreateIpForwardEntry2(
    _In_ CONST MIB_IPFORWARD_ROW2 *Row)
{
    if (Row == NULL)
        return STATUS_INVALID_PARAMETER;
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
DeleteIpForwardEntry2(
    _In_ CONST MIB_IPFORWARD_ROW2 *Row)
{
    if (Row == NULL)
        return STATUS_INVALID_PARAMETER;
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
ConvertInterfaceLuidToGuid(
    _In_ CONST NET_LUID *InterfaceLuid,
    _Out_ GUID *InterfaceGuid)
{
    if ((InterfaceLuid == NULL) || (InterfaceGuid == NULL))
        return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(InterfaceGuid, sizeof(*InterfaceGuid));
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
NotifyUnicastIpAddressChange(
    _In_ ADDRESS_FAMILY Family,
    _In_ PUNICAST_IPADDRESS_CHANGE_CALLBACK Callback,
    _In_opt_ PVOID CallerContext,
    _In_ BOOLEAN InitialNotification,
    _Inout_ HANDLE *NotificationHandle)
{
    UNREFERENCED_PARAMETER(Family);
    UNREFERENCED_PARAMETER(CallerContext);
    UNREFERENCED_PARAMETER(InitialNotification);

    if ((Callback == NULL) || (NotificationHandle == NULL))
        return STATUS_INVALID_PARAMETER;
    *NotificationHandle = NULL;
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
SetInterfaceDnsSettings(
    _In_ GUID Interface,
    _In_ CONST VOID *Settings)
{
    UNREFERENCED_PARAMETER(Interface);

    if (Settings == NULL)
        return STATUS_INVALID_PARAMETER;
    return STATUS_NOT_SUPPORTED;
}
