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

NTSTATUS
TestEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PCUNICODE_STRING RegistryPath,
    _Out_ PCWSTR *DeviceName,
    _Inout_ INT *Flags)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    UNREFERENCED_PARAMETER(Flags);

    *DeviceName = L"NetioIpHlp";

    return KmtRegisterMessageHandler(IOCTL_NETIOIPHLP_GET_IF_ENTRY2, NULL, TestGetIfEntry2);
}

VOID
TestUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(DriverObject);
}
