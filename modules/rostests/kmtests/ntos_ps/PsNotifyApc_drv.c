/*
 * PROJECT:     LiberNT kernel-mode tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     State a process notify routine runs in, driver part
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include <kmt_test.h>

#include "PsNotifyApc.h"

static KMT_IRP_HANDLER TestDeviceControl;
static BOOLEAN NotifyRegistered;
static HANDLE WatchedParent;
static HANDLE WatchedChild;
static PSNOTIFYAPC_RESULT Result;

static
VOID
NTAPI
ProcessNotify(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create)
{
    ULONG Irql = KeGetCurrentIrql();
    ULONG ApcsDisabled = KeAreApcsDisabled();

    if (Create && WatchedParent != NULL && ParentId == WatchedParent && WatchedChild == NULL)
    {
        WatchedChild = ProcessId;
        Result.CreateCalls++;
        Result.CreateIrql = Irql;
        Result.CreateApcsDisabled = ApcsDisabled;
    }
    else if (!Create && WatchedChild != NULL && ProcessId == WatchedChild)
    {
        Result.ExitCalls++;
        Result.ExitIrql = Irql;
        Result.ExitApcsDisabled = ApcsDisabled;
    }
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

    *DeviceName = L"PsNotifyApc";
    return KmtRegisterIrpHandler(IRP_MJ_DEVICE_CONTROL, NULL, TestDeviceControl);
}

VOID
TestUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(DriverObject);

    if (NotifyRegistered)
        ok_eq_hex(PsSetCreateProcessNotifyRoutine(ProcessNotify, TRUE), STATUS_SUCCESS);
}

static
NTSTATUS
TestDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation)
{
    PVOID Buffer = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG_PTR Information = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    switch (IoStackLocation->Parameters.DeviceIoControl.IoControlCode)
    {
        case KMT_MAKE_CODE(IOCTL_PSNOTIFYAPC_WATCH):
            if (!Buffer || IoStackLocation->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG))
            {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            WatchedParent = NULL;
            WatchedChild = NULL;
            RtlZeroMemory(&Result, sizeof(Result));
            if (!NotifyRegistered)
            {
                Status = PsSetCreateProcessNotifyRoutine(ProcessNotify, FALSE);
                if (!NT_SUCCESS(Status))
                    break;
                NotifyRegistered = TRUE;
            }
            WatchedParent = (HANDLE)(ULONG_PTR)*(PULONG)Buffer;
            break;

        case KMT_MAKE_CODE(IOCTL_PSNOTIFYAPC_QUERY):
            if (!Buffer || IoStackLocation->Parameters.DeviceIoControl.OutputBufferLength < sizeof(Result))
            {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            RtlCopyMemory(Buffer, &Result, sizeof(Result));
            Information = sizeof(Result);
            break;

        default:
            Status = STATUS_NOT_SUPPORTED;
            break;
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}
