/*
 * PROJECT:     LiberNT kernel-mode tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Cancelling a synchronous request that has no cancel routine, driver part
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include <kmt_test.h>

#include "IoCancelSync.h"

static KMT_IRP_HANDLER TestDeviceControl;
static KEVENT NeverSetEvent;
static LONG CancelCalls;

NTSTATUS
TestEntry(
    IN PDRIVER_OBJECT DriverObject,
    IN PCUNICODE_STRING RegistryPath,
    OUT PCWSTR *DeviceName,
    IN OUT INT *Flags)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    UNREFERENCED_PARAMETER(Flags);

    *DeviceName = L"IoCancelSync";
    KeInitializeEvent(&NeverSetEvent, NotificationEvent, FALSE);
    return KmtRegisterIrpHandler(IRP_MJ_DEVICE_CONTROL, NULL, TestDeviceControl);
}

VOID
TestUnload(
    IN PDRIVER_OBJECT DriverObject)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(DriverObject);
}

static
VOID
NTAPI
TestCancelRoutine(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    IoReleaseCancelSpinLock(Irp->CancelIrql);
    InterlockedIncrement(&CancelCalls);
}

static
NTSTATUS
TestDeviceControl(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PIO_STACK_LOCATION IoStackLocation)
{
    PULONG Buffer = Irp->AssociatedIrp.SystemBuffer;
    LARGE_INTEGER Timeout;
    NTSTATUS Status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (!Buffer || IoStackLocation->Parameters.DeviceIoControl.OutputBufferLength < sizeof(ULONG))
    {
        Status = STATUS_BUFFER_TOO_SMALL;
    }
    else
    {
        /* The request stays in the dispatch routine; only the last one has a cancel routine, which leaves it there */
        switch (IoStackLocation->Parameters.DeviceIoControl.IoControlCode)
        {
            case KMT_MAKE_CODE(IOCTL_IOCANCELSYNC_WAIT_ALERTABLE):
                Timeout.QuadPart = -10000LL * IOCANCELSYNC_ALERTABLE_TIMEOUT_MS;
                *Buffer = (ULONG)KeWaitForSingleObject(&NeverSetEvent, Executive, UserMode, TRUE, &Timeout);
                break;

            case KMT_MAKE_CODE(IOCTL_IOCANCELSYNC_WAIT_PLAIN):
                Timeout.QuadPart = -10000LL * IOCANCELSYNC_PLAIN_DELAY_MS;
                *Buffer = (ULONG)KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
                break;

            case KMT_MAKE_CODE(IOCTL_IOCANCELSYNC_WAIT_CANCELLABLE):
                InterlockedExchange(&CancelCalls, 0);
                IoSetCancelRoutine(Irp, TestCancelRoutine);
                Timeout.QuadPart = -10000LL * IOCANCELSYNC_PLAIN_DELAY_MS;
                KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
                IoSetCancelRoutine(Irp, NULL);
                *Buffer = (ULONG)InterlockedCompareExchange(&CancelCalls, 0, 0);
                break;

            default:
                Status = STATUS_NOT_SUPPORTED;
                break;
        }
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = NT_SUCCESS(Status) ? sizeof(ULONG) : 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}
