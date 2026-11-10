/*
 * PROJECT:     LiberNT kernel-mode tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     CancelSynchronousIo on a request without a cancel routine, driver part
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include <kmt_test.h>

#include "IoCancelSync.h"

static KMT_MESSAGE_HANDLER TestMessageHandler;
static KEVENT NeverSetEvent;

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
    KmtRegisterMessageHandler(0, NULL, TestMessageHandler);
    return STATUS_SUCCESS;
}

VOID
TestUnload(
    IN PDRIVER_OBJECT DriverObject)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(DriverObject);
}

static
NTSTATUS
TestMessageHandler(
    IN PDEVICE_OBJECT DeviceObject,
    IN ULONG ControlCode,
    IN PVOID Buffer OPTIONAL,
    IN SIZE_T InLength,
    IN OUT PSIZE_T OutLength)
{
    LARGE_INTEGER Timeout;
    NTSTATUS WaitStatus;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(InLength);

    if (!Buffer || *OutLength < sizeof(ULONG))
        return STATUS_BUFFER_TOO_SMALL;

    /* The request stays in the dispatch routine and has no cancel routine */
    switch (ControlCode)
    {
        case IOCTL_IOCANCELSYNC_WAIT_ALERTABLE:
            Timeout.QuadPart = -10000LL * IOCANCELSYNC_ALERTABLE_TIMEOUT_MS;
            WaitStatus = KeWaitForSingleObject(&NeverSetEvent, Executive, UserMode, TRUE, &Timeout);
            break;

        case IOCTL_IOCANCELSYNC_WAIT_PLAIN:
            Timeout.QuadPart = -10000LL * IOCANCELSYNC_PLAIN_DELAY_MS;
            WaitStatus = KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
            break;

        default:
            return STATUS_NOT_SUPPORTED;
    }

    *(PULONG)Buffer = (ULONG)WaitStatus;
    *OutLength = sizeof(ULONG);
    return STATUS_SUCCESS;
}
