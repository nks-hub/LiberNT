/*
 * PROJECT:     LiberNT kernel-mode tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Cancelling a synchronous request that has no cancel routine, user-mode part
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include <kmt_test.h>
#include <ndk/kefuncs.h>
#include <ndk/psfuncs.h>

#include "IoCancelSync.h"

typedef enum _CANCEL_KIND
{
    CancelSynchronous,
    CancelHandle
} CANCEL_KIND;

typedef struct _WORKER
{
    HANDLE Device;
    DWORD ControlCode;
    HANDLE Ready;
    BOOL Result;
    DWORD Error;
    ULONG WaitStatus;
    DWORD Elapsed;
    NTSTATUS TestAlert;
    NTSTATUS Waits[3];
} WORKER;

static
DWORD
WINAPI
WorkerThread(PVOID Parameter)
{
    WORKER *Worker = Parameter;
    LARGE_INTEGER Interval;
    DWORD Returned = 0, Start, i;

    SetEvent(Worker->Ready);
    Start = GetTickCount();
    Worker->Result = DeviceIoControl(Worker->Device, KMT_MAKE_CODE(Worker->ControlCode), &Worker->WaitStatus,
                                     sizeof(Worker->WaitStatus), &Worker->WaitStatus, sizeof(Worker->WaitStatus), &Returned, NULL);
    Worker->Error = GetLastError();
    Worker->Elapsed = GetTickCount() - Start;

    /* NtTestAlert takes a user-mode alert only; an alertable wait takes a user-mode alert, then a kernel-mode one */
    Worker->TestAlert = NtTestAlert();
    Interval.QuadPart = -10000LL * 20;
    for (i = 0; i < RTL_NUMBER_OF(Worker->Waits); i++)
        Worker->Waits[i] = NtDelayExecution(TRUE, &Interval);
    return 0;
}

static
VOID
RunWorker(DWORD ControlCode, BOOL AlertFirst, CANCEL_KIND Kind, WORKER *Worker)
{
    HANDLE Thread;
    BOOL Cancelled = FALSE;
    ULONG Try;

    ZeroMemory(Worker, sizeof(*Worker));
    Worker->ControlCode = ControlCode;
    Worker->Device = CreateFileW(L"\\\\.\\Global\\GLOBALROOT\\Device\\Kmtest-IoCancelSync", GENERIC_READ | GENERIC_WRITE, 0, NULL,
                                 OPEN_EXISTING, 0, NULL);
    ok(Worker->Device != INVALID_HANDLE_VALUE, "CreateFileW failed: %lu\n", GetLastError());
    if (Worker->Device == INVALID_HANDLE_VALUE)
        return;

    Worker->Ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    Thread = CreateThread(NULL, 0, WorkerThread, Worker, 0, NULL);
    ok(Thread != NULL, "CreateThread failed: %lu\n", GetLastError());
    if (Thread)
    {
        WaitForSingleObject(Worker->Ready, INFINITE);
        Sleep(300);
        if (AlertFirst)
            ok_eq_hex(NtAlertThread(Thread), STATUS_SUCCESS);

        /* The request may not be in the driver yet */
        for (Try = 0; !Cancelled && Try < 20; Try++)
        {
            Cancelled = Kind == CancelHandle ? CancelIoEx(Worker->Device, NULL) : CancelSynchronousIo(Thread);
            if (!Cancelled)
                Sleep(20);
        }
        ok(Cancelled, "The request was not found: %lu\n", GetLastError());

        ok_eq_ulong(WaitForSingleObject(Thread, 3 * IOCANCELSYNC_ALERTABLE_TIMEOUT_MS), WAIT_OBJECT_0);
        CloseHandle(Thread);
    }
    CloseHandle(Worker->Ready);
    CloseHandle(Worker->Device);
}

/* The expected values are those of Windows 11 22621, measured with a driver of the same two requests */
START_TEST(IoCancelSync)
{
    WORKER Worker;
    DWORD Error;

    Error = KmtLoadAndOpenDriver(L"IoCancelSync", TRUE);
    ok_eq_int(Error, ERROR_SUCCESS);
    if (Error)
        return;

    /* The alertable wait of the driver takes the alert at once */
    RunWorker(IOCTL_IOCANCELSYNC_WAIT_ALERTABLE, FALSE, CancelSynchronous, &Worker);
    ok_eq_int(Worker.Result, TRUE);
    ok_eq_hex(Worker.WaitStatus, STATUS_ALERTED);
    ok(Worker.Elapsed < IOCANCELSYNC_ALERTABLE_TIMEOUT_MS / 2, "The request took %lu ms\n", Worker.Elapsed);
    ok_eq_hex(Worker.TestAlert, STATUS_SUCCESS);
    ok_eq_hex(Worker.Waits[0], STATUS_SUCCESS);
    ok_eq_hex(Worker.Waits[1], STATUS_SUCCESS);

    /* A request that does not wait alertably ends by itself and leaves the thread alerted in kernel mode */
    RunWorker(IOCTL_IOCANCELSYNC_WAIT_PLAIN, FALSE, CancelSynchronous, &Worker);
    ok_eq_int(Worker.Result, TRUE);
    ok_eq_hex(Worker.WaitStatus, STATUS_SUCCESS);
    ok_eq_hex(Worker.TestAlert, STATUS_SUCCESS);
    ok_eq_hex(Worker.Waits[0], STATUS_ALERTED);
    ok_eq_hex(Worker.Waits[1], STATUS_SUCCESS);

    /* CancelIoEx does the same to a synchronous request */
    RunWorker(IOCTL_IOCANCELSYNC_WAIT_PLAIN, FALSE, CancelHandle, &Worker);
    ok_eq_int(Worker.Result, TRUE);
    ok_eq_hex(Worker.WaitStatus, STATUS_SUCCESS);
    ok_eq_hex(Worker.TestAlert, STATUS_SUCCESS);
    ok_eq_hex(Worker.Waits[0], STATUS_ALERTED);
    ok_eq_hex(Worker.Waits[1], STATUS_SUCCESS);

    /* The user-mode alert of another thread is kept next to it */
    RunWorker(IOCTL_IOCANCELSYNC_WAIT_PLAIN, TRUE, CancelSynchronous, &Worker);
    ok_eq_int(Worker.Result, TRUE);
    ok_eq_hex(Worker.WaitStatus, STATUS_SUCCESS);
    ok_eq_hex(Worker.TestAlert, STATUS_ALERTED);
    ok_eq_hex(Worker.Waits[0], STATUS_ALERTED);
    ok_eq_hex(Worker.Waits[1], STATUS_SUCCESS);

    KmtCloseDriver();
    KmtUnloadDriver();
}
