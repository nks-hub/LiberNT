/*
 * PROJECT:     LiberNT kernel-mode tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     CancelSynchronousIo on a request without a cancel routine, user-mode part
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include <kmt_test.h>

#include "IoCancelSync.h"

typedef struct _WORKER
{
    DWORD ControlCode;
    HANDLE Ready;
    DWORD Error;
    ULONG WaitStatus;
    DWORD Elapsed;
    NTSTATUS FirstWait;
    NTSTATUS SecondWait;
} WORKER;

static
DWORD
WINAPI
WorkerThread(PVOID Parameter)
{
    WORKER *Worker = Parameter;
    LARGE_INTEGER Interval;
    DWORD OutLength = sizeof(Worker->WaitStatus);
    DWORD Start;

    SetEvent(Worker->Ready);
    Start = GetTickCount();
    Worker->Error = KmtSendBufferToDriver(Worker->ControlCode, &Worker->WaitStatus, sizeof(Worker->WaitStatus), &OutLength);
    Worker->Elapsed = GetTickCount() - Start;

    /* An alertable wait reports what the request left behind: an alert first, then a queued APC */
    Interval.QuadPart = -10000LL * 20;
    Worker->FirstWait = NtDelayExecution(TRUE, &Interval);
    Worker->SecondWait = NtDelayExecution(TRUE, &Interval);
    return 0;
}

static
VOID
RunWorker(DWORD ControlCode, BOOL AlertFirst, WORKER *Worker)
{
    HANDLE Thread;
    BOOL Cancelled = FALSE;
    ULONG Try;

    ZeroMemory(Worker, sizeof(*Worker));
    Worker->ControlCode = ControlCode;
    Worker->Ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    Thread = CreateThread(NULL, 0, WorkerThread, Worker, 0, NULL);
    ok(Thread != NULL, "CreateThread failed: %lu\n", GetLastError());
    if (!Thread)
    {
        CloseHandle(Worker->Ready);
        return;
    }
    WaitForSingleObject(Worker->Ready, INFINITE);

    /* The request may not be in the driver yet */
    for (Try = 0; !Cancelled && Try < 50; Try++)
    {
        Sleep(20);
        if (AlertFirst && Try == 5)
            ok_eq_hex(NtAlertThread(Thread), STATUS_SUCCESS);
        if (Try >= 5)
            Cancelled = CancelSynchronousIo(Thread);
        if (!Cancelled && Try >= 5 && GetLastError() != ERROR_NOT_FOUND)
            break;
    }
    ok(Cancelled, "CancelSynchronousIo failed: %lu\n", GetLastError());

    ok_eq_ulong(WaitForSingleObject(Thread, 3 * IOCANCELSYNC_ALERTABLE_TIMEOUT_MS), WAIT_OBJECT_0);
    CloseHandle(Thread);
    CloseHandle(Worker->Ready);
}

START_TEST(IoCancelSync)
{
    WORKER Worker;
    DWORD Error;

    Error = KmtLoadAndOpenDriver(L"IoCancelSync", TRUE);
    ok_eq_int(Error, ERROR_SUCCESS);
    if (Error)
        return;

    /* The alertable wait of the driver ends at once and nothing stays behind */
    RunWorker(IOCTL_IOCANCELSYNC_WAIT_ALERTABLE, FALSE, &Worker);
    ok_eq_ulong(Worker.Error, ERROR_SUCCESS);
    ok_eq_hex(Worker.WaitStatus, STATUS_USER_APC);
    ok(Worker.Elapsed < IOCANCELSYNC_ALERTABLE_TIMEOUT_MS / 2, "The request took %lu ms\n", Worker.Elapsed);
    ok_eq_hex(Worker.FirstWait, STATUS_SUCCESS);
    ok_eq_hex(Worker.SecondWait, STATUS_SUCCESS);

    /* A request that does not wait alertably ends by itself and nothing stays behind */
    RunWorker(IOCTL_IOCANCELSYNC_WAIT_PLAIN, FALSE, &Worker);
    ok_eq_ulong(Worker.Error, ERROR_SUCCESS);
    ok_eq_hex(Worker.WaitStatus, STATUS_SUCCESS);
    ok_eq_hex(Worker.FirstWait, STATUS_SUCCESS);
    ok_eq_hex(Worker.SecondWait, STATUS_SUCCESS);

    /* An alert of another thread is still pending after that request, and only that alert */
    RunWorker(IOCTL_IOCANCELSYNC_WAIT_PLAIN, TRUE, &Worker);
    ok_eq_ulong(Worker.Error, ERROR_SUCCESS);
    ok_eq_hex(Worker.WaitStatus, STATUS_SUCCESS);
    ok_eq_hex(Worker.FirstWait, STATUS_ALERTED);
    ok_eq_hex(Worker.SecondWait, STATUS_SUCCESS);

    KmtCloseDriver();
    KmtUnloadDriver();
}
