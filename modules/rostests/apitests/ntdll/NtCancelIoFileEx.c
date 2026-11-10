/*
 * PROJECT:     LiberNT API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test for the thread alert around a cancelled synchronous request
 */

#include "precomp.h"

typedef struct _READER
{
    HANDLE Pipe;
    HANDLE Ready;
    BOOL ReadResult;
    DWORD ReadError;
    NTSTATUS AlertStatus;
} READER;

static
DWORD
WINAPI
ReaderThread(PVOID Parameter)
{
    READER *Reader = Parameter;
    DWORD Read;
    char Buffer[16];

    SetEvent(Reader->Ready);
    Reader->ReadResult = ReadFile(Reader->Pipe, Buffer, sizeof(Buffer), &Read, NULL);
    Reader->ReadError = GetLastError();
    Reader->AlertStatus = NtTestAlert();
    return 0;
}

/* Blocks a thread in a synchronous read of a pipe, cancels it and reports what the thread saw */
static
VOID
RunReader(BOOL AlertFirst, BOOL CancelSynchronous, READER *Reader)
{
    static LONG Counter;
    WCHAR Name[64];
    HANDLE Server, Client, Thread;
    BOOL Cancelled = FALSE;
    ULONG Try;

    swprintf(Name, L"\\.\pipe\NtCancelIoFileEx%lu_%ld", GetCurrentProcessId(), InterlockedIncrement(&Counter));
    Server = CreateNamedPipeW(Name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, NULL);
    ok(Server != INVALID_HANDLE_VALUE, "CreateNamedPipeW failed: %lu\n", GetLastError());
    Client = CreateFileW(Name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    ok(Client != INVALID_HANDLE_VALUE, "CreateFileW failed: %lu\n", GetLastError());

    ZeroMemory(Reader, sizeof(*Reader));
    Reader->Pipe = Server;
    Reader->Ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    Thread = CreateThread(NULL, 0, ReaderThread, Reader, 0, NULL);
    ok(Thread != NULL, "CreateThread failed: %lu\n", GetLastError());
    WaitForSingleObject(Reader->Ready, INFINITE);

    if (AlertFirst)
        ok_ntstatus(NtAlertThread(Thread), STATUS_SUCCESS);

    /* The read may not have started yet */
    for (Try = 0; !Cancelled && Try < 100; Try++)
    {
        Sleep(20);
        Cancelled = CancelSynchronous ? CancelSynchronousIo(Thread) : CancelIoEx(Server, NULL);
        if (!Cancelled && GetLastError() != ERROR_NOT_FOUND)
            break;
    }
    ok(Cancelled, "The read was not cancelled: %lu\n", GetLastError());
    if (!Cancelled)
        WriteFile(Client, "x", 1, &Try, NULL);

    ok_int(WaitForSingleObject(Thread, 10000), WAIT_OBJECT_0);
    CloseHandle(Thread);
    CloseHandle(Reader->Ready);
    CloseHandle(Client);
    CloseHandle(Server);
}

START_TEST(NtCancelIoFileEx)
{
    READER Reader;

    /* An alert sent by another thread stays pending after the request it did not wake is cancelled */
    RunReader(TRUE, FALSE, &Reader);
    ok_int(Reader.ReadResult, FALSE);
    ok_int(Reader.ReadError, ERROR_OPERATION_ABORTED);
    ok_ntstatus(Reader.AlertStatus, STATUS_ALERTED);

    RunReader(TRUE, TRUE, &Reader);
    ok_int(Reader.ReadResult, FALSE);
    ok_int(Reader.ReadError, ERROR_OPERATION_ABORTED);
    ok_ntstatus(Reader.AlertStatus, STATUS_ALERTED);

    /* Cancelling leaves no alert of its own behind */
    RunReader(FALSE, FALSE, &Reader);
    ok_int(Reader.ReadResult, FALSE);
    ok_int(Reader.ReadError, ERROR_OPERATION_ABORTED);
    ok_ntstatus(Reader.AlertStatus, STATUS_SUCCESS);

    RunReader(FALSE, TRUE, &Reader);
    ok_int(Reader.ReadResult, FALSE);
    ok_int(Reader.ReadError, ERROR_OPERATION_ABORTED);
    ok_ntstatus(Reader.AlertStatus, STATUS_SUCCESS);
}
