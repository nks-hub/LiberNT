/*
 * PROJECT:     LiberNT API Tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Tests for a CopyFileExW that stops or fails before the end
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include "precomp.h"

#define SOURCE_SIZE (6 * 1024 * 1024)
#define STOP_AT (2 * 1024 * 1024)
#define LOCK_AT (3 * 1024 * 1024 + 4096)

static WCHAR Source[MAX_PATH], Dest[MAX_PATH];
static LONGLONG StopAt;
static LONGLONG FirstChunk;

static DWORD CALLBACK
Progress(LARGE_INTEGER TotalFileSize, LARGE_INTEGER TotalBytesTransferred, LARGE_INTEGER StreamSize,
         LARGE_INTEGER StreamBytesTransferred, DWORD StreamNumber, DWORD Reason, HANDLE SourceFile,
         HANDLE DestFile, LPVOID Data)
{
    if (Reason == CALLBACK_CHUNK_FINISHED && FirstChunk < 0)
        FirstChunk = TotalBytesTransferred.QuadPart;
    if (StopAt && TotalBytesTransferred.QuadPart >= StopAt)
        return PROGRESS_STOP;
    return PROGRESS_CONTINUE;
}

static BOOL
Copy(DWORD Flags, LONGLONG Stop)
{
    StopAt = Stop;
    FirstChunk = -1;
    SetLastError(0xdeadbeef);
    return CopyFileExW(Source, Dest, Progress, NULL, NULL, Flags);
}

static BOOL
SameAsSource(void)
{
    static UCHAR A[65536], B[65536];
    HANDLE S, D;
    DWORD ReadS, ReadD;
    BOOL Same = FALSE;

    S = CreateFileW(Source, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    D = CreateFileW(Dest, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (S != INVALID_HANDLE_VALUE && D != INVALID_HANDLE_VALUE)
    {
        while (ReadFile(S, A, sizeof(A), &ReadS, NULL) && ReadFile(D, B, sizeof(B), &ReadD, NULL) &&
               ReadS == ReadD && !memcmp(A, B, ReadS))
        {
            if (!ReadS)
            {
                Same = TRUE;
                break;
            }
        }
    }
    if (S != INVALID_HANDLE_VALUE)
        CloseHandle(S);
    if (D != INVALID_HANDLE_VALUE)
        CloseHandle(D);
    return Same;
}

static void
test_Stop(DWORD Flags)
{
    BOOL Ret;

    DeleteFileW(Dest);
    Ret = Copy(Flags, STOP_AT);
    ok(!Ret && GetLastError() == ERROR_REQUEST_ABORTED, "Flags 0x%lx: stopped copy returned %d (%lu)\n",
       Flags, Ret, GetLastError());
    ok(GetFileAttributesW(Dest) == INVALID_FILE_ATTRIBUTES, "Flags 0x%lx: the stopped copy left its destination\n",
       Flags);

    /* On a local disk the copy starts again from the beginning */
    Ret = Copy(Flags, 0);
    ok(Ret, "Flags 0x%lx: copy after the stop failed (%lu)\n", Flags, GetLastError());
    ok(FirstChunk > 0 && FirstChunk <= STOP_AT / 2, "Flags 0x%lx: first chunk after the stop ended at %I64d\n",
       Flags, FirstChunk);
    ok(SameAsSource(), "Flags 0x%lx: the destination differs from the source\n", Flags);
}

static void
test_FailedRead(DWORD Flags)
{
    HANDLE Lock;
    BOOL Ret;

    DeleteFileW(Dest);
    Lock = CreateFileW(Source, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    ok(LockFile(Lock, LOCK_AT, 0, 4096, 0), "LockFile failed (%lu)\n", GetLastError());
    Ret = Copy(Flags, 0);
    ok(!Ret && GetLastError() == ERROR_LOCK_VIOLATION, "Flags 0x%lx: copy over a locked range returned %d (%lu)\n",
       Flags, Ret, GetLastError());
    ok(GetFileAttributesW(Dest) == INVALID_FILE_ATTRIBUTES, "Flags 0x%lx: the failed copy left its destination\n",
       Flags);
    UnlockFile(Lock, LOCK_AT, 0, 4096, 0);
    CloseHandle(Lock);

    Ret = Copy(Flags, 0);
    ok(Ret, "Flags 0x%lx: copy after the unlock failed (%lu)\n", Flags, GetLastError());
    ok(FirstChunk > 0 && FirstChunk <= STOP_AT / 2, "Flags 0x%lx: first chunk after the unlock ended at %I64d\n",
       Flags, FirstChunk);
    ok(SameAsSource(), "Flags 0x%lx: the destination differs from the source\n", Flags);
}

START_TEST(CopyFileExStop)
{
    static UCHAR Chunk[65536];
    WCHAR Dir[MAX_PATH];
    HANDLE File;
    DWORD i, Written;

    GetTempPathW(ARRAYSIZE(Dir), Dir);
    StringCchPrintfW(Source, ARRAYSIZE(Source), L"%sCopyFileExStop-src.bin", Dir);
    StringCchPrintfW(Dest, ARRAYSIZE(Dest), L"%sCopyFileExStop-dst.bin", Dir);

    File = CreateFileW(Source, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "Cannot create the source (%lu)\n", GetLastError());
    if (File == INVALID_HANDLE_VALUE)
        return;
    for (Written = 0; Written < SOURCE_SIZE; Written += sizeof(Chunk))
    {
        for (i = 0; i < sizeof(Chunk); i++)
            Chunk[i] = (UCHAR)((Written + i) * 7 % 251);
        WriteFile(File, Chunk, sizeof(Chunk), &i, NULL);
    }
    CloseHandle(File);

    /* COPY_FILE_RESTARTABLE changes nothing when both files are local */
    test_Stop(0);
    test_Stop(COPY_FILE_RESTARTABLE);
    test_FailedRead(0);
    test_FailedRead(COPY_FILE_RESTARTABLE);

    DeleteFileW(Dest);
    DeleteFileW(Source);
}
