/*
 * PROJECT:     LiberNT API Tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Tests for a CopyFileExW that stops or fails before the end
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include "precomp.h"
#include <sddl.h>

#define SOURCE_SIZE (6 * 1024 * 1024)
#define STOP_AT (2 * 1024 * 1024)
#define LOCK_AT (3 * 1024 * 1024 + 4096)

static WCHAR Source[MAX_PATH], Dest[MAX_PATH], Renamed[MAX_PATH];
static LONGLONG StopAt, StoppedAt;
static LONGLONG FirstReport, FirstChunk;
static DWORD StopAction;
static BOOL (WINAPI *pSetFileInformationByHandle)(HANDLE, FILE_INFO_BY_HANDLE_CLASS, void *, DWORD);
static BOOL RenamedDest, ReplacedDest;
static DWORD RenameError;

static DWORD CALLBACK
RenameProgress(LARGE_INTEGER TotalFileSize, LARGE_INTEGER TotalBytesTransferred, LARGE_INTEGER StreamSize,
               LARGE_INTEGER StreamBytesTransferred, DWORD StreamNumber, DWORD Reason, HANDLE SourceFile,
               HANDLE DestFile, LPVOID Data)
{
    union
    {
        FILE_RENAME_INFO Info;
        UCHAR Buffer[sizeof(FILE_RENAME_INFO) + MAX_PATH * sizeof(WCHAR)];
    } Rename;
    HANDLE File;

    if (TotalBytesTransferred.QuadPart < STOP_AT)
        return PROGRESS_CONTINUE;

    memset(&Rename, 0, sizeof(Rename));
    Rename.Info.FileNameLength = (DWORD)(wcslen(Renamed) * sizeof(WCHAR));
    memcpy(Rename.Info.FileName, Renamed, Rename.Info.FileNameLength + sizeof(WCHAR));
    RenamedDest = pSetFileInformationByHandle(DestFile, FileRenameInfo, &Rename, sizeof(Rename));
    RenameError = GetLastError();
    if (RenamedDest)
    {
        File = CreateFileW(Dest, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
        ReplacedDest = File != INVALID_HANDLE_VALUE;
        if (ReplacedDest)
            CloseHandle(File);
    }
    return PROGRESS_STOP;
}

static DWORD CALLBACK
Progress(LARGE_INTEGER TotalFileSize, LARGE_INTEGER TotalBytesTransferred, LARGE_INTEGER StreamSize,
         LARGE_INTEGER StreamBytesTransferred, DWORD StreamNumber, DWORD Reason, HANDLE SourceFile,
         HANDLE DestFile, LPVOID Data)
{
    if (FirstReport < 0)
        FirstReport = TotalBytesTransferred.QuadPart;
    if (Reason == CALLBACK_CHUNK_FINISHED && FirstChunk < 0)
        FirstChunk = TotalBytesTransferred.QuadPart;
    if (StopAt && TotalBytesTransferred.QuadPart >= StopAt)
    {
        StoppedAt = TotalBytesTransferred.QuadPart;
        return StopAction;
    }
    return PROGRESS_CONTINUE;
}

static BOOL
Copy(DWORD Flags, LONGLONG Stop, DWORD Action)
{
    StopAt = Stop;
    StopAction = Action;
    StoppedAt = FirstReport = FirstChunk = -1;
    SetLastError(0xdeadbeef);
    return CopyFileExW(Source, Dest, Progress, NULL, NULL, Flags);
}

static BOOL
DestMissing(void)
{
    return GetFileAttributesW(Dest) == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND;
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
test_Stop(DWORD Flags, DWORD Action)
{
    BOOL Ret;

    DeleteFileW(Dest);
    Ret = Copy(Flags, STOP_AT, Action);
    ok(!Ret && GetLastError() == ERROR_REQUEST_ABORTED, "Flags 0x%lx, action %lu: stopped copy returned %d (%lu)\n",
       Flags, Action, Ret, GetLastError());
    ok(StoppedAt >= STOP_AT && StoppedAt < SOURCE_SIZE, "Flags 0x%lx, action %lu: stopped at %I64d\n",
       Flags, Action, StoppedAt);
    trace("Flags 0x%lx, action %lu: stopped at %I64d\n", Flags, Action, StoppedAt);
    ok(DestMissing(), "Flags 0x%lx, action %lu: the stopped copy left its destination (%lu)\n",
       Flags, Action, GetLastError());

    Ret = Copy(Flags, 0, PROGRESS_CONTINUE);
    ok(Ret, "Flags 0x%lx, action %lu: copy after the stop failed (%lu)\n", Flags, Action, GetLastError());
    ok(FirstReport == 0, "Flags 0x%lx, action %lu: first report after the stop at %I64d\n",
       Flags, Action, FirstReport);
    ok(FirstChunk > 0 && FirstChunk <= STOP_AT / 2, "Flags 0x%lx, action %lu: first chunk after the stop ended at %I64d\n",
       Flags, Action, FirstChunk);
    ok(SameAsSource(), "Flags 0x%lx, action %lu: the destination differs from the source\n", Flags, Action);
}

static void
test_FailedRead(DWORD Flags)
{
    HANDLE Lock;
    BOOL Ret;

    DeleteFileW(Dest);
    Lock = CreateFileW(Source, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    ok(LockFile(Lock, LOCK_AT, 0, 4096, 0), "LockFile failed (%lu)\n", GetLastError());
    Ret = Copy(Flags, 0, PROGRESS_CONTINUE);
    ok(!Ret && GetLastError() == ERROR_LOCK_VIOLATION, "Flags 0x%lx: copy over a locked range returned %d (%lu)\n",
       Flags, Ret, GetLastError());
    ok(DestMissing(), "Flags 0x%lx: the failed copy left its destination (%lu)\n", Flags, GetLastError());
    UnlockFile(Lock, LOCK_AT, 0, 4096, 0);
    CloseHandle(Lock);

    Ret = Copy(Flags, 0, PROGRESS_CONTINUE);
    ok(Ret, "Flags 0x%lx: copy after the unlock failed (%lu)\n", Flags, GetLastError());
    ok(FirstReport == 0, "Flags 0x%lx: first report after the unlock at %I64d\n", Flags, FirstReport);
    ok(FirstChunk > 0 && FirstChunk <= STOP_AT / 2, "Flags 0x%lx: first chunk after the unlock ended at %I64d\n",
       Flags, FirstChunk);
    ok(SameAsSource(), "Flags 0x%lx: the destination differs from the source\n", Flags);
}

static void
test_StopAfterRename(void)
{
    BOOL Ret;

    pSetFileInformationByHandle = (void *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "SetFileInformationByHandle");
    if (!pSetFileInformationByHandle)
    {
        skip("SetFileInformationByHandle is not available\n");
        return;
    }

    DeleteFileW(Dest);
    DeleteFileW(Renamed);
    RenamedDest = ReplacedDest = FALSE;
    RenameError = 0;
    SetLastError(0xdeadbeef);
    Ret = CopyFileExW(Source, Dest, RenameProgress, NULL, NULL, 0);
    ok(!Ret && GetLastError() == ERROR_REQUEST_ABORTED, "Copy stopped after a rename returned %d (%lu)\n", Ret, GetLastError());
    if (!RenamedDest || !ReplacedDest)
    {
        skip("Cannot replace the destination during the copy (renamed %d, error %lu, replaced %d)\n",
             RenamedDest, RenameError, ReplacedDest);
    }
    else
    {
        ok(GetFileAttributesW(Dest) != INVALID_FILE_ATTRIBUTES,
           "The stopped copy deleted the file that replaced its destination (%lu)\n", GetLastError());
        ok(GetFileAttributesW(Renamed) == INVALID_FILE_ATTRIBUTES, "The stopped copy left its renamed destination behind\n");
    }
    DeleteFileW(Renamed);
    DeleteFileW(Dest);
}

static BOOL
SetDacl(LPCWSTR Path, LPCWSTR Sddl)
{
    PSECURITY_DESCRIPTOR Descriptor;
    BOOL Ret;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Descriptor, NULL))
        return FALSE;
    Ret = SetFileSecurityW(Path, DACL_SECURITY_INFORMATION, Descriptor);
    LocalFree(Descriptor);
    return Ret;
}

static void
RemoveNoDeleteDir(LPCWSTR SubDir)
{
    SetDacl(SubDir, L"D:(A;;FA;;;WD)");
    SetDacl(Dest, L"D:(A;;FA;;;WD)");
    DeleteFileW(Dest);
    RemoveDirectoryW(SubDir);
}

static void
test_NoDeleteAccess(LPCWSTR Dir, LPCWSTR FileSystem)
{
    WCHAR SubDir[MAX_PATH];
    HANDLE File;
    DWORD Error;
    BOOL Ret;

    if (wcscmp(FileSystem, L"NTFS"))
    {
        skip("No file security on %S\n", FileSystem);
        return;
    }

    StringCchPrintfW(SubDir, ARRAYSIZE(SubDir), L"%sCopyFileExStop-nodelete", Dir);
    StringCchPrintfW(Dest, ARRAYSIZE(Dest), L"%s\\dst.bin", SubDir);
    RemoveNoDeleteDir(SubDir);

    Ret = CreateDirectoryW(SubDir, NULL);
    ok(Ret, "Cannot create %S (%lu)\n", SubDir, GetLastError());
    File = CreateFileW(Dest, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "Cannot create the destination (%lu)\n", GetLastError());
    if (File != INVALID_HANDLE_VALUE)
        CloseHandle(File);

    /* Everyone: generic read and write on the file, all but FILE_DELETE_CHILD on the directory */
    Ret = SetDacl(Dest, L"D:P(A;;0x12019f;;;WD)") && SetDacl(SubDir, L"D:P(A;;0x1f01bf;;;WD)");
    ok(Ret, "Cannot set the DACLs (%lu)\n", GetLastError());

    SetLastError(0xdeadbeef);
    File = CreateFileW(Dest, DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    if (!Ret || File != INVALID_HANDLE_VALUE)
    {
        skip("The destination can still be opened for deletion\n");
        if (File != INVALID_HANDLE_VALUE)
            CloseHandle(File);
    }
    else
    {
        ok(GetLastError() == ERROR_ACCESS_DENIED, "Open for deletion failed with %lu\n", GetLastError());

        Ret = Copy(0, 0, PROGRESS_CONTINUE);
        ok(Ret, "Copy over a destination without DELETE access failed (%lu)\n", GetLastError());
        ok(SameAsSource(), "The destination without DELETE access differs from the source\n");

        Ret = Copy(0, STOP_AT, PROGRESS_STOP);
        Error = GetLastError();
        ok(!Ret && Error == ERROR_REQUEST_ABORTED, "Stopped copy over a destination without DELETE access returned %d (%lu)\n", Ret, Error);
        trace("Stopped copy over a destination without DELETE access returned %d (%lu), the destination %s\n",
              Ret, Error, GetFileAttributesW(Dest) == INVALID_FILE_ATTRIBUTES ? "is gone" : "still exists");
    }

    RemoveNoDeleteDir(SubDir);
}

START_TEST(CopyFileExStop)
{
    static UCHAR Chunk[65536];
    WCHAR Dir[MAX_PATH], Root[MAX_PATH], FileSystem[MAX_PATH];
    HANDLE File;
    DWORD i, Written, Done;
    BOOL Wrote = TRUE;

    GetTempPathW(ARRAYSIZE(Dir), Dir);

    /* Windows resumes a restartable copy only when one of the files is on the network */
    if (!GetVolumePathNameW(Dir, Root, ARRAYSIZE(Root)) || GetDriveTypeW(Root) != DRIVE_FIXED)
    {
        skip("%S is not on a local disk\n", Dir);
        return;
    }
    if (!GetVolumeInformationW(Root, NULL, 0, NULL, NULL, NULL, FileSystem, ARRAYSIZE(FileSystem)))
        FileSystem[0] = UNICODE_NULL;
    trace("Copying in %S on %S\n", Dir, FileSystem);
    StringCchPrintfW(Source, ARRAYSIZE(Source), L"%sCopyFileExStop-src.bin", Dir);
    StringCchPrintfW(Dest, ARRAYSIZE(Dest), L"%sCopyFileExStop-dst.bin", Dir);
    StringCchPrintfW(Renamed, ARRAYSIZE(Renamed), L"%sCopyFileExStop-renamed.bin", Dir);

    File = CreateFileW(Source, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "Cannot create the source (%lu)\n", GetLastError());
    if (File == INVALID_HANDLE_VALUE)
        return;
    for (Written = 0; Written < SOURCE_SIZE; Written += sizeof(Chunk))
    {
        for (i = 0; i < sizeof(Chunk); i++)
            Chunk[i] = (UCHAR)((Written + i) * 7 % 251);
        if (!WriteFile(File, Chunk, sizeof(Chunk), &Done, NULL) || Done != sizeof(Chunk))
        {
            Wrote = FALSE;
            break;
        }
    }
    CloseHandle(File);
    ok(Wrote, "Cannot write the source (%lu)\n", GetLastError());
    if (!Wrote)
    {
        DeleteFileW(Source);
        return;
    }

    test_Stop(0, PROGRESS_STOP);
    test_Stop(COPY_FILE_RESTARTABLE, PROGRESS_STOP);
    test_Stop(0, PROGRESS_CANCEL);
    test_Stop(COPY_FILE_RESTARTABLE, PROGRESS_CANCEL);
    test_FailedRead(0);
    test_FailedRead(COPY_FILE_RESTARTABLE);
    test_StopAfterRename();

    DeleteFileW(Dest);
    test_NoDeleteAccess(Dir, FileSystem);
    DeleteFileW(Source);
}
