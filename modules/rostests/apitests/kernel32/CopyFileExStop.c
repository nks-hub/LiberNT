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
    if (StopAt < 0 || (StopAt && TotalBytesTransferred.QuadPart >= StopAt))
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

/* Windows 11 keeps what PROGRESS_STOP leaves before the first chunk, between two remote files, and when restartable with one */
static void
test_StopPoints(LPCWSTR From, LPCWSTR To, DWORD RemoteFiles)
{
    static const LONGLONG Stops[] = { -1, STOP_AT, SOURCE_SIZE };
    WCHAR LocalSource[MAX_PATH], LocalDest[MAX_PATH];
    DWORD Flags, Action, i, Error;
    BOOL Ret, Kept, Left;

    StringCchCopyW(LocalSource, ARRAYSIZE(LocalSource), Source);
    StringCchCopyW(LocalDest, ARRAYSIZE(LocalDest), Dest);
    StringCchCopyW(Source, ARRAYSIZE(Source), From);
    StringCchCopyW(Dest, ARRAYSIZE(Dest), To);

    for (Flags = 0; Flags <= COPY_FILE_RESTARTABLE; Flags += COPY_FILE_RESTARTABLE)
    {
        for (Action = PROGRESS_CANCEL; Action <= PROGRESS_STOP; Action++)
        {
            for (i = 0; i < ARRAYSIZE(Stops); i++)
            {
                DeleteFileW(Dest);
                Ret = Copy(Flags, Stops[i], Action);
                Error = GetLastError();
                Left = GetFileAttributesW(Dest) != INVALID_FILE_ATTRIBUTES;
                Kept = Action == PROGRESS_STOP && (Stops[i] < 0 || RemoteFiles == 2 || (RemoteFiles && Flags));
                ok(!Ret && Error == ERROR_REQUEST_ABORTED, "%S to %S, flags 0x%lx, action %lu, stop %I64d: returned %d (%lu)\n",
                   From, To, Flags, Action, Stops[i], Ret, Error);
                ok(StoppedAt >= 0 && StoppedAt >= Stops[i], "%S to %S, flags 0x%lx, action %lu, stop %I64d: stopped at %I64d\n",
                   From, To, Flags, Action, Stops[i], StoppedAt);
                ok(Left == Kept, "%S to %S, flags 0x%lx, action %lu, stop %I64d: destination left %d, expected %d\n",
                   From, To, Flags, Action, Stops[i], Left, Kept);
            }
        }
    }

    Ret = Copy(0, 0, PROGRESS_CONTINUE);
    ok(Ret, "%S to %S: copy after the stops failed (%lu)\n", From, To, GetLastError());
    ok(SameAsSource(), "%S to %S: the destination differs from the source\n", From, To);
    DeleteFileW(Dest);

    StringCchCopyW(Source, ARRAYSIZE(Source), LocalSource);
    StringCchCopyW(Dest, ARRAYSIZE(Dest), LocalDest);
}

/* The administrative share of the local disk is the remote end; it needs a server service and an administrator */
static void
test_Remote(void)
{
    WCHAR RemoteSource[MAX_PATH], RemoteDest[MAX_PATH], Share[MAX_PATH];

    StringCchPrintfW(RemoteSource, ARRAYSIZE(RemoteSource), L"\\\\localhost\\%c$%s", Source[0], Source + 2);
    StringCchPrintfW(RemoteDest, ARRAYSIZE(RemoteDest), L"\\\\localhost\\%c$%s", Dest[0], Dest + 2);
    StringCchPrintfW(Share, ARRAYSIZE(Share), L"\\\\localhost\\%c$\\", Source[0]);

    test_StopPoints(Source, Dest, 0);
    if (GetFileAttributesW(RemoteSource) == INVALID_FILE_ATTRIBUTES || GetDriveTypeW(Share) != DRIVE_REMOTE)
    {
        skip("Cannot reach %S (%lu)\n", RemoteSource, GetLastError());
        return;
    }
    test_StopPoints(Source, RemoteDest, 1);
    test_StopPoints(RemoteSource, Dest, 1);
    test_StopPoints(RemoteSource, RemoteDest, 2);
}

/* A copy killed halfway leaves a destination of the full size; on Windows 11 the next copy starts over even when restartable */
static void
test_PartialDest(DWORD Flags)
{
    static UCHAR Buffer[65536];
    WIN32_FIND_STREAM_DATA Stream;
    HANDLE In, Out, Find;
    DWORD Done, Count, Streams = 0;
    LONGLONG Copied;
    BOOL Ret = TRUE;

    In = CreateFileW(Source, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    Out = CreateFileW(Dest, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    ok(In != INVALID_HANDLE_VALUE && Out != INVALID_HANDLE_VALUE, "Flags 0x%lx: cannot open the files (%lu)\n", Flags, GetLastError());
    for (Copied = 0; Ret && Copied < STOP_AT; Copied += sizeof(Buffer))
        Ret = ReadFile(In, Buffer, sizeof(Buffer), &Count, NULL) && WriteFile(Out, Buffer, Count, &Done, NULL);
    Ret = Ret && SetFilePointer(Out, SOURCE_SIZE, NULL, FILE_BEGIN) == SOURCE_SIZE && SetEndOfFile(Out);
    ok(Ret, "Flags 0x%lx: cannot write the partial destination (%lu)\n", Flags, GetLastError());
    CloseHandle(In);
    CloseHandle(Out);

    Ret = Copy(Flags, 0, PROGRESS_CONTINUE);
    ok(Ret, "Flags 0x%lx: copy over a partial destination failed (%lu)\n", Flags, GetLastError());
    ok(FirstReport == 0, "Flags 0x%lx: first report over a partial destination at %I64d\n", Flags, FirstReport);
    ok(FirstChunk > 0 && FirstChunk <= STOP_AT / 2, "Flags 0x%lx: first chunk over a partial destination ended at %I64d\n",
       Flags, FirstChunk);
    ok(SameAsSource(), "Flags 0x%lx: the destination differs from the source\n", Flags);

    Find = FindFirstStreamW(Dest, FindStreamInfoStandard, &Stream, 0);
    if (Find == INVALID_HANDLE_VALUE)
    {
        skip("Flags 0x%lx: cannot list the streams of the destination (%lu)\n", Flags, GetLastError());
        return;
    }
    do
        Streams++;
    while (FindNextStreamW(Find, &Stream));
    FindClose(Find);
    ok(Streams == 1, "Flags 0x%lx: the destination has %lu streams\n", Flags, Streams);
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
        ok(GetFileAttributesW(Dest) != INVALID_FILE_ATTRIBUTES, "The destination without DELETE access is gone after the stopped copy\n");
    }

    RemoveNoDeleteDir(SubDir);
}

/* A move to another volume is a copy; on Windows 11 a stop removes the partial file there and keeps the source */
static void
test_MoveToOtherVolume(LPCWSTR Root)
{
    WCHAR Other[] = L"A:\\", Moved[MAX_PATH];
    DWORD Drives = GetLogicalDrives(), Action, Error;
    HANDLE File = INVALID_HANDLE_VALUE;
    BOOL Ret;

    for (; Other[0] <= L'Z'; Other[0]++)
    {
        if (!(Drives & (1 << (Other[0] - L'A'))) || Other[0] == towupper(Root[0]) || GetDriveTypeW(Other) != DRIVE_FIXED)
            continue;
        StringCchPrintfW(Moved, ARRAYSIZE(Moved), L"%sCopyFileExStop-%lu-%lu.bin", Other, GetCurrentProcessId(), GetTickCount());
        File = CreateFileW(Moved, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_FLAG_DELETE_ON_CLOSE, NULL);
        if (File != INVALID_HANDLE_VALUE)
            break;
    }
    if (File == INVALID_HANDLE_VALUE)
    {
        skip("No second local volume to move to\n");
        return;
    }
    CloseHandle(File);

    for (Action = PROGRESS_CANCEL; Action <= PROGRESS_STOP; Action++)
    {
        StopAt = STOP_AT;
        StopAction = Action;
        StoppedAt = FirstReport = FirstChunk = -1;
        SetLastError(0xdeadbeef);
        Ret = MoveFileWithProgressW(Source, Moved, Progress, NULL, MOVEFILE_COPY_ALLOWED);
        Error = GetLastError();
        ok(!Ret && Error == ERROR_REQUEST_ABORTED, "Action %lu: move to %S returned %d (%lu)\n", Action, Other, Ret, Error);
        ok(GetFileAttributesW(Source) != INVALID_FILE_ATTRIBUTES, "Action %lu: the source is gone after the stopped move\n", Action);
        ok(GetFileAttributesW(Moved) == INVALID_FILE_ATTRIBUTES, "Action %lu: the stopped move left its destination\n", Action);
        DeleteFileW(Moved);

        /* The file that the move was to replace is gone as well */
        File = CreateFileW(Moved, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
        ok(File != INVALID_HANDLE_VALUE, "Action %lu: cannot create %S (%lu)\n", Action, Moved, GetLastError());
        if (File == INVALID_HANDLE_VALUE)
            continue;
        CloseHandle(File);
        StoppedAt = FirstReport = FirstChunk = -1;
        SetLastError(0xdeadbeef);
        Ret = MoveFileWithProgressW(Source, Moved, Progress, NULL, MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING);
        Error = GetLastError();
        ok(!Ret && Error == ERROR_REQUEST_ABORTED, "Action %lu: move over a file on %S returned %d (%lu)\n", Action, Other, Ret, Error);
        ok(GetFileAttributesW(Source) != INVALID_FILE_ATTRIBUTES, "Action %lu: the source is gone after the stopped replacing move\n", Action);
        ok(GetFileAttributesW(Moved) == INVALID_FILE_ATTRIBUTES, "Action %lu: the stopped move left the file it was to replace\n", Action);
        DeleteFileW(Moved);
    }
}

START_TEST(CopyFileExStop)
{
    static UCHAR Chunk[65536];
    WCHAR Dir[MAX_PATH], Root[MAX_PATH], FileSystem[MAX_PATH];
    HANDLE File;
    DWORD i, Written, Done;
    BOOL Wrote = TRUE;

    GetTempPathW(ARRAYSIZE(Dir), Dir);

    /* The results below were measured on Windows 11 with both files on local disks */
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
    test_PartialDest(0);
    test_PartialDest(COPY_FILE_RESTARTABLE);
    test_FailedRead(0);
    test_FailedRead(COPY_FILE_RESTARTABLE);
    test_StopAfterRename();
    test_Remote();
    test_MoveToOtherVolume(Root);

    DeleteFileW(Dest);
    test_NoDeleteAccess(Dir, FileSystem);
    DeleteFileW(Source);
}
