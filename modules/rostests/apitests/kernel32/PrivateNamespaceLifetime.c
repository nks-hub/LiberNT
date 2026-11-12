/*
 * PROJECT:     LiberNT API Tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Test when a private namespace stops being found, and closing it while other processes open it
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include "precomp.h"
#include <ndk/obfuncs.h>

#define STRESS_BOUNDARY L"K32NsStress"
#define STRESS_CHILDREN 4
#define STRESS_ROUNDS 20000

static BYTE WorldSid[SECURITY_MAX_SID_SIZE];

static HANDLE
MakeBoundary(PCWSTR Name)
{
    HANDLE Boundary = CreateBoundaryDescriptorW(Name, 0);

    if (Boundary && !AddSIDToBoundaryDescriptor(&Boundary, WorldSid))
    {
        DeleteBoundaryDescriptor(Boundary);
        Boundary = NULL;
    }
    return Boundary;
}

static HANDLE
CreateNs(PCWSTR Name, PCWSTR Alias, PDWORD Error)
{
    HANDLE Boundary = MakeBoundary(Name), Namespace;

    SetLastError(0xdeadbeef);
    Namespace = Boundary ? CreatePrivateNamespaceW(NULL, Boundary, Alias) : NULL;
    *Error = GetLastError();
    if (Boundary)
        DeleteBoundaryDescriptor(Boundary);
    return Namespace;
}

static HANDLE
OpenNs(PCWSTR Name, PCWSTR Alias, PDWORD Error)
{
    HANDLE Boundary = MakeBoundary(Name), Namespace;

    SetLastError(0xdeadbeef);
    Namespace = Boundary ? OpenPrivateNamespaceW(Boundary, Alias) : NULL;
    *Error = GetLastError();
    if (Boundary)
        DeleteBoundaryDescriptor(Boundary);
    return Namespace;
}

static void
ExpectGone(PCWSTR Name, PCWSTR Alias, int Line)
{
    HANDLE Namespace;
    DWORD Error;

    Namespace = OpenNs(Name, Alias, &Error);
    ok_(__FILE__, Line)(Namespace == NULL && Error == ERROR_PATH_NOT_FOUND, "%S still opens: %p, error %lu\n", Name, Namespace, Error);
    if (Namespace)
        ClosePrivateNamespace(Namespace, 0);
}

static void
TestLastHandle(void)
{
    HANDLE Namespace, Second, Mutex;
    DWORD Error;

    Namespace = CreateNs(L"K32NsLast", L"K32NsA", &Error);
    ok(Namespace != NULL, "CreatePrivateNamespace failed with %lu\n", Error);
    if (!Namespace)
        return;
    ok(ClosePrivateNamespace(Namespace, 0), "ClosePrivateNamespace failed with %lu\n", GetLastError());
    ExpectGone(L"K32NsLast", L"K32NsB", __LINE__);
    Namespace = CreateNs(L"K32NsLast", L"K32NsA", &Error);
    ok(Namespace != NULL, "creating again after the last handle failed with %lu\n", Error);
    if (Namespace)
        ClosePrivateNamespace(Namespace, 0);

    Namespace = CreateNs(L"K32NsChild", L"K32NsC", &Error);
    ok(Namespace != NULL, "CreatePrivateNamespace failed with %lu\n", Error);
    if (!Namespace)
        return;
    Mutex = CreateMutexW(NULL, FALSE, L"K32NsC\\Lock");
    ok(Mutex != NULL, "CreateMutex in the namespace failed with %lu\n", GetLastError());
    ok(ClosePrivateNamespace(Namespace, 0), "ClosePrivateNamespace failed with %lu\n", GetLastError());
    ExpectGone(L"K32NsChild", L"K32NsD", __LINE__);
    Second = CreateNs(L"K32NsChild", L"K32NsC", &Error);
    ok(Second != NULL, "creating again while an object inside the old one lives failed with %lu\n", Error);
    if (Second)
        ok(ClosePrivateNamespace(Second, PRIVATE_NAMESPACE_FLAG_DESTROY), "destroy failed with %lu\n", GetLastError());
    if (Mutex)
        CloseHandle(Mutex);
    ExpectGone(L"K32NsChild", L"K32NsD", __LINE__);

    Namespace = CreateNs(L"K32NsTwo", L"K32NsE", &Error);
    Second = OpenNs(L"K32NsTwo", L"K32NsF", &Error);
    ok(Namespace != NULL && Second != NULL, "two handles: %p %p, error %lu\n", Namespace, Second, Error);
    if (Namespace)
        ClosePrivateNamespace(Namespace, 0);
    Namespace = OpenNs(L"K32NsTwo", L"K32NsG", &Error);
    ok(Namespace != NULL, "open with one handle left failed with %lu\n", Error);
    if (Namespace)
        ClosePrivateNamespace(Namespace, 0);
    if (Second)
        ClosePrivateNamespace(Second, 0);
    ExpectGone(L"K32NsTwo", L"K32NsG", __LINE__);
}

static void
TestDestroyAndClose(void)
{
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Namespace, Old, Directory;
    NTSTATUS Status;
    DWORD Error;

    Namespace = CreateNs(L"K32NsDestroy", L"K32NsH", &Error);
    Old = OpenNs(L"K32NsDestroy", L"K32NsI", &Error);
    ok(Namespace != NULL && Old != NULL, "two handles: %p %p, error %lu\n", Namespace, Old, Error);
    if (!Namespace || !Old)
        return;
    ok(ClosePrivateNamespace(Namespace, PRIVATE_NAMESPACE_FLAG_DESTROY), "destroy failed with %lu\n", GetLastError());
    ExpectGone(L"K32NsDestroy", L"K32NsJ", __LINE__);
    Namespace = CreateNs(L"K32NsDestroy", L"K32NsH", &Error);
    ok(Namespace != NULL, "creating again while a destroyed one is open failed with %lu\n", Error);
    ok_hex(NtDeletePrivateNamespace(Old), STATUS_INVALID_HANDLE);
    ok(ClosePrivateNamespace(Old, 0), "closing the destroyed namespace failed with %lu\n", GetLastError());
    if (Namespace)
    {
        ok_hex(NtDeletePrivateNamespace(Namespace), STATUS_SUCCESS);
        ok_hex(NtDeletePrivateNamespace(Namespace), STATUS_INVALID_HANDLE);
        ok(ClosePrivateNamespace(Namespace, 0), "ClosePrivateNamespace failed with %lu\n", GetLastError());
        SetLastError(0xdeadbeef);
        ok(!ClosePrivateNamespace(Namespace, 0), "second close succeeded\n");
        ok_err(ERROR_INVALID_HANDLE);
        SetLastError(0xdeadbeef);
        ok(!ClosePrivateNamespace(Namespace, PRIVATE_NAMESPACE_FLAG_DESTROY), "destroying a closed handle succeeded\n");
        ok_err(ERROR_INVALID_HANDLE);
    }

    InitializeObjectAttributes(&Attributes, NULL, 0, NULL, NULL);
    Status = NtCreateDirectoryObject(&Directory, DIRECTORY_ALL_ACCESS, &Attributes);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ok_hex(NtDeletePrivateNamespace(Directory), STATUS_INVALID_HANDLE);
        CloseHandle(Directory);
    }
}

static DWORD
RunStressChild(ULONG Id)
{
    HANDLE Namespace, Mutex;
    DWORD CreateError, OpenError, Unexpected = 0;
    ULONG Round, Try;

    for (Round = 0; Round < STRESS_ROUNDS; Round++)
    {
        Namespace = NULL;
        for (Try = 0; !Namespace && Try < 3; Try++)
        {
            Namespace = CreateNs(STRESS_BOUNDARY, L"K32NsS", &CreateError);
            if (Namespace)
                break;
            Namespace = OpenNs(STRESS_BOUNDARY, L"K32NsS", &OpenError);
            if (!Namespace && (CreateError != ERROR_ALREADY_EXISTS || OpenError != ERROR_PATH_NOT_FOUND))
                Unexpected++;
        }
        if (!Namespace)
            continue;
        Mutex = CreateMutexW(NULL, FALSE, L"K32NsS\\Lock");
        if (!Mutex)
            Unexpected++;
        if ((Round + Id) & 1)
        {
            if (!ClosePrivateNamespace(Namespace, 0))
                Unexpected++;
            if (Mutex)
                CloseHandle(Mutex);
        }
        else
        {
            if (Mutex)
                CloseHandle(Mutex);
            if (!ClosePrivateNamespace(Namespace, 0))
                Unexpected++;
        }
    }
    return Unexpected;
}

static void
TestCloseWhileOthersOpen(void)
{
    WCHAR Application[MAX_PATH], CommandLine[MAX_PATH + 64];
    PROCESS_INFORMATION Info[STRESS_CHILDREN];
    STARTUPINFOW Startup = { sizeof(Startup) };
    HANDLE Namespace;
    DWORD ExitCode, Error;
    ULONG Index;

    if (!GetModuleFileNameW(NULL, Application, ARRAYSIZE(Application)))
    {
        skip("GetModuleFileNameW failed with %lu\n", GetLastError());
        return;
    }
    ZeroMemory(Info, sizeof(Info));
    for (Index = 0; Index < STRESS_CHILDREN; Index++)
    {
        StringCchPrintfW(CommandLine, ARRAYSIZE(CommandLine), L"\"%s\" PrivateNamespaceLifetime child %lu", Application, Index);
        ok(CreateProcessW(Application, CommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &Startup, &Info[Index]),
           "CreateProcess failed with %lu\n", GetLastError());
    }
    for (Index = 0; Index < STRESS_CHILDREN; Index++)
    {
        if (!Info[Index].hProcess)
            continue;
        ok(WaitForSingleObject(Info[Index].hProcess, 300000) == WAIT_OBJECT_0, "child %lu did not finish\n", Index);
        ok(GetExitCodeProcess(Info[Index].hProcess, &ExitCode), "GetExitCodeProcess failed with %lu\n", GetLastError());
        ok(ExitCode == 0, "child %lu saw %lu unexpected results\n", Index, ExitCode);
        CloseHandle(Info[Index].hThread);
        CloseHandle(Info[Index].hProcess);
    }

    ExpectGone(STRESS_BOUNDARY, L"K32NsS", __LINE__);
    Namespace = CreateNs(STRESS_BOUNDARY, L"K32NsS", &Error);
    ok(Namespace != NULL, "creating after all children closed failed with %lu\n", Error);
    if (Namespace)
        ClosePrivateNamespace(Namespace, PRIVATE_NAMESPACE_FLAG_DESTROY);
}

START_TEST(PrivateNamespaceLifetime)
{
    DWORD Size = sizeof(WorldSid);
    char **Arguments;
    int Count = winetest_get_mainargs(&Arguments);

    if (!CreateWellKnownSid(WinWorldSid, NULL, WorldSid, &Size))
    {
        skip("CreateWellKnownSid failed with %lu\n", GetLastError());
        return;
    }
    if (Count >= 4 && !strcmp(Arguments[2], "child"))
        ExitProcess(RunStressChild(strtoul(Arguments[3], NULL, 10)));

    TestLastHandle();
    TestDestroyAndClose();
    TestCloseWhileOthersOpen();
}
