/*
 * PROJECT:     LiberNT API Tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Tests for NciGetConnectionName and NciSetConnectionName
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include <apitest.h>

#define WIN32_NO_STATUS
#include <winsock2.h>
#include <iphlpapi.h>
#include <objbase.h>
#include <sddl.h>
#include <stdio.h>
#include <string.h>
#include <strsafe.h>

#ifndef WRITE_RESTRICTED
#define WRITE_RESTRICTED 0x8
#endif

typedef DWORD (WINAPI *PFN_NCI_GET)(const GUID *, PWSTR, DWORD, DWORD *);
typedef DWORD (WINAPI *PFN_NCI_SET)(const GUID *, PCWSTR);

static PFN_NCI_GET pNciGetConnectionName;
static PFN_NCI_SET pNciSetConnectionName;

static ULONG
GetConnections(GUID *Guids, WCHAR Names[][256])
{
    IP_ADAPTER_ADDRESSES *Addresses, *Adapter;
    ULONG Size = 0, Count = 0;
    WCHAR Text[64];

    GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &Size);
    Addresses = HeapAlloc(GetProcessHeap(), 0, Size);
    if (!Addresses || GetAdaptersAddresses(AF_UNSPEC, 0, NULL, Addresses, &Size) != NO_ERROR)
    {
        HeapFree(GetProcessHeap(), 0, Addresses);
        return 0;
    }
    for (Adapter = Addresses; Adapter && Count < 2; Adapter = Adapter->Next)
    {
        if (Adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK ||
            !MultiByteToWideChar(CP_ACP, 0, Adapter->AdapterName, -1, Text, ARRAYSIZE(Text)) ||
            FAILED(CLSIDFromString(Text, &Guids[Count])))
        {
            continue;
        }
        lstrcpynW(Names[Count], Adapter->FriendlyName, 256);
        Count++;
    }
    HeapFree(GetProcessHeap(), 0, Addresses);
    return Count;
}

/* The token the service control manager builds for a service with SERVICE_SID_TYPE_RESTRICTED */
static HANDLE
CreateRestrictedServiceToken(void)
{
    static SID_IDENTIFIER_AUTHORITY NtAuthority = { SECURITY_NT_AUTHORITY }, WorldAuthority = { SECURITY_WORLD_SID_AUTHORITY };
    HANDLE Token, Restricted = NULL, Impersonation = NULL;
    PSID Service = NULL, World = NULL, WriteRestricted = NULL;
    SID_AND_ATTRIBUTES Restricting[4];
    BYTE Buffer[4096];
    TOKEN_GROUPS *Groups = (TOKEN_GROUPS *)Buffer;
    DWORD Count = 0, Size, i;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &Token))
        return NULL;
    ZeroMemory(Restricting, sizeof(Restricting));
    if (AllocateAndInitializeSid(&NtAuthority, 6, SECURITY_SERVICE_ID_BASE_RID, 1, 2, 3, 4, 5, 0, 0, &Service) &&
        AllocateAndInitializeSid(&WorldAuthority, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &World) &&
        AllocateAndInitializeSid(&NtAuthority, 1, SECURITY_WRITE_RESTRICTED_CODE_RID, 0, 0, 0, 0, 0, 0, 0, &WriteRestricted))
    {
        Restricting[Count++].Sid = Service;
        if (GetTokenInformation(Token, TokenGroups, Buffer, sizeof(Buffer), &Size))
        {
            for (i = 0; i < Groups->GroupCount; i++)
            {
                if (Groups->Groups[i].Attributes & SE_GROUP_LOGON_ID)
                {
                    Restricting[Count++].Sid = Groups->Groups[i].Sid;
                    break;
                }
            }
        }
        Restricting[Count++].Sid = World;
        Restricting[Count++].Sid = WriteRestricted;
        if (CreateRestrictedToken(Token, WRITE_RESTRICTED, 0, NULL, 0, NULL, Count, Restricting, &Restricted))
        {
            DuplicateTokenEx(Restricted, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &Impersonation);
            CloseHandle(Restricted);
        }
    }
    if (Service)
        FreeSid(Service);
    if (World)
        FreeSid(World);
    if (WriteRestricted)
        FreeSid(WriteRestricted);
    CloseHandle(Token);
    return Impersonation;
}

/* Opens the lock of a private namespace of administrators the way the library opens the lock of the connection names */
static HANDLE
OpenNamespaceLock(PCWSTR Name, PCWSTR Dacl, BOOL Create, HANDLE *Namespace, DWORD *Error)
{
    SECURITY_ATTRIBUTES Security = { sizeof(Security), NULL, FALSE };
    BYTE Admins[SECURITY_MAX_SID_SIZE];
    DWORD Size = sizeof(Admins);
    WCHAR LockName[64];
    HANDLE Boundary, Lock;

    *Namespace = NULL;
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, Admins, &Size) ||
        !ConvertStringSecurityDescriptorToSecurityDescriptorW(Dacl, SDDL_REVISION_1, &Security.lpSecurityDescriptor, NULL))
    {
        *Error = GetLastError();
        return NULL;
    }
    Boundary = CreateBoundaryDescriptorW(Name, 0);
    if (Boundary && AddSIDToBoundaryDescriptor(&Boundary, Admins))
    {
        if (Create)
            *Namespace = CreatePrivateNamespaceW(&Security, Boundary, Name);
        if (!*Namespace)
            *Namespace = OpenPrivateNamespaceW(Boundary, Name);
    }
    if (Boundary)
        DeleteBoundaryDescriptor(Boundary);

    /* A namespace this process has open already cannot be opened again, and its name leads to the lock all the same */
    StringCchPrintfW(LockName, ARRAYSIZE(LockName), L"%s\\Lock", Name);
    SetLastError(ERROR_SUCCESS);
    Lock = CreateMutexW(&Security, FALSE, LockName);
    *Error = GetLastError();
    LocalFree(Security.lpSecurityDescriptor);
    return Lock;
}

#define LIBRARY_NAMESPACE L"NetworkConnectionNames"
#define LIBRARY_DACL L"D:(A;;GA;;;BA)(A;;GA;;;SY)(A;;GA;;;S-1-5-33)"
#define ADMIN_NAMESPACE L"NciTestAdministratorsOnly"
#define ADMIN_DACL L"D:(A;;GA;;;BA)(A;;GA;;;SY)"

#define RESTRICTED_RAN 0x100
#define RESTRICTED_NAMESPACE_OPENED 0x1
#define RESTRICTED_LOCK_OPENED 0x2
#define RESTRICTED_LOCK_TAKEN 0x4
#define RESTRICTED_ADMIN_LOCK_DENIED 0x8

/* Opens the locks its parent holds as a restricted service would and reports what it got in its exit code */
static void
RunRestrictedChild(void)
{
    HANDLE Token = CreateRestrictedServiceToken(), Namespace, AdminNamespace, Lock, AdminLock;
    DWORD Error, AdminError, Code = RESTRICTED_RAN;

    if (!Token || !SetThreadToken(NULL, Token))
        ExitProcess(0);
    Lock = OpenNamespaceLock(LIBRARY_NAMESPACE, LIBRARY_DACL, FALSE, &Namespace, &Error);
    AdminLock = OpenNamespaceLock(ADMIN_NAMESPACE, ADMIN_DACL, FALSE, &AdminNamespace, &AdminError);
    RevertToSelf();

    if (Namespace)
        Code |= RESTRICTED_NAMESPACE_OPENED;
    if (Lock && Error == ERROR_ALREADY_EXISTS)
        Code |= RESTRICTED_LOCK_OPENED;
    if (Lock && WaitForSingleObject(Lock, 10000) == WAIT_OBJECT_0)
    {
        Code |= RESTRICTED_LOCK_TAKEN;
        ReleaseMutex(Lock);
    }
    if (!AdminLock && AdminError == ERROR_ACCESS_DENIED)
        Code |= RESTRICTED_ADMIN_LOCK_DENIED;
    printf("The restricted child got namespace %p, lock %p (error %lu), administrators only lock %p (error %lu)\n",
           Namespace, Lock, Error, AdminLock, AdminError);
    ExitProcess(Code);
}

/* Windows 11 grants a write-restricted token all access to a mutex only when the DACL of the mutex names a restricting SID of the token */
static void
test_RestrictedServiceLock(void)
{
    HANDLE HeldNamespace, HeldLock, HeldAdminNamespace, HeldAdminLock;
    WCHAR Path[MAX_PATH], CommandLine[MAX_PATH + 48];
    STARTUPINFOW Startup = { sizeof(Startup) };
    PROCESS_INFORMATION Process;
    DWORD Error, AdminError, ExitCode = 0;

    /* The library holds its lock from its first rename on; on Windows the test holds a lock with the same DACL instead */
    HeldLock = OpenNamespaceLock(LIBRARY_NAMESPACE, LIBRARY_DACL, TRUE, &HeldNamespace, &Error);
    HeldAdminLock = OpenNamespaceLock(ADMIN_NAMESPACE, ADMIN_DACL, TRUE, &HeldAdminNamespace, &AdminError);
    GetModuleFileNameW(NULL, Path, ARRAYSIZE(Path));
    StringCchPrintfW(CommandLine, ARRAYSIZE(CommandLine), L"\"%s\" NciConnectionName restricted", Path);
    if (!HeldLock || !HeldAdminLock)
    {
        skip("No lock in a namespace of administrators (errors %lu, %lu)\n", Error, AdminError);
    }
    else if (!CreateProcessW(Path, CommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &Startup, &Process))
    {
        skip("CreateProcessW failed (%lu)\n", GetLastError());
    }
    else
    {
        WaitForSingleObject(Process.hProcess, 60000);
        GetExitCodeProcess(Process.hProcess, &ExitCode);
        CloseHandle(Process.hThread);
        CloseHandle(Process.hProcess);
        if (!(ExitCode & RESTRICTED_RAN))
        {
            skip("The child has no write-restricted token (exit code 0x%lx)\n", ExitCode);
        }
        else
        {
            ok(ExitCode & RESTRICTED_NAMESPACE_OPENED, "A restricted service cannot open the namespace of the connection names\n");
            ok(ExitCode & RESTRICTED_LOCK_OPENED, "A restricted service cannot open the lock of the connection names another process holds\n");
            ok(ExitCode & RESTRICTED_LOCK_TAKEN, "A restricted service cannot take the lock of the connection names\n");
            ok(ExitCode & RESTRICTED_ADMIN_LOCK_DENIED, "A restricted service opened a lock whose DACL only names administrators\n");
        }
    }

    if (HeldLock)
        CloseHandle(HeldLock);
    if (HeldAdminLock)
        CloseHandle(HeldAdminLock);
    if (HeldNamespace)
        ClosePrivateNamespace(HeldNamespace, 0);
    if (HeldAdminNamespace)
        ClosePrivateNamespace(HeldAdminNamespace, 0);
}

typedef struct _RENAME
{
    const GUID *Guid;
    PCWSTR Name;
    DWORD Error;
} RENAME;

static DWORD WINAPI
RenameThread(PVOID Parameter)
{
    RENAME *Rename = Parameter;

    Rename->Error = pNciSetConnectionName(Rename->Guid, Rename->Name);
    return 0;
}

/* netcfgx holds the namespace of the connection names under the alias NetworkConnectionNames and takes the lock while it names a connection */
static void
test_LockSharedWithNetcfgx(const GUID *Guid, PCWSTR Name)
{
    RENAME Rename = { Guid, Name, ERROR_GEN_FAILURE };
    HMODULE Netcfgx = LoadLibraryW(L"netcfgx.dll");
    HANDLE Namespace, Lock, Thread;
    BOOL Owned = FALSE;
    DWORD Error, Wait;

    ok(Netcfgx != NULL, "LoadLibrary(netcfgx.dll) failed with %lu\n", GetLastError());
    Lock = OpenNamespaceLock(LIBRARY_NAMESPACE, LIBRARY_DACL, TRUE, &Namespace, &Error);
    ok(Namespace != NULL && Lock != NULL, "Namespace %p and lock %p of the connection names, error %lu\n", Namespace, Lock, Error);
    if (Lock)
        Owned = (WaitForSingleObject(Lock, 10000) == WAIT_OBJECT_0);
    Thread = CreateThread(NULL, 0, RenameThread, &Rename, 0, NULL);
    ok(Thread != NULL, "CreateThread failed with %lu\n", GetLastError());
    if (Thread)
    {
        Wait = WaitForSingleObject(Thread, 500);
        trace("The rename %s for the lock of the connection names\n", Wait == WAIT_TIMEOUT ? "waited" : "did not wait");
    }
    if (Owned)
        ReleaseMutex(Lock);
    if (Thread)
    {
        ok(WaitForSingleObject(Thread, 60000) == WAIT_OBJECT_0, "The rename did not finish\n");
        CloseHandle(Thread);
    }
    ok(Rename.Error == NO_ERROR, "Renaming while the alias NetworkConnectionNames is in use returned %lu\n", Rename.Error);

    if (Lock)
        CloseHandle(Lock);
    if (Namespace)
        ClosePrivateNamespace(Namespace, 0);
    if (Netcfgx)
        FreeLibrary(Netcfgx);
}

START_TEST(NciConnectionName)
{
    HMODULE hNci = LoadLibraryW(L"nci.dll");
    GUID Guids[2], Unknown = { 0x12345678, 0x1234, 0x1234, { 1, 2, 3, 4, 5, 6, 7, 8 } };
    WCHAR Names[2][256], Name[256], Path[160];
    DWORD Error, Size;
    HKEY Key;
    ULONG Count;
    char **argv;

    if (winetest_get_mainargs(&argv) >= 3 && !strcmp(argv[2], "restricted"))
        RunRestrictedChild();

    if (!hNci)
    {
        skip("nci.dll is missing\n");
        return;
    }
    pNciGetConnectionName = (PFN_NCI_GET)GetProcAddress(hNci, "NciGetConnectionName");
    pNciSetConnectionName = (PFN_NCI_SET)GetProcAddress(hNci, "NciSetConnectionName");
    if (!pNciGetConnectionName || !pNciSetConnectionName)
    {
        skip("nci.dll has no connection name functions\n");
        return;
    }

    Size = sizeof(Name);
    Error = pNciGetConnectionName(&Unknown, Name, sizeof(Name), &Size);
    trace("NciGetConnectionName(unknown GUID) returned %lu\n", Error);
    ok(Error != NO_ERROR, "A connection that does not exist has a name\n");

    Count = GetConnections(Guids, Names);

    CoCreateGuid(&Unknown);
    StringFromGUID2(&Unknown, Name, ARRAYSIZE(Name));
    StringCchPrintfW(Path, ARRAYSIZE(Path), L"SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s", Name);
    Error = pNciSetConnectionName(&Unknown, L"NciConnectionName unknown");
    ok(Error == ERROR_FILE_NOT_FOUND, "Naming an unknown connection returned %lu\n", Error);
    if (Count)
    {
        Error = pNciSetConnectionName(&Unknown, Names[0]);
        ok(Error == ERROR_FILE_NOT_FOUND, "Giving an unknown connection a used name returned %lu\n", Error);
    }
    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, Path, 0, KEY_READ, &Key);
    ok(Error == ERROR_FILE_NOT_FOUND, "Opening the key of an unknown connection returned %lu\n", Error);
    if (Error == ERROR_SUCCESS)
    {
        RegDeleteKeyW(Key, L"Connection");
        RegCloseKey(Key);
        RegDeleteKeyW(HKEY_LOCAL_MACHINE, Path);
    }
    Size = sizeof(Name);
    Error = pNciGetConnectionName(&Unknown, Name, sizeof(Name), &Size);
    ok(Error == ERROR_FILE_NOT_FOUND, "Reading the name of an unknown connection returned %lu\n", Error);

    if (Count == 0)
    {
        skip("No connection to test with\n");
        return;
    }

    Size = 0;
    Error = pNciGetConnectionName(&Guids[0], NULL, 0, &Size);
    ok(Error == NO_ERROR, "NciGetConnectionName(NULL, 0) returned %lu\n", Error);
    ok(Size == (lstrlenW(Names[0]) + 1) * sizeof(WCHAR), "Size %lu for name %S\n", Size, Names[0]);

    Size = sizeof(Name);
    Error = pNciGetConnectionName(&Guids[0], Name, sizeof(Name), &Size);
    ok(Error == NO_ERROR, "NciGetConnectionName returned %lu\n", Error);
    ok(Error != NO_ERROR || !lstrcmpW(Name, Names[0]), "Name %S, expected %S\n", Name, Names[0]);

    /* First: the library creates its lock with its first rename */
    test_LockSharedWithNetcfgx(&Guids[0], Names[0]);
    Error = pNciSetConnectionName(&Guids[0], Names[0]);
    ok(Error == NO_ERROR, "Setting the current name returned %lu\n", Error);
    test_RestrictedServiceLock();

    if (Count < 2)
    {
        skip("A second connection is needed to test a duplicate name\n");
        return;
    }
    Error = pNciSetConnectionName(&Guids[0], Names[1]);
    trace("Setting the name of another connection returned %lu\n", Error);
    ok(Error != NO_ERROR, "The name of another connection was accepted\n");
    Size = sizeof(Name);
    if (pNciGetConnectionName(&Guids[0], Name, sizeof(Name), &Size) == NO_ERROR)
        ok(!lstrcmpW(Name, Names[0]), "The name changed to %S\n", Name);
    if (Error == NO_ERROR)
        pNciSetConnectionName(&Guids[0], Names[0]);
}
