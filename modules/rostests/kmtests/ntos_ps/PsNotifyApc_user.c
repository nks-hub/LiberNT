/*
 * PROJECT:     LiberNT kernel-mode tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     State a process notify routine runs in, user-mode part
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include <kmt_test.h>

#include "PsNotifyApc.h"

START_TEST(PsNotifyApc)
{
    PSNOTIFYAPC_RESULT Result;
    PROCESS_INFORMATION Info;
    STARTUPINFOW Startup;
    WCHAR Path[MAX_PATH];
    DWORD Length;
    DWORD Error;

    Error = KmtLoadAndOpenDriver(L"PsNotifyApc", TRUE);
    ok_eq_int(Error, ERROR_SUCCESS);
    if (Error)
        return;

    Error = KmtSendUlongToDriver(IOCTL_PSNOTIFYAPC_WATCH, GetCurrentProcessId());
    ok_eq_int(Error, ERROR_SUCCESS);

    Length = GetModuleFileNameW(NULL, Path, RTL_NUMBER_OF(Path));
    ok(Length != 0 && Length < RTL_NUMBER_OF(Path), "GetModuleFileNameW failed: %lu\n", GetLastError());

    /* The child never runs: creating it and ending its suspended thread is enough to call both notifications */
    ZeroMemory(&Info, sizeof(Info));
    ZeroMemory(&Startup, sizeof(Startup));
    Startup.cb = sizeof(Startup);
    if (!Error && Length != 0 && Length < RTL_NUMBER_OF(Path) &&
        !CreateProcessW(Path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &Startup, &Info))
    {
        Error = GetLastError();
        ok(FALSE, "CreateProcessW failed: %lu\n", Error);
    }

    if (Info.hProcess)
    {
        ok(TerminateProcess(Info.hProcess, 0), "TerminateProcess failed: %lu\n", GetLastError());
        ok_eq_ulong(WaitForSingleObject(Info.hProcess, 10000), WAIT_OBJECT_0);
        CloseHandle(Info.hThread);
        CloseHandle(Info.hProcess);

        ZeroMemory(&Result, sizeof(Result));
        Length = sizeof(Result);
        Error = KmtSendBufferToDriver(IOCTL_PSNOTIFYAPC_QUERY, &Result, 0, &Length);
        ok_eq_int(Error, ERROR_SUCCESS);
        ok_eq_ulong(Length, (DWORD)sizeof(Result));

        /* Process notify routines run at PASSIVE_LEVEL in a critical region, for creation and exit alike */
        ok_eq_ulong(Result.CreateCalls, 1UL);
        ok_eq_ulong(Result.CreateIrql, 0UL);
        ok_eq_ulong(Result.CreateApcsDisabled, 1UL);
        ok_eq_ulong(Result.ExitCalls, 1UL);
        ok_eq_ulong(Result.ExitIrql, 0UL);
        ok_eq_ulong(Result.ExitApcsDisabled, 1UL);
    }

    KmtCloseDriver();
    KmtUnloadDriver();
}
