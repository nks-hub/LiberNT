/*
 * PROJECT:     LiberNT Printing Include files
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Printer environments and store lookup shared by the spooler API and the router for driver packages
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#ifndef _LIBERNT_DRVPKGENV_H
#define _LIBERNT_DRVPKGENV_H

extern const WCHAR wszCurrentEnvironment[];

HRESULT WINAPI DriverStoreFindDriverPackageW(PCWSTR InfPath, PVOID Reserved1, PVOID Reserved2, WORD Architecture,
                                             PVOID Reserved3, PWSTR ReturnPath, PDWORD ReturnLength);

static const struct
{
    PCWSTR Environment;
    WORD Architecture;
    PCWSTR Decoration;
}
EnvironmentArchitectures[] =
{
    { L"Windows NT x86", PROCESSOR_ARCHITECTURE_INTEL, L"x86" },
    { L"Windows x64", PROCESSOR_ARCHITECTURE_AMD64, L"amd64" },
    { L"Windows ARM64", PROCESSOR_ARCHITECTURE_ARM64, L"arm64" },
    { L"Windows ARM", PROCESSOR_ARCHITECTURE_ARM, L"arm" },
    { L"ReactOS RISC-V64", PROCESSOR_ARCHITECTURE_RISCV64, L"riscv64" },
    { L"Windows NT PowerPC", PROCESSOR_ARCHITECTURE_PPC, L"ppc" },
};

static inline HRESULT
CheckLocalRequest(PCWSTR pszServer, PCWSTR pszEnvironment, PCWSTR *Environment, PWORD Architecture)
{
    WCHAR ComputerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD Size = ARRAYSIZE(ComputerName), i;

    if (!pszEnvironment || !*pszEnvironment)
        pszEnvironment = wszCurrentEnvironment;

    for (i = 0; i < ARRAYSIZE(EnvironmentArchitectures); i++)
    {
        if (_wcsicmp(pszEnvironment, EnvironmentArchitectures[i].Environment) == 0)
            break;
    }
    if (i == ARRAYSIZE(EnvironmentArchitectures))
        return HRESULT_FROM_WIN32(ERROR_INVALID_ENVIRONMENT);
    *Environment = EnvironmentArchitectures[i].Environment;
    *Architecture = EnvironmentArchitectures[i].Architecture;

    if (!pszServer || !*pszServer)
        return S_OK;

    while (*pszServer == L'\\')
        pszServer++;

    if (GetComputerNameW(ComputerName, &Size) && _wcsicmp(pszServer, ComputerName) == 0)
        return S_OK;

    return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
}

/* Gives the store INF that a path names, however it is spelled, or the full path when the store has none */
static inline BOOL
ResolvePackageInf(PCWSTR InfPath, WORD Architecture, PWSTR Resolved)
{
    DWORD Length = MAX_PATH;

    if (SUCCEEDED(DriverStoreFindDriverPackageW(InfPath, NULL, NULL, Architecture, NULL, Resolved, &Length)))
        return TRUE;

    Length = GetFullPathNameW(InfPath, MAX_PATH, Resolved, NULL);
    if (Length == 0 || Length >= MAX_PATH)
        *Resolved = UNICODE_NULL;
    return FALSE;
}

#endif
