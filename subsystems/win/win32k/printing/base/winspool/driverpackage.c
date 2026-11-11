/*
 * PROJECT:     LiberNT Spooler API
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Printer driver packages in the driver store
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include "precomp.h"
#include <setupapi.h>
#include <winnls.h>
#include <drvpkglock.h>

extern const WCHAR wszCurrentEnvironment[];

HRESULT WINAPI DriverStoreAddDriverPackageW(PCWSTR InfPath, PVOID Reserved1, PVOID Reserved2,
                                            WORD Architecture, PWSTR ReturnPath, PDWORD ReturnLength);
HRESULT WINAPI DriverStoreDeleteDriverPackageW(PCWSTR InfPath, PVOID Reserved1, PVOID Reserved2);
HRESULT WINAPI DriverStoreFindDriverPackageW(PCWSTR InfPath, PVOID Reserved1, PVOID Reserved2, WORD Architecture,
                                             PVOID Reserved3, PWSTR ReturnPath, PDWORD ReturnLength);

#define DRIVERS_KEY L"SYSTEM\\CurrentControlSet\\Control\\Print\\Environments\\%s\\Drivers\\Version-3"

typedef struct _PACKAGE_FILES
{
    DWORD Count;
    DWORD Capacity;
    PWSTR *Names;
    PWSTR *Sources;
} PACKAGE_FILES, *PPACKAGE_FILES;

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

static HRESULT
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

static HRESULT
ReturnString(PCWSTR Source, PWSTR Destination, PULONG pcchDestination)
{
    ULONG Needed = (ULONG)wcslen(Source) + 1;

    if (!Destination || *pcchDestination < Needed)
    {
        *pcchDestination = Needed;
        return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
    }

    StringCchCopyW(Destination, *pcchDestination, Source);
    *pcchDestination = Needed;
    return S_OK;
}

HRESULT WINAPI
UploadPrinterDriverPackageW(LPCWSTR pszServer, LPCWSTR pszInfPath, LPCWSTR pszEnvironment, DWORD dwFlags,
                            HWND hwnd, LPWSTR pszDestInfPath, PULONG pcchDestInfPath)
{
    WCHAR StoreInf[MAX_PATH];
    DWORD Length = ARRAYSIZE(StoreInf);
    HANDLE Namespace, Lock;
    PCWSTR Environment;
    WORD Architecture;
    HRESULT hr;

    TRACE("UploadPrinterDriverPackageW(%S, %S, %S, 0x%lx, %p, %p, %p)\n",
          pszServer, pszInfPath, pszEnvironment, dwFlags, hwnd, pszDestInfPath, pcchDestInfPath);

    UNREFERENCED_PARAMETER(hwnd);

    if (!pszInfPath || !pcchDestInfPath ||
        (dwFlags & ~(UPDP_SILENT_UPLOAD | UPDP_UPLOAD_ALWAYS | UPDP_CHECK_DRIVERSTORE)))
    {
        return E_INVALIDARG;
    }

    hr = CheckLocalRequest(pszServer, pszEnvironment, &Environment, &Architecture);
    if (FAILED(hr))
        return hr;

    if (!AcquirePackageLock(&Namespace, &Lock))
        return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);

    if (!(dwFlags & UPDP_UPLOAD_ALWAYS))
        hr = DriverStoreFindDriverPackageW(pszInfPath, NULL, NULL, Architecture, NULL, StoreInf, &Length);
    if ((dwFlags & UPDP_UPLOAD_ALWAYS) || FAILED(hr))
    {
        Length = ARRAYSIZE(StoreInf);
        hr = DriverStoreAddDriverPackageW(pszInfPath, NULL, NULL, Architecture, StoreInf, &Length);
    }

    ReleasePackageLock(Namespace, Lock);
    if (FAILED(hr))
        return hr;

    return ReturnString(StoreInf, pszDestInfPath, pcchDestInfPath);
}

/* Gives the store INF that a path names, however it is spelled, or the full path when the store has none */
static BOOL
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

static HRESULT
IsDriverPackageInUse(PCWSTR InfPath, PCWSTR Environment, WORD Architecture)
{
    WCHAR Key[MAX_PATH], Name[MAX_PATH], Value[MAX_PATH], Used[MAX_PATH];
    HRESULT hr = S_FALSE;
    HKEY hDrivers;
    DWORD i, Size;
    LSTATUS Error;

    if (FAILED(StringCchPrintfW(Key, ARRAYSIZE(Key), DRIVERS_KEY, Environment)))
        return E_FAIL;
    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, Key, 0, KEY_READ, &hDrivers);
    if (Error == ERROR_FILE_NOT_FOUND)
        return S_FALSE;
    if (Error != ERROR_SUCCESS)
        return HRESULT_FROM_WIN32(Error);

    for (i = 0; hr == S_FALSE; i++)
    {
        Size = ARRAYSIZE(Name);
        Error = RegEnumKeyExW(hDrivers, i, Name, &Size, NULL, NULL, NULL, NULL);
        if (Error == ERROR_NO_MORE_ITEMS)
            break;
        if (Error != ERROR_SUCCESS)
        {
            hr = HRESULT_FROM_WIN32(Error);
            break;
        }
        Size = sizeof(Value);
        Error = RegGetValueW(hDrivers, Name, L"InfPath", RRF_RT_REG_SZ, NULL, Value, &Size);
        if (Error == ERROR_FILE_NOT_FOUND)
            continue;
        if (Error != ERROR_SUCCESS)
            hr = HRESULT_FROM_WIN32(Error);
        else
        {
            ResolvePackageInf(Value, Architecture, Used);
            if (CompareStringOrdinal(Used, -1, InfPath, -1, TRUE) == CSTR_EQUAL)
                hr = S_OK;
        }
    }

    RegCloseKey(hDrivers);
    return hr;
}

HRESULT WINAPI
DeletePrinterDriverPackageW(LPCWSTR pszServer, LPCWSTR pszInfPath, LPCWSTR pszEnvironment)
{
    WCHAR Package[MAX_PATH];
    HANDLE Namespace, Lock;
    PCWSTR Environment;
    WORD Architecture;
    BOOL Stored;
    HRESULT hr;

    TRACE("DeletePrinterDriverPackageW(%S, %S, %S)\n", pszServer, pszInfPath, pszEnvironment);

    if (!pszInfPath)
        return E_INVALIDARG;

    hr = CheckLocalRequest(pszServer, pszEnvironment, &Environment, &Architecture);
    if (FAILED(hr))
        return hr;

    Stored = ResolvePackageInf(pszInfPath, Architecture, Package);
    if (!*Package)
        return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);

    if (!AcquirePackageLock(&Namespace, &Lock))
        return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);

    hr = IsDriverPackageInUse(Package, Environment, Architecture);
    if (hr == S_OK)
        hr = HRESULT_FROM_WIN32(ERROR_PRINTER_DRIVER_PACKAGE_IN_USE);
    else if (hr == S_FALSE)
        hr = Stored ? DriverStoreDeleteDriverPackageW(Package, NULL, NULL) : HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);

    ReleasePackageLock(Namespace, Lock);
    return hr;
}

static BOOL
AddPackageFile(PPACKAGE_FILES Files, PCWSTR Name, PCWSTR Source)
{
    DWORD i;

    if (!Name || !*Name)
        return TRUE;

    for (i = 0; i < Files->Count; i++)
    {
        if (_wcsicmp(Files->Names[i], Name) == 0)
            return TRUE;
    }

    if (Files->Count == Files->Capacity)
    {
        DWORD Capacity = Files->Capacity ? Files->Capacity * 2 : 32;
        PWSTR *Grown;

        if (Capacity <= Files->Capacity || Capacity > MAXDWORD / sizeof(PWSTR))
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return FALSE;
        }
        Grown = DllAllocSplMem(Capacity * sizeof(PWSTR));
        if (!Grown)
            return FALSE;
        if (Files->Names)
        {
            CopyMemory(Grown, Files->Names, Files->Count * sizeof(PWSTR));
            DllFreeSplMem(Files->Names);
        }
        Files->Names = Grown;
        Grown = DllAllocSplMem(Capacity * sizeof(PWSTR));
        if (!Grown)
            return FALSE;
        if (Files->Sources)
        {
            CopyMemory(Grown, Files->Sources, Files->Count * sizeof(PWSTR));
            DllFreeSplMem(Files->Sources);
        }
        Files->Sources = Grown;
        Files->Capacity = Capacity;
    }

    Files->Names[Files->Count] = AllocSplStr(Name);
    Files->Sources[Files->Count] = NULL;
    if (!Files->Names[Files->Count])
        return FALSE;
    if (Source && *Source && _wcsicmp(Source, Name) != 0)
    {
        Files->Sources[Files->Count] = AllocSplStr(Source);
        if (!Files->Sources[Files->Count])
        {
            DllFreeSplStr(Files->Names[Files->Count]);
            return FALSE;
        }
    }
    Files->Count++;
    return TRUE;
}

static VOID
FreePackageFiles(PPACKAGE_FILES Files)
{
    while (Files->Count)
    {
        Files->Count--;
        DllFreeSplStr(Files->Names[Files->Count]);
        if (Files->Sources[Files->Count])
            DllFreeSplStr(Files->Sources[Files->Count]);
    }
    if (Files->Names)
        DllFreeSplMem(Files->Names);
    if (Files->Sources)
        DllFreeSplMem(Files->Sources);
    Files->Names = Files->Sources = NULL;
    Files->Capacity = 0;
}

static BOOL
CollectCopyFiles(HINF hInf, PCWSTR Section, PPACKAGE_FILES Files)
{
    WCHAR Entry[MAX_PATH], Name[MAX_PATH], Source[MAX_PATH];
    INFCONTEXT Context, FileContext;
    DWORD Field, FieldCount;

    if (!SetupFindFirstLineW(hInf, Section, L"CopyFiles", &Context))
        return TRUE;

    do
    {
        FieldCount = SetupGetFieldCount(&Context);
        for (Field = 1; Field <= FieldCount; Field++)
        {
            if (!SetupGetStringFieldW(&Context, Field, Entry, ARRAYSIZE(Entry), NULL) || !*Entry)
                continue;

            if (Entry[0] == L'@')
            {
                if (!AddPackageFile(Files, Entry + 1, NULL))
                    return FALSE;
                continue;
            }

            if (SetupGetLineCountW(hInf, Entry) < 0)
            {
                ERR("CopyFiles section %S not found\n", Entry);
                SetLastError(ERROR_SECTION_NOT_FOUND);
                return FALSE;
            }
            if (!SetupFindFirstLineW(hInf, Entry, NULL, &FileContext))
                continue;
            do
            {
                if (!SetupGetStringFieldW(&FileContext, 2, Source, ARRAYSIZE(Source), NULL))
                    *Source = UNICODE_NULL;
                if (SetupGetStringFieldW(&FileContext, 1, Name, ARRAYSIZE(Name), NULL) &&
                    !AddPackageFile(Files, Name, Source))
                {
                    return FALSE;
                }
            } while (SetupFindNextLine(&FileContext, &FileContext));
        }
    } while (SetupFindNextMatchLineW(&Context, L"CopyFiles", &Context));

    return TRUE;
}

static BOOL
GetDirective(HINF hInf, PWSTR *Sections, DWORD SectionCount, PCWSTR Key, PWSTR Value, DWORD ValueSize)
{
    WCHAR DataSection[MAX_PATH];
    INFCONTEXT Context;
    DWORD i;

    for (i = 0; i < SectionCount; i++)
    {
        if (SetupFindFirstLineW(hInf, Sections[i], Key, &Context) &&
            SetupGetStringFieldW(&Context, 1, Value, ValueSize, NULL))
        {
            return TRUE;
        }
    }

    for (i = 0; i < SectionCount; i++)
    {
        if (SetupFindFirstLineW(hInf, Sections[i], L"DataSection", &Context) &&
            SetupGetStringFieldW(&Context, 1, DataSection, ARRAYSIZE(DataSection), NULL) &&
            SetupFindFirstLineW(hInf, DataSection, Key, &Context) &&
            SetupGetStringFieldW(&Context, 1, Value, ValueSize, NULL))
        {
            return TRUE;
        }
    }

    *Value = UNICODE_NULL;
    return FALSE;
}

static BOOL
FindModelSection(HINF hInf, PSP_ALTPLATFORM_INFO Platform, PCWSTR DriverName, PWSTR Section, DWORD SectionSize)
{
    WCHAR Models[MAX_PATH];
    INFCONTEXT MfgContext, ModelContext;

    if (!SetupFindFirstLineW(hInf, L"Manufacturer", NULL, &MfgContext))
        return FALSE;

    do
    {
        /* SetupDiGetActualModelsSectionW fails for a line without TargetOSVersion, which names its section itself */
        if (SetupGetFieldCount(&MfgContext) < 2
                ? !SetupGetStringFieldW(&MfgContext, 1, Models, ARRAYSIZE(Models), NULL)
                : !SetupDiGetActualModelsSectionW(&MfgContext, Platform, Models, ARRAYSIZE(Models), NULL, NULL))
        {
            continue;
        }

        if (SetupFindFirstLineW(hInf, Models, DriverName, &ModelContext) &&
            SetupGetStringFieldW(&ModelContext, 1, Section, SectionSize, NULL))
        {
            return TRUE;
        }
    } while (SetupFindNextLine(&MfgContext, &MfgContext));

    return FALSE;
}

static BOOL
FindSourceDisksLine(HINF hInf, PCWSTR Section, PCWSTR Decoration, PCWSTR Key, PINFCONTEXT Context)
{
    WCHAR Decorated[64];

    return (SUCCEEDED(StringCchPrintfW(Decorated, ARRAYSIZE(Decorated), L"%s.%s", Section, Decoration)) &&
            SetupFindFirstLineW(hInf, Decorated, Key, Context)) ||
           SetupFindFirstLineW(hInf, Section, Key, Context);
}

static BOOL
LocatePackageFile(HINF hInf, PCWSTR Decoration, PCWSTR PackageDir, PCWSTR DriverDir, PCWSTR Name, PWSTR Path, DWORD PathSize)
{
    WCHAR SourcePath[MAX_PATH] = L"", SubDir[MAX_PATH] = L"", DiskName[16];
    INFCONTEXT Line;
    INT SourceId;

    if (FindSourceDisksLine(hInf, L"SourceDisksFiles", Decoration, Name, &Line) && SetupGetIntField(&Line, 1, &SourceId))
    {
        if (!SetupGetStringFieldW(&Line, 2, SubDir, ARRAYSIZE(SubDir), NULL))
            *SubDir = UNICODE_NULL;
        StringCchPrintfW(DiskName, ARRAYSIZE(DiskName), L"%d", SourceId);
        if (!FindSourceDisksLine(hInf, L"SourceDisksNames", Decoration, DiskName, &Line) ||
            !SetupGetStringFieldW(&Line, 4, SourcePath, ARRAYSIZE(SourcePath), NULL))
        {
            *SourcePath = UNICODE_NULL;
        }
    }

    if (SUCCEEDED(StringCchPrintfW(Path, PathSize, L"%s%s%s%s%s\\%s", PackageDir,
                                   *SourcePath ? L"\\" : L"", SourcePath,
                                   *SubDir ? L"\\" : L"", SubDir, Name)) &&
        GetFileAttributesW(Path) != INVALID_FILE_ATTRIBUTES)
    {
        return TRUE;
    }

    if (SUCCEEDED(StringCchPrintfW(Path, PathSize, L"%s\\3\\%s", DriverDir, Name)) &&
        GetFileAttributesW(Path) != INVALID_FILE_ATTRIBUTES)
    {
        return TRUE;
    }

    ERR("Printer driver file %S not found\n", Name);
    return FALSE;
}

static BOOL
ResolvePackageFile(HINF hInf, PCWSTR Decoration, PPACKAGE_FILES Files, PCWSTR PackageDir, PCWSTR DriverDir, PCWSTR Name,
                   PWSTR StagingDir, PPACKAGE_FILES Staged, PWSTR Path, DWORD PathSize)
{
    WCHAR Copy[MAX_PATH];
    PCWSTR Source = Name;
    DWORD i, Attempt;

    for (i = 0; i < Files->Count; i++)
    {
        if (Files->Sources[i] && _wcsicmp(Files->Names[i], Name) == 0)
            Source = Files->Sources[i];
    }

    if (!LocatePackageFile(hInf, Decoration, PackageDir, DriverDir, Source, Path, PathSize))
        return FALSE;
    if (Source == Name)
        return TRUE;

    for (Attempt = 0; !*StagingDir && Attempt < 100; Attempt++)
    {
        if (FAILED(StringCchPrintfW(StagingDir, MAX_PATH, L"%s\\pkgstage-%lx-%lx", DriverDir,
                                    GetCurrentProcessId(), GetTickCount() + Attempt)))
        {
            *StagingDir = UNICODE_NULL;
            break;
        }
        if (!CreateDirectoryW(StagingDir, NULL))
            *StagingDir = UNICODE_NULL;
    }
    if (!*StagingDir || FAILED(StringCchPrintfW(Copy, ARRAYSIZE(Copy), L"%s\\%s", StagingDir, Name)))
    {
        ERR("No staging directory for %S (%lu)\n", Name, GetLastError());
        return FALSE;
    }

    for (i = 0; i < Staged->Count && _wcsicmp(Staged->Names[i], Copy) != 0; i++);
    if (i == Staged->Count)
    {
        if (!CopyFileW(Path, Copy, TRUE))
        {
            ERR("Cannot copy %S as %S (%lu)\n", Source, Name, GetLastError());
            return FALSE;
        }
        if (!AddPackageFile(Staged, Copy, NULL))
        {
            DeleteFileW(Copy);
            return FALSE;
        }
    }
    return SUCCEEDED(StringCchCopyW(Path, PathSize, Copy));
}

HRESULT WINAPI
InstallPrinterDriverFromPackageW(LPCWSTR pszServer, LPCWSTR pszInfPath, LPCWSTR pszDriverName,
                                 LPCWSTR pszEnvironment, DWORD dwFlags)
{
    WCHAR InstallSection[MAX_PATH], ActualSection[MAX_PATH], NeedsSection[MAX_PATH], Include[MAX_PATH];
    WCHAR DriverFile[MAX_PATH], ConfigFile[MAX_PATH], DataFile[MAX_PATH], HelpFile[MAX_PATH];
    WCHAR DefaultDataType[MAX_PATH], PackageDir[MAX_PATH], DriverDir[MAX_PATH];
    WCHAR DriverPath[MAX_PATH], ConfigPath[MAX_PATH], DataPath[MAX_PATH], HelpPath[MAX_PATH], FilePath[MAX_PATH];
    DWORD Field, FieldCount, Size, i, DependentLength = 1;
    PACKAGE_FILES Files = { 0 }, Staged = { 0 }, Sections = { 0 }, Includes = { 0 };
    WCHAR StagingDir[MAX_PATH] = L"", RecordedInf[MAX_PATH], IncludePath[MAX_PATH];
    BOOL Found;
    PWSTR DependentFiles = NULL, Next, Slash;
    DRIVER_INFO_8W DriverInfo = { 0 };
    PSP_ALTPLATFORM_INFO Platform = NULL;
    SP_ALTPLATFORM_INFO OtherPlatform;
    RTL_OSVERSIONINFOW Version;
    INFCONTEXT Context;
    PCWSTR Environment, Decoration = L"";
    WORD Architecture;
    HINF hInf;
    HRESULT hr;

    TRACE("InstallPrinterDriverFromPackageW(%S, %S, %S, %S, 0x%lx)\n",
          pszServer, pszInfPath, pszDriverName, pszEnvironment, dwFlags);

    if (!pszDriverName || !*pszDriverName || (dwFlags & ~IPDFP_COPY_ALL_FILES))
        return E_INVALIDARG;

    if (!pszInfPath)
        return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);

    hr = CheckLocalRequest(pszServer, pszEnvironment, &Environment, &Architecture);
    if (FAILED(hr))
        return hr;

    for (i = 0; i < ARRAYSIZE(EnvironmentArchitectures); i++)
    {
        if (EnvironmentArchitectures[i].Architecture == Architecture)
            Decoration = EnvironmentArchitectures[i].Decoration;
    }

    if (_wcsicmp(Environment, wszCurrentEnvironment) != 0)
    {
        Version.dwOSVersionInfoSize = sizeof(Version);
        RtlGetVersion(&Version);
        ZeroMemory(&OtherPlatform, sizeof(OtherPlatform));
        OtherPlatform.cbSize = sizeof(OtherPlatform);
        OtherPlatform.Platform = VER_PLATFORM_WIN32_NT;
        OtherPlatform.MajorVersion = Version.dwMajorVersion;
        OtherPlatform.MinorVersion = Version.dwMinorVersion;
        OtherPlatform.ProcessorArchitecture = Architecture;
        Platform = &OtherPlatform;
    }

    if (FAILED(StringCchCopyW(PackageDir, ARRAYSIZE(PackageDir), pszInfPath)) ||
        !(Slash = wcsrchr(PackageDir, L'\\')))
    {
        return E_INVALIDARG;
    }
    *Slash = UNICODE_NULL;

    Size = sizeof(DriverDir);
    if (!GetPrinterDriverDirectoryW(NULL, (PWSTR)Environment, 1, (PBYTE)DriverDir, Size, &Size))
        return HRESULT_FROM_WIN32(GetLastError());

    hInf = SetupOpenInfFileW(pszInfPath, NULL, INF_STYLE_WIN4, NULL);
    if (hInf == INVALID_HANDLE_VALUE)
        return HRESULT_FROM_WIN32(GetLastError());

    if (!FindModelSection(hInf, Platform, pszDriverName, InstallSection, ARRAYSIZE(InstallSection)) ||
        !SetupDiGetActualSectionToInstallExW(hInf, InstallSection, Platform, ActualSection, ARRAYSIZE(ActualSection),
                                             NULL, NULL, NULL))
    {
        hr = HRESULT_FROM_WIN32(ERROR_UNKNOWN_PRINTER_DRIVER);
        goto Cleanup;
    }
    if (!AddPackageFile(&Sections, ActualSection, NULL) || !AddPackageFile(&Includes, Slash + 1, NULL))
    {
        hr = E_OUTOFMEMORY;
        goto Cleanup;
    }

    for (i = 0; i < Sections.Count; i++)
    {
        for (Found = SetupFindFirstLineW(hInf, Sections.Names[i], L"Include", &Context);
             Found;
             Found = SetupFindNextMatchLineW(&Context, L"Include", &Context))
        {
            FieldCount = SetupGetFieldCount(&Context);
            for (Field = 1; Field <= FieldCount; Field++)
            {
                if (!SetupGetStringFieldW(&Context, Field, Include, ARRAYSIZE(Include), NULL))
                    continue;

                Size = Includes.Count;
                if (!AddPackageFile(&Includes, Include, NULL))
                {
                    hr = E_OUTOFMEMORY;
                    goto Cleanup;
                }
                if (Includes.Count == Size)
                    continue;

                if (wcspbrk(Include, L"\\/:") ||
                    FAILED(StringCchPrintfW(IncludePath, ARRAYSIZE(IncludePath), L"%s\\%s", PackageDir, Include)) ||
                    GetFileAttributesW(IncludePath) == INVALID_FILE_ATTRIBUTES)
                {
                    StringCchCopyW(IncludePath, ARRAYSIZE(IncludePath), Include);
                }
                if (!SetupOpenAppendInfFileW(IncludePath, hInf, NULL))
                {
                    hr = HRESULT_FROM_WIN32(GetLastError());
                    goto Cleanup;
                }
            }
        }

        if (!SetupFindFirstLineW(hInf, Sections.Names[i], L"Needs", &Context))
            continue;
        FieldCount = SetupGetFieldCount(&Context);
        for (Field = 1; Field <= FieldCount; Field++)
        {
            if (!SetupGetStringFieldW(&Context, Field, NeedsSection, ARRAYSIZE(NeedsSection), NULL) ||
                !*NeedsSection)
            {
                continue;
            }
            if (SetupGetLineCountW(hInf, NeedsSection) < 0)
            {
                ERR("Needed section %S not found\n", NeedsSection);
                hr = HRESULT_FROM_WIN32(ERROR_SECTION_NOT_FOUND);
                goto Cleanup;
            }
            if (!AddPackageFile(&Sections, NeedsSection, NULL))
            {
                hr = E_OUTOFMEMORY;
                goto Cleanup;
            }
        }
    }

    if (SetupFindFirstLineW(hInf, L"Version", L"ClassVer", &Context) &&
        SetupGetStringFieldW(&Context, 1, Include, ARRAYSIZE(Include), NULL) && Include[0] == L'4')
    {
        hr = HRESULT_FROM_WIN32(ERROR_UNKNOWN_PRINTER_DRIVER);
        goto Cleanup;
    }

    if (!GetDirective(hInf, Sections.Names, Sections.Count, L"DriverFile", DriverFile, ARRAYSIZE(DriverFile)))
        StringCchCopyW(DriverFile, ARRAYSIZE(DriverFile), InstallSection);
    if (!GetDirective(hInf, Sections.Names, Sections.Count, L"ConfigFile", ConfigFile, ARRAYSIZE(ConfigFile)))
        StringCchCopyW(ConfigFile, ARRAYSIZE(ConfigFile), DriverFile);
    GetDirective(hInf, Sections.Names, Sections.Count, L"HelpFile", HelpFile, ARRAYSIZE(HelpFile));
    GetDirective(hInf, Sections.Names, Sections.Count, L"DefaultDataType", DefaultDataType, ARRAYSIZE(DefaultDataType));
    if (!GetDirective(hInf, Sections.Names, Sections.Count, L"DataFile", DataFile, ARRAYSIZE(DataFile)))
        StringCchCopyW(DataFile, ARRAYSIZE(DataFile), InstallSection);

    /* TODO: LanguageMonitor and VendorSetup are not processed */

    for (i = 0; i < Sections.Count; i++)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        if (!CollectCopyFiles(hInf, Sections.Names[i], &Files))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto Cleanup;
        }
    }

    if (!ResolvePackageFile(hInf, Decoration, &Files, PackageDir, DriverDir, DriverFile, StagingDir, &Staged, DriverPath, ARRAYSIZE(DriverPath)) ||
        !ResolvePackageFile(hInf, Decoration, &Files, PackageDir, DriverDir, ConfigFile, StagingDir, &Staged, ConfigPath, ARRAYSIZE(ConfigPath)) ||
        !ResolvePackageFile(hInf, Decoration, &Files, PackageDir, DriverDir, DataFile, StagingDir, &Staged, DataPath, ARRAYSIZE(DataPath)) ||
        (*HelpFile &&
         !ResolvePackageFile(hInf, Decoration, &Files, PackageDir, DriverDir, HelpFile, StagingDir, &Staged, HelpPath, ARRAYSIZE(HelpPath))))
    {
        hr = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
        goto Cleanup;
    }

    for (i = 0; i < Files.Count; i++)
    {
        if (!ResolvePackageFile(hInf, Decoration, &Files, PackageDir, DriverDir, Files.Names[i], StagingDir, &Staged,
                                FilePath, ARRAYSIZE(FilePath)))
        {
            hr = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
            goto Cleanup;
        }
        DependentLength += (DWORD)wcslen(FilePath) + 1;
    }

    DependentFiles = DllAllocSplMem(DependentLength * sizeof(WCHAR));
    if (!DependentFiles)
    {
        hr = E_OUTOFMEMORY;
        goto Cleanup;
    }

    Next = DependentFiles;
    for (i = 0; i < Files.Count; i++)
    {
        if (!_wcsicmp(Files.Names[i], DriverFile) || !_wcsicmp(Files.Names[i], ConfigFile) ||
            !_wcsicmp(Files.Names[i], DataFile) || !_wcsicmp(Files.Names[i], HelpFile))
        {
            continue;
        }

        if (!ResolvePackageFile(hInf, Decoration, &Files, PackageDir, DriverDir, Files.Names[i], StagingDir, &Staged,
                                FilePath, ARRAYSIZE(FilePath)) ||
            FAILED(StringCchCopyW(Next, DependentLength - (DWORD)(Next - DependentFiles), FilePath)))
        {
            hr = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
            goto Cleanup;
        }
        Next += wcslen(Next) + 1;
    }
    *Next = UNICODE_NULL;

    DriverInfo.cVersion = 3;
    DriverInfo.pName = (PWSTR)pszDriverName;
    DriverInfo.pEnvironment = (PWSTR)Environment;
    DriverInfo.pDriverPath = DriverPath;
    DriverInfo.pConfigFile = ConfigPath;
    DriverInfo.pDataFile = DataPath;
    DriverInfo.pHelpFile = *HelpFile ? HelpPath : NULL;
    DriverInfo.pDependentFiles = DependentFiles;
    DriverInfo.pDefaultDataType = *DefaultDataType ? DefaultDataType : NULL;
    ResolvePackageInf(pszInfPath, Architecture, RecordedInf);
    DriverInfo.pszInfPath = *RecordedInf ? RecordedInf : (PWSTR)pszInfPath;

    if (!AddPrinterDriverExW(NULL, 8, (PBYTE)&DriverInfo,
                             APD_COPY_FROM_DIRECTORY |
                             ((dwFlags & IPDFP_COPY_ALL_FILES) ? APD_COPY_ALL_FILES : APD_COPY_NEW_FILES)))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    hr = S_OK;

Cleanup:
    if (DependentFiles)
        DllFreeSplMem(DependentFiles);
    for (i = 0; i < Staged.Count; i++)
        DeleteFileW(Staged.Names[i]);
    if (*StagingDir)
        RemoveDirectoryW(StagingDir);
    FreePackageFiles(&Staged);
    FreePackageFiles(&Files);
    FreePackageFiles(&Sections);
    FreePackageFiles(&Includes);
    SetupCloseInfFile(hInf);
    return hr;
}

static PWSTR
AnsiToHeapUnicode(PCSTR Ansi, HRESULT *phr)
{
    PWSTR Unicode;
    INT Length;

    if (!Ansi)
        return NULL;

    Length = MultiByteToWideChar(CP_ACP, 0, Ansi, -1, NULL, 0);
    Unicode = Length ? DllAllocSplMem(Length * sizeof(WCHAR)) : NULL;
    if (!Unicode)
    {
        *phr = E_OUTOFMEMORY;
        return NULL;
    }

    MultiByteToWideChar(CP_ACP, 0, Ansi, -1, Unicode, Length);
    return Unicode;
}

HRESULT WINAPI
UploadPrinterDriverPackageA(LPCSTR pszServer, LPCSTR pszInfPath, LPCSTR pszEnvironment, DWORD dwFlags,
                            HWND hwnd, LPSTR pszDestInfPath, PULONG pcchDestInfPath)
{
    PWSTR ServerW, InfPathW, EnvironmentW;
    WCHAR DestW[MAX_PATH];
    ULONG DestLength = ARRAYSIZE(DestW);
    HRESULT hr = S_OK;
    INT Needed;

    if (!pcchDestInfPath)
        return E_INVALIDARG;

    ServerW = AnsiToHeapUnicode(pszServer, &hr);
    InfPathW = AnsiToHeapUnicode(pszInfPath, &hr);
    EnvironmentW = AnsiToHeapUnicode(pszEnvironment, &hr);
    if (SUCCEEDED(hr))
        hr = UploadPrinterDriverPackageW(ServerW, InfPathW, EnvironmentW, dwFlags, hwnd, DestW, &DestLength);

    if (SUCCEEDED(hr))
    {
        Needed = WideCharToMultiByte(CP_ACP, 0, DestW, -1, NULL, 0, NULL, NULL);
        if (!pszDestInfPath || *pcchDestInfPath < (ULONG)Needed)
            hr = HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        else
            WideCharToMultiByte(CP_ACP, 0, DestW, -1, pszDestInfPath, Needed, NULL, NULL);
        *pcchDestInfPath = Needed;
    }

    DllFreeSplMem(ServerW);
    DllFreeSplMem(InfPathW);
    DllFreeSplMem(EnvironmentW);
    return hr;
}

HRESULT WINAPI
DeletePrinterDriverPackageA(LPCSTR pszServer, LPCSTR pszInfPath, LPCSTR pszEnvironment)
{
    PWSTR ServerW, InfPathW, EnvironmentW;
    HRESULT hr = S_OK;

    ServerW = AnsiToHeapUnicode(pszServer, &hr);
    InfPathW = AnsiToHeapUnicode(pszInfPath, &hr);
    EnvironmentW = AnsiToHeapUnicode(pszEnvironment, &hr);
    if (SUCCEEDED(hr))
        hr = DeletePrinterDriverPackageW(ServerW, InfPathW, EnvironmentW);

    DllFreeSplMem(ServerW);
    DllFreeSplMem(InfPathW);
    DllFreeSplMem(EnvironmentW);
    return hr;
}

HRESULT WINAPI
InstallPrinterDriverFromPackageA(LPCSTR pszServer, LPCSTR pszInfPath, LPCSTR pszDriverName,
                                 LPCSTR pszEnvironment, DWORD dwFlags)
{
    PWSTR ServerW, InfPathW, DriverNameW, EnvironmentW;
    HRESULT hr = S_OK;

    ServerW = AnsiToHeapUnicode(pszServer, &hr);
    InfPathW = AnsiToHeapUnicode(pszInfPath, &hr);
    DriverNameW = AnsiToHeapUnicode(pszDriverName, &hr);
    EnvironmentW = AnsiToHeapUnicode(pszEnvironment, &hr);
    if (SUCCEEDED(hr))
        hr = InstallPrinterDriverFromPackageW(ServerW, InfPathW, DriverNameW, EnvironmentW, dwFlags);

    DllFreeSplMem(ServerW);
    DllFreeSplMem(InfPathW);
    DllFreeSplMem(DriverNameW);
    DllFreeSplMem(EnvironmentW);
    return hr;
}
