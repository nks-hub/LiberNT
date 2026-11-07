/*
 * PROJECT:     LiberNT Spooler API
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Printer driver packages in the driver store
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include "precomp.h"
#include <setupapi.h>

extern const WCHAR wszCurrentEnvironment[];

/* setupapi driver store, not declared in the SDK */
HRESULT WINAPI DriverStoreAddDriverPackageW(PCWSTR InfPath, PVOID Reserved1, PVOID Reserved2,
                                            WORD Architecture, PWSTR ReturnPath, PDWORD ReturnLength);
HRESULT WINAPI DriverStoreDeleteDriverPackageW(PCWSTR InfPath, PVOID Reserved1, PVOID Reserved2);

#define MAX_PACKAGE_FILES 128
#define DRIVERS_KEY L"SYSTEM\\CurrentControlSet\\Control\\Print\\Environments\\%s\\Drivers\\Version-3"

typedef struct _PACKAGE_FILES
{
    DWORD Count;
    PWSTR Names[MAX_PACKAGE_FILES];
} PACKAGE_FILES, *PPACKAGE_FILES;

/* Only the local spooler is supported, like LocalAddPrinterDriverEx. */
static HRESULT
CheckLocalRequest(PCWSTR pszServer, PCWSTR pszEnvironment)
{
    WCHAR ComputerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD Size = ARRAYSIZE(ComputerName);

    if (pszEnvironment && *pszEnvironment && _wcsicmp(pszEnvironment, wszCurrentEnvironment) != 0)
        return HRESULT_FROM_WIN32(ERROR_INVALID_ENVIRONMENT);

    if (!pszServer || !*pszServer)
        return S_OK;

    while (*pszServer == L'\\')
        pszServer++;

    if (GetComputerNameW(ComputerName, &Size) && _wcsicmp(pszServer, ComputerName) == 0)
        return S_OK;

    return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
}

static WORD
GetNativeArchitecture(VOID)
{
    SYSTEM_INFO SystemInfo;

    GetNativeSystemInfo(&SystemInfo);
    return SystemInfo.wProcessorArchitecture;
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
    HRESULT hr;

    TRACE("UploadPrinterDriverPackageW(%S, %S, %S, 0x%lx, %p, %p, %p)\n",
          pszServer, pszInfPath, pszEnvironment, dwFlags, hwnd, pszDestInfPath, pcchDestInfPath);

    UNREFERENCED_PARAMETER(hwnd);

    if (!pszInfPath || !pcchDestInfPath ||
        (dwFlags & ~(UPDP_SILENT_UPLOAD | UPDP_UPLOAD_ALWAYS | UPDP_CHECK_DRIVERSTORE)))
    {
        return E_INVALIDARG;
    }

    hr = CheckLocalRequest(pszServer, pszEnvironment);
    if (FAILED(hr))
        return hr;

    /* The local spooler shares the driver store with the caller, an existing package is reused */
    hr = DriverStoreAddDriverPackageW(pszInfPath, NULL, NULL, GetNativeArchitecture(), StoreInf, &Length);
    if (FAILED(hr))
        return hr;

    return ReturnString(StoreInf, pszDestInfPath, pcchDestInfPath);
}

/* TRUE when the InfPath value of an installed version 3 driver names this package */
static BOOL
IsDriverPackageInUse(PCWSTR InfPath)
{
    WCHAR Key[MAX_PATH], Name[MAX_PATH], Value[MAX_PATH];
    BOOL InUse = FALSE;
    HKEY hDrivers;
    DWORD i, Size;

    if (FAILED(StringCchPrintfW(Key, ARRAYSIZE(Key), DRIVERS_KEY, wszCurrentEnvironment)) ||
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, Key, 0, KEY_READ, &hDrivers) != ERROR_SUCCESS)
    {
        return FALSE;
    }

    for (i = 0; !InUse; i++)
    {
        Size = ARRAYSIZE(Name);
        if (RegEnumKeyExW(hDrivers, i, Name, &Size, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;
        Size = sizeof(Value);
        InUse = RegGetValueW(hDrivers, Name, L"InfPath", RRF_RT_REG_SZ, NULL, Value, &Size) == ERROR_SUCCESS &&
                _wcsicmp(Value, InfPath) == 0;
    }

    RegCloseKey(hDrivers);
    return InUse;
}

HRESULT WINAPI
DeletePrinterDriverPackageW(LPCWSTR pszServer, LPCWSTR pszInfPath, LPCWSTR pszEnvironment)
{
    HRESULT hr;

    TRACE("DeletePrinterDriverPackageW(%S, %S, %S)\n", pszServer, pszInfPath, pszEnvironment);

    if (!pszInfPath)
        return E_INVALIDARG;

    hr = CheckLocalRequest(pszServer, pszEnvironment);
    if (FAILED(hr))
        return hr;

    if (IsDriverPackageInUse(pszInfPath))
        return HRESULT_FROM_WIN32(ERROR_PRINTER_DRIVER_PACKAGE_IN_USE);

    return DriverStoreDeleteDriverPackageW(pszInfPath, NULL, NULL);
}

static BOOL
AddPackageFile(PPACKAGE_FILES Files, PCWSTR Name)
{
    DWORD i;

    if (!Name || !*Name)
        return TRUE;

    for (i = 0; i < Files->Count; i++)
    {
        if (_wcsicmp(Files->Names[i], Name) == 0)
            return TRUE;
    }

    if (Files->Count == MAX_PACKAGE_FILES)
        return FALSE;

    Files->Names[Files->Count] = AllocSplStr(Name);
    return Files->Names[Files->Count++] != NULL;
}

static VOID
FreePackageFiles(PPACKAGE_FILES Files)
{
    while (Files->Count)
        DllFreeSplStr(Files->Names[--Files->Count]);
}

/* Collects the file names of every CopyFiles directive of a section */
static BOOL
CollectCopyFiles(HINF hInf, PCWSTR Section, PPACKAGE_FILES Files)
{
    WCHAR Entry[MAX_PATH], Name[MAX_PATH];
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
                if (!AddPackageFile(Files, Entry + 1))
                    return FALSE;
                continue;
            }

            if (!SetupFindFirstLineW(hInf, Entry, NULL, &FileContext))
                continue;
            do
            {
                if (SetupGetStringFieldW(&FileContext, 1, Name, ARRAYSIZE(Name), NULL) &&
                    !AddPackageFile(Files, Name))
                {
                    return FALSE;
                }
            } while (SetupFindNextLine(&FileContext, &FileContext));
        }
    } while (SetupFindNextMatchLineW(&Context, L"CopyFiles", &Context));

    return TRUE;
}

/* Looks a directive up in the install sections first, then in their DataSection */
static BOOL
GetDirective(HINF hInf, PCWSTR *Sections, DWORD SectionCount, PCWSTR Key, PWSTR Value, DWORD ValueSize)
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

/* Finds the install section of the model called DriverName in the [Manufacturer] tree */
static BOOL
FindModelSection(HINF hInf, PCWSTR DriverName, PWSTR Section, DWORD SectionSize)
{
    WCHAR Models[MAX_PATH];
    INFCONTEXT MfgContext, ModelContext;

    if (!SetupFindFirstLineW(hInf, L"Manufacturer", NULL, &MfgContext))
        return FALSE;

    do
    {
        if (!SetupDiGetActualModelsSectionW(&MfgContext, NULL, Models, ARRAYSIZE(Models), NULL, NULL))
            continue;

        if (SetupFindFirstLineW(hInf, Models, DriverName, &ModelContext) &&
            SetupGetStringFieldW(&ModelContext, 1, Section, SectionSize, NULL))
        {
            return TRUE;
        }
    } while (SetupFindNextLine(&MfgContext, &MfgContext));

    return FALSE;
}

/*
 * Full path of a package file: where SourceDisksFiles and SourceDisksNames
 * put it below the package folder, or the spooler driver folder for core
 * driver files that the package does not carry.
 */
static BOOL
LocatePackageFile(HINF hInf, PCWSTR PackageDir, PCWSTR DriverDir, PCWSTR Name, PWSTR Path, DWORD PathSize)
{
    WCHAR SourcePath[MAX_PATH] = L"", SubDir[MAX_PATH] = L"";
    UINT SourceId;

    if (SetupGetSourceFileLocationW(hInf, NULL, Name, &SourceId, SubDir, ARRAYSIZE(SubDir), NULL))
        SetupGetSourceInfoW(hInf, SourceId, SRCINFO_PATH, SourcePath, ARRAYSIZE(SourcePath), NULL);

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

HRESULT WINAPI
InstallPrinterDriverFromPackageW(LPCWSTR pszServer, LPCWSTR pszInfPath, LPCWSTR pszDriverName,
                                 LPCWSTR pszEnvironment, DWORD dwFlags)
{
    WCHAR InstallSection[MAX_PATH], ActualSection[MAX_PATH], NeedsSection[MAX_PATH], Include[MAX_PATH];
    WCHAR DriverFile[MAX_PATH], ConfigFile[MAX_PATH], DataFile[MAX_PATH], HelpFile[MAX_PATH];
    WCHAR DefaultDataType[MAX_PATH], PackageDir[MAX_PATH], DriverDir[MAX_PATH];
    WCHAR DriverPath[MAX_PATH], ConfigPath[MAX_PATH], DataPath[MAX_PATH], HelpPath[MAX_PATH], FilePath[MAX_PATH];
    PCWSTR Sections[16];
    DWORD SectionCount = 0, Field, FieldCount, Size, i, DependentLength = 1;
    PACKAGE_FILES Files = { 0 };
    PWSTR DependentFiles = NULL, Next, Slash;
    DRIVER_INFO_3W DriverInfo = { 0 };
    INFCONTEXT Context;
    HINF hInf;
    HRESULT hr;

    TRACE("InstallPrinterDriverFromPackageW(%S, %S, %S, %S, 0x%lx)\n",
          pszServer, pszInfPath, pszDriverName, pszEnvironment, dwFlags);

    if (!pszDriverName || !*pszDriverName || (dwFlags & ~IPDFP_COPY_ALL_FILES))
        return E_INVALIDARG;

    /* Without a package Windows installs a driver from its inbox drivers; LiberNT has none to offer */
    if (!pszInfPath)
        return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);

    hr = CheckLocalRequest(pszServer, pszEnvironment);
    if (FAILED(hr))
        return hr;

    if (FAILED(StringCchCopyW(PackageDir, ARRAYSIZE(PackageDir), pszInfPath)) ||
        !(Slash = wcsrchr(PackageDir, L'\\')))
    {
        return E_INVALIDARG;
    }
    *Slash = UNICODE_NULL;

    Size = sizeof(DriverDir);
    if (!GetPrinterDriverDirectoryW(NULL, (PWSTR)wszCurrentEnvironment, 1, (PBYTE)DriverDir, Size, &Size))
        return HRESULT_FROM_WIN32(GetLastError());

    hInf = SetupOpenInfFileW(pszInfPath, NULL, INF_STYLE_WIN4, NULL);
    if (hInf == INVALID_HANDLE_VALUE)
        return HRESULT_FROM_WIN32(GetLastError());

    if (!FindModelSection(hInf, pszDriverName, InstallSection, ARRAYSIZE(InstallSection)) ||
        !SetupDiGetActualSectionToInstallW(hInf, InstallSection, ActualSection, ARRAYSIZE(ActualSection),
                                           NULL, NULL))
    {
        hr = HRESULT_FROM_WIN32(ERROR_UNKNOWN_PRINTER_DRIVER);
        goto Cleanup;
    }
    Sections[SectionCount++] = ActualSection;

    /* Include= appends other INF files (usually ntprint.inf), Needs= names their sections we use */
    if (SetupFindFirstLineW(hInf, ActualSection, L"Include", &Context))
    {
        FieldCount = SetupGetFieldCount(&Context);
        for (Field = 1; Field <= FieldCount; Field++)
        {
            if (SetupGetStringFieldW(&Context, Field, Include, ARRAYSIZE(Include), NULL) &&
                !SetupOpenAppendInfFileW(Include, hInf, NULL))
            {
                hr = HRESULT_FROM_WIN32(GetLastError());
                goto Cleanup;
            }
        }
    }
    if (SetupFindFirstLineW(hInf, ActualSection, L"Needs", &Context))
    {
        FieldCount = SetupGetFieldCount(&Context);
        for (Field = 1; Field <= FieldCount; Field++)
        {
            if (!SetupGetStringFieldW(&Context, Field, NeedsSection, ARRAYSIZE(NeedsSection), NULL))
                continue;
            if (SectionCount == ARRAYSIZE(Sections))
            {
                hr = HRESULT_FROM_WIN32(ERROR_BUFFER_OVERFLOW);
                goto Cleanup;
            }
            Sections[SectionCount] = AllocSplStr(NeedsSection);
            if (!Sections[SectionCount])
            {
                hr = E_OUTOFMEMORY;
                goto Cleanup;
            }
            SectionCount++;
        }
    }

    GetDirective(hInf, Sections, SectionCount, L"DriverFile", DriverFile, ARRAYSIZE(DriverFile));
    GetDirective(hInf, Sections, SectionCount, L"ConfigFile", ConfigFile, ARRAYSIZE(ConfigFile));
    GetDirective(hInf, Sections, SectionCount, L"HelpFile", HelpFile, ARRAYSIZE(HelpFile));
    GetDirective(hInf, Sections, SectionCount, L"DefaultDataType", DefaultDataType, ARRAYSIZE(DefaultDataType));
    if (!GetDirective(hInf, Sections, SectionCount, L"DataFile", DataFile, ARRAYSIZE(DataFile)))
        StringCchCopyW(DataFile, ARRAYSIZE(DataFile), InstallSection);

    /* Version 4 drivers have neither, the spooler only runs version 3 drivers */
    if (!*DriverFile || !*ConfigFile)
    {
        hr = HRESULT_FROM_WIN32(ERROR_UNKNOWN_PRINTER_DRIVER);
        goto Cleanup;
    }

    // shortcut: LanguageMonitor and VendorSetup directives are not processed, install the monitor separately.

    for (i = 0; i < SectionCount; i++)
    {
        if (!CollectCopyFiles(hInf, Sections[i], &Files))
        {
            hr = HRESULT_FROM_WIN32(ERROR_BUFFER_OVERFLOW);
            goto Cleanup;
        }
    }

    if (!LocatePackageFile(hInf, PackageDir, DriverDir, DriverFile, DriverPath, ARRAYSIZE(DriverPath)) ||
        !LocatePackageFile(hInf, PackageDir, DriverDir, ConfigFile, ConfigPath, ARRAYSIZE(ConfigPath)) ||
        !LocatePackageFile(hInf, PackageDir, DriverDir, DataFile, DataPath, ARRAYSIZE(DataPath)) ||
        (*HelpFile && !LocatePackageFile(hInf, PackageDir, DriverDir, HelpFile, HelpPath, ARRAYSIZE(HelpPath))))
    {
        hr = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
        goto Cleanup;
    }

    /* Every other copied file is a dependent file */
    for (i = 0; i < Files.Count; i++)
    {
        if (!LocatePackageFile(hInf, PackageDir, DriverDir, Files.Names[i], FilePath, ARRAYSIZE(FilePath)))
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

        LocatePackageFile(hInf, PackageDir, DriverDir, Files.Names[i], Next, DependentLength - (DWORD)(Next - DependentFiles));
        Next += wcslen(Next) + 1;
    }
    *Next = UNICODE_NULL;

    DriverInfo.cVersion = 3;
    DriverInfo.pName = (PWSTR)pszDriverName;
    DriverInfo.pEnvironment = (PWSTR)wszCurrentEnvironment;
    DriverInfo.pDriverPath = DriverPath;
    DriverInfo.pConfigFile = ConfigPath;
    DriverInfo.pDataFile = DataPath;
    DriverInfo.pHelpFile = *HelpFile ? HelpPath : NULL;
    DriverInfo.pDependentFiles = DependentFiles;
    DriverInfo.pDefaultDataType = *DefaultDataType ? DefaultDataType : NULL;

    if (!AddPrinterDriverExW(NULL, 3, (PBYTE)&DriverInfo,
                             APD_COPY_FROM_DIRECTORY |
                             ((dwFlags & IPDFP_COPY_ALL_FILES) ? APD_COPY_ALL_FILES : APD_COPY_NEW_FILES)))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    /* As on Windows, the driver key names its package; DeletePrinterDriverPackage checks it */
    if (SUCCEEDED(StringCchPrintfW(FilePath, ARRAYSIZE(FilePath), DRIVERS_KEY L"\\%s",
                                   wszCurrentEnvironment, pszDriverName)) &&
        RegSetKeyValueW(HKEY_LOCAL_MACHINE, FilePath, L"InfPath", REG_SZ, pszInfPath,
                        (DWORD)((wcslen(pszInfPath) + 1) * sizeof(WCHAR))) != ERROR_SUCCESS)
    {
        ERR("Could not record the package of driver %S\n", pszDriverName);
    }

    hr = S_OK;

Cleanup:
    if (DependentFiles)
        DllFreeSplMem(DependentFiles);
    FreePackageFiles(&Files);
    for (i = 1; i < SectionCount; i++)
        DllFreeSplStr((PWSTR)Sections[i]);
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
