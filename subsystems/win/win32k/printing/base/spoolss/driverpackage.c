/*
 * PROJECT:     LiberNT Spooler Router
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Installing a printer driver from a package in the driver store
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include "precomp.h"
#include <winuser.h>
#include <setupapi.h>
#include <strsafe.h>
#include <drvpkglock.h>
#include <drvpkgenv.h>

typedef struct _PACKAGE_FILES
{
    DWORD Count;
    DWORD Capacity;
    PWSTR *Names;
    PWSTR *Sources;
} PACKAGE_FILES, *PPACKAGE_FILES;

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
CollectCopyFiles(HINF hInf, PCWSTR Section, PPACKAGE_FILES Files, BOOL Required)
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

            if (Required && SetupGetLineCountW(hInf, Entry) < 0)
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
IsBelowDirectory(PCWSTR Directory, PWSTR Path)
{
    WCHAR Base[MAX_PATH];
    DWORD Length = GetFullPathNameW(Directory, ARRAYSIZE(Base), Base, NULL), Attributes;
    PWSTR Cursor;
    WCHAR Saved;

    if (Length == 0 || Length >= ARRAYSIZE(Base))
        return FALSE;
    if (Base[Length - 1] == L'\\')
        Length--;
    if (_wcsnicmp(Path, Base, Length) != 0 || Path[Length] != L'\\' || !Path[Length + 1])
        return FALSE;

    /* A junction or a link, the directory itself or below it, leads out of the directory although the path does not */
    for (Cursor = Path + Length; ; Cursor++)
    {
        Saved = *Cursor;
        if (Saved != L'\\' && Saved != UNICODE_NULL)
            continue;

        *Cursor = UNICODE_NULL;
        Attributes = GetFileAttributesW(Path);
        *Cursor = Saved;
        if (Attributes != INVALID_FILE_ATTRIBUTES && (Attributes & FILE_ATTRIBUTE_REPARSE_POINT))
            return FALSE;
        if (Saved == UNICODE_NULL)
            break;
    }
    return TRUE;
}

static BOOL
IsSafeRelativePath(PCWSTR Relative)
{
    PCWSTR Cursor = Relative;
    SIZE_T Length;

    if (wcschr(Relative, L':') || *Relative == L'\\' || *Relative == L'/')
        return FALSE;

    while (*Cursor)
    {
        Length = wcscspn(Cursor, L"\\/");
        if (Length == 2 && Cursor[0] == L'.' && Cursor[1] == L'.')
            return FALSE;
        Cursor += Length;
        if (*Cursor)
            Cursor++;
    }
    return TRUE;
}

static BOOL
LocatePackageFile(HINF hInf, PCWSTR Decoration, PCWSTR PackageDir, PCWSTR DriverDir, PCWSTR Name, PWSTR Path, DWORD PathSize)
{
    WCHAR SourcePath[MAX_PATH] = L"", SubDir[MAX_PATH] = L"", DiskName[16], Joined[MAX_PATH];
    INFCONTEXT Line;
    INT SourceId;
    DWORD Length;

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

    if (SUCCEEDED(StringCchPrintfW(Joined, ARRAYSIZE(Joined), L"%s%s%s%s%s\\%s", PackageDir,
                                   *SourcePath ? L"\\" : L"", SourcePath,
                                   *SubDir ? L"\\" : L"", SubDir, Name)) &&
        !wcschr(Joined + wcslen(PackageDir), L':') &&
        (Length = GetFullPathNameW(Joined, PathSize, Path, NULL)) != 0 && Length < PathSize &&
        IsBelowDirectory(PackageDir, Path) &&
        GetFileAttributesW(Path) != INVALID_FILE_ATTRIBUTES)
    {
        return TRUE;
    }

    /* Only a file that the package does not copy itself is taken from the driver directory */
    if (DriverDir && !wcspbrk(Name, L"\\/:") &&
        SUCCEEDED(StringCchPrintfW(Path, PathSize, L"%s\\3\\%s", DriverDir, Name)) &&
        GetFileAttributesW(Path) != INVALID_FILE_ATTRIBUTES)
    {
        return TRUE;
    }

    ERR("Printer driver file %S not found\n", Name);
    return FALSE;
}

static BOOL
ResolvePackageFile(HINF hInf, PCWSTR Decoration, PPACKAGE_FILES Files, PPACKAGE_FILES Owned, PCWSTR PackageDir, PCWSTR DriverDir,
                   PCWSTR Name, PWSTR StagingDir, PPACKAGE_FILES Staged, PWSTR Path, DWORD PathSize)
{
    WCHAR Copy[MAX_PATH];
    PCWSTR Source = Name;
    DWORD i, Attempt;

    for (i = 0; i < Files->Count; i++)
    {
        if (Files->Sources[i] && _wcsicmp(Files->Names[i], Name) == 0)
            Source = Files->Sources[i];
    }

    for (i = 0; i < Owned->Count && _wcsicmp(Owned->Names[i], Name) != 0; i++);
    if (!LocatePackageFile(hInf, Decoration, PackageDir, i == Owned->Count ? DriverDir : NULL, Source, Path, PathSize))
        return FALSE;
    if (Source == Name)
        return TRUE;
    if (wcspbrk(Name, L"\\/:"))
    {
        ERR("%S is not a file name\n", Name);
        return FALSE;
    }

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

static HRESULT
InstallFromPackage(PCWSTR pszInfPath, PCWSTR pszDriverName, PCWSTR Environment, WORD Architecture, DWORD dwFlags,
                   HANDLE Namespace, HANDLE Lock, PBOOL Locked)
{
    WCHAR InstallSection[MAX_PATH], ActualSection[MAX_PATH], NeedsSection[MAX_PATH], Include[MAX_PATH];
    WCHAR DriverFile[MAX_PATH], ConfigFile[MAX_PATH], DataFile[MAX_PATH], HelpFile[MAX_PATH];
    WCHAR DefaultDataType[MAX_PATH], PackageDir[MAX_PATH], DriverDir[MAX_PATH];
    WCHAR DriverPath[MAX_PATH], ConfigPath[MAX_PATH], DataPath[MAX_PATH], HelpPath[MAX_PATH], FilePath[MAX_PATH];
    DWORD Field, FieldCount, Size, i, DependentLength = 1;
    PACKAGE_FILES Files = { 0 }, Staged = { 0 }, Sections = { 0 }, Includes = { 0 }, Owned = { 0 };
    WCHAR StagingDir[MAX_PATH] = L"", IncludePath[MAX_PATH], InfPath[MAX_PATH];
    BOOL Found, InPackage;
    PWSTR DependentFiles = NULL, Next, Slash;
    DRIVER_INFO_8W DriverInfo = { 0 };
    PSP_ALTPLATFORM_INFO Platform = NULL;
    SP_ALTPLATFORM_INFO OtherPlatform;
    RTL_OSVERSIONINFOW Version;
    INFCONTEXT Context;
    PCWSTR Decoration = L"";
    HINF hInf, hPackage;
    HANDLE hPin = INVALID_HANDLE_VALUE;
    HRESULT hr;

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

    /* Windows 11 takes the INF of a package in the store alone, and not the INF that the package was uploaded from */
    Size = GetFullPathNameW(pszInfPath, ARRAYSIZE(FilePath), FilePath, NULL);
    i = ARRAYSIZE(InfPath);
    if (Size == 0 || Size >= ARRAYSIZE(FilePath) ||
        FAILED(DriverStoreFindDriverPackageW(FilePath, NULL, NULL, Architecture, NULL, InfPath, &i)) ||
        _wcsicmp(FilePath, InfPath) != 0 ||
        FAILED(StringCchCopyW(PackageDir, ARRAYSIZE(PackageDir), InfPath)) ||
        !(Slash = wcsrchr(PackageDir, L'\\')))
    {
        return E_INVALIDARG;
    }
    *Slash = UNICODE_NULL;

    if (!IsBelowDirectory(PackageDir, InfPath))
    {
        ERR("INF %S cannot be taken from the package directory\n", InfPath);
        return HRESULT_FROM_WIN32(ERROR_BAD_PATHNAME);
    }

    Size = sizeof(DriverDir);
    if (!GetPrinterDriverDirectoryW(NULL, (PWSTR)Environment, 1, (PBYTE)DriverDir, Size, &Size))
        return HRESULT_FROM_WIN32(GetLastError());

    hInf = SetupOpenInfFileW(InfPath, NULL, INF_STYLE_WIN4, NULL);
    if (hInf == INVALID_HANDLE_VALUE)
        return HRESULT_FROM_WIN32(GetLastError());

    /* The INFs of the package alone, to tell the files it copies from those a system INF copies */
    hPackage = SetupOpenInfFileW(InfPath, NULL, INF_STYLE_WIN4, NULL);
    if (hPackage == INVALID_HANDLE_VALUE)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        SetupCloseInfFile(hInf);
        return hr;
    }

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

                if (!IsSafeRelativePath(Include))
                {
                    ERR("Included INF %S is not a name in the package directory\n", Include);
                    hr = HRESULT_FROM_WIN32(ERROR_BAD_PATHNAME);
                    goto Cleanup;
                }

                InPackage = SUCCEEDED(StringCchPrintfW(FilePath, ARRAYSIZE(FilePath), L"%s\\%s", PackageDir, Include)) &&
                            (Size = GetFullPathNameW(FilePath, ARRAYSIZE(IncludePath), IncludePath, NULL)) != 0 &&
                            Size < ARRAYSIZE(IncludePath) &&
                            IsBelowDirectory(PackageDir, IncludePath) &&
                            GetFileAttributesW(IncludePath) != INVALID_FILE_ATTRIBUTES;
                if (!InPackage)
                {
                    /* Only an INF without a directory is one of the system */
                    if (wcspbrk(Include, L"\\/"))
                    {
                        ERR("Included INF %S not found\n", Include);
                        hr = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
                        goto Cleanup;
                    }
                    StringCchCopyW(IncludePath, ARRAYSIZE(IncludePath), Include);
                }
                if (!SetupOpenAppendInfFileW(IncludePath, hInf, NULL) ||
                    (InPackage && !SetupOpenAppendInfFileW(IncludePath, hPackage, NULL)))
                {
                    hr = HRESULT_FROM_WIN32(GetLastError());
                    goto Cleanup;
                }
            }
        }

        for (Found = SetupFindFirstLineW(hInf, Sections.Names[i], L"Needs", &Context);
             Found;
             Found = SetupFindNextMatchLineW(&Context, L"Needs", &Context))
        {
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
        if (!CollectCopyFiles(hInf, Sections.Names[i], &Files, TRUE) ||
            !CollectCopyFiles(hPackage, Sections.Names[i], &Owned, FALSE))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto Cleanup;
        }
    }

    if (!ResolvePackageFile(hInf, Decoration, &Files, &Owned, PackageDir, DriverDir, DriverFile, StagingDir, &Staged, DriverPath, ARRAYSIZE(DriverPath)) ||
        !ResolvePackageFile(hInf, Decoration, &Files, &Owned, PackageDir, DriverDir, ConfigFile, StagingDir, &Staged, ConfigPath, ARRAYSIZE(ConfigPath)) ||
        !ResolvePackageFile(hInf, Decoration, &Files, &Owned, PackageDir, DriverDir, DataFile, StagingDir, &Staged, DataPath, ARRAYSIZE(DataPath)) ||
        (*HelpFile &&
         !ResolvePackageFile(hInf, Decoration, &Files, &Owned, PackageDir, DriverDir, HelpFile, StagingDir, &Staged, HelpPath, ARRAYSIZE(HelpPath))))
    {
        hr = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
        goto Cleanup;
    }

    for (i = 0; i < Files.Count; i++)
    {
        if (!ResolvePackageFile(hInf, Decoration, &Files, &Owned, PackageDir, DriverDir, Files.Names[i], StagingDir, &Staged,
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

        if (!ResolvePackageFile(hInf, Decoration, &Files, &Owned, PackageDir, DriverDir, Files.Names[i], StagingDir, &Staged,
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
    DriverInfo.pszInfPath = InfPath;

    /* A package directory with an open file cannot be renamed, so the package is neither deleted nor replaced without the lock */
    hPin = CreateFileW(InfPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hPin == INVALID_HANDLE_VALUE)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }
    ReleasePackageLock(Namespace, Lock);
    *Locked = FALSE;

    if (!AddPrinterDriverExW(NULL, 8, (PBYTE)&DriverInfo,
                             APD_COPY_FROM_DIRECTORY |
                             ((dwFlags & IPDFP_COPY_ALL_FILES) ? APD_COPY_ALL_FILES : APD_COPY_NEW_FILES)))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    hr = S_OK;

Cleanup:
    if (hPin != INVALID_HANDLE_VALUE)
        CloseHandle(hPin);
    if (DependentFiles)
        DllFreeSplMem(DependentFiles);
    for (i = 0; i < Staged.Count; i++)
        DeleteFileW(Staged.Names[i]);
    if (*StagingDir)
        RemoveDirectoryW(StagingDir);
    FreePackageFiles(&Staged);
    FreePackageFiles(&Files);
    FreePackageFiles(&Owned);
    FreePackageFiles(&Sections);
    FreePackageFiles(&Includes);
    SetupCloseInfFile(hPackage);
    SetupCloseInfFile(hInf);
    return hr;
}

HRESULT WINAPI
InstallPrinterDriverFromPackageW(LPCWSTR pszServer, LPCWSTR pszInfPath, LPCWSTR pszDriverName,
                                 LPCWSTR pszEnvironment, DWORD dwFlags)
{
    HANDLE Namespace, Lock;
    PCWSTR Environment;
    WORD Architecture;
    BOOL Locked = TRUE;
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

    /* The lock is held while the package is read; the print provider takes it again to copy the files and register the driver */
    if (!AcquirePackageLock(&Namespace, &Lock))
        return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);

    hr = InstallFromPackage(pszInfPath, pszDriverName, Environment, Architecture, dwFlags, Namespace, Lock, &Locked);

    if (Locked)
        ReleasePackageLock(Namespace, Lock);
    return hr;
}
