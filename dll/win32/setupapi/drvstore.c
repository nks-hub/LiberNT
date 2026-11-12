/*
 * PROJECT:     LiberNT Setup API
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Driver store staging for published OEM driver packages
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif.ing@outlook.com>
 */

#include "setupapi_private.h"
#include <drvpkglock.h>

static const WCHAR RepositoryPath[] = L"\\System32\\DriverStore\\FileRepository";
static const WCHAR VersionSection[] = L"Version";
static const WCHAR CatalogFile[] = L"CatalogFile";
static const WCHAR StagingPattern[] = L".stage-*";

/* The thread whose staging is for DriverStoreAddDriverPackageW; written under the package lock */
static DWORD VerifyingThread;

#define RESTORE_ATTEMPTS 5
#define RESTORE_DELAY 100

static BOOL
DeleteDirectoryTree(
    IN PCWSTR Directory);

static BOOL
FindStoreInf(
    IN PCWSTR Published,
    IN PCWSTR RequiredName,
    IN WORD Architecture,
    OUT PWSTR StoreInfFileName);

static WORD
GetNativeArchitecture(VOID)
{
    SYSTEM_INFO SystemInfo;

    GetNativeSystemInfo(&SystemInfo);
    return SystemInfo.wProcessorArchitecture;
}

static WORD
GetProcessArchitecture(VOID)
{
    SYSTEM_INFO SystemInfo;

    GetSystemInfo(&SystemInfo);
    return SystemInfo.wProcessorArchitecture;
}

static PCWSTR
GetArchitectureName(
    IN WORD Architecture)
{
    switch (Architecture)
    {
        case PROCESSOR_ARCHITECTURE_INTEL: return L"x86";
        case PROCESSOR_ARCHITECTURE_AMD64: return L"amd64";
        case PROCESSOR_ARCHITECTURE_ARM:   return L"arm";
        case PROCESSOR_ARCHITECTURE_ARM64: return L"arm64";
        case PROCESSOR_ARCHITECTURE_IA64:  return L"ia64";
        case PROCESSOR_ARCHITECTURE_RISCV64: return L"riscv64";
        case PROCESSOR_ARCHITECTURE_PPC:   return L"ppc";
        default:                           return L"unknown";
    }
}

static const WORD StoreArchitectures[] =
{
    PROCESSOR_ARCHITECTURE_INTEL,
    PROCESSOR_ARCHITECTURE_AMD64,
    PROCESSOR_ARCHITECTURE_ARM,
    PROCESSOR_ARCHITECTURE_ARM64,
    PROCESSOR_ARCHITECTURE_IA64,
    PROCESSOR_ARCHITECTURE_RISCV64,
    PROCESSOR_ARCHITECTURE_PPC,
};

static BOOL
GetRepositoryRoot(
    OUT PWSTR Buffer,
    IN DWORD BufferSize)
{
    UINT Length = GetWindowsDirectoryW(Buffer, BufferSize);

    if (Length == 0 || Length + ARRAY_SIZE(RepositoryPath) > BufferSize)
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    lstrcatW(Buffer, RepositoryPath);
    return TRUE;
}

static BOOL
HashFileContents(
    IN PCWSTR FileName,
    OUT PULONGLONG Hash)
{
    BYTE Buffer[4096];
    ULONGLONG Value = 0xcbf29ce484222325ULL;
    DWORD Read, i;
    HANDLE hFile;
    BOOL Result = TRUE;

    hFile = CreateFileW(FileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;

    for (;;)
    {
        if (!ReadFile(hFile, Buffer, sizeof(Buffer), &Read, NULL))
        {
            Result = FALSE;
            break;
        }
        if (Read == 0)
            break;

        for (i = 0; i < Read; i++)
        {
            Value ^= Buffer[i];
            Value *= 0x100000001b3ULL;
        }
    }

    CloseHandle(hFile);
    *Hash = Value;
    return Result;
}

static BOOL
FilesAreIdentical(
    IN PCWSTR FirstName,
    IN PCWSTR SecondName)
{
    BYTE First[4096], Second[4096];
    DWORD FirstRead, SecondRead;
    HANDLE hFirst, hSecond;
    BOOL Result = FALSE;

    hFirst = CreateFileW(FirstName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         NULL, OPEN_EXISTING, 0, NULL);
    if (hFirst == INVALID_HANDLE_VALUE)
        return FALSE;

    hSecond = CreateFileW(SecondName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                          NULL, OPEN_EXISTING, 0, NULL);
    if (hSecond == INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFirst);
        return FALSE;
    }

    for (;;)
    {
        if (!ReadFile(hFirst, First, sizeof(First), &FirstRead, NULL) ||
            !ReadFile(hSecond, Second, sizeof(Second), &SecondRead, NULL) ||
            FirstRead != SecondRead)
        {
            break;
        }
        if (FirstRead == 0)
        {
            Result = TRUE;
            break;
        }
        if (memcmp(First, Second, FirstRead) != 0)
            break;
    }

    CloseHandle(hSecond);
    CloseHandle(hFirst);
    return Result;
}

static BOOL
CreateDirectoryPath(
    IN PCWSTR Path)
{
    WCHAR Buffer[MAX_PATH];
    PWSTR Cursor;
    DWORD Attributes;

    if (lstrlenW(Path) >= MAX_PATH)
    {
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
        return FALSE;
    }
    lstrcpyW(Buffer, Path);

    for (Cursor = Buffer + 3; ; Cursor++)
    {
        WCHAR Saved = *Cursor;

        if (Saved != L'\\' && Saved != UNICODE_NULL)
            continue;

        *Cursor = UNICODE_NULL;
        if (!CreateDirectoryW(Buffer, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
            return FALSE;
        if (Saved == UNICODE_NULL)
            break;
        *Cursor = Saved;
    }

    Attributes = GetFileAttributesW(Buffer);
    if (Attributes == INVALID_FILE_ATTRIBUTES || !(Attributes & FILE_ATTRIBUTE_DIRECTORY))
    {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return FALSE;
    }
    return TRUE;
}

static BOOL
CombinePath(
    OUT PWSTR Buffer,
    IN PCWSTR Root,
    IN PCWSTR Relative)
{
    DWORD RootLength = lstrlenW(Root);

    while (*Relative == L'\\' || *Relative == L'/')
        Relative++;

    if (RootLength + 1 + lstrlenW(Relative) >= MAX_PATH)
        return FALSE;

    lstrcpyW(Buffer, Root);
    if (RootLength && Buffer[RootLength - 1] != L'\\' && *Relative)
        lstrcatW(Buffer, L"\\");
    lstrcatW(Buffer, Relative);
    return TRUE;
}

static BOOL
IsSafeRelativePath(
    IN PCWSTR Relative)
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

static DWORD
ResolvePackagePath(
    IN PCWSTR Root,
    IN PCWSTR Relative,
    OUT PWSTR Path)
{
    WCHAR Joined[MAX_PATH], Base[MAX_PATH];
    DWORD Length, BaseLength;

    if (!CombinePath(Joined, Root, Relative))
        return ERROR_FILENAME_EXCED_RANGE;

    Length = GetFullPathNameW(Joined, MAX_PATH, Path, NULL);
    BaseLength = GetFullPathNameW(Root, MAX_PATH, Base, NULL);
    if (Length >= MAX_PATH || BaseLength >= MAX_PATH)
        return ERROR_FILENAME_EXCED_RANGE;
    if (Length == 0 || BaseLength == 0)
        return ERROR_BAD_PATHNAME;

    if (Base[BaseLength - 1] == L'\\')
        BaseLength--;
    if (_wcsnicmp(Path, Base, BaseLength) != 0 || Path[BaseLength] != L'\\' || !Path[BaseLength + 1])
        return ERROR_BAD_PATHNAME;

    /* Windows 11 follows a junction and a directory link of the package; what it stages has to be in the catalog */
    return ERROR_SUCCESS;
}

static BOOL
GetCompressedSourceName(
    IN PCWSTR Source,
    OUT PWSTR Compressed,
    IN DWORD CompressedSize)
{
    PWSTR Name, Extension;
    SIZE_T Length = wcslen(Source);

    if (Length + 3 > CompressedSize)
        return FALSE;

    wcscpy(Compressed, Source);
    Name = wcsrchr(Compressed, L'\\');
    Name = Name ? Name + 1 : Compressed;
    Extension = wcschr(Name, L'.');
    if (!Extension)
        wcscat(Compressed, L"._");
    else if (wcslen(Extension + 1) < 3)
        wcscat(Compressed, L"_");
    else
        Compressed[Length - 1] = L'_';

    return TRUE;
}

typedef struct _STAGE_NAME_LIST
{
    PWSTR *Names;
    DWORD Count;
    DWORD Capacity;
} STAGE_NAME_LIST, *PSTAGE_NAME_LIST;

typedef struct _STAGE_PACKAGE_CONTEXT
{
    PCWSTR SourceRoot;
    PCWSTR StoreRoot;
    STAGE_NAME_LIST Sections;
    STAGE_NAME_LIST Files;
    STAGE_NAME_LIST Installs;
    STAGE_NAME_LIST Includes;
    PSP_ALTPLATFORM_INFO Platform;
    WORD Architecture;
    BOOL Required;
    BOOL Verify;
} STAGE_PACKAGE_CONTEXT, *PSTAGE_PACKAGE_CONTEXT;

static BOOL
MarkNameSeen(
    IN OUT PSTAGE_NAME_LIST List,
    IN PCWSTR Name,
    OUT PBOOL Added)
{
    PWSTR Copy;
    DWORD i;

    *Added = FALSE;
    for (i = 0; i < List->Count; i++)
    {
        if (!_wcsicmp(List->Names[i], Name))
            return TRUE;
    }

    if (List->Count == List->Capacity)
    {
        DWORD Capacity = List->Capacity ? List->Capacity * 2 : 128;
        PWSTR *Names = List->Names ? MyRealloc(List->Names, Capacity * sizeof(PWSTR))
                                   : MyMalloc(Capacity * sizeof(PWSTR));

        if (!Names)
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return FALSE;
        }
        List->Names = Names;
        List->Capacity = Capacity;
    }

    Copy = MyMalloc((lstrlenW(Name) + 1) * sizeof(WCHAR));
    if (!Copy)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    lstrcpyW(Copy, Name);
    List->Names[List->Count++] = Copy;
    *Added = TRUE;
    return TRUE;
}

static VOID
FreeNameList(
    IN OUT PSTAGE_NAME_LIST List)
{
    DWORD i;

    for (i = 0; i < List->Count; i++)
        MyFree(List->Names[i]);
    MyFree(List->Names);
    List->Names = NULL;
    List->Count = List->Capacity = 0;
}

typedef struct _STAGE_CABINET_CONTEXT
{
    PCWSTR FileName;
    PCWSTR Target;
    BOOL Found;
} STAGE_CABINET_CONTEXT, *PSTAGE_CABINET_CONTEXT;

static UINT CALLBACK
StageCabinetCallback(
    IN PVOID Context,
    IN UINT Notification,
    IN UINT_PTR Param1,
    IN UINT_PTR Param2)
{
    PSTAGE_CABINET_CONTEXT Stage = Context;

    switch (Notification)
    {
        case SPFILENOTIFY_FILEINCABINET:
        {
            PFILE_IN_CABINET_INFO_W Info = (PFILE_IN_CABINET_INFO_W)Param1;
            PCWSTR Name = wcsrchr(Info->NameInCabinet, L'\\');

            Name = Name ? Name + 1 : Info->NameInCabinet;
            if (_wcsicmp(Name, Stage->FileName) != 0)
                return FILEOP_SKIP;

            Stage->Found = TRUE;
            lstrcpynW(Info->FullTargetName, Stage->Target, ARRAY_SIZE(Info->FullTargetName));
            return FILEOP_DOIT;
        }

        case SPFILENOTIFY_FILEEXTRACTED:
            return ((PFILEPATHS_W)Param1)->Win32Error;

        case SPFILENOTIFY_NEEDNEWCABINET:
            lstrcpyW((PWSTR)Param2, ((PCABINET_INFO_W)Param1)->CabinetPath);
            return NO_ERROR;

        default:
            return NO_ERROR;
    }
}

static BOOL
StagePackageFile(
    IN PCWSTR SourceRoot,
    IN PCWSTR StoreRoot,
    IN PCWSTR Relative,
    IN PCWSTR Cabinet OPTIONAL,
    IN BOOL Required)
{
    WCHAR Source[MAX_PATH], Target[MAX_PATH], Compressed[MAX_PATH];
    STAGE_CABINET_CONTEXT Stage;
    PWSTR Last;
    DWORD Error, Attributes;

    Error = IsSafeRelativePath(Relative) ? ResolvePackagePath(SourceRoot, Relative, Source) : ERROR_BAD_PATHNAME;
    if (Error == ERROR_SUCCESS)
        Error = ResolvePackagePath(StoreRoot, Relative, Target);
    if (Error != ERROR_SUCCESS)
    {
        if (!Required)
            return TRUE;
        ERR("Package file %s cannot be taken from the package directory\n", debugstr_w(Relative));
        /* Windows 11 tells of a file outside the package directory that its hash is not in the catalog */
        if (Error == ERROR_BAD_PATHNAME && VerifyingThread == GetCurrentThreadId())
            Error = (DWORD)SPAPI_E_FILE_HASH_NOT_IN_CATALOG;
        SetLastError(Error);
        return FALSE;
    }

    Compressed[0] = UNICODE_NULL;
    if (GetFileAttributesW(Source) == INVALID_FILE_ATTRIBUTES)
    {
        if (!GetCompressedSourceName(Source, Compressed, ARRAY_SIZE(Compressed)) ||
            (Attributes = GetFileAttributesW(Compressed)) == INVALID_FILE_ATTRIBUTES ||
            (Attributes & FILE_ATTRIBUTE_REPARSE_POINT))
        {
            Compressed[0] = UNICODE_NULL;
            if (!Cabinet || GetFileAttributesW(Cabinet) == INVALID_FILE_ATTRIBUTES)
            {
                if (!Required)
                    return TRUE;
                ERR("Package file %s is missing\n", debugstr_w(Source));
                SetLastError(ERROR_FILE_NOT_FOUND);
                return FALSE;
            }
        }
        else
        {
            Cabinet = NULL;
        }
    }
    else
    {
        if (GetFileAttributesW(Target) != INVALID_FILE_ATTRIBUTES && FilesAreIdentical(Source, Target))
            return TRUE;
        Cabinet = NULL;
    }

    Last = wcsrchr(Target, L'\\');
    if (Last)
    {
        *Last = UNICODE_NULL;
        if (!CreateDirectoryPath(Target))
            return FALSE;
        *Last = L'\\';
    }

    if (Cabinet)
    {
        Stage.FileName = wcsrchr(Source, L'\\') + 1;
        Stage.Target = Target;
        Stage.Found = FALSE;
        if (!SetupIterateCabinetW(Cabinet, 0, StageCabinetCallback, &Stage))
        {
            ERR("Extracting %s from %s failed with error %lu\n", debugstr_w(Relative), debugstr_w(Cabinet), GetLastError());
            return FALSE;
        }
        if (!Stage.Found && Required)
        {
            ERR("Package file %s is missing from %s\n", debugstr_w(Relative), debugstr_w(Cabinet));
            SetLastError(ERROR_FILE_NOT_FOUND);
            return FALSE;
        }
    }
    else if (Compressed[0])
    {
        Error = SetupDecompressOrCopyFileW(Compressed, Target, NULL);
        if (Error != ERROR_SUCCESS)
        {
            ERR("Expanding %s failed with error %lu\n", debugstr_w(Compressed), Error);
            SetLastError(Error);
            return FALSE;
        }
    }
    else if (!CopyFileW(Source, Target, FALSE))
    {
        ERR("Staging %s failed with error %lu\n", debugstr_w(Source), GetLastError());
        return FALSE;
    }
    return TRUE;
}

static BOOL
FindSourceDisksLine(
    IN HINF hInf,
    IN PCWSTR Section,
    IN WORD Architecture,
    IN PCWSTR Key,
    OUT PINFCONTEXT Context)
{
    WCHAR Decorated[64];

    swprintf(Decorated, ARRAY_SIZE(Decorated), L"%s.%s", Section, GetArchitectureName(Architecture));
    return SetupFindFirstLineW(hInf, Decorated, Key, Context) ||
           SetupFindFirstLineW(hInf, Section, Key, Context);
}

static BOOL
StageCopyFile(
    IN HINF hInf,
    IN PCWSTR FileName,
    IN OUT PSTAGE_PACKAGE_CONTEXT Package)
{
    WCHAR SubDir[MAX_PATH], DiskPath[MAX_PATH], Tag[MAX_PATH], Relative[MAX_PATH], Cabinet[MAX_PATH], DiskName[16];
    WCHAR CabinetName[MAX_PATH];
    PCWSTR CabinetPath = NULL, Disk;
    INFCONTEXT Line;
    SIZE_T Length;
    INT DiskId;
    BOOL Added;

    if (!MarkNameSeen(&Package->Files, FileName, &Added))
        return FALSE;
    if (!Added)
        return TRUE;

    /* A file without a SourceDisksFiles line is taken from the package directory itself */
    if (!FindSourceDisksLine(hInf, L"SourceDisksFiles", Package->Architecture, FileName, &Line) ||
        !SetupGetIntField(&Line, 1, &DiskId))
    {
        return StagePackageFile(Package->SourceRoot, Package->StoreRoot, FileName, NULL, Package->Required);
    }
    if (!SetupGetStringFieldW(&Line, 2, SubDir, ARRAY_SIZE(SubDir), NULL))
        SubDir[0] = UNICODE_NULL;

    DiskPath[0] = UNICODE_NULL;
    Tag[0] = UNICODE_NULL;
    swprintf(DiskName, ARRAY_SIZE(DiskName), L"%d", DiskId);
    if (FindSourceDisksLine(hInf, L"SourceDisksNames", Package->Architecture, DiskName, &Line))
    {
        if (!SetupGetStringFieldW(&Line, 4, DiskPath, ARRAY_SIZE(DiskPath), NULL))
            DiskPath[0] = UNICODE_NULL;
        if (!SetupGetStringFieldW(&Line, 2, Tag, ARRAY_SIZE(Tag), NULL))
            Tag[0] = UNICODE_NULL;
    }

    /* SourceDisksNames gives the path of a disk with one leading separator */
    Disk = DiskPath;
    if (*Disk == L'\\' || *Disk == L'/')
        Disk++;

    if (!CombinePath(Relative, Disk, SubDir) ||
        lstrlenW(Relative) + 1 + lstrlenW(FileName) >= MAX_PATH)
    {
        if (!Package->Required)
            return TRUE;
        ERR("The source path of package file %s is too long\n", debugstr_w(FileName));
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
        return FALSE;
    }
    if (Relative[0] && Relative[lstrlenW(Relative) - 1] != L'\\')
        lstrcatW(Relative, L"\\");
    lstrcatW(Relative, FileName);

    Length = wcslen(Tag);
    if (Length > 4 && _wcsicmp(Tag + Length - 4, L".cab") == 0 &&
        IsSafeRelativePath(Disk) && IsSafeRelativePath(Tag) &&
        CombinePath(CabinetName, Disk, Tag) &&
        ResolvePackagePath(Package->SourceRoot, CabinetName, Cabinet) == ERROR_SUCCESS)
    {
        CabinetPath = Cabinet;
    }

    return StagePackageFile(Package->SourceRoot, Package->StoreRoot, Relative, CabinetPath, Package->Required);
}

static BOOL
StageCopyFilesSection(
    IN HINF hInf,
    IN PCWSTR Section,
    IN OUT PSTAGE_PACKAGE_CONTEXT Package)
{
    WCHAR Target[MAX_PATH], Source[MAX_PATH];
    INFCONTEXT Context;
    BOOL Added;

    if (Section[0] == L'@')
        return StageCopyFile(hInf, Section + 1, Package);

    if (!MarkNameSeen(&Package->Sections, Section, &Added))
        return FALSE;
    if (!Added || !SetupFindFirstLineW(hInf, Section, NULL, &Context))
        return TRUE;

    do
    {
        if (!SetupGetStringFieldW(&Context, 1, Target, ARRAY_SIZE(Target), NULL) || !Target[0])
            continue;
        if (!SetupGetStringFieldW(&Context, 2, Source, ARRAY_SIZE(Source), NULL) || !Source[0])
            lstrcpyW(Source, Target);

        if (!StageCopyFile(hInf, Source, Package))
            return FALSE;
    } while (SetupFindNextLine(&Context, &Context));
    return TRUE;
}

static BOOL
StageSectionCopyFiles(
    IN HINF hInf,
    IN PCWSTR Section,
    IN OUT PSTAGE_PACKAGE_CONTEXT Package)
{
    WCHAR Files[MAX_INF_SECTION_NAME_LENGTH + 1];
    DWORD Field, FieldCount;
    INFCONTEXT Context;
    BOOL Found;

    for (Found = SetupFindFirstLineW(hInf, Section, L"CopyFiles", &Context);
         Found;
         Found = SetupFindNextMatchLineW(&Context, L"CopyFiles", &Context))
    {
        FieldCount = SetupGetFieldCount(&Context);
        for (Field = 1; Field <= FieldCount; Field++)
        {
            if (SetupGetStringFieldW(&Context, Field, Files, ARRAY_SIZE(Files), NULL) && Files[0] &&
                !StageCopyFilesSection(hInf, Files, Package))
            {
                return FALSE;
            }
        }
    }
    return TRUE;
}

static BOOL
StageIncludedInfs(
    IN HINF hInf,
    IN PCWSTR Section,
    IN OUT PSTAGE_PACKAGE_CONTEXT Package)
{
    WCHAR Name[MAX_PATH], Path[MAX_PATH];
    DWORD Field, FieldCount;
    INFCONTEXT Context;
    BOOL Found, Added;

    for (Found = SetupFindFirstLineW(hInf, Section, L"Include", &Context);
         Found;
         Found = SetupFindNextMatchLineW(&Context, L"Include", &Context))
    {
        FieldCount = SetupGetFieldCount(&Context);
        for (Field = 1; Field <= FieldCount; Field++)
        {
            if (!SetupGetStringFieldW(&Context, Field, Name, ARRAY_SIZE(Name), NULL) || !Name[0])
                continue;
            /* For a printer driver package Windows 11 includes the INF that another package of the store is published as, and */
            /* stages what its needed sections copy from the including package. It neither stages nor reads an INF of the package */
            /* directory or one that only lies in the INF directory */
            if (Package->Verify)
            {
                if (wcspbrk(Name, L"\\/:") || !SETUPAPI_FindDriverStoreInf(Name, Path))
                    continue;
                if (!MarkNameSeen(&Package->Includes, Name, &Added))
                    return FALSE;
                if (!Added)
                    continue;
                if (!SetupOpenAppendInfFileW(Path, hInf, NULL))
                    return FALSE;
                continue;
            }

            /* The Setup API stages a package whatever its Include names; an INF outside the package directory is not of the package */
            if (!IsSafeRelativePath(Name) || ResolvePackagePath(Package->SourceRoot, Name, Path) != ERROR_SUCCESS ||
                GetFileAttributesW(Path) == INVALID_FILE_ATTRIBUTES)
            {
                continue;
            }

            if (!MarkNameSeen(&Package->Includes, Name, &Added))
                return FALSE;
            if (!Added)
                continue;

            if (!StagePackageFile(Package->SourceRoot, Package->StoreRoot, Name, NULL, TRUE) ||
                !SetupOpenAppendInfFileW(Path, hInf, NULL))
            {
                return FALSE;
            }
        }
    }
    return TRUE;
}

static BOOL
StageInstallSection(
    IN HINF hInf,
    IN PCWSTR Section,
    IN OUT PSTAGE_PACKAGE_CONTEXT Package)
{
    WCHAR Needs[MAX_INF_SECTION_NAME_LENGTH + 1];
    DWORD Index = Package->Installs.Count, Field, FieldCount;
    INFCONTEXT Context;
    PCWSTR Current;
    BOOL Found, Added;

    if (!MarkNameSeen(&Package->Installs, Section, &Added))
        return FALSE;
    if (!Added)
        return TRUE;

    for (; Index < Package->Installs.Count; Index++)
    {
        Current = Package->Installs.Names[Index];
        if (!StageIncludedInfs(hInf, Current, Package) ||
            !StageSectionCopyFiles(hInf, Current, Package))
        {
            return FALSE;
        }

        for (Found = SetupFindFirstLineW(hInf, Current, L"Needs", &Context);
             Found;
             Found = SetupFindNextMatchLineW(&Context, L"Needs", &Context))
        {
            FieldCount = SetupGetFieldCount(&Context);
            for (Field = 1; Field <= FieldCount; Field++)
            {
                if (SetupGetStringFieldW(&Context, Field, Needs, ARRAY_SIZE(Needs), NULL) && Needs[0] &&
                    !MarkNameSeen(&Package->Installs, Needs, &Added))
                {
                    return FALSE;
                }
            }
        }
    }
    return TRUE;
}

static BOOL
StageModelCopyFiles(
    IN HINF hInf,
    IN OUT PSTAGE_PACKAGE_CONTEXT Package)
{
    WCHAR Models[LINE_LEN + 1], Undecorated[LINE_LEN + 1], Install[LINE_LEN], Actual[LINE_LEN + 16];
    INFCONTEXT Manufacturer, Model;
    BOOL Found;

    if (!SetupFindFirstLineW(hInf, L"Manufacturer", NULL, &Manufacturer))
        return TRUE;

    do
    {
        /* SetupDiGetActualModelsSectionW fails for a line without TargetOSVersion, which names its section itself */
        Found = SetupGetFieldCount(&Manufacturer) < 2
                    ? SetupGetStringFieldW(&Manufacturer, 1, Models, ARRAY_SIZE(Models), NULL)
                    : SetupDiGetActualModelsSectionW(&Manufacturer, Package->Platform, Models, ARRAY_SIZE(Models), NULL, NULL);
        if (!Found || !SetupFindFirstLineW(hInf, Models, NULL, &Model) || Model.CurrentInf != Model.Inf)
            continue;
        /* Windows 11 does not install a 64-bit model from a section without the decoration, so its files can be missing */
        if (Package->Architecture != PROCESSOR_ARCHITECTURE_INTEL &&
            SetupGetStringFieldW(&Manufacturer, 1, Undecorated, ARRAY_SIZE(Undecorated), NULL) && !_wcsicmp(Models, Undecorated))
        {
            continue;
        }

        do
        {
            if (!SetupGetStringFieldW(&Model, 1, Install, ARRAY_SIZE(Install), NULL) ||
                !SetupDiGetActualSectionToInstallExW(hInf, Install, Package->Platform, Actual, LINE_LEN, NULL, NULL, NULL))
            {
                continue;
            }

            if (!StageInstallSection(hInf, Actual, Package))
                return FALSE;
            lstrcatW(Actual, L".CoInstallers");
            if (!StageInstallSection(hInf, Actual, Package))
                return FALSE;
        } while (SetupFindNextLine(&Model, &Model) && Model.CurrentInf == Model.Inf);
        /* The models of an INF that a model includes are not of this package */
    } while (SetupFindNextLine(&Manufacturer, &Manufacturer) && Manufacturer.CurrentInf == Manufacturer.Inf);
    return TRUE;
}

static BOOL
StageCopyFiles(
    IN HINF hInf,
    IN OUT PSTAGE_PACKAGE_CONTEXT Package)
{
    WCHAR Section[MAX_INF_SECTION_NAME_LENGTH + 1];
    DWORD Index;

    Package->Required = TRUE;
    if (!StageModelCopyFiles(hInf, Package))
        return FALSE;

    /* For a printer driver package Windows 11 stages what a model installs and nothing else, not the CopyFiles of a DataSection */
    if (Package->Verify)
        return TRUE;

    Package->Required = FALSE;
    for (Index = 0; SetupEnumInfSectionsW(hInf, Index, Section, ARRAY_SIZE(Section), NULL); Index++)
    {
        if (!StageSectionCopyFiles(hInf, Section, Package))
            return FALSE;
    }
    return TRUE;
}

static BOOL
StageCatalogFiles(
    IN HINF hInf,
    IN PCWSTR SourceRoot,
    IN PCWSTR StoreRoot)
{
    WCHAR Key[LINE_LEN], Value[MAX_PATH];
    INFCONTEXT Context;

    if (!SetupFindFirstLineW(hInf, VersionSection, NULL, &Context))
        return TRUE;

    do
    {
        if (!SetupGetStringFieldW(&Context, 0, Key, ARRAY_SIZE(Key), NULL) ||
            _wcsnicmp(Key, CatalogFile, ARRAY_SIZE(CatalogFile) - 1) != 0)
        {
            continue;
        }

        if (SetupGetStringFieldW(&Context, 1, Value, ARRAY_SIZE(Value), NULL) && Value[0] &&
            !StagePackageFile(SourceRoot, StoreRoot, Value, NULL, FALSE))
        {
            return FALSE;
        }
    } while (SetupFindNextLine(&Context, &Context));
    return TRUE;
}

static BOOL
GetDriverPackageId(
    IN PCWSTR InfFileName,
    IN PCWSTR InfBaseName,
    IN WORD Architecture,
    OUT PWSTR PackageId,
    IN DWORD PackageIdSize)
{
    ULONGLONG Hash;

    if (!HashFileContents(InfFileName, &Hash))
        return FALSE;

    if ((DWORD)lstrlenW(InfBaseName) + 32 >= PackageIdSize)
    {
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
        return FALSE;
    }

    swprintf(PackageId, PackageIdSize, L"%s_%s_%016I64x", InfBaseName, GetArchitectureName(Architecture), Hash);
    CharLowerW(PackageId);
    return TRUE;
}

BOOL
SETUPAPI_GetDriverPackageId(
    IN PCWSTR InfFileName,
    IN PCWSTR InfBaseName,
    OUT PWSTR PackageId,
    IN DWORD PackageIdSize)
{
    return GetDriverPackageId(InfFileName, InfBaseName, GetNativeArchitecture(), PackageId, PackageIdSize);
}

static BOOL
BuildStoreDirectory(
    IN PCWSTR InfFileName,
    IN PCWSTR InfBaseName,
    IN WORD Architecture,
    OUT PWSTR StoreDirectory)
{
    WCHAR Root[MAX_PATH], Name[MAX_PATH];

    if (!GetRepositoryRoot(Root, ARRAY_SIZE(Root)) ||
        !GetDriverPackageId(InfFileName, InfBaseName, Architecture, Name, ARRAY_SIZE(Name)))
    {
        return FALSE;
    }

    if (!CombinePath(StoreDirectory, Root, Name))
    {
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
        return FALSE;
    }
    return TRUE;
}

static BOOL
IsSystemInfDirectory(
    IN PCWSTR Directory)
{
    WCHAR InfDirectory[MAX_PATH];
    SIZE_T Length;
    UINT Result;

    Result = GetSystemWindowsDirectoryW(InfDirectory, ARRAY_SIZE(InfDirectory));
    if (Result == 0 || Result + 5 >= ARRAY_SIZE(InfDirectory))
        return FALSE;
    lstrcatW(InfDirectory, L"\\inf");

    Length = lstrlenW(InfDirectory);
    return _wcsnicmp(Directory, InfDirectory, Length) == 0 &&
           (Directory[Length] == UNICODE_NULL ||
            (Directory[Length] == L'\\' && Directory[Length + 1] == UNICODE_NULL));
}

static BOOL
CreateStagingDirectory(
    IN PCWSTR Store,
    OUT PWSTR Staging)
{
    WCHAR Suffix[32];
    DWORD Attempt;

    for (Attempt = 0; Attempt < 100; Attempt++)
    {
        swprintf(Suffix, ARRAY_SIZE(Suffix), L".stage-%lx-%lx", GetCurrentProcessId(), GetTickCount() + Attempt);
        if (lstrlenW(Store) + lstrlenW(Suffix) >= MAX_PATH)
        {
            SetLastError(ERROR_FILENAME_EXCED_RANGE);
            return FALSE;
        }
        lstrcpyW(Staging, Store);
        lstrcatW(Staging, Suffix);
        if (CreateDirectoryW(Staging, NULL))
            return TRUE;
        if (GetLastError() != ERROR_ALREADY_EXISTS)
            return FALSE;
    }
    return FALSE;
}

static BOOL
IsTreeInStore(
    IN PCWSTR Directory,
    IN PCWSTR Store,
    IN BOOL Contents)
{
    WCHAR Path[MAX_PATH], Other[MAX_PATH];
    WIN32_FIND_DATAW FindData;
    DWORD Attributes;
    HANDLE hFind;
    BOOL Result = TRUE;

    if (!CombinePath(Path, Directory, L"*"))
        return FALSE;

    hFind = FindFirstFileW(Path, &FindData);
    if (hFind == INVALID_HANDLE_VALUE)
        return FALSE;

    do
    {
        if (!wcscmp(FindData.cFileName, L".") || !wcscmp(FindData.cFileName, L".."))
            continue;

        if (!CombinePath(Path, Directory, FindData.cFileName) || !CombinePath(Other, Store, FindData.cFileName))
            Result = FALSE;
        else if (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            Result = IsTreeInStore(Path, Other, Contents);
        else if (Contents)
            Result = FilesAreIdentical(Path, Other);
        else
            Result = (Attributes = GetFileAttributesW(Other)) != INVALID_FILE_ATTRIBUTES && !(Attributes & FILE_ATTRIBUTE_DIRECTORY);
    } while (Result && FindNextFileW(hFind, &FindData));

    if (Result && GetLastError() != ERROR_NO_MORE_FILES)
        Result = FALSE;

    FindClose(hFind);
    return Result;
}

static BOOL
ReplaceStoreDirectory(
    IN PCWSTR Staging,
    IN PCWSTR Store)
{
    WCHAR Old[MAX_PATH];
    DWORD Error, RestoreError, Attempt;

    if (GetFileAttributesW(Store) == INVALID_FILE_ATTRIBUTES)
        return MoveFileW(Staging, Store);

    /* The contents are compared one way; the other way finds what only the store has */
    if (IsTreeInStore(Staging, Store, TRUE) && IsTreeInStore(Store, Staging, FALSE))
    {
        DeleteDirectoryTree(Staging);
        return TRUE;
    }

    if (lstrlenW(Staging) + 4 >= MAX_PATH)
    {
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
        return FALSE;
    }
    lstrcpyW(Old, Staging);
    lstrcatW(Old, L".old");

    if (!MoveFileW(Store, Old))
        return FALSE;
    if (!MoveFileW(Staging, Store))
    {
        Error = GetLastError();
        for (Attempt = 1; !MoveFileW(Old, Store); Attempt++)
        {
            RestoreError = GetLastError();
            /* A package another caller put in place makes the backup stale; the next staging deletes it */
            if (GetFileAttributesW(Store) != INVALID_FILE_ATTRIBUTES)
                break;
            if (Attempt == RESTORE_ATTEMPTS)
            {
                ERR("Driver package %s is left in %s, restoring it failed with error %lu\n",
                    debugstr_w(Store), debugstr_w(Old), RestoreError);
                Error = RestoreError;
                break;
            }
            Sleep(RESTORE_DELAY);
        }
        SetLastError(Error);
        return FALSE;
    }

    DeleteDirectoryTree(Old);
    return TRUE;
}

static BOOL
RestoreStoreBackup(
    IN PCWSTR Store)
{
    WCHAR Backup[MAX_PATH];
    WIN32_FIND_DATAW FindData;
    HANDLE hFind;
    PWSTR Name;
    DWORD Error = ERROR_SUCCESS;
    INT Length;

    if (lstrlenW(Store) + ARRAY_SIZE(StagingPattern) > MAX_PATH)
        return TRUE;
    lstrcpyW(Backup, Store);
    lstrcatW(Backup, StagingPattern);

    hFind = FindFirstFileW(Backup, &FindData);
    if (hFind == INVALID_HANDLE_VALUE)
        return TRUE;

    Name = wcsrchr(Backup, L'\\');
    do
    {
        if (!Name || !(FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
            (Name - Backup) + 1 + lstrlenW(FindData.cFileName) >= MAX_PATH)
        {
            continue;
        }
        lstrcpyW(Name + 1, FindData.cFileName);

        /* Staging runs under the package lock, so a staging directory found here is one its owner could not delete */
        Length = lstrlenW(FindData.cFileName);
        if (Length < 4 || _wcsicmp(FindData.cFileName + Length - 4, L".old") != 0 ||
            GetFileAttributesW(Store) != INVALID_FILE_ATTRIBUTES)
        {
            DeleteDirectoryTree(Backup);
        }
        else if (!MoveFileW(Backup, Store))
        {
            Error = GetLastError();
            ERR("Driver package %s is left in %s, restoring it failed with error %lu\n",
                debugstr_w(Store), debugstr_w(Backup), Error);
        }
    } while (Error == ERROR_SUCCESS && FindNextFileW(hFind, &FindData));

    FindClose(hFind);
    if (Error != ERROR_SUCCESS)
    {
        SetLastError(Error);
        return FALSE;
    }
    return TRUE;
}

/* What a deletion that could not finish left of the packages of an INF */
static BOOL
DeleteStoreLeftovers(
    IN PCWSTR InfFileName)
{
    WCHAR Root[MAX_PATH], Name[64], Path[MAX_PATH];
    WIN32_FIND_DATAW FindData;
    DWORD Error = ERROR_SUCCESS;
    ULONGLONG Hash;
    HANDLE hFind;

    if (!GetRepositoryRoot(Root, ARRAY_SIZE(Root)) || !HashFileContents(InfFileName, &Hash))
        return TRUE;

    swprintf(Name, ARRAY_SIZE(Name), L"*_%016I64x.delete-*", Hash);
    if (!CombinePath(Path, Root, Name))
        return TRUE;

    hFind = FindFirstFileW(Path, &FindData);
    if (hFind == INVALID_HANDLE_VALUE)
        return TRUE;

    do
    {
        if ((FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
            CombinePath(Path, Root, FindData.cFileName) &&
            !DeleteDirectoryTree(Path))
        {
            Error = GetLastError();
        }
    } while (FindNextFileW(hFind, &FindData));

    FindClose(hFind);
    SetLastError(Error);
    return Error == ERROR_SUCCESS;
}

static BOOL
GetCatalogName(
    IN HINF hInf,
    IN WORD Architecture,
    OUT PWSTR Name,
    IN DWORD NameSize)
{
    WCHAR Key[64];
    INFCONTEXT Context;

    swprintf(Key, ARRAY_SIZE(Key), L"%s.NT%s", CatalogFile, GetArchitectureName(Architecture));
    return (SetupFindFirstLineW(hInf, VersionSection, Key, &Context) ||
            SetupFindFirstLineW(hInf, VersionSection, L"CatalogFile.NT", &Context) ||
            SetupFindFirstLineW(hInf, VersionSection, CatalogFile, &Context)) &&
           SetupGetStringFieldW(&Context, 1, Name, NameSize, NULL) && Name[0];
}

/* A catalog names a member by its hash, as bytes or as the upper case hexadecimal string of them */
static BOOL
IsFileInCatalog(
    IN PCCTL_CONTEXT Catalog,
    IN HCATADMIN Sha256 OPTIONAL,
    IN PCWSTR FileName)
{
    BYTE Hash[2][32];
    DWORD Size[2] = { sizeof(Hash[0]), sizeof(Hash[1]) }, Kind, Entry, i, TagSize;
    PCRYPT_DATA_BLOB Id;
    WCHAR Tag[65];
    HANDLE hFile;

    hFile = CreateFileW(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    if (!CryptCATAdminCalcHashFromFileHandle(hFile, &Size[0], Hash[0], 0))
        Size[0] = 0;
    if (!Sha256 || SetFilePointer(hFile, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER ||
        !CryptCATAdminCalcHashFromFileHandle2(Sha256, hFile, &Size[1], Hash[1], 0))
    {
        Size[1] = 0;
    }
    CloseHandle(hFile);

    for (Kind = 0; Kind < ARRAY_SIZE(Size); Kind++)
    {
        if (Size[Kind] == 0 || Size[Kind] > sizeof(Hash[Kind]))
            continue;
        for (i = 0; i < Size[Kind]; i++)
            swprintf(Tag + i * 2, 3, L"%02X", Hash[Kind][i]);
        TagSize = Size[Kind] * 2 * sizeof(WCHAR);

        for (Entry = 0; Entry < Catalog->pCtlInfo->cCTLEntry; Entry++)
        {
            Id = &Catalog->pCtlInfo->rgCTLEntry[Entry].SubjectIdentifier;
            if ((Id->cbData == Size[Kind] && !memcmp(Id->pbData, Hash[Kind], Size[Kind])) ||
                ((Id->cbData == TagSize || Id->cbData == TagSize + sizeof(WCHAR)) && !memcmp(Id->pbData, Tag, TagSize)))
            {
                return TRUE;
            }
        }
    }
    return FALSE;
}

static BOOL
IsTreeInCatalog(
    IN PCWSTR Directory,
    IN PCCTL_CONTEXT Catalog,
    IN HCATADMIN Sha256 OPTIONAL)
{
    WCHAR Path[MAX_PATH];
    WIN32_FIND_DATAW FindData;
    SIZE_T Length;
    HANDLE hFind;
    BOOL Result = TRUE;

    if (!CombinePath(Path, Directory, L"*"))
        return FALSE;

    hFind = FindFirstFileW(Path, &FindData);
    if (hFind == INVALID_HANDLE_VALUE)
        return FALSE;

    do
    {
        if (!wcscmp(FindData.cFileName, L".") || !wcscmp(FindData.cFileName, L".."))
            continue;

        /* A catalog does not list itself */
        Length = wcslen(FindData.cFileName);
        if (!(FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && Length > 4 &&
            !_wcsicmp(FindData.cFileName + Length - 4, L".cat"))
        {
            continue;
        }

        if (!CombinePath(Path, Directory, FindData.cFileName))
            Result = FALSE;
        else if (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            Result = IsTreeInCatalog(Path, Catalog, Sha256);
        else
            Result = IsFileInCatalog(Catalog, Sha256, Path);
    } while (Result && FindNextFileW(hFind, &FindData));

    FindClose(hFind);
    return Result;
}

/* The errors are those of Windows 11 22621, which also takes a package whose signer certificate has expired */
static DWORD
VerifyStagedPackage(
    IN PCWSTR Staging,
    IN PCWSTR CatalogName)
{
    CERT_CHAIN_PARA ChainPara = { sizeof(ChainPara) };
    CERT_CHAIN_POLICY_PARA PolicyPara = { sizeof(PolicyPara), CERT_CHAIN_POLICY_IGNORE_ALL_NOT_TIME_VALID_FLAGS };
    CERT_CHAIN_POLICY_PARA RootPara = { sizeof(RootPara) };
    CERT_CHAIN_POLICY_STATUS Status = { sizeof(Status) }, RootStatus = { sizeof(RootStatus) };
    PCCERT_CONTEXT Signer = NULL, Publisher = NULL;
    BOOL Trusted;
    PCCERT_CHAIN_CONTEXT Chain = NULL;
    PCCTL_CONTEXT Catalog = NULL;
    HCERTSTORE Certificates, Publishers;
    HCATADMIN Sha256 = NULL;
    DWORD Error = (DWORD)TRUST_E_NOSIGNATURE, Size, Read, Signers = 0;
    WCHAR Path[MAX_PATH];
    PBYTE Data = NULL;
    HANDLE hFile;

    if (!CatalogName[0] || !CombinePath(Path, Staging, CatalogName))
        return ERROR_CANCELLED;
    hFile = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return ERROR_CANCELLED;

    Size = GetFileSize(hFile, NULL);
    if (Size != INVALID_FILE_SIZE && Size != 0)
        Data = MyMalloc(Size);
    if (Data && ReadFile(hFile, Data, Size, &Read, NULL) && Read == Size)
        Catalog = CertCreateCTLContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, Data, Size);
    CloseHandle(hFile);
    MyFree(Data);
    if (!Catalog)
        return Error;

    Size = sizeof(Signers);
    if (CryptMsgGetParam(Catalog->hCryptMsg, CMSG_SIGNER_COUNT_PARAM, 0, &Signers, &Size) && Signers != 0 &&
        CryptMsgGetAndVerifySigner(Catalog->hCryptMsg, 0, NULL, 0, &Signer, NULL))
    {
        Certificates = CertOpenStore(CERT_STORE_PROV_MSG, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, Catalog->hCryptMsg);
        if (!CertGetCertificateChain(NULL, Signer, NULL, Certificates, &ChainPara, 0, NULL, &Chain) ||
            !CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_BASE, Chain, &PolicyPara, &Status))
        {
            Error = (DWORD)CERT_E_UNTRUSTEDROOT;
        }
        else if (Status.dwError != ERROR_SUCCESS)
        {
            Error = Status.dwError;
        }
        else
        {
            /* Windows 11 takes a hardware compatibility signature, which chains to a root of Microsoft, without a trusted publisher */
            Trusted = CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_MICROSOFT_ROOT, Chain, &RootPara, &RootStatus) &&
                      RootStatus.dwError == ERROR_SUCCESS;
            Publishers = Trusted ? NULL : CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                                                        CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG, L"TrustedPublisher");
            if (Publishers)
            {
                Publisher = CertFindCertificateInStore(Publishers, X509_ASN_ENCODING, 0, CERT_FIND_EXISTING, Signer, NULL);
                CertCloseStore(Publishers, 0);
            }
            if (Publisher)
            {
                CertFreeCertificateContext(Publisher);
                Trusted = TRUE;
            }

            if (!Trusted)
            {
                Error = (DWORD)SPAPI_E_AUTHENTICODE_TRUST_NOT_ESTABLISHED;
            }
            else
            {
                if (!CryptCATAdminAcquireContext2(&Sha256, NULL, L"SHA256", NULL, 0))
                    Sha256 = NULL;
                Error = IsTreeInCatalog(Staging, Catalog, Sha256) ? ERROR_SUCCESS : (DWORD)SPAPI_E_FILE_HASH_NOT_IN_CATALOG;
                if (Sha256)
                    CryptCATAdminReleaseContext(Sha256, 0);
            }
        }

        if (Chain)
            CertFreeCertificateChain(Chain);
        if (Certificates)
            CertCloseStore(Certificates, 0);
        CertFreeCertificateContext(Signer);
    }

    CertFreeCTLContext(Catalog);
    return Error;
}


static BOOL
StageLockedDriverPackage(
    IN PCWSTR SourceInfFileName,
    IN WORD Architecture,
    OUT PWSTR StoreInfFileName OPTIONAL)
{
    WCHAR Source[MAX_PATH], SourceRoot[MAX_PATH], Root[MAX_PATH], Store[MAX_PATH], Staging[MAX_PATH], Target[MAX_PATH];
    WCHAR Catalog[MAX_PATH] = L"";
    STAGE_PACKAGE_CONTEXT Package;
    SP_ALTPLATFORM_INFO Platform;
    PWSTR BaseName;
    HINF hInf;
    DWORD Length, Error;
    BOOL Staged, Added, Verify = VerifyingThread == GetCurrentThreadId();

    Length = GetFullPathNameW(SourceInfFileName, ARRAY_SIZE(Source), Source, &BaseName);
    if (Length == 0 || Length >= ARRAY_SIZE(Source) || !BaseName)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    lstrcpynW(SourceRoot, Source, (INT)(BaseName - Source) + 1);

    if (!GetRepositoryRoot(Root, ARRAY_SIZE(Root)))
        return FALSE;
    if (IsSystemInfDirectory(SourceRoot))
        return TRUE;
    /* A package in the store is the source of the package of another architecture */
    Length = lstrlenW(Root);
    if (_wcsnicmp(SourceRoot, Root, Length) == 0 && SourceRoot[Length] == L'\\' &&
        FindStoreInf(Source, BaseName, Architecture, StoreInfFileName ? StoreInfFileName : Store))
    {
        return TRUE;
    }

    Error = ResolvePackagePath(SourceRoot, BaseName, Target);
    if (Error != ERROR_SUCCESS)
    {
        ERR("INF %s cannot be taken from the package directory\n", debugstr_w(Source));
        SetLastError(Error);
        return FALSE;
    }

    if (!BuildStoreDirectory(Source, BaseName, Architecture, Store) ||
        !CreateDirectoryPath(Root) ||
        !RestoreStoreBackup(Store) ||
        !CreateStagingDirectory(Store, Staging))
    {
        return FALSE;
    }
    DeleteStoreLeftovers(Source);

    Staged = CombinePath(Target, Staging, BaseName);
    Error = ERROR_FILENAME_EXCED_RANGE;

    hInf = Staged ? SetupOpenInfFileW(Source, NULL, INF_STYLE_WIN4, NULL) : INVALID_HANDLE_VALUE;
    if (hInf != INVALID_HANDLE_VALUE)
    {
        ZeroMemory(&Package, sizeof(Package));
        Package.SourceRoot = SourceRoot;
        Package.StoreRoot = Staging;
        Package.Architecture = Architecture;
        Package.Verify = Verify;
        if (Architecture != GetProcessArchitecture())
        {
            ZeroMemory(&Platform, sizeof(Platform));
            Platform.cbSize = sizeof(Platform);
            Platform.Platform = VER_PLATFORM_WIN32_NT;
            Platform.MajorVersion = OsVersionInfo.dwMajorVersion;
            Platform.MinorVersion = OsVersionInfo.dwMinorVersion;
            Platform.ProcessorArchitecture = Architecture;
            Package.Platform = &Platform;
        }
        Staged = MarkNameSeen(&Package.Includes, BaseName, &Added) &&
                 StageCatalogFiles(hInf, SourceRoot, Staging) && StageCopyFiles(hInf, &Package);
        Error = GetLastError();
        if (!Verify || !GetCatalogName(hInf, Architecture, Catalog, ARRAY_SIZE(Catalog)))
            Catalog[0] = UNICODE_NULL;
        FreeNameList(&Package.Sections);
        FreeNameList(&Package.Files);
        FreeNameList(&Package.Installs);
        FreeNameList(&Package.Includes);
        SetupCloseInfFile(hInf);
    }
    else if (Staged)
    {
        Error = GetLastError();
        Staged = FALSE;
    }

    if (Staged)
    {
        Staged = CopyFileW(Source, Target, FALSE);
        Error = GetLastError();
    }
    if (Staged && Verify)
    {
        Error = VerifyStagedPackage(Staging, Catalog);
        Staged = Error == ERROR_SUCCESS;
    }
    if (Staged)
    {
        Staged = ReplaceStoreDirectory(Staging, Store);
        Error = GetLastError();
    }
    if (!Staged)
    {
        DeleteDirectoryTree(Staging);
        SetLastError(Error);
    }
    else if (StoreInfFileName)
    {
        CombinePath(StoreInfFileName, Store, BaseName);
    }
    return Staged;
}

static BOOL
StageDriverPackage(
    IN PCWSTR SourceInfFileName,
    IN WORD Architecture,
    OUT PWSTR StoreInfFileName OPTIONAL)
{
    HANDLE Namespace, Lock;
    DWORD Error;
    BOOL Staged;

    if (!AcquirePackageLock(&Namespace, &Lock))
    {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    Staged = StageLockedDriverPackage(SourceInfFileName, Architecture, StoreInfFileName);
    Error = GetLastError();
    ReleasePackageLock(Namespace, Lock);
    SetLastError(Error);
    return Staged;
}

BOOL
SETUPAPI_StageLockedDriverPackage(
    IN PCWSTR SourceInfFileName)
{
    return StageLockedDriverPackage(SourceInfFileName, GetNativeArchitecture(), NULL);
}

static BOOL
GetPublishedInfPath(
    IN PCWSTR FileName,
    OUT PWSTR Buffer)
{
    UINT Length;

    if (wcschr(FileName, L'\\') || wcschr(FileName, L'/'))
    {
        Length = GetFullPathNameW(FileName, MAX_PATH, Buffer, NULL);
        return Length != 0 && Length < MAX_PATH;
    }

    Length = GetSystemWindowsDirectoryW(Buffer, MAX_PATH);
    if (Length == 0 || Length + 5 + lstrlenW(FileName) >= MAX_PATH)
        return FALSE;

    lstrcatW(Buffer, L"\\inf\\");
    lstrcatW(Buffer, FileName);
    return TRUE;
}

static BOOL
FindStoreInf(
    IN PCWSTR Published,
    IN PCWSTR RequiredName,
    IN WORD Architecture,
    OUT PWSTR StoreInfFileName)
{
    WCHAR Root[MAX_PATH], Pattern[MAX_PATH], Candidate[MAX_PATH], Suffix[64], Long[MAX_PATH];
    WIN32_FIND_DATAW FindData;
    PCWSTR Directory, Name;
    DWORD Length, Attributes;
    ULONGLONG Hash;
    HANDLE hFind;
    BOOL Found = FALSE;

    if (!GetRepositoryRoot(Root, ARRAY_SIZE(Root)))
        return FALSE;

    Length = GetLongPathNameW(Published, Long, ARRAY_SIZE(Long));
    if (Length != 0 && Length < ARRAY_SIZE(Long))
        Published = Long;

    if (!HashFileContents(Published, &Hash))
        return FALSE;

    swprintf(Suffix, ARRAY_SIZE(Suffix), L"_%s_%016I64x", GetArchitectureName(Architecture), Hash);

    Length = lstrlenW(Root);
    if (_wcsnicmp(Published, Root, Length) == 0 && Published[Length] == L'\\')
    {
        /* Only <name>.inf in a directory <name>.inf_<suffix> names a package, no other file, stream or directory */
        Directory = Published + Length + 1;
        Name = wcschr(Directory, L'\\');
        if (!Name || wcschr(Name + 1, L'\\') || wcschr(Directory, L':'))
            return FALSE;
        Name++;
        Length = lstrlenW(Name);
        if (Length < 4 || _wcsicmp(Name + Length - 4, L".inf") != 0 ||
            _wcsnicmp(Directory, Name, Length) != 0 || Directory[Length] != L'_')
        {
            return FALSE;
        }
        Attributes = GetFileAttributesW(Published);
        if (Attributes == INVALID_FILE_ATTRIBUTES || (Attributes & FILE_ATTRIBUTE_DIRECTORY))
            return FALSE;
        if (_wcsnicmp(Directory + Length, Suffix, lstrlenW(Suffix)) != 0 ||
            Directory + Length + lstrlenW(Suffix) + 1 != Name)
        {
            return FALSE;
        }
        lstrcpyW(StoreInfFileName, Published);
        return TRUE;
    }

    if (lstrlenW(Root) + 2 + lstrlenW(Suffix) >= MAX_PATH)
        return FALSE;

    lstrcpyW(Pattern, Root);
    lstrcatW(Pattern, L"\\*");
    lstrcatW(Pattern, Suffix);

    hFind = FindFirstFileW(Pattern, &FindData);
    if (hFind == INVALID_HANDLE_VALUE)
        return FALSE;

    do
    {
        WCHAR InfName[MAX_PATH];
        DWORD NameLength = lstrlenW(FindData.cFileName);
        DWORD SuffixLength = lstrlenW(Suffix);

        if (!(FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || NameLength <= SuffixLength)
            continue;

        lstrcpynW(InfName, FindData.cFileName, NameLength - SuffixLength + 1);
        if (RequiredName && _wcsicmp(InfName, RequiredName))
            continue;
        if (lstrlenW(Root) + 2 + NameLength + lstrlenW(InfName) >= MAX_PATH)
            continue;

        swprintf(Candidate, ARRAY_SIZE(Candidate), L"%s\\%s\\%s", Root, FindData.cFileName, InfName);
        if (FilesAreIdentical(Published, Candidate))
        {
            lstrcpyW(StoreInfFileName, Candidate);
            Found = TRUE;
        }
    } while (!Found && FindNextFileW(hFind, &FindData));

    FindClose(hFind);
    return Found;
}

static BOOL
FindStoreInfOfAnyArchitecture(
    IN PCWSTR Published,
    IN PCWSTR RequiredName,
    OUT PWSTR StoreInfFileName)
{
    DWORD i;

    if (FindStoreInf(Published, RequiredName, GetNativeArchitecture(), StoreInfFileName))
        return TRUE;

    for (i = 0; i < ARRAY_SIZE(StoreArchitectures); i++)
    {
        if (FindStoreInf(Published, RequiredName, StoreArchitectures[i], StoreInfFileName))
            return TRUE;
    }
    return FALSE;
}

BOOL
SETUPAPI_FindDriverStoreInf(
    IN PCWSTR FileName,
    OUT PWSTR StoreInfFileName)
{
    WCHAR Published[MAX_PATH];

    if (!GetPublishedInfPath(FileName, Published))
        return FALSE;
    return FindStoreInfOfAnyArchitecture(Published, NULL, StoreInfFileName);
}

PCWSTR
SETUPAPI_GetInfSourceDirectory(
    IN const struct InfFileDetails *InfFileDetails,
    OUT PWSTR Buffer)
{
    WCHAR Published[MAX_PATH];
    PWSTR Last;

    if (!InfFileDetails->DirectoryName ||
        _wcsnicmp(InfFileDetails->FileName, L"oem", 3) != 0 ||
        !IsSystemInfDirectory(InfFileDetails->DirectoryName) ||
        !CombinePath(Published, InfFileDetails->DirectoryName, InfFileDetails->FileName) ||
        !SETUPAPI_FindDriverStoreInf(Published, Buffer))
    {
        return InfFileDetails->DirectoryName;
    }

    Last = wcsrchr(Buffer, L'\\');
    if (!Last)
        return InfFileDetails->DirectoryName;

    *Last = UNICODE_NULL;
    return Buffer;
}

VOID
SETUPAPI_RecordPublishedDriverPackage(
    IN PCWSTR PublishedInfFileName,
    IN PCWSTR SourceInfFileName)
{
    WCHAR Source[MAX_PATH];
    PCWSTR PublishedName;
    PWSTR BaseName;
    DWORD Length;

    PublishedName = wcsrchr(PublishedInfFileName, L'\\');
    PublishedName = PublishedName ? PublishedName + 1 : PublishedInfFileName;

    Length = GetFullPathNameW(SourceInfFileName, ARRAY_SIZE(Source), Source, &BaseName);
    if (Length == 0 || Length >= ARRAY_SIZE(Source) || !BaseName || BaseName == Source)
        return;

    BaseName[-1] = UNICODE_NULL;
    SETUPAPI_RecordDriverDatabasePackage(PublishedInfFileName, PublishedName, BaseName, Source);
}

BOOL
SETUPAPI_GetOriginalInfName(
    IN PCWSTR PublishedInfFileName,
    OUT PWSTR OriginalName,
    IN DWORD OriginalNameSize)
{
    WCHAR Directory[MAX_PATH], StoreInf[MAX_PATH];
    WIN32_FIND_DATAW FindData;
    HANDLE hFind;
    PWSTR Last;

    if (lstrlenW(PublishedInfFileName) >= ARRAY_SIZE(Directory))
        return FALSE;
    lstrcpyW(Directory, PublishedInfFileName);
    Last = wcsrchr(Directory, L'\\');
    if (!Last)
        return FALSE;
    *Last = UNICODE_NULL;
    if (!IsSystemInfDirectory(Directory) ||
        !FindStoreInf(PublishedInfFileName, NULL, GetNativeArchitecture(), StoreInf))
    {
        return FALSE;
    }

    hFind = FindFirstFileW(StoreInf, &FindData);
    if (hFind == INVALID_HANDLE_VALUE)
        return FALSE;
    FindClose(hFind);

    if ((DWORD)lstrlenW(FindData.cFileName) >= OriginalNameSize)
        return FALSE;
    lstrcpyW(OriginalName, FindData.cFileName);
    return TRUE;
}

VOID
SETUPAPI_RecordInstalledDriverPackage(
    IN const struct InfFileDetails *InfFileDetails)
{
    WCHAR Published[MAX_PATH], Path[MAX_PATH + 64];
    HKEY Key;

    if (!InfFileDetails->DirectoryName ||
        _wcsnicmp(InfFileDetails->FileName, L"oem", 3) == 0 ||
        !IsSystemInfDirectory(InfFileDetails->DirectoryName) ||
        !CombinePath(Published, InfFileDetails->DirectoryName, InfFileDetails->FileName))
    {
        return;
    }

    swprintf(Path, ARRAY_SIZE(Path), L"SYSTEM\\DriverDatabase\\DriverInfFiles\\%s", InfFileDetails->FileName);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, Path, 0, KEY_QUERY_VALUE, &Key) == ERROR_SUCCESS)
    {
        RegCloseKey(Key);
        return;
    }

    SETUPAPI_RecordDriverDatabasePackage(Published, InfFileDetails->FileName, InfFileDetails->FileName, NULL);
}

static BOOL
DeleteDirectoryTree(
    IN PCWSTR Directory)
{
    WCHAR Path[MAX_PATH];
    WIN32_FIND_DATAW FindData;
    HANDLE hFind;

    if (!CombinePath(Path, Directory, L"*"))
    {
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
        return FALSE;
    }

    hFind = FindFirstFileW(Path, &FindData);
    if (hFind != INVALID_HANDLE_VALUE)
    {
        do
        {
            if (!wcscmp(FindData.cFileName, L".") || !wcscmp(FindData.cFileName, L".."))
                continue;
            if (!CombinePath(Path, Directory, FindData.cFileName))
                continue;

            if (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                DeleteDirectoryTree(Path);
            }
            else
            {
                SetFileAttributesW(Path, FILE_ATTRIBUTE_NORMAL);
                DeleteFileW(Path);
            }
        } while (FindNextFileW(hFind, &FindData));
        FindClose(hFind);
    }

    return RemoveDirectoryW(Directory);
}

/* The rename fails while a file of the package is open, before anything of the package is changed */
static BOOL
MoveStoreDirectoryAside(
    IN PCWSTR Directory,
    OUT PWSTR Aside)
{
    WCHAR Suffix[32];

    swprintf(Suffix, ARRAY_SIZE(Suffix), L".delete-%lx-%lx", GetCurrentProcessId(), GetTickCount());
    if (lstrlenW(Directory) + lstrlenW(Suffix) >= MAX_PATH)
    {
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
        return FALSE;
    }
    lstrcpyW(Aside, Directory);
    lstrcatW(Aside, Suffix);
    return MoveFileW(Directory, Aside);
}

BOOL
SETUPAPI_DeleteLockedDriverStorePackage(
    IN PCWSTR PublishedInfFileName)
{
    WCHAR StoreInf[MAX_PATH], Aside[MAX_PATH];
    BOOL Deleted;
    PWSTR Last;

    Deleted = DeleteStoreLeftovers(PublishedInfFileName);
    if (Deleted && SETUPAPI_FindDriverStoreInf(PublishedInfFileName, StoreInf) && (Last = wcsrchr(StoreInf, L'\\')) != NULL)
    {
        *Last = UNICODE_NULL;
        Deleted = MoveStoreDirectoryAside(StoreInf, Aside) && DeleteDirectoryTree(Aside);
    }
    return Deleted;
}

static HRESULT
CheckStoreRequest(
    IN WORD Architecture,
    IN PDWORD ReturnLength)
{
    DWORD i;

    if (*ReturnLength < MAX_PATH)
        return E_INVALIDARG;

    for (i = 0; i < ARRAY_SIZE(StoreArchitectures); i++)
    {
        if (Architecture == StoreArchitectures[i])
            return S_OK;
    }
    return E_INVALIDARG;
}

static HRESULT
ReturnStorePath(
    IN PCWSTR Path,
    OUT PWSTR ReturnPath,
    IN OUT PDWORD ReturnLength)
{
    DWORD Length = lstrlenW(Path) + 1;

    if (Length > *ReturnLength)
    {
        *ReturnLength = Length;
        return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
    }

    lstrcpyW(ReturnPath, Path);
    *ReturnLength = Length;
    return S_OK;
}

static BOOL
FindSourceStoreInf(
    IN PCWSTR InfPath,
    IN WORD Architecture,
    OUT PWSTR Source,
    OUT PWSTR StoreInfFileName)
{
    PWSTR BaseName;
    DWORD Length;

    Length = GetFullPathNameW(InfPath, MAX_PATH, Source, &BaseName);
    if (Length == 0 || Length >= MAX_PATH || !BaseName)
        return FALSE;

    return FindStoreInf(Source, BaseName, Architecture, StoreInfFileName);
}

typedef struct _PUBLISHED_INFS
{
    STAGE_NAME_LIST Names;
    PHANDLE Handles;
    DWORD Held;
} PUBLISHED_INFS, *PPUBLISHED_INFS;

static BOOL
ReleasePublishedInfs(
    IN OUT PPUBLISHED_INFS Infs,
    IN BOOL Delete)
{
    DWORD Error = ERROR_SUCCESS, i;
    PWSTR Extension;

    for (i = 0; i < Infs->Held; i++)
    {
        if (Delete)
        {
            if (!DeleteFileW(Infs->Names.Names[i]))
            {
                Error = GetLastError();
            }
            else if ((Extension = wcsrchr(Infs->Names.Names[i], L'.')) != NULL)
            {
                lstrcpyW(Extension, L".pnf");
                DeleteFileW(Infs->Names.Names[i]);
            }
        }
        CloseHandle(Infs->Handles[i]);
    }

    MyFree(Infs->Handles);
    Infs->Handles = NULL;
    Infs->Held = 0;
    FreeNameList(&Infs->Names);
    SetLastError(Error);
    return Error == ERROR_SUCCESS;
}

/* A file that is open for deletion cannot be opened by anyone who would prevent deleting it later */
static BOOL
HoldPublishedInfs(
    IN PCWSTR StoreInfFileName,
    IN OUT PPUBLISHED_INFS Infs)
{
    WCHAR InfDirectory[MAX_PATH], Pattern[MAX_PATH], Published[MAX_PATH];
    WIN32_FIND_DATAW FindData;
    DWORD Error = ERROR_SUCCESS;
    HANDLE hFind;
    BOOL Added;
    UINT Length;

    Length = GetSystemWindowsDirectoryW(InfDirectory, ARRAY_SIZE(InfDirectory));
    if (Length == 0 || Length + 5 >= ARRAY_SIZE(InfDirectory) ||
        !CombinePath(Pattern, lstrcatW(InfDirectory, L"\\inf"), L"oem*.inf"))
    {
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
        return FALSE;
    }

    hFind = FindFirstFileW(Pattern, &FindData);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        Error = GetLastError();
        return Error == ERROR_FILE_NOT_FOUND || Error == ERROR_PATH_NOT_FOUND || Error == ERROR_NO_MORE_FILES;
    }

    do
    {
        if ((FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
            !CombinePath(Published, InfDirectory, FindData.cFileName) ||
            !FilesAreIdentical(Published, StoreInfFileName))
        {
            continue;
        }

        if (FindData.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
            Error = ERROR_ACCESS_DENIED;
        else if (!MarkNameSeen(&Infs->Names, Published, &Added))
            Error = GetLastError();
    } while (Error == ERROR_SUCCESS && FindNextFileW(hFind, &FindData));

    if (Error == ERROR_SUCCESS && GetLastError() != ERROR_NO_MORE_FILES)
        Error = GetLastError();

    FindClose(hFind);

    if (Error == ERROR_SUCCESS && Infs->Names.Count)
    {
        Infs->Handles = MyMalloc(Infs->Names.Count * sizeof(HANDLE));
        if (!Infs->Handles)
            Error = ERROR_NOT_ENOUGH_MEMORY;
    }
    while (Error == ERROR_SUCCESS && Infs->Held < Infs->Names.Count)
    {
        Infs->Handles[Infs->Held] = CreateFileW(Infs->Names.Names[Infs->Held], DELETE,
                                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                                NULL, OPEN_EXISTING, 0, NULL);
        if (Infs->Handles[Infs->Held] == INVALID_HANDLE_VALUE)
            Error = GetLastError();
        else
            Infs->Held++;
    }

    if (Error != ERROR_SUCCESS)
    {
        ReleasePublishedInfs(Infs, FALSE);
        SetLastError(Error);
        return FALSE;
    }
    return TRUE;
}

HRESULT
WINAPI
DriverStoreFindDriverPackageW(
    IN PCWSTR InfPath,
    IN PVOID Reserved1,
    IN PVOID Reserved2,
    IN WORD Architecture,
    IN PVOID Reserved3,
    OUT PWSTR ReturnPath,
    IN OUT PDWORD ReturnLength)
{
    WCHAR Source[MAX_PATH], StoreInf[MAX_PATH];
    HRESULT hr;

    hr = CheckStoreRequest(Architecture, ReturnLength);
    if (FAILED(hr))
        return hr;

    Source[0] = UNICODE_NULL;
    if (FindSourceStoreInf(InfPath, Architecture, Source, StoreInf))
        return ReturnStorePath(StoreInf, ReturnPath, ReturnLength);

    *ReturnPath = UNICODE_NULL;
    *ReturnLength = 0;
    if (GetFileAttributesW(Source) == INVALID_FILE_ATTRIBUTES)
        return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
    return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
}

static HRESULT
AddLockedDriverPackage(
    IN OUT PWSTR Source,
    IN PCWSTR BaseName,
    IN WORD Architecture,
    OUT PWSTR StoreInf)
{
    WCHAR Published[MAX_PATH];

    /* SetupCopyOEMInfW publishes for the native architecture only */
    if (Architecture == GetNativeArchitecture())
    {
        if (!SetupCopyOEMInfW(Source, NULL, SPOST_NONE, 0, Published, ARRAY_SIZE(Published), NULL, NULL))
            return HRESULT_FROM_WIN32(GetLastError());
        /* A source inside the store that is not a package INF does not name the package staged from it */
        if (!FindStoreInf(Published, BaseName, Architecture, StoreInf))
            return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
        return S_OK;
    }

    /* A published INF stands for the package it was published from */
    lstrcpynW(StoreInf, Source, (INT)(BaseName - Source) + 1);
    if (IsSystemInfDirectory(StoreInf))
    {
        if (!FindStoreInfOfAnyArchitecture(Source, NULL, StoreInf))
            return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
        lstrcpyW(Source, StoreInf);
    }
    if (!StageDriverPackage(Source, Architecture, StoreInf))
        return HRESULT_FROM_WIN32(GetLastError());

    return S_OK;
}

HRESULT
WINAPI
DriverStoreAddDriverPackageW(
    IN PCWSTR InfPath,
    IN PVOID Reserved1,
    IN PVOID Reserved2,
    IN WORD Architecture,
    OUT PWSTR ReturnPath,
    IN OUT PDWORD ReturnLength)
{
    WCHAR Source[MAX_PATH], StoreInf[MAX_PATH];
    HANDLE Namespace, Lock;
    PWSTR BaseName;
    DWORD Length;
    HRESULT hr;

    hr = CheckStoreRequest(Architecture, ReturnLength);
    if (FAILED(hr))
        return hr;

    Length = GetFullPathNameW(InfPath, ARRAY_SIZE(Source), Source, &BaseName);
    if (Length == 0 || Length >= ARRAY_SIZE(Source) || !BaseName || GetFileAttributesW(Source) == INVALID_FILE_ATTRIBUTES)
        return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);

    if (!AcquirePackageLock(&Namespace, &Lock))
        return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);

    VerifyingThread = GetCurrentThreadId();
    hr = AddLockedDriverPackage(Source, BaseName, Architecture, StoreInf);
    VerifyingThread = 0;
    ReleasePackageLock(Namespace, Lock);
    if (FAILED(hr))
        return hr;

    return ReturnStorePath(StoreInf, ReturnPath, ReturnLength);
}

static HRESULT
DeleteLockedDriverPackage(
    IN PCWSTR InfPath)
{
    WCHAR Source[MAX_PATH], StoreInf[MAX_PATH], Aside[MAX_PATH];
    PUBLISHED_INFS Infs;
    PWSTR Last, BaseName;
    DWORD Length, Error;
    BOOL Published, Deleted = TRUE;

    Length = GetFullPathNameW(InfPath, ARRAY_SIZE(Source), Source, &BaseName);
    if (Length == 0 || Length >= ARRAY_SIZE(Source) || !BaseName)
        return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);

    DeleteStoreLeftovers(Source);
    if (!FindStoreInfOfAnyArchitecture(Source, BaseName, StoreInf))
        return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);

    /* Only the package of the native architecture is published */
    Published = FindStoreInf(StoreInf, NULL, GetNativeArchitecture(), Source);

    Last = wcsrchr(StoreInf, L'\\');
    if (!Last)
        return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);

    *Last = UNICODE_NULL;
    if (!MoveStoreDirectoryAside(StoreInf, Aside))
        return HRESULT_FROM_WIN32(GetLastError());

    ZeroMemory(&Infs, sizeof(Infs));
    if (Published)
    {
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
        Deleted = CombinePath(Source, Aside, Last + 1) && HoldPublishedInfs(Source, &Infs);
    }
    if (!Deleted)
    {
        Error = GetLastError();
        if (!MoveFileW(Aside, StoreInf))
            ERR("Driver package %s is left in %s, restoring it failed with error %lu\n",
                debugstr_w(StoreInf), debugstr_w(Aside), GetLastError());
        return HRESULT_FROM_WIN32(Error);
    }

    /* The deleted files cannot be put back, so the INF stays published and the package can be staged from it again */
    if (!DeleteDirectoryTree(Aside))
    {
        Error = GetLastError();
        ERR("The driver package %s is left partly deleted in %s (%lu)\n", debugstr_w(StoreInf), debugstr_w(Aside), Error);
        ReleasePublishedInfs(&Infs, FALSE);
        return HRESULT_FROM_WIN32(Error);
    }

    if (!ReleasePublishedInfs(&Infs, TRUE))
        return HRESULT_FROM_WIN32(GetLastError());
    return S_OK;
}

HRESULT
WINAPI
DriverStoreDeleteDriverPackageW(
    IN PCWSTR InfPath,
    IN PVOID Reserved1,
    IN PVOID Reserved2)
{
    HANDLE Namespace, Lock;
    HRESULT hr;

    if (!AcquirePackageLock(&Namespace, &Lock))
        return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);

    hr = DeleteLockedDriverPackage(InfPath);
    ReleasePackageLock(Namespace, Lock);
    return hr;
}

static PWSTR
StoreAnsiToUnicode(
    IN PCSTR String)
{
    PWSTR Result;
    INT Length;

    Length = MultiByteToWideChar(CP_ACP, 0, String, -1, NULL, 0);
    if (Length == 0)
        return NULL;

    Result = MyMalloc(Length * sizeof(WCHAR));
    if (Result)
        MultiByteToWideChar(CP_ACP, 0, String, -1, Result, Length);
    return Result;
}

static HRESULT
ReturnStorePathA(
    IN HRESULT hr,
    IN PCWSTR PathW,
    OUT PSTR ReturnPath,
    IN OUT PDWORD ReturnLength)
{
    INT Length;

    if (FAILED(hr))
    {
        if (hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND) ||
            hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND))
        {
            *ReturnPath = ANSI_NULL;
            *ReturnLength = 0;
        }
        return hr;
    }

    Length = WideCharToMultiByte(CP_ACP, 0, PathW, -1, NULL, 0, NULL, NULL);
    if ((DWORD)Length > *ReturnLength)
    {
        *ReturnLength = Length;
        return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
    }

    WideCharToMultiByte(CP_ACP, 0, PathW, -1, ReturnPath, Length, NULL, NULL);
    *ReturnLength = Length;
    return S_OK;
}

HRESULT
WINAPI
DriverStoreFindDriverPackageA(
    IN PCSTR InfPath,
    IN PVOID Reserved1,
    IN PVOID Reserved2,
    IN WORD Architecture,
    IN PVOID Reserved3,
    OUT PSTR ReturnPath,
    IN OUT PDWORD ReturnLength)
{
    WCHAR PathW[MAX_PATH];
    DWORD LengthW = ARRAY_SIZE(PathW);
    PWSTR InfPathW;
    HRESULT hr;

    if (*ReturnLength < MAX_PATH)
        return E_INVALIDARG;

    InfPathW = StoreAnsiToUnicode(InfPath);
    if (!InfPathW)
        return E_OUTOFMEMORY;

    hr = DriverStoreFindDriverPackageW(InfPathW, Reserved1, Reserved2, Architecture, Reserved3, PathW, &LengthW);
    MyFree(InfPathW);
    return ReturnStorePathA(hr, PathW, ReturnPath, ReturnLength);
}

HRESULT
WINAPI
DriverStoreAddDriverPackageA(
    IN PCSTR InfPath,
    IN PVOID Reserved1,
    IN PVOID Reserved2,
    IN WORD Architecture,
    OUT PSTR ReturnPath,
    IN OUT PDWORD ReturnLength)
{
    WCHAR PathW[MAX_PATH];
    DWORD LengthW = ARRAY_SIZE(PathW);
    PWSTR InfPathW;
    HRESULT hr;

    if (*ReturnLength < MAX_PATH)
        return E_INVALIDARG;

    InfPathW = StoreAnsiToUnicode(InfPath);
    if (!InfPathW)
        return E_OUTOFMEMORY;

    hr = DriverStoreAddDriverPackageW(InfPathW, Reserved1, Reserved2, Architecture, PathW, &LengthW);
    MyFree(InfPathW);
    return ReturnStorePathA(hr, PathW, ReturnPath, ReturnLength);
}

HRESULT
WINAPI
DriverStoreDeleteDriverPackageA(
    IN PCSTR InfPath,
    IN PVOID Reserved1,
    IN PVOID Reserved2)
{
    PWSTR InfPathW;
    HRESULT hr;

    InfPathW = StoreAnsiToUnicode(InfPath);
    if (!InfPathW)
        return E_OUTOFMEMORY;

    hr = DriverStoreDeleteDriverPackageW(InfPathW, Reserved1, Reserved2);
    MyFree(InfPathW);
    return hr;
}
