/*
 * PROJECT:     LiberNT Print Spooler DLL API Tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Tests for Upload/InstallFromPackage/DeletePrinterDriverPackage
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include <apitest.h>

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winioctl.h>
#include <wingdi.h>
#include <winreg.h>
#include <winspool.h>
#include <strsafe.h>
#include <drvpkglock.h>

#define ERROR_SECTION_NOT_FOUND (APPLICATION_ERROR_MASK | ERROR_SEVERITY_ERROR | 0x101)

BOOL WINAPI SetupCopyOEMInfW(PCWSTR SourceInfFileName, PCWSTR OEMSourceMediaLocation, DWORD OEMSourceMediaType, DWORD CopyStyle,
                             PWSTR DestinationInfFileName, DWORD DestinationInfFileNameSize, PDWORD RequiredSize,
                             PWSTR *DestinationInfFileNameComponent);
BOOL WINAPI SetupUninstallOEMInfW(PCWSTR InfFileName, DWORD Flags, PVOID Reserved);

#define TEST_DRIVER_NAME L"LiberNT Package Test Printer"
#define NEEDS_DRIVER_NAME L"LiberNT Package Needs Printer"
#define BROKEN_DRIVER_NAME L"LiberNT Package Broken Printer"
#define LOCK_DRIVER_NAME L"LiberNT Package Lock Printer"

#define CROSS_DRIVER_NAME L"LiberNT Package Cross Printer"

#if defined(_M_AMD64)
#define TEST_ENVIRONMENT L"Windows x64"
#define TEST_STORE_ARCHITECTURE L"amd64"
#define OTHER_ENVIRONMENT L"Windows NT x86"
#define OTHER_STORE_ARCHITECTURE L"x86"
#define OTHER_DRIVER_FILE L"TESTX86.DLL"
#elif defined(_M_ARM64)
#define TEST_ENVIRONMENT L"Windows ARM64"
#define TEST_STORE_ARCHITECTURE L"arm64"
#define OTHER_ENVIRONMENT L"Windows NT x86"
#define OTHER_STORE_ARCHITECTURE L"x86"
#define OTHER_DRIVER_FILE L"TESTX86.DLL"
#else
#define TEST_ENVIRONMENT L"Windows NT x86"
#define TEST_STORE_ARCHITECTURE L"x86"
#define OTHER_ENVIRONMENT L"Windows x64"
#define OTHER_STORE_ARCHITECTURE L"amd64"
#define OTHER_DRIVER_FILE L"TESTA64.DLL"
#endif
#define TEST_DRIVERS_KEY L"SYSTEM\\CurrentControlSet\\Control\\Print\\Environments\\" TEST_ENVIRONMENT L"\\Drivers\\Version-3"
#define OTHER_DRIVER_KEY L"SYSTEM\\CurrentControlSet\\Control\\Print\\Environments\\" OTHER_ENVIRONMENT L"\\Drivers\\Version-3\\" CROSS_DRIVER_NAME

#define TEST_MODELS \
    "\"LiberNT Package Test Printer\"=TESTPKG.GPD,LiberNT_Package_Test\r\n" \
    "\"LiberNT Package Needs Printer\"=TESTNEEDS,LiberNT_Package_Needs\r\n" \
    "\"LiberNT Package Broken Printer\"=TESTBROKEN,LiberNT_Package_Broken\r\n"

static const char TestInf[] =
    "[Version]\r\n"
    "Signature=\"$Windows NT$\"\r\n"
    "Class=Printer\r\n"
    "ClassGUID={4D36E979-E325-11CE-BFC1-08002BE10318}\r\n"
    "Provider=LiberNT\r\n"
    "DriverVer=11/06/2026,1.0.0.0\r\n"
    "\r\n"
    "[Manufacturer]\r\n"
    "\"LiberNT\"=Models,NTamd64,NTx86,NTarm64\r\n"
    "\r\n"
    "[Models.NTamd64]\r\n"
    TEST_MODELS
    "[Models.NTx86]\r\n"
    TEST_MODELS
    "[Models.NTarm64]\r\n"
    TEST_MODELS
    "\r\n"
    "[TESTPKG.GPD]\r\n"
    "CopyFiles=@TESTPKG.GPD,TESTPKG_FILES\r\n"
    "DataSection=TESTPKG_DATA\r\n"
    "\r\n"
    "[TESTNEEDS]\r\n"
    "CopyFiles=@TESTPKG.GPD\r\n"
    "DataFile=TESTPKG.GPD\r\n"
    "DataSection=TESTPKG_DATA\r\n"
    "Needs=NEEDS_A\r\n"
    "\r\n"
    "[NEEDS_A]\r\n"
    "Needs=NEEDS_B\r\n"
    "\r\n"
    "[NEEDS_B]\r\n"
    "Needs=NEEDS_A\r\n"
    "CopyFiles=TESTPKG_FILES\r\n"
    "\r\n"
    "[TESTBROKEN]\r\n"
    "CopyFiles=@TESTPKG.GPD,TESTPKG_FILES\r\n"
    "DataSection=TESTPKG_DATA\r\n"
    "Needs=NO_SUCH_SECTION\r\n"
    "\r\n"
    "[TESTPKG_DATA]\r\n"
    "DriverFile=TESTDRV.DLL\r\n"
    "ConfigFile=TESTUI.DLL\r\n"
    "HelpFile=TESTPKG.HLP\r\n"
    "\r\n"
    "[TESTPKG_FILES]\r\n"
    "TESTDRV.DLL\r\n"
    "TESTUI.DLL\r\n"
    "TESTPKG.HLP\r\n"
    "TESTPKG.DAT\r\n"
    "TESTREN.DAT,TESTPKG.DAT\r\n"
    "\r\n"
    "[TESTPKG_OPTIONAL]\r\n"
    "CopyFiles=@TESTOPT.DAT\r\n"
    "\r\n"
    "[DestinationDirs]\r\n"
    "DefaultDestDir=66000\r\n"
    "\r\n"
    "[SourceDisksNames]\r\n"
    "1=\"Disk\",,,\r\n"
    "\r\n"
    "[SourceDisksFiles]\r\n"
    "TESTPKG.GPD=1\r\n"
    "TESTDRV.DLL=1\r\n"
    "TESTUI.DLL=1\r\n"
    "TESTPKG.HLP=1\r\n"
    "TESTPKG.DAT=1\r\n";

static BOOL
WriteTestFile(PCWSTR Dir, PCWSTR Name, const void *Data, DWORD Size)
{
    WCHAR Path[MAX_PATH];
    HANDLE hFile;
    DWORD Written;
    BOOL Ret;

    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\%s", Dir, Name);
    hFile = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    Ret = WriteFile(hFile, Data, Size, &Written, NULL) && Written == Size;
    CloseHandle(hFile);
    return Ret;
}

static BOOL
CreateTestPackage(PWSTR Dir, PWSTR InfPath)
{
    WCHAR System[MAX_PATH], Source[MAX_PATH], Target[MAX_PATH];
    static const char Text[] = "LiberNT package test file\r\n";

    GetTempPathW(MAX_PATH, Dir);
    StringCchCatW(Dir, MAX_PATH, L"lntprnpkg");
    CreateDirectoryW(Dir, NULL);
    StringCchPrintfW(InfPath, MAX_PATH, L"%s\\lntprnpkg.inf", Dir);

    GetSystemDirectoryW(System, ARRAYSIZE(System));
    StringCchPrintfW(Source, ARRAYSIZE(Source), L"%s\\version.dll", System);
    StringCchPrintfW(Target, ARRAYSIZE(Target), L"%s\\TESTDRV.DLL", Dir);
    if (!CopyFileW(Source, Target, FALSE))
        return FALSE;
    StringCchPrintfW(Target, ARRAYSIZE(Target), L"%s\\TESTUI.DLL", Dir);
    if (!CopyFileW(Source, Target, FALSE))
        return FALSE;

    return WriteTestFile(Dir, L"lntprnpkg.inf", TestInf, sizeof(TestInf) - 1) &&
           WriteTestFile(Dir, L"TESTPKG.GPD", Text, sizeof(Text) - 1) &&
           WriteTestFile(Dir, L"TESTPKG.HLP", Text, sizeof(Text) - 1) &&
           WriteTestFile(Dir, L"TESTPKG.DAT", Text, sizeof(Text) - 1);
}

static VOID
DeleteTestPackage(PCWSTR Dir)
{
    static const PCWSTR Names[] = { L"lntprnpkg.inf", L"TESTPKG.GPD", L"TESTDRV.DLL", L"TESTUI.DLL",
                                    L"TESTPKG.HLP", L"TESTPKG.DAT" };
    WCHAR Path[MAX_PATH];
    UINT i;

    for (i = 0; i < ARRAYSIZE(Names); i++)
    {
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\%s", Dir, Names[i]);
        DeleteFileW(Path);
    }
    RemoveDirectoryW(Dir);
}

static BOOL
DriverFileExists(PCWSTR Name)
{
    WCHAR Dir[MAX_PATH], Path[MAX_PATH];
    DWORD Size = sizeof(Dir);

    if (!GetPrinterDriverDirectoryW(NULL, NULL, 1, (PBYTE)Dir, Size, &Size))
        return FALSE;
    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\3\\%s", Dir, Name);
    return GetFileAttributesW(Path) != INVALID_FILE_ATTRIBUTES;
}

static HKEY
OpenDriverKey(PCWSTR DriverName)
{
    WCHAR Key[MAX_PATH];
    HKEY hKey;

    StringCchPrintfW(Key, ARRAYSIZE(Key), L"%s\\%s", TEST_DRIVERS_KEY, DriverName);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, Key, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return NULL;
    return hKey;
}

static BOOL
FilesMatch(PCWSTR First, PCWSTR Second)
{
    char A[256], B[256];
    DWORD ReadA = 0, ReadB = 0;
    HANDLE hA, hB;

    hA = CreateFileW(First, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    hB = CreateFileW(Second, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hA != INVALID_HANDLE_VALUE)
    {
        ReadFile(hA, A, sizeof(A), &ReadA, NULL);
        CloseHandle(hA);
    }
    if (hB != INVALID_HANDLE_VALUE)
    {
        ReadFile(hB, B, sizeof(B), &ReadB, NULL);
        CloseHandle(hB);
    }
    return ReadA != 0 && ReadA == ReadB && memcmp(A, B, ReadA) == 0;
}

static VOID
DeleteTestDriver(VOID)
{
    static const PCWSTR Names[] = { L"TESTDRV.DLL", L"TESTUI.DLL", L"TESTPKG.GPD", L"TESTPKG.HLP", L"TESTPKG.DAT",
                                    L"TESTREN.DAT", L"TESTROLL.DAT", L"TESTROLL.DAT.apd-new", L"TESTROLL.DAT.apd-old" };
    static const PCWSTR Drivers[] = { TEST_DRIVER_NAME, NEEDS_DRIVER_NAME, BROKEN_DRIVER_NAME, LOCK_DRIVER_NAME };
    WCHAR Key[MAX_PATH], Dir[MAX_PATH], Path[MAX_PATH];
    DWORD Size = sizeof(Dir);
    UINT i;

    for (i = 0; i < ARRAYSIZE(Drivers); i++)
    {
        StringCchPrintfW(Key, ARRAYSIZE(Key), L"%s\\%s", TEST_DRIVERS_KEY, Drivers[i]);
        RegDeleteKeyW(HKEY_LOCAL_MACHINE, Key);
    }

    if (!GetPrinterDriverDirectoryW(NULL, NULL, 1, (PBYTE)Dir, Size, &Size))
        return;
    for (i = 0; i < ARRAYSIZE(Names); i++)
    {
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\3\\%s", Dir, Names[i]);
        DeleteFileW(Path);
    }
}

static const char MissingInf[] =
    "[Version]\r\n"
    "Signature=\"$Windows NT$\"\r\n"
    "Class=Printer\r\n"
    "ClassGUID={4D36E979-E325-11CE-BFC1-08002BE10318}\r\n"
    "Provider=LiberNT\r\n"
    "DriverVer=11/06/2026,1.0.0.0\r\n"
    "\r\n"
    "[Manufacturer]\r\n"
    "\"LiberNT\"=Models\r\n"
    "\r\n"
    "[Models]\r\n"
    "\"LiberNT Package Missing Printer\"=TESTMISS,LiberNT_Package_Missing\r\n"
    "\r\n"
    "[TESTMISS]\r\n"
    "CopyFiles=TESTMISS_FILES\r\n"
    "\r\n"
    "[TESTMISS_FILES]\r\n"
    "TESTMISS.DAT\r\n"
    "TESTGONE.DLL\r\n"
    "\r\n"
    "[DestinationDirs]\r\n"
    "DefaultDestDir=66000\r\n"
    "\r\n"
    "[SourceDisksNames]\r\n"
    "1=\"Disk\",,,\r\n"
    "\r\n"
    "[SourceDisksFiles]\r\n"
    "TESTMISS.DAT=1\r\n"
    "TESTGONE.DLL=1\r\n";

static const char NeedsMissingInf[] =
    "[Version]\r\n"
    "Signature=\"$Windows NT$\"\r\n"
    "Class=Printer\r\n"
    "ClassGUID={4D36E979-E325-11CE-BFC1-08002BE10318}\r\n"
    "Provider=LiberNT\r\n"
    "DriverVer=11/06/2026,1.0.0.0\r\n"
    "\r\n"
    "[Manufacturer]\r\n"
    "\"LiberNT\"=Models\r\n"
    "\r\n"
    "[Models]\r\n"
    "\"LiberNT Package Needs Missing Printer\"=TESTNM,LiberNT_Package_Needs_Missing\r\n"
    "\r\n"
    "[TESTNM]\r\n"
    "CopyFiles=TESTNM_FILES\r\n"
    "Needs=TESTNM_MORE\r\n"
    "\r\n"
    "[TESTNM_MORE]\r\n"
    "CopyFiles=TESTNM_MORE_FILES\r\n"
    "Needs=TESTNM\r\n"
    "\r\n"
    "[TESTNM_FILES]\r\n"
    "TESTNM.DAT\r\n"
    "\r\n"
    "[TESTNM_MORE_FILES]\r\n"
    "TESTNMGONE.DLL\r\n"
    "\r\n"
    "[DestinationDirs]\r\n"
    "DefaultDestDir=66000\r\n"
    "\r\n"
    "[SourceDisksNames]\r\n"
    "1=\"Disk\",,,\r\n"
    "\r\n"
    "[SourceDisksFiles]\r\n"
    "TESTNM.DAT=1\r\n"
    "TESTNMGONE.DLL=1\r\n";

static const char UnlistedInf[] =
    "[Version]\r\n"
    "Signature=\"$Windows NT$\"\r\n"
    "Class=Printer\r\n"
    "ClassGUID={4D36E979-E325-11CE-BFC1-08002BE10318}\r\n"
    "Provider=LiberNT\r\n"
    "DriverVer=11/06/2026,1.0.0.0\r\n"
    "\r\n"
    "[Manufacturer]\r\n"
    "\"LiberNT\"=Models\r\n"
    "\r\n"
    "[Models]\r\n"
    "\"LiberNT Package Unlisted Printer\"=TESTUNL,LiberNT_Package_Unlisted\r\n"
    "\r\n"
    "[TESTUNL]\r\n"
    "CopyFiles=TESTUNL_FILES\r\n"
    "\r\n"
    "[TESTUNL_FILES]\r\n"
    "TESTUNL.DAT\r\n"
    "TESTUNLGONE.DLL\r\n"
    "\r\n"
    "[DestinationDirs]\r\n"
    "DefaultDestDir=66000\r\n"
    "\r\n"
    "[SourceDisksNames]\r\n"
    "1=\"Disk\",,,\r\n"
    "\r\n"
    "[SourceDisksFiles]\r\n"
    "TESTUNL.DAT=1\r\n";

static const char EscapeInf[] =
    "[Version]\r\n"
    "Signature=\"$Windows NT$\"\r\n"
    "Class=Printer\r\n"
    "ClassGUID={4D36E979-E325-11CE-BFC1-08002BE10318}\r\n"
    "Provider=LiberNT\r\n"
    "DriverVer=11/06/2026,1.0.0.0\r\n"
    "\r\n"
    "[Manufacturer]\r\n"
    "\"LiberNT\"=Models\r\n"
    "\r\n"
    "[Models]\r\n"
    "\"LiberNT Package Escape Printer\"=TESTESC,LiberNT_Package_Escape\r\n"
    "\r\n"
    "[TESTESC]\r\n"
    "CopyFiles=TESTESC_FILES\r\n"
    "\r\n"
    "[TESTESC_FILES]\r\n"
    "TESTESC.DAT\r\n"
    "..\\lntprnesc.dll\r\n"
    "\r\n"
    "[DestinationDirs]\r\n"
    "DefaultDestDir=66000\r\n"
    "\r\n"
    "[SourceDisksNames]\r\n"
    "1=\"Disk\",,,\r\n"
    "\r\n"
    "[SourceDisksFiles]\r\n"
    "TESTESC.DAT=1\r\n"
    "..\\lntprnesc.dll=1\r\n";

static const char IncludeEscapeInf[] =
    "[Version]\r\n"
    "Signature=\"$Windows NT$\"\r\n"
    "Class=Printer\r\n"
    "ClassGUID={4D36E979-E325-11CE-BFC1-08002BE10318}\r\n"
    "Provider=LiberNT\r\n"
    "DriverVer=11/06/2026,1.0.0.0\r\n"
    "\r\n"
    "[Manufacturer]\r\n"
    "\"LiberNT\"=Models\r\n"
    "\r\n"
    "[Models]\r\n"
    "\"LiberNT Package Include Escape Printer\"=TESTIES,LiberNT_Package_Include_Escape\r\n"
    "\r\n"
    "[TESTIES]\r\n"
    "Include=../lntprnout.inf\r\n"
    "CopyFiles=@TESTIES.DAT\r\n"
    "\r\n"
    "[DestinationDirs]\r\n"
    "DefaultDestDir=66000\r\n"
    "\r\n"
    "[SourceDisksNames]\r\n"
    "1=\"Disk\",,,\r\n"
    "\r\n"
    "[SourceDisksFiles]\r\n"
    "TESTIES.DAT=1\r\n";

static const char SlashEscapeInf[] =
    "[Version]\r\n"
    "Signature=\"$Windows NT$\"\r\n"
    "Class=Printer\r\n"
    "ClassGUID={4D36E979-E325-11CE-BFC1-08002BE10318}\r\n"
    "Provider=LiberNT\r\n"
    "DriverVer=11/06/2026,1.0.0.0\r\n"
    "\r\n"
    "[Manufacturer]\r\n"
    "\"LiberNT\"=Models\r\n"
    "\r\n"
    "[Models]\r\n"
    "\"LiberNT Package Slash Escape Printer\"=TESTSLE,LiberNT_Package_Slash_Escape\r\n"
    "\r\n"
    "[TESTSLE]\r\n"
    "CopyFiles=TESTSLE_FILES\r\n"
    "\r\n"
    "[TESTSLE_FILES]\r\n"
    "TESTSLE.DAT\r\n"
    "../lntprnout.dll\r\n"
    "\r\n"
    "[DestinationDirs]\r\n"
    "DefaultDestDir=66000\r\n"
    "\r\n"
    "[SourceDisksNames]\r\n"
    "1=\"Disk\",,,\r\n"
    "\r\n"
    "[SourceDisksFiles]\r\n"
    "TESTSLE.DAT=1\r\n";

static const char OutsideInf[] =
    "[Version]\r\n"
    "Signature=\"$Windows NT$\"\r\n";

static const char MalformedInf[] =
    "[Version]\r\n"
    "Signature=\"$LiberNT$\"\r\n"
    "Class=Printer\r\n"
    "\r\n"
    "[Manufacturer]\r\n"
    "\"LiberNT\"=Models\r\n";

static VOID
TestRefusedPackage(PCWSTR Name, const char *Inf, DWORD InfSize, PCWSTR Present, PCWSTR Outside, HRESULT Expected)
{
    WCHAR Dir[MAX_PATH], InfName[MAX_PATH], InfPath[MAX_PATH], StoreInf[MAX_PATH], Path[MAX_PATH], Temp[MAX_PATH];
    static const char Text[] = "LiberNT package test file\r\n";
    ULONG Length = ARRAYSIZE(StoreInf);
    WIN32_FIND_DATAW Find;
    HANDLE hFind;
    HRESULT hr;

    GetTempPathW(MAX_PATH, Temp);
    StringCchPrintfW(Dir, ARRAYSIZE(Dir), L"%s%s", Temp, Name);
    CreateDirectoryW(Dir, NULL);
    StringCchPrintfW(InfName, ARRAYSIZE(InfName), L"%s.inf", Name);
    StringCchPrintfW(InfPath, ARRAYSIZE(InfPath), L"%s\\%s", Dir, InfName);

    if (WriteTestFile(Dir, InfName, Inf, InfSize) &&
        WriteTestFile(Dir, Present, Text, sizeof(Text) - 1) &&
        (!Outside || WriteTestFile(Temp, Outside, OutsideInf, sizeof(OutsideInf) - 1)))
    {
        hr = UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_SILENT_UPLOAD, NULL, StoreInf, &Length);
        ok(Expected == S_OK ? FAILED(hr) : hr == Expected, "UploadPrinterDriverPackageW(%S) returned 0x%lx\n", InfName, hr);
        if (hr == S_OK)
            DeletePrinterDriverPackageW(NULL, StoreInf, NULL);

        GetWindowsDirectoryW(Path, ARRAYSIZE(Path));
        StringCchCatW(Path, ARRAYSIZE(Path), L"\\System32\\DriverStore\\FileRepository\\");
        StringCchCatW(Path, ARRAYSIZE(Path), InfName);
        StringCchCatW(Path, ARRAYSIZE(Path), L"_*");
        hFind = FindFirstFileW(Path, &Find);
        ok(hFind == INVALID_HANDLE_VALUE, "%S was staged\n", hFind == INVALID_HANDLE_VALUE ? L"" : Find.cFileName);
        if (hFind != INVALID_HANDLE_VALUE)
            FindClose(hFind);

        if (Outside)
        {
            GetWindowsDirectoryW(Path, ARRAYSIZE(Path));
            StringCchCatW(Path, ARRAYSIZE(Path), L"\\System32\\DriverStore\\FileRepository\\");
            StringCchCatW(Path, ARRAYSIZE(Path), Outside);
            ok(GetFileAttributesW(Path) == INVALID_FILE_ATTRIBUTES, "%S was created outside the package directory\n", Path);
            DeleteFileW(Path);
        }
    }
    else
    {
        skip("Failed to create the package %S (%lu)\n", InfName, GetLastError());
    }

    if (Outside)
    {
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s%s", Temp, Outside);
        DeleteFileW(Path);
    }
    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\%s", Dir, Present);
    DeleteFileW(Path);
    DeleteFileW(InfPath);
    RemoveDirectoryW(Dir);
}

static const char PlainInf[] =
    "[Version]\r\n"
    "Signature=\"$Windows NT$\"\r\n"
    "Class=Printer\r\n"
    "ClassGUID={4D36E979-E325-11CE-BFC1-08002BE10318}\r\n"
    "Provider=LiberNT\r\n"
    "DriverVer=11/06/2026,1.0.0.0\r\n"
    "\r\n"
    "[Manufacturer]\r\n"
    "LiberNT=Models\r\n"
    "\r\n"
    "[Models]\r\n"
    "\"LiberNT Package Plain Printer\"=TESTPLAIN,LiberNT_Package_Plain\r\n"
    "\r\n"
    "[TESTPLAIN]\r\n"
    "CopyFiles=TESTPLAIN_FILES\r\n"
    "DriverFile=TESTPLAIN.DLL\r\n"
    "ConfigFile=TESTPLAIN.DLL\r\n"
    "DataFile=TESTPLAIN.GPD\r\n"
    "\r\n"
    "[TESTPLAIN_FILES]\r\n"
    "TESTPLAIN.DLL\r\n"
    "TESTPLAIN.GPD\r\n"
    "\r\n"
    "[DestinationDirs]\r\n"
    "DefaultDestDir=66000\r\n"
    "\r\n"
    "[SourceDisksNames]\r\n"
    "1=\"Disk\",,,\r\n"
    "\r\n"
    "[SourceDisksFiles]\r\n"
    "TESTPLAIN.DLL=1\r\n";

static const char TwoNeedsInf[] =
    "[Version]\r\n"
    "Signature=\"$Windows NT$\"\r\n"
    "Class=Printer\r\n"
    "ClassGUID={4D36E979-E325-11CE-BFC1-08002BE10318}\r\n"
    "Provider=LiberNT\r\n"
    "DriverVer=11/06/2026,1.0.0.0\r\n"
    "\r\n"
    "[Manufacturer]\r\n"
    "LiberNT=Models\r\n"
    "\r\n"
    "[Models]\r\n"
    "\"LiberNT Package Two Needs Printer\"=TESTTWO,LiberNT_Package_Two_Needs\r\n"
    "\r\n"
    "[TESTTWO]\r\n"
    "CopyFiles=@TESTTWO.DLL\r\n"
    "DriverFile=TESTTWO.DLL\r\n"
    "ConfigFile=TESTTWO.DLL\r\n"
    "DataFile=TESTTWO0.DAT\r\n"
    "Needs=TESTTWO_A\r\n"
    "Needs=TESTTWO_B\r\n"
    "\r\n"
    "[TESTTWO_A]\r\n"
    "CopyFiles=@TESTTWO0.DAT\r\n"
    "\r\n"
    "[TESTTWO_B]\r\n"
    "CopyFiles=@TESTTWO1.DAT\r\n"
    "\r\n"
    "[DestinationDirs]\r\n"
    "DefaultDestDir=66000\r\n"
    "\r\n"
    "[SourceDisksNames]\r\n"
    "1=\"Disk\",,,\r\n"
    "\r\n"
    "[SourceDisksFiles]\r\n"
    "TESTTWO.DLL=1\r\n"
    "TESTTWO0.DAT=1\r\n"
    "TESTTWO1.DAT=1\r\n";

#define BIG_SECTIONS 20
#define BIG_SECTION_FILES 7

static char BigInf[16384];

static DWORD
BuildBigInf(VOID)
{
    char Line[96];
    UINT i, j;

    StringCchCopyA(BigInf, ARRAYSIZE(BigInf),
                   "[Version]\r\n"
                   "Signature=\"$Windows NT$\"\r\n"
                   "Class=Printer\r\n"
                   "ClassGUID={4D36E979-E325-11CE-BFC1-08002BE10318}\r\n"
                   "Provider=LiberNT\r\n"
                   "DriverVer=11/06/2026,1.0.0.0\r\n"
                   "\r\n"
                   "[Manufacturer]\r\n"
                   "LiberNT=Models\r\n"
                   "\r\n"
                   "[Models]\r\n"
                   "\"LiberNT Package Big Printer\"=TESTBIG,LiberNT_Package_Big\r\n"
                   "\r\n"
                   "[TESTBIG]\r\n"
                   "CopyFiles=@TESTBIG.DLL\r\n"
                   "DriverFile=TESTBIG.DLL\r\n"
                   "ConfigFile=TESTBIG.DLL\r\n"
                   "DataFile=TESTBIG000.DAT\r\n"
                   "Needs=TESTBIG_N00");
    for (i = 1; i < BIG_SECTIONS; i++)
    {
        StringCchPrintfA(Line, ARRAYSIZE(Line), ",TESTBIG_N%02u", i);
        StringCchCatA(BigInf, ARRAYSIZE(BigInf), Line);
    }
    StringCchCatA(BigInf, ARRAYSIZE(BigInf), "\r\n");

    for (i = 0; i < BIG_SECTIONS; i++)
    {
        StringCchPrintfA(Line, ARRAYSIZE(Line), "\r\n[TESTBIG_N%02u]\r\nCopyFiles=TESTBIG_F%02u\r\n\r\n[TESTBIG_F%02u]\r\n", i, i, i);
        StringCchCatA(BigInf, ARRAYSIZE(BigInf), Line);
        for (j = 0; j < BIG_SECTION_FILES; j++)
        {
            StringCchPrintfA(Line, ARRAYSIZE(Line), "TESTBIG%03u.DAT\r\n", i * BIG_SECTION_FILES + j);
            StringCchCatA(BigInf, ARRAYSIZE(BigInf), Line);
        }
    }

    StringCchCatA(BigInf, ARRAYSIZE(BigInf),
                  "\r\n"
                  "[DestinationDirs]\r\n"
                  "DefaultDestDir=66000\r\n"
                  "\r\n"
                  "[SourceDisksNames]\r\n"
                  "1=\"Disk\",,,\r\n"
                  "\r\n"
                  "[SourceDisksFiles]\r\n"
                  "TESTBIG.DLL=1\r\n");
    for (i = 0; i < BIG_SECTIONS * BIG_SECTION_FILES; i++)
    {
        StringCchPrintfA(Line, ARRAYSIZE(Line), "TESTBIG%03u.DAT=1\r\n", i);
        StringCchCatA(BigInf, ARRAYSIZE(BigInf), Line);
    }
    return (DWORD)strlen(BigInf);
}

#define INCLUDE_INF(Model, Include) \
    "[Version]\r\n" \
    "Signature=\"$Windows NT$\"\r\n" \
    "Class=Printer\r\n" \
    "ClassGUID={4D36E979-E325-11CE-BFC1-08002BE10318}\r\n" \
    "Provider=LiberNT\r\n" \
    "DriverVer=11/06/2026,1.0.0.0\r\n" \
    "\r\n" \
    "[Manufacturer]\r\n" \
    "LiberNT=Models\r\n" \
    "\r\n" \
    "[Models]\r\n" \
    "\"" Model "\"=TESTINC,LiberNT_Package_Include\r\n" \
    "\r\n" \
    "[TESTINC]\r\n" \
    "Include=" Include "\r\n" \
    "Needs=TESTINC_COMMON\r\n" \
    "\r\n" \
    "[DestinationDirs]\r\n" \
    "DefaultDestDir=66000\r\n" \
    "\r\n" \
    "[SourceDisksNames]\r\n" \
    "1=\"Disk\",,,\r\n" \
    "\r\n" \
    "[SourceDisksFiles]\r\n" \
    "TESTINC.DLL=1\r\n" \
    "TESTINC0.DAT=1\r\n" \
    "TESTINC1.DAT=1\r\n"

#define ABSOLUTE_DRIVER_NAME L"LiberNT Package Absolute Include Printer"

static const char IncludeInf[] = INCLUDE_INF("LiberNT Package Include Printer", "lntprncmn.inf");
static const char SubdirIncludeInf[] = INCLUDE_INF("LiberNT Package Subdir Include Printer", "sub\\lntprncmn.inf");
static const char AbsoluteIncludeInf[] = INCLUDE_INF("LiberNT Package Absolute Include Printer", "\"%S\"");

#define INCLUDED_INF(Files) \
    "[Version]\r\n" \
    "Signature=\"$Windows NT$\"\r\n" \
    "\r\n" \
    "[TESTINC_COMMON]\r\n" \
    "CopyFiles=TESTINC_FILES\r\n" \
    "DriverFile=TESTINC.DLL\r\n" \
    "ConfigFile=TESTINC.DLL\r\n" \
    "DataFile=TESTINC0.DAT\r\n" \
    "\r\n" \
    "[TESTINC_FILES]\r\n" \
    "TESTINC.DLL\r\n" \
    "TESTINC0.DAT\r\n" \
    Files

static const char IncludedInf[] = INCLUDED_INF("TESTINC1.DAT\r\n");
static const char SystemIncludedInf[] = INCLUDED_INF("");

static VOID
TestInstallPackage(PCWSTR Name, PCWSTR DriverName, const char *Inf, DWORD InfSize, PCWSTR DriverFile,
                   PCWSTR FilePattern, UINT FileCount, PCWSTR Dependent, PCWSTR IncludeName)
{
    WCHAR Dir[MAX_PATH], InfName[MAX_PATH], InfPath[MAX_PATH], StoreInf[MAX_PATH], Path[MAX_PATH], File[MAX_PATH];
    WCHAR SystemInfDir[MAX_PATH], IncludeDir[MAX_PATH];
    static const char Text[] = "LiberNT package test file\r\n";
    static WCHAR Value[4096];
    WCHAR DriverDir[MAX_PATH] = L"";
    PWSTR Entry;
    DWORD Size = sizeof(DriverDir);
    ULONG Length = ARRAYSIZE(StoreInf);
    BOOL Created;
    HRESULT hr;
    HKEY hKey;
    UINT i;

    GetTempPathW(MAX_PATH, Dir);
    StringCchCatW(Dir, MAX_PATH, Name);
    CreateDirectoryW(Dir, NULL);
    StringCchPrintfW(InfName, ARRAYSIZE(InfName), L"%s.inf", Name);
    StringCchPrintfW(InfPath, ARRAYSIZE(InfPath), L"%s\\%s", Dir, InfName);

    GetSystemDirectoryW(Path, ARRAYSIZE(Path));
    StringCchCatW(Path, ARRAYSIZE(Path), L"\\version.dll");
    StringCchPrintfW(File, ARRAYSIZE(File), L"%s\\%s", Dir, DriverFile);
    Created = CopyFileW(Path, File, FALSE) && WriteTestFile(Dir, InfName, Inf, InfSize);
    for (i = 0; Created && i < FileCount; i++)
    {
        StringCchPrintfW(File, ARRAYSIZE(File), FilePattern, i);
        Created = WriteTestFile(Dir, File, Text, sizeof(Text) - 1);
    }

    GetWindowsDirectoryW(SystemInfDir, ARRAYSIZE(SystemInfDir));
    StringCchCatW(SystemInfDir, ARRAYSIZE(SystemInfDir), L"\\inf");
    IncludeDir[0] = UNICODE_NULL;
    if (Created && IncludeName && wcschr(IncludeName, L'\\'))
    {
        StringCchPrintfW(IncludeDir, ARRAYSIZE(IncludeDir), L"%s\\%.*s", Dir, (int)(wcschr(IncludeName, L'\\') - IncludeName), IncludeName);
        Created = CreateDirectoryW(IncludeDir, NULL) && WriteTestFile(Dir, IncludeName, IncludedInf, sizeof(IncludedInf) - 1);
    }
    else if (Created && IncludeName)
    {
        Created = WriteTestFile(Dir, IncludeName, IncludedInf, sizeof(IncludedInf) - 1) &&
                  WriteTestFile(SystemInfDir, IncludeName, SystemIncludedInf, sizeof(SystemIncludedInf) - 1);
    }

    if (Created)
    {
        hr = UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_SILENT_UPLOAD, NULL, StoreInf, &Length);
        ok(hr == S_OK, "UploadPrinterDriverPackageW(%S) returned 0x%lx\n", InfName, hr);
        if (hr == S_OK)
        {
            hr = InstallPrinterDriverFromPackageW(NULL, StoreInf, DriverName, NULL, 0);
            ok(hr == S_OK, "InstallPrinterDriverFromPackageW(%S) returned 0x%lx\n", DriverName, hr);
            for (i = 0; i < FileCount; i++)
            {
                StringCchPrintfW(File, ARRAYSIZE(File), FilePattern, i);
                ok(DriverFileExists(File), "%S of %S was not installed\n", File, DriverName);
            }
            hKey = OpenDriverKey(DriverName);
            ok(hKey != NULL, "Driver %S is not registered\n", DriverName);
            if (hKey && Dependent)
            {
                Size = sizeof(Value) - 2 * sizeof(WCHAR);
                ZeroMemory(Value, sizeof(Value));
                ok(RegQueryValueExW(hKey, L"Dependent Files", NULL, NULL, (PBYTE)Value, &Size) == ERROR_SUCCESS,
                   "No Dependent Files of %S\n", DriverName);
                for (Entry = Value; *Entry && _wcsicmp(Entry, Dependent); Entry += wcslen(Entry) + 1);
                ok(*Entry != UNICODE_NULL, "%S is not a dependent file of %S\n", Dependent, DriverName);
            }
            if (hKey)
                RegCloseKey(hKey);

            StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\%s", TEST_DRIVERS_KEY, DriverName);
            RegDeleteKeyW(HKEY_LOCAL_MACHINE, Path);
            hr = DeletePrinterDriverPackageW(NULL, StoreInf, NULL);
            ok(hr == S_OK, "DeletePrinterDriverPackageW(%S) returned 0x%lx\n", StoreInf, hr);
        }
    }
    else
    {
        skip("Failed to create the package %S (%lu)\n", InfName, GetLastError());
    }

    Size = sizeof(DriverDir);
    if (!GetPrinterDriverDirectoryW(NULL, NULL, 1, (PBYTE)DriverDir, Size, &Size))
        DriverDir[0] = UNICODE_NULL;
    for (i = 0; i <= FileCount; i++)
    {
        if (i < FileCount)
            StringCchPrintfW(File, ARRAYSIZE(File), FilePattern, i);
        else
            StringCchCopyW(File, ARRAYSIZE(File), DriverFile);
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\%s", Dir, File);
        DeleteFileW(Path);
        if (DriverDir[0])
        {
            StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\3\\%s", DriverDir, File);
            DeleteFileW(Path);
        }
    }
    if (IncludeName)
    {
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\%s", Dir, IncludeName);
        DeleteFileW(Path);
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\%s", SystemInfDir, IncludeName);
        DeleteFileW(Path);
    }
    if (IncludeDir[0])
        RemoveDirectoryW(IncludeDir);
    DeleteFileW(InfPath);
    RemoveDirectoryW(Dir);
}

/* The INF outside the package has all that the driver needs, so only the refusal of its path stops the installation */
static VOID
TestAbsoluteInclude(VOID)
{
    WCHAR Temp[MAX_PATH], Dir[MAX_PATH], InfPath[MAX_PATH], Outside[MAX_PATH], Path[MAX_PATH], StoreInf[MAX_PATH];
    static const char Text[] = "LiberNT package test file\r\n";
    static char Inf[sizeof(AbsoluteIncludeInf) + MAX_PATH];
    ULONG Length = ARRAYSIZE(StoreInf);
    DWORD Size = sizeof(Path);
    HRESULT hr;
    HKEY hKey;

    GetTempPathW(ARRAYSIZE(Temp), Temp);
    StringCchPrintfW(Dir, ARRAYSIZE(Dir), L"%slntprnabs", Temp);
    StringCchPrintfW(InfPath, ARRAYSIZE(InfPath), L"%s\\lntprnabs.inf", Dir);
    StringCchPrintfW(Outside, ARRAYSIZE(Outside), L"%slntprnabsc.inf", Temp);
    CreateDirectoryW(Dir, NULL);

    GetSystemDirectoryW(Path, ARRAYSIZE(Path));
    StringCchCatW(Path, ARRAYSIZE(Path), L"\\version.dll");
    StringCchPrintfW(StoreInf, ARRAYSIZE(StoreInf), L"%s\\TESTINC.DLL", Dir);
    if (SUCCEEDED(StringCchPrintfA(Inf, ARRAYSIZE(Inf), AbsoluteIncludeInf, Outside)) &&
        CopyFileW(Path, StoreInf, FALSE) &&
        WriteTestFile(Dir, L"lntprnabs.inf", Inf, (DWORD)strlen(Inf)) &&
        WriteTestFile(Dir, L"TESTINC0.DAT", Text, sizeof(Text) - 1) &&
        WriteTestFile(Temp, L"lntprnabsc.inf", SystemIncludedInf, sizeof(SystemIncludedInf) - 1))
    {
        hr = InstallPrinterDriverFromPackageW(NULL, InfPath, ABSOLUTE_DRIVER_NAME, NULL, 0);
        ok(hr == HRESULT_FROM_WIN32(ERROR_BAD_PATHNAME), "InstallPrinterDriverFromPackageW returned 0x%lx for an INF that includes %S\n", hr, Outside);
        hKey = OpenDriverKey(ABSOLUTE_DRIVER_NAME);
        ok(hKey == NULL, "Driver %S is registered\n", ABSOLUTE_DRIVER_NAME);
        if (hKey)
            RegCloseKey(hKey);

        hr = UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_SILENT_UPLOAD, NULL, StoreInf, &Length);
        ok(FAILED(hr), "UploadPrinterDriverPackageW returned 0x%lx for an INF that includes %S\n", hr, Outside);
        if (hr == S_OK)
            DeletePrinterDriverPackageW(NULL, StoreInf, NULL);
    }
    else
    {
        skip("Failed to create the package lntprnabs.inf (%lu)\n", GetLastError());
    }

    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\%s", TEST_DRIVERS_KEY, ABSOLUTE_DRIVER_NAME);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, Path);
    if (GetPrinterDriverDirectoryW(NULL, NULL, 1, (PBYTE)Path, Size, &Size))
    {
        StringCchCopyW(StoreInf, ARRAYSIZE(StoreInf), Path);
        StringCchCatW(StoreInf, ARRAYSIZE(StoreInf), L"\\3\\TESTINC.DLL");
        DeleteFileW(StoreInf);
        StringCchCatW(Path, ARRAYSIZE(Path), L"\\3\\TESTINC0.DAT");
        DeleteFileW(Path);
    }
    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\TESTINC.DLL", Dir);
    DeleteFileW(Path);
    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\TESTINC0.DAT", Dir);
    DeleteFileW(Path);
    DeleteFileW(Outside);
    DeleteFileW(InfPath);
    RemoveDirectoryW(Dir);
}

#define CROSS_INSTALL(Section, File) \
    "[" Section "]\r\n" \
    "CopyFiles=@" File ",@TESTCROSS.GPD\r\n" \
    "DriverFile=" File "\r\n" \
    "ConfigFile=" File "\r\n" \
    "DataFile=TESTCROSS.GPD\r\n" \
    "\r\n"

static const char CrossInf[] =
    "[Version]\r\n"
    "Signature=\"$Windows NT$\"\r\n"
    "Class=Printer\r\n"
    "ClassGUID={4D36E979-E325-11CE-BFC1-08002BE10318}\r\n"
    "Provider=LiberNT\r\n"
    "DriverVer=11/06/2026,1.0.0.0\r\n"
    "\r\n"
    "[Manufacturer]\r\n"
    "\"LiberNT\"=Models,NTamd64,NTx86,NTarm64\r\n"
    "\r\n"
    "[Models.NTamd64]\r\n"
    "\"LiberNT Package Cross Printer\"=TESTCROSS_A64,LiberNT_Package_Cross\r\n"
    "[Models.NTx86]\r\n"
    "\"LiberNT Package Cross Printer\"=TESTCROSS_X86,LiberNT_Package_Cross\r\n"
    "[Models.NTarm64]\r\n"
    "\"LiberNT Package Cross Printer\"=TESTCROSS_ARM,LiberNT_Package_Cross\r\n"
    "\r\n"
    CROSS_INSTALL("TESTCROSS_A64", "TESTA64.DLL")
    CROSS_INSTALL("TESTCROSS_X86", "TESTX86.DLL")
    CROSS_INSTALL("TESTCROSS_ARM", "TESTARM.DLL")
    "[DestinationDirs]\r\n"
    "DefaultDestDir=66000\r\n"
    "\r\n"
    "[SourceDisksNames]\r\n"
    "1=\"Disk\",,,\r\n"
    "\r\n"
    "[SourceDisksFiles]\r\n"
    "TESTCROSS.GPD=1\r\n"
    "\r\n"
    "[SourceDisksFiles.amd64]\r\n"
    "TESTA64.DLL=1,bin\r\n"
    "\r\n"
    "[SourceDisksFiles.x86]\r\n"
    "TESTX86.DLL=1,bin\r\n"
    "\r\n"
    "[SourceDisksFiles.arm64]\r\n"
    "TESTARM.DLL=1,bin\r\n";

static VOID
TestOtherEnvironment(VOID)
{
    WCHAR Dir[MAX_PATH], InfPath[MAX_PATH], StoreInf[MAX_PATH], Path[MAX_PATH], Value[MAX_PATH];
    static const PCWSTR Names[] = { L"lntprncross.inf", OTHER_DRIVER_FILE, L"TESTCROSS.GPD" };
    static const char Text[] = "LiberNT package test file\r\n";
    WCHAR DriverDir[MAX_PATH] = L"";
    ULONG Length = ARRAYSIZE(StoreInf);
    DWORD Size;
    HRESULT hr;
    HKEY hKey;
    UINT i;

    GetTempPathW(MAX_PATH, Dir);
    StringCchCatW(Dir, MAX_PATH, L"lntprncross");
    CreateDirectoryW(Dir, NULL);
    StringCchPrintfW(InfPath, ARRAYSIZE(InfPath), L"%s\\lntprncross.inf", Dir);
    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\bin", Dir);
    CreateDirectoryW(Path, NULL);

    if (WriteTestFile(Dir, L"lntprncross.inf", CrossInf, sizeof(CrossInf) - 1) &&
        WriteTestFile(Dir, L"bin\\" OTHER_DRIVER_FILE, Text, sizeof(Text) - 1) &&
        WriteTestFile(Dir, L"TESTCROSS.GPD", Text, sizeof(Text) - 1))
    {
        hr = UploadPrinterDriverPackageW(NULL, InfPath, OTHER_ENVIRONMENT, UPDP_SILENT_UPLOAD, NULL, StoreInf, &Length);
        ok(hr == S_OK, "UploadPrinterDriverPackageW(%S) returned 0x%lx\n", OTHER_ENVIRONMENT, hr);
        if (hr == S_OK)
        {
            ok(wcsstr(StoreInf, L"\\lntprncross.inf_" OTHER_STORE_ARCHITECTURE L"_") != NULL,
               "%S is not a package of %S\n", StoreInf, OTHER_ENVIRONMENT);

            hr = InstallPrinterDriverFromPackageW(NULL, StoreInf, CROSS_DRIVER_NAME, OTHER_ENVIRONMENT, 0);
            ok(hr == S_OK, "InstallPrinterDriverFromPackageW(%S) returned 0x%lx\n", OTHER_ENVIRONMENT, hr);

            hKey = OpenDriverKey(CROSS_DRIVER_NAME);
            ok(hKey == NULL, "Driver %S is registered for %S\n", CROSS_DRIVER_NAME, TEST_ENVIRONMENT);
            if (hKey)
                RegCloseKey(hKey);

            hKey = NULL;
            ok(RegOpenKeyExW(HKEY_LOCAL_MACHINE, OTHER_DRIVER_KEY, 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS,
               "Driver %S is not registered for %S\n", CROSS_DRIVER_NAME, OTHER_ENVIRONMENT);
            if (hKey)
            {
                Size = sizeof(Value);
                ok(RegQueryValueExW(hKey, L"Driver", NULL, NULL, (PBYTE)Value, &Size) == ERROR_SUCCESS &&
                   !_wcsicmp(Value, OTHER_DRIVER_FILE), "Driver is %S\n", Value);
                Size = sizeof(Value);
                ok(RegQueryValueExW(hKey, L"InfPath", NULL, NULL, (PBYTE)Value, &Size) == ERROR_SUCCESS &&
                   !_wcsicmp(Value, StoreInf), "InfPath is %S\n", Value);
                RegCloseKey(hKey);

                hr = DeletePrinterDriverPackageW(NULL, StoreInf, OTHER_ENVIRONMENT);
                ok(hr == HRESULT_FROM_WIN32(ERROR_PRINTER_DRIVER_PACKAGE_IN_USE),
                   "DeletePrinterDriverPackageW(%S) returned 0x%lx\n", OTHER_ENVIRONMENT, hr);
            }

            hr = DeletePrinterDriverPackageW(NULL, StoreInf, TEST_ENVIRONMENT);
            ok(FAILED(hr), "DeletePrinterDriverPackageW(%S) returned 0x%lx for a package of %S\n",
               TEST_ENVIRONMENT, hr, OTHER_ENVIRONMENT);
            ok(GetFileAttributesW(StoreInf) != INVALID_FILE_ATTRIBUTES, "%S was deleted\n", StoreInf);

            RegDeleteKeyW(HKEY_LOCAL_MACHINE, OTHER_DRIVER_KEY);
            RegDeleteKeyW(HKEY_LOCAL_MACHINE, TEST_DRIVERS_KEY L"\\" CROSS_DRIVER_NAME);
            hr = DeletePrinterDriverPackageW(NULL, StoreInf, OTHER_ENVIRONMENT);
            ok(hr == S_OK, "DeletePrinterDriverPackageW(%S) returned 0x%lx\n", OTHER_ENVIRONMENT, hr);
        }
    }
    else
    {
        skip("Failed to create the package for %S (%lu)\n", OTHER_ENVIRONMENT, GetLastError());
    }

    Size = sizeof(DriverDir);
    if (!GetPrinterDriverDirectoryW(NULL, (PWSTR)OTHER_ENVIRONMENT, 1, (PBYTE)DriverDir, Size, &Size))
        DriverDir[0] = UNICODE_NULL;
    for (i = 0; i < ARRAYSIZE(Names); i++)
    {
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\%s", Dir, Names[i]);
        DeleteFileW(Path);
        if (DriverDir[0])
        {
            StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\3\\%s", DriverDir, Names[i]);
            DeleteFileW(Path);
        }
    }
    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\bin\\%s", Dir, OTHER_DRIVER_FILE);
    DeleteFileW(Path);
    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\bin", Dir);
    RemoveDirectoryW(Path);
    RemoveDirectoryW(Dir);
}

static const char JunctionInf[] =
    "[Version]\r\n"
    "Signature=\"$Windows NT$\"\r\n"
    "Class=Printer\r\n"
    "ClassGUID={4D36E979-E325-11CE-BFC1-08002BE10318}\r\n"
    "Provider=LiberNT\r\n"
    "DriverVer=11/06/2026,1.0.0.0\r\n"
    "\r\n"
    "[Manufacturer]\r\n"
    "LiberNT=Models\r\n"
    "\r\n"
    "[Models]\r\n"
    "\"LiberNT Package Junction Printer\"=TESTJNC,LiberNT_Package_Junction\r\n"
    "\r\n"
    "[TESTJNC]\r\n"
    "CopyFiles=TESTJNC_FILES\r\n"
    "DriverFile=TESTJNC.DLL\r\n"
    "ConfigFile=TESTJNC.DLL\r\n"
    "DataFile=TESTJNC.GPD\r\n"
    "\r\n"
    "[TESTJNC_FILES]\r\n"
    "TESTJNC.DLL\r\n"
    "TESTJNC.GPD\r\n"
    "\r\n"
    "[DestinationDirs]\r\n"
    "DefaultDestDir=66000\r\n"
    "\r\n"
    "[SourceDisksNames]\r\n"
    "1=\"Disk\",,,\r\n"
    "2=\"Disk\",,,\\link\r\n"
    "\r\n"
    "[SourceDisksFiles]\r\n"
    "TESTJNC.GPD=1\r\n"
    "TESTJNC.DLL=2\r\n";

typedef struct _TEST_MOUNT_POINT
{
    ULONG ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    USHORT SubstituteNameOffset;
    USHORT SubstituteNameLength;
    USHORT PrintNameOffset;
    USHORT PrintNameLength;
    WCHAR PathBuffer[MAX_PATH + 8];
} TEST_MOUNT_POINT;

static BOOL
CreateTestJunction(PCWSTR Link, PCWSTR Target)
{
    TEST_MOUNT_POINT Buffer;
    DWORD Length, Returned, Error;
    HANDLE hLink;

    ZeroMemory(&Buffer, sizeof(Buffer));
    if (FAILED(StringCchPrintfW(Buffer.PathBuffer, MAX_PATH + 4, L"\\??\\%s", Target)) || !CreateDirectoryW(Link, NULL))
        return FALSE;

    /* The substitute name is followed by its terminator and by an empty print name */
    Length = (DWORD)wcslen(Buffer.PathBuffer) * sizeof(WCHAR);
    Buffer.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    Buffer.SubstituteNameLength = (USHORT)Length;
    Buffer.PrintNameOffset = (USHORT)(Length + sizeof(WCHAR));
    Buffer.ReparseDataLength = (USHORT)(4 * sizeof(USHORT) + Length + 2 * sizeof(WCHAR));

    hLink = CreateFileW(Link, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (hLink != INVALID_HANDLE_VALUE &&
        DeviceIoControl(hLink, FSCTL_SET_REPARSE_POINT, &Buffer, FIELD_OFFSET(TEST_MOUNT_POINT, SubstituteNameOffset) + Buffer.ReparseDataLength,
                        NULL, 0, &Returned, NULL))
    {
        CloseHandle(hLink);
        return TRUE;
    }

    Error = GetLastError();
    if (hLink != INVALID_HANDLE_VALUE)
        CloseHandle(hLink);
    RemoveDirectoryW(Link);
    SetLastError(Error);
    return FALSE;
}

static VOID
TestLinkedInf(PCWSTR InfPath, PCSTR What)
{
    static const PCWSTR Names[] = { L"TESTPLAIN.DLL", L"TESTPLAIN.GPD" };
    WCHAR StoreInf[MAX_PATH], Dir[MAX_PATH], Path[MAX_PATH];
    ULONG Length = ARRAYSIZE(StoreInf);
    DWORD Size = sizeof(Dir);
    HRESULT hr;
    HKEY hKey;
    UINT i;

    hr = UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_SILENT_UPLOAD, NULL, StoreInf, &Length);
    ok(FAILED(hr), "UploadPrinterDriverPackageW returned 0x%lx for %s\n", hr, What);
    if (hr == S_OK)
        DeletePrinterDriverPackageW(NULL, StoreInf, NULL);

    hr = InstallPrinterDriverFromPackageW(NULL, InfPath, L"LiberNT Package Plain Printer", NULL, 0);
    ok(FAILED(hr), "InstallPrinterDriverFromPackageW returned 0x%lx for %s\n", hr, What);
    hKey = OpenDriverKey(L"LiberNT Package Plain Printer");
    ok(hKey == NULL, "A driver was registered from %s\n", What);
    if (hKey)
        RegCloseKey(hKey);

    RegDeleteKeyW(HKEY_LOCAL_MACHINE, TEST_DRIVERS_KEY L"\\LiberNT Package Plain Printer");
    if (GetPrinterDriverDirectoryW(NULL, NULL, 1, (PBYTE)Dir, Size, &Size))
    {
        for (i = 0; i < ARRAYSIZE(Names); i++)
        {
            StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\3\\%s", Dir, Names[i]);
            DeleteFileW(Path);
        }
    }
}

/* The INF takes TESTJNC.DLL from a directory of the package that is a junction to a directory outside of it */
static VOID
TestJunctionPackage(VOID)
{
    static const char Text[] = "LiberNT package test file\r\n";
    WCHAR Dir[MAX_PATH], Outside[MAX_PATH], Link[MAX_PATH], InfPath[MAX_PATH], StoreInf[MAX_PATH], Path[MAX_PATH];
    ULONG Length = ARRAYSIZE(StoreInf);
    HRESULT hr;
    HKEY hKey;

    GetTempPathW(MAX_PATH, Dir);
    StringCchCopyW(Outside, ARRAYSIZE(Outside), Dir);
    StringCchCatW(Dir, ARRAYSIZE(Dir), L"lntprnjnc");
    StringCchCatW(Outside, ARRAYSIZE(Outside), L"lntprnjnco");
    StringCchPrintfW(Link, ARRAYSIZE(Link), L"%s\\link", Dir);
    StringCchPrintfW(InfPath, ARRAYSIZE(InfPath), L"%s\\lntprnjnc.inf", Dir);
    CreateDirectoryW(Dir, NULL);
    CreateDirectoryW(Outside, NULL);

    if (!WriteTestFile(Dir, L"lntprnjnc.inf", JunctionInf, sizeof(JunctionInf) - 1) ||
        !WriteTestFile(Dir, L"TESTJNC.GPD", Text, sizeof(Text) - 1) ||
        !WriteTestFile(Outside, L"TESTJNC.DLL", Text, sizeof(Text) - 1))
    {
        skip("Failed to create the package lntprnjnc.inf (%lu)\n", GetLastError());
    }
    else if (!CreateTestJunction(Link, Outside))
    {
        skip("The file system does not take a junction (%lu)\n", GetLastError());
    }
    else
    {
        hr = UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_SILENT_UPLOAD, NULL, StoreInf, &Length);
        ok(FAILED(hr), "UploadPrinterDriverPackageW returned 0x%lx for a file behind a junction\n", hr);
        if (hr == S_OK)
            DeletePrinterDriverPackageW(NULL, StoreInf, NULL);

        hr = InstallPrinterDriverFromPackageW(NULL, InfPath, L"LiberNT Package Junction Printer", NULL, 0);
        ok(FAILED(hr), "InstallPrinterDriverFromPackageW returned 0x%lx for a file behind a junction\n", hr);
        hKey = OpenDriverKey(L"LiberNT Package Junction Printer");
        ok(hKey == NULL, "A driver was registered with a file from outside the package\n");
        if (hKey)
            RegCloseKey(hKey);
        ok(!DriverFileExists(L"TESTJNC.DLL"), "TESTJNC.DLL was installed from outside the package\n");

        RegDeleteKeyW(HKEY_LOCAL_MACHINE, TEST_DRIVERS_KEY L"\\LiberNT Package Junction Printer");
        Length = sizeof(Path);
        if (GetPrinterDriverDirectoryW(NULL, NULL, 1, (PBYTE)Path, Length, &Length))
        {
            StringCchCatW(Path, ARRAYSIZE(Path), L"\\3\\TESTJNC.DLL");
            DeleteFileW(Path);
            *wcsrchr(Path, L'.') = UNICODE_NULL;
            StringCchCatW(Path, ARRAYSIZE(Path), L".GPD");
            DeleteFileW(Path);
        }
        RemoveDirectoryW(Link);
    }

    /* A whole package whose directory is reached through a junction, and whose INF is reached through a link */
    if (!WriteTestFile(Outside, L"lntprnroot.inf", PlainInf, sizeof(PlainInf) - 1) ||
        !WriteTestFile(Outside, L"TESTPLAIN.DLL", Text, sizeof(Text) - 1) ||
        !WriteTestFile(Outside, L"TESTPLAIN.GPD", Text, sizeof(Text) - 1))
    {
        skip("Failed to create the package lntprnroot.inf (%lu)\n", GetLastError());
    }
    else
    {
        StringCchPrintfW(Link, ARRAYSIZE(Link), L"%sr", Outside);
        if (CreateTestJunction(Link, Outside))
        {
            StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\lntprnroot.inf", Link);
            TestLinkedInf(Path, "a package directory that is a junction");
            RemoveDirectoryW(Link);
        }
        else
        {
            skip("The file system does not take a junction (%lu)\n", GetLastError());
        }

        StringCchPrintfW(Link, ARRAYSIZE(Link), L"%s\\lntprnlink.inf", Outside);
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\lntprnroot.inf", Outside);
        if (CreateSymbolicLinkW(Link, Path, 0))
        {
            TestLinkedInf(Link, "an INF that is a link");
            DeleteFileW(Link);
        }
        else
        {
            skip("The file system does not take a link (%lu)\n", GetLastError());
        }
    }

    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\lntprnroot.inf", Outside);
    DeleteFileW(Path);
    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\TESTPLAIN.DLL", Outside);
    DeleteFileW(Path);
    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\TESTPLAIN.GPD", Outside);
    DeleteFileW(Path);
    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\TESTJNC.DLL", Outside);
    DeleteFileW(Path);
    RemoveDirectoryW(Outside);
    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\TESTJNC.GPD", Dir);
    DeleteFileW(Path);
    DeleteFileW(InfPath);
    RemoveDirectoryW(Dir);
}

/* Only <name>.inf in FileRepository\<name>.inf_<architecture>_<hash> is a staged package; any other INF is a package source */
static VOID
TestMisplacedPackage(PCWSTR Parent, PCWSTR Directory, PCWSTR InfName)
{
    static const PCWSTR Names[] = { L"TESTPLAIN.DLL", L"TESTPLAIN.GPD" };
    static const char Text[] = "LiberNT package test file\r\n";
    WCHAR Root[MAX_PATH], Dir[MAX_PATH], InfPath[MAX_PATH], StoreInf[MAX_PATH], Path[MAX_PATH];
    ULONG Length = ARRAYSIZE(StoreInf);
    HRESULT hr;
    PWSTR Last;
    UINT i;

    GetWindowsDirectoryW(Root, ARRAYSIZE(Root));
    StringCchCatW(Root, ARRAYSIZE(Root), L"\\System32\\DriverStore\\");
    StringCchCatW(Root, ARRAYSIZE(Root), Parent);
    CreateDirectoryW(Root, NULL);
    StringCchPrintfW(Dir, ARRAYSIZE(Dir), L"%s\\%s", Root, Directory);
    CreateDirectoryW(Dir, NULL);
    StringCchPrintfW(InfPath, ARRAYSIZE(InfPath), L"%s\\%s", Dir, InfName);

    if (WriteTestFile(Dir, InfName, PlainInf, sizeof(PlainInf) - 1) &&
        WriteTestFile(Dir, Names[0], Text, sizeof(Text) - 1) &&
        WriteTestFile(Dir, Names[1], Text, sizeof(Text) - 1))
    {
        hr = UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_SILENT_UPLOAD, NULL, StoreInf, &Length);
        ok(hr == S_OK, "UploadPrinterDriverPackageW(%S) returned 0x%lx\n", InfPath, hr);
        if (hr == S_OK)
        {
            StringCchPrintfW(Path, ARRAYSIZE(Path), L"\\FileRepository\\%s_" TEST_STORE_ARCHITECTURE L"_", InfName);
            ok(wcsstr(StoreInf, Path) != NULL && _wcsicmp(StoreInf, InfPath) != 0, "%S was taken for the staged package %S\n", InfPath, StoreInf);

            StringCchCopyW(Path, ARRAYSIZE(Path), StoreInf);
            Last = wcsrchr(Path, L'\\');
            if (Last)
            {
                StringCchCopyW(Last + 1, ARRAYSIZE(Path) - (Last + 1 - Path), Names[0]);
                ok(GetFileAttributesW(Path) != INVALID_FILE_ATTRIBUTES, "%S was not staged from %S\n", Path, Dir);
            }

            hr = DeletePrinterDriverPackageW(NULL, StoreInf, NULL);
            ok(hr == S_OK, "DeletePrinterDriverPackageW(%S) returned 0x%lx\n", StoreInf, hr);
        }
    }
    else
    {
        skip("Failed to create the package %S (%lu)\n", InfPath, GetLastError());
    }

    for (i = 0; i < ARRAYSIZE(Names); i++)
    {
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\%s", Dir, Names[i]);
        DeleteFileW(Path);
    }
    DeleteFileW(InfPath);
    RemoveDirectoryW(Dir);
    if (wcscmp(Parent, L"FileRepository") != 0)
        RemoveDirectoryW(Root);
}

static BOOL
FindPublishedInf(PCWSTR InfPath, PWSTR Published)
{
    WCHAR InfDir[MAX_PATH], Pattern[MAX_PATH];
    WIN32_FIND_DATAW Find;
    HANDLE hFind;
    BOOL Found = FALSE;

    GetWindowsDirectoryW(InfDir, ARRAYSIZE(InfDir));
    StringCchCatW(InfDir, ARRAYSIZE(InfDir), L"\\inf");
    StringCchPrintfW(Pattern, ARRAYSIZE(Pattern), L"%s\\oem*.inf", InfDir);
    hFind = FindFirstFileW(Pattern, &Find);
    if (hFind == INVALID_HANDLE_VALUE)
        return FALSE;
    do
    {
        StringCchPrintfW(Published, MAX_PATH, L"%s\\%s", InfDir, Find.cFileName);
        Found = FilesMatch(Published, InfPath);
    } while (!Found && FindNextFileW(hFind, &Find));
    FindClose(hFind);
    return Found;
}

/* The package of the test environment and the one of the other environment are staged from the same INF */
static VOID
TestSharedInf(PCWSTR InfPath, PCWSTR StoreInf)
{
    WCHAR Published[MAX_PATH], Other[MAX_PATH];
    ULONG Length = ARRAYSIZE(Other);
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HRESULT hr;
    UINT i;

    /* A published INF that is open without delete sharing cannot be deleted */
    if (FindPublishedInf(InfPath, Published))
        hFile = CreateFileW(Published, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    ok(hFile != INVALID_HANDLE_VALUE, "%S is not published or cannot be opened (%lu)\n", InfPath, GetLastError());
    if (hFile != INVALID_HANDLE_VALUE)
    {
        hr = DeletePrinterDriverPackageW(NULL, StoreInf, NULL);
        ok(FAILED(hr), "DeletePrinterDriverPackageW returned 0x%lx while the published INF could not be deleted\n", hr);
        ok(GetFileAttributesW(StoreInf) != INVALID_FILE_ATTRIBUTES, "%S was deleted and %S was not\n", StoreInf, Published);
        CloseHandle(hFile);
        ok(GetFileAttributesW(Published) != INVALID_FILE_ATTRIBUTES, "%S was deleted\n", Published);
    }

    hr = UploadPrinterDriverPackageW(NULL, InfPath, OTHER_ENVIRONMENT, UPDP_SILENT_UPLOAD, NULL, Other, &Length);
    ok(hr == S_OK, "UploadPrinterDriverPackageW(%S) returned 0x%lx\n", OTHER_ENVIRONMENT, hr);
    if (hr != S_OK)
        return;
    ok(wcsstr(Other, L"\\lntprnpkg.inf_" OTHER_STORE_ARCHITECTURE L"_") != NULL, "%S is not a package of %S\n", Other, OTHER_ENVIRONMENT);

    hr = DeletePrinterDriverPackageW(NULL, Other, OTHER_ENVIRONMENT);
    ok(hr == S_OK, "DeletePrinterDriverPackageW(%S) returned 0x%lx\n", OTHER_ENVIRONMENT, hr);
    ok(GetFileAttributesW(Other) == INVALID_FILE_ATTRIBUTES, "%S still exists\n", Other);
    ok(GetFileAttributesW(StoreInf) != INVALID_FILE_ATTRIBUTES, "%S was deleted with the package of %S\n", StoreInf, OTHER_ENVIRONMENT);
    ok(FindPublishedInf(InfPath, Published), "The published INF was deleted with the package of %S\n", OTHER_ENVIRONMENT);

    hr = InstallPrinterDriverFromPackageW(NULL, StoreInf, NEEDS_DRIVER_NAME, NULL, 0);
    ok(hr == S_OK, "InstallPrinterDriverFromPackageW returned 0x%lx\n", hr);
    DeleteTestDriver();

    for (i = 0; i < 2; i++)
    {
        PCWSTR Source = i ? Published : StoreInf;

        Length = ARRAYSIZE(Other);
        hr = UploadPrinterDriverPackageW(NULL, Source, OTHER_ENVIRONMENT, UPDP_SILENT_UPLOAD, NULL, Other, &Length);
        ok(hr == S_OK, "UploadPrinterDriverPackageW(%S, %S) returned 0x%lx\n", Source, OTHER_ENVIRONMENT, hr);
        if (hr != S_OK)
            continue;
        ok(wcsstr(Other, L"\\lntprnpkg.inf_" OTHER_STORE_ARCHITECTURE L"_") != NULL, "%S is not a package of %S\n", Other, OTHER_ENVIRONMENT);
        ok(GetFileAttributesW(Other) != INVALID_FILE_ATTRIBUTES, "%S does not exist\n", Other);
        hr = DeletePrinterDriverPackageW(NULL, Other, OTHER_ENVIRONMENT);
        ok(hr == S_OK, "DeletePrinterDriverPackageW(%S) returned 0x%lx\n", Other, hr);
    }
}

typedef struct _LOCK_TEST
{
    DRIVER_INFO_8W Info;
    PCWSTR UploadInf;
    DWORD Error;
} LOCK_TEST, *PLOCK_TEST;

static DWORD WINAPI
LockTestThread(PVOID Parameter)
{
    PLOCK_TEST Test = Parameter;
    WCHAR StoreInf[MAX_PATH];
    ULONG Length = ARRAYSIZE(StoreInf);

    if (Test->UploadInf)
        Test->Error = UploadPrinterDriverPackageW(NULL, Test->UploadInf, NULL, UPDP_CHECK_DRIVERSTORE, NULL, StoreInf, &Length);
    else if (AddPrinterDriverExW(NULL, 8, (PBYTE)&Test->Info, APD_COPY_ALL_FILES | APD_COPY_FROM_DIRECTORY))
        Test->Error = ERROR_SUCCESS;
    else
        Test->Error = GetLastError();
    return 0;
}

static VOID
RunWhileLocked(PLOCK_TEST Test, PCSTR What)
{
    HANDLE Namespace, Lock, hThread;
    HKEY hKey;

    if (!AcquirePackageLock(&Namespace, &Lock))
    {
        skip("Cannot take the package lock (%lu)\n", GetLastError());
        return;
    }

    Test->Error = 0xdeadbeef;
    hThread = CreateThread(NULL, 0, LockTestThread, Test, 0, NULL);
    ok(hThread != NULL, "CreateThread failed with %lu\n", GetLastError());
    if (hThread)
    {
        ok(WaitForSingleObject(hThread, 2000) == WAIT_TIMEOUT, "%s did not wait for the package lock\n", What);
        hKey = OpenDriverKey(LOCK_DRIVER_NAME);
        ok(hKey == NULL || Test->UploadInf, "%s registered the driver while the package lock was held\n", What);
        if (hKey)
            RegCloseKey(hKey);
    }

    ReleasePackageLock(Namespace, Lock);
    if (hThread)
    {
        ok(WaitForSingleObject(hThread, 60000) == WAIT_OBJECT_0, "%s did not finish\n", What);
        CloseHandle(hThread);
    }
}

typedef struct _OEM_INF_TEST
{
    PCWSTR InfPath;
    WCHAR Published[MAX_PATH];
    PWSTR Component;
    BOOL Uninstall;
    BOOL Result;
    DWORD Error;
} OEM_INF_TEST, *POEM_INF_TEST;

static DWORD WINAPI
OemInfThread(PVOID Parameter)
{
    POEM_INF_TEST Test = Parameter;

    if (Test->Uninstall)
        Test->Result = SetupUninstallOEMInfW(Test->Component, 0, NULL);
    else
        Test->Result = SetupCopyOEMInfW(Test->InfPath, NULL, 0, 0, Test->Published, ARRAYSIZE(Test->Published), NULL, &Test->Component);
    Test->Error = GetLastError();
    return 0;
}

/* The Setup API stages and removes a package under the lock that the package functions of the spooler hold */
static VOID
TestSetupLock(VOID)
{
    static const PCWSTR Names[] = { L"lntprnoem.inf", L"TESTPLAIN.DLL", L"TESTPLAIN.GPD" };
    static const char Text[] = "LiberNT package test file\r\n";
    WCHAR Dir[MAX_PATH], InfPath[MAX_PATH], Pattern[MAX_PATH], Path[MAX_PATH];
    static OEM_INF_TEST Test;
    HANDLE Namespace, Lock, hThread, hFind;
    WIN32_FIND_DATAW Find;
    BOOL Published = FALSE;
    UINT i;

    GetTempPathW(MAX_PATH, Dir);
    StringCchCatW(Dir, MAX_PATH, L"lntprnoem");
    CreateDirectoryW(Dir, NULL);
    StringCchPrintfW(InfPath, ARRAYSIZE(InfPath), L"%s\\%s", Dir, Names[0]);
    GetWindowsDirectoryW(Pattern, ARRAYSIZE(Pattern));
    StringCchCatW(Pattern, ARRAYSIZE(Pattern), L"\\System32\\DriverStore\\FileRepository\\lntprnoem.inf_*");

    if (WriteTestFile(Dir, Names[0], PlainInf, sizeof(PlainInf) - 1) &&
        WriteTestFile(Dir, Names[1], Text, sizeof(Text) - 1) &&
        WriteTestFile(Dir, Names[2], Text, sizeof(Text) - 1))
    {
        Test.InfPath = InfPath;
        for (i = 0; i < 2; i++)
        {
            PCSTR What = i ? "SetupUninstallOEMInfW" : "SetupCopyOEMInfW";

            if (!AcquirePackageLock(&Namespace, &Lock))
            {
                skip("Cannot take the package lock (%lu)\n", GetLastError());
                break;
            }
            Test.Uninstall = i;
            Test.Result = FALSE;
            hThread = CreateThread(NULL, 0, OemInfThread, &Test, 0, NULL);
            ok(hThread != NULL, "CreateThread failed with %lu\n", GetLastError());
            if (hThread)
                ok(WaitForSingleObject(hThread, 2000) == WAIT_TIMEOUT, "%s did not wait for the package lock\n", What);
            ReleasePackageLock(Namespace, Lock);
            if (hThread)
            {
                ok(WaitForSingleObject(hThread, 60000) == WAIT_OBJECT_0, "%s did not finish\n", What);
                CloseHandle(hThread);
            }
            ok(Test.Result, "%s failed with %lu\n", What, Test.Error);
            if (!Test.Result)
                break;
            Published = !i;

            hFind = FindFirstFileW(Pattern, &Find);
            ok((hFind != INVALID_HANDLE_VALUE) == Published, "After %s the store %s the package\n", What,
               hFind != INVALID_HANDLE_VALUE ? "holds" : "does not hold");
            if (hFind != INVALID_HANDLE_VALUE)
                FindClose(hFind);
        }
        if (Published)
            SetupUninstallOEMInfW(Test.Component, 0, NULL);
    }
    else
    {
        skip("Failed to create the package lntprnoem.inf (%lu)\n", GetLastError());
    }

    for (i = 0; i < ARRAYSIZE(Names); i++)
    {
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\%s", Dir, Names[i]);
        DeleteFileW(Path);
    }
    RemoveDirectoryW(Dir);
}

static BOOL
DriverFileIs(PCWSTR Name, PCSTR Text)
{
    WCHAR Dir[MAX_PATH], Path[MAX_PATH];
    DWORD Size = sizeof(Dir), Read = 0;
    char Buffer[64];
    HANDLE hFile;

    if (!GetPrinterDriverDirectoryW(NULL, NULL, 1, (PBYTE)Dir, Size, &Size))
        return FALSE;
    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\3\\%s", Dir, Name);
    hFile = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    ReadFile(hFile, Buffer, sizeof(Buffer), &Read, NULL);
    CloseHandle(hFile);
    return Read == strlen(Text) && !memcmp(Buffer, Text, Read);
}

static const char UpdateInf[] =
    "[Version]\r\n"
    "Signature=\"$Windows NT$\"\r\n"
    "Class=Printer\r\n"
    "ClassGUID={4D36E979-E325-11CE-BFC1-08002BE10318}\r\n"
    "Provider=LiberNT\r\n"
    "DriverVer=11/06/2026,1.0.0.0\r\n"
    "\r\n"
    "[Manufacturer]\r\n"
    "LiberNT=Models\r\n"
    "\r\n"
    "[Models]\r\n"
    "\"LiberNT Package Update Printer\"=TESTUPD,LiberNT_Package_Update\r\n"
    "\r\n"
    "[TESTUPD]\r\n"
    "CopyFiles=TESTUPD_FILES\r\n"
    "DriverFile=TESTUPD.DLL\r\n"
    "ConfigFile=TESTUPD.DLL\r\n"
    "DataFile=TESTUPD.GPD\r\n"
    "\r\n"
    "[TESTUPD_FILES]\r\n"
    "TESTUPD.DLL\r\n"
    "TESTUPD.GPD\r\n"
    "TESTUPD.DAT\r\n"
    "\r\n"
    "[DestinationDirs]\r\n"
    "DefaultDestDir=66000\r\n"
    "\r\n"
    "[SourceDisksNames]\r\n"
    "1=\"Disk\",,,\r\n"
    "\r\n"
    "[SourceDisksFiles]\r\n"
    "TESTUPD.DLL=1\r\n"
    "TESTUPD.GPD=1\r\n"
    "TESTUPD.DAT=1\r\n";

/* The package lacks TESTUPD.DAT, and the driver directory holds a file of that name */
static VOID
TestIncompleteUpdate(VOID)
{
    static const PCWSTR Names[] = { L"lntprnupd.inf", L"TESTUPD.DLL", L"TESTUPD.GPD", L"TESTUPD.DAT" };
    static const char Text[] = "LiberNT package test file\r\n";
    static const char Installed[] = "the installed file\r\n";
    WCHAR Dir[MAX_PATH], InfPath[MAX_PATH], DriverDir[MAX_PATH], Path[MAX_PATH];
    DWORD Size = sizeof(DriverDir);
    HRESULT hr;
    HKEY hKey;
    UINT i;

    if (!GetPrinterDriverDirectoryW(NULL, NULL, 1, (PBYTE)DriverDir, Size, &Size))
    {
        skip("No printer driver directory (%lu)\n", GetLastError());
        return;
    }
    StringCchCatW(DriverDir, ARRAYSIZE(DriverDir), L"\\3");
    CreateDirectoryW(DriverDir, NULL);

    GetTempPathW(MAX_PATH, Dir);
    StringCchCatW(Dir, MAX_PATH, L"lntprnupd");
    CreateDirectoryW(Dir, NULL);
    StringCchPrintfW(InfPath, ARRAYSIZE(InfPath), L"%s\\lntprnupd.inf", Dir);

    if (WriteTestFile(Dir, L"lntprnupd.inf", UpdateInf, sizeof(UpdateInf) - 1) &&
        WriteTestFile(Dir, L"TESTUPD.DLL", Text, sizeof(Text) - 1) &&
        WriteTestFile(Dir, L"TESTUPD.GPD", Text, sizeof(Text) - 1) &&
        WriteTestFile(DriverDir, L"TESTUPD.DAT", Installed, sizeof(Installed) - 1))
    {
        hr = InstallPrinterDriverFromPackageW(NULL, InfPath, L"LiberNT Package Update Printer", NULL, IPDFP_COPY_ALL_FILES);
        ok(hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), "InstallPrinterDriverFromPackageW returned 0x%lx\n", hr);

        hKey = OpenDriverKey(L"LiberNT Package Update Printer");
        ok(hKey == NULL, "A driver was registered from a package without TESTUPD.DAT\n");
        if (hKey)
            RegCloseKey(hKey);
        ok(DriverFileIs(L"TESTUPD.DAT", Installed), "The installed TESTUPD.DAT was changed\n");
        ok(!DriverFileExists(L"TESTUPD.GPD"), "TESTUPD.GPD was installed from a package without TESTUPD.DAT\n");
    }
    else
    {
        skip("Failed to create the package lntprnupd.inf (%lu)\n", GetLastError());
    }

    RegDeleteKeyW(HKEY_LOCAL_MACHINE, TEST_DRIVERS_KEY L"\\LiberNT Package Update Printer");
    for (i = 0; i < ARRAYSIZE(Names); i++)
    {
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\%s", Dir, Names[i]);
        DeleteFileW(Path);
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\%s", DriverDir, Names[i]);
        DeleteFileW(Path);
    }
    RemoveDirectoryW(Dir);
}

/* The driver directory holds a file of the size and the write time of the source, with other content, that cannot be replaced */
static VOID
TestLockedDestination(PLOCK_TEST Test, PCWSTR SourceDir)
{
    static const char Wanted[] = "the package file\r\n";
    static const char Locked[] = "another file 123\r\n";
    WCHAR DriverDir[MAX_PATH], Source[MAX_PATH], Installed[MAX_PATH];
    WIN32_FILE_ATTRIBUTE_DATA Data;
    DWORD Size = sizeof(DriverDir);
    PWSTR ConfigFile = Test->Info.pConfigFile;
    HANDLE hFile;

    C_ASSERT(sizeof(Wanted) == sizeof(Locked));

    if (!GetPrinterDriverDirectoryW(NULL, NULL, 1, (PBYTE)DriverDir, Size, &Size))
    {
        skip("No printer driver directory (%lu)\n", GetLastError());
        return;
    }
    StringCchCatW(DriverDir, ARRAYSIZE(DriverDir), L"\\3");
    StringCchPrintfW(Source, ARRAYSIZE(Source), L"%s\\TESTSAME.DAT", SourceDir);
    StringCchPrintfW(Installed, ARRAYSIZE(Installed), L"%s\\TESTSAME.DAT", DriverDir);

    if (!WriteTestFile(SourceDir, L"TESTSAME.DAT", Wanted, sizeof(Wanted) - 1) ||
        !WriteTestFile(DriverDir, L"TESTSAME.DAT", Locked, sizeof(Locked) - 1) ||
        !GetFileAttributesExW(Source, GetFileExInfoStandard, &Data))
    {
        skip("Cannot write TESTSAME.DAT (%lu)\n", GetLastError());
        DeleteFileW(Source);
        DeleteFileW(Installed);
        return;
    }

    hFile = CreateFileW(Installed, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        SetFileTime(hFile, NULL, NULL, &Data.ftLastWriteTime);
        CloseHandle(hFile);
    }

    hFile = CreateFileW(Installed, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    ok(hFile != INVALID_HANDLE_VALUE, "Cannot open %S (%lu)\n", Installed, GetLastError());

    Test->Info.pConfigFile = Source;
    ok(!AddPrinterDriverExW(NULL, 8, (PBYTE)&Test->Info, APD_COPY_ALL_FILES | APD_COPY_FROM_DIRECTORY),
       "AddPrinterDriverExW took the locked %S for the file of the package\n", Installed);
    Test->Info.pConfigFile = ConfigFile;

    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);
    ok(DriverFileIs(L"TESTSAME.DAT", Locked), "%S was changed\n", Installed);

    DeleteFileW(Source);
    DeleteFileW(Installed);
}

static VOID
TestDriverUpdate(PLOCK_TEST Test, PCWSTR SourceDir, PCWSTR Gone)
{
    static const char First[] = "version A\r\n";
    static const char Second[] = "version B, longer\r\n";
    static const char Foreign[] = "not a file of the update\r\n";
    WCHAR Fresh[MAX_PATH], Path[MAX_PATH] = L"", Value[MAX_PATH] = L"";
    PWSTR DataFile = Test->Info.pDataFile, ConfigFile = Test->Info.pConfigFile;
    DWORD Size = sizeof(Path);
    WIN32_FIND_DATAW Find;
    BOOL HasForeign = FALSE;
    HANDLE hFind;
    HKEY hKey;

    if (GetPrinterDriverDirectoryW(NULL, NULL, 1, (PBYTE)Path, Size, &Size))
    {
        StringCchCatW(Path, ARRAYSIZE(Path), L"\\3");
        CreateDirectoryW(Path, NULL);
        HasForeign = WriteTestFile(Path, L"TESTROLL.DAT.apd-new", Foreign, sizeof(Foreign) - 1) &&
                     WriteTestFile(Path, L"TESTROLL.DAT.apd-old", Foreign, sizeof(Foreign) - 1);
    }
    ok(HasForeign, "Cannot write TESTROLL.DAT.apd-new and TESTROLL.DAT.apd-old (%lu)\n", GetLastError());

    StringCchPrintfW(Fresh, ARRAYSIZE(Fresh), L"%s\\TESTROLL.DAT", SourceDir);
    if (!WriteTestFile(SourceDir, L"TESTROLL.DAT", First, sizeof(First) - 1))
    {
        skip("Cannot write %S (%lu)\n", Fresh, GetLastError());
        TestLockedDestination(Test, SourceDir);
        return;
    }

    Test->Info.pDataFile = Fresh;
    ok(AddPrinterDriverExW(NULL, 8, (PBYTE)&Test->Info, APD_COPY_ALL_FILES | APD_COPY_FROM_DIRECTORY),
       "AddPrinterDriverExW failed with %lu\n", GetLastError());
    ok(DriverFileIs(L"TESTROLL.DAT", First), "TESTROLL.DAT is not the first version\n");

    ok(WriteTestFile(SourceDir, L"TESTROLL.DAT", Second, sizeof(Second) - 1), "Cannot change %S\n", Fresh);
    Test->Info.pConfigFile = (PWSTR)Gone;
    ok(!AddPrinterDriverExW(NULL, 8, (PBYTE)&Test->Info, APD_COPY_ALL_FILES | APD_COPY_FROM_DIRECTORY),
       "AddPrinterDriverExW succeeded although %S does not exist\n", Gone);
    Test->Info.pConfigFile = ConfigFile;
    ok(DriverFileIs(L"TESTROLL.DAT", First), "TESTROLL.DAT was replaced by an update that failed\n");

    TestLockedDestination(Test, SourceDir);
    ok(DriverFileIs(L"TESTROLL.DAT", First), "TESTROLL.DAT was not restored after an update that failed\n");

    if (HasForeign)
    {
        ok(DriverFileIs(L"TESTROLL.DAT.apd-new", Foreign), "An update that failed changed TESTROLL.DAT.apd-new\n");
        ok(DriverFileIs(L"TESTROLL.DAT.apd-old", Foreign), "An update that failed changed TESTROLL.DAT.apd-old\n");
    }
    ok(AddPrinterDriverExW(NULL, 8, (PBYTE)&Test->Info, APD_COPY_ALL_FILES | APD_COPY_FROM_DIRECTORY),
       "AddPrinterDriverExW failed with %lu\n", GetLastError());
    ok(DriverFileIs(L"TESTROLL.DAT", Second), "TESTROLL.DAT is not the second version\n");
    if (HasForeign)
    {
        ok(DriverFileIs(L"TESTROLL.DAT.apd-new", Foreign), "The update changed TESTROLL.DAT.apd-new\n");
        ok(DriverFileIs(L"TESTROLL.DAT.apd-old", Foreign), "The update changed TESTROLL.DAT.apd-old\n");
    }
    StringCchPrintfW(Value, ARRAYSIZE(Value), L"%s\\TESTROLL.DAT.apd-new", Path);
    DeleteFileW(Value);
    StringCchPrintfW(Value, ARRAYSIZE(Value), L"%s\\TESTROLL.DAT.apd-old", Path);
    DeleteFileW(Value);
    Value[0] = UNICODE_NULL;

    hKey = OpenDriverKey(LOCK_DRIVER_NAME);
    ok(hKey != NULL, "Driver %S is not registered any more\n", LOCK_DRIVER_NAME);
    if (hKey)
    {
        Size = sizeof(Value);
        ok(RegQueryValueExW(hKey, L"Configuration File", NULL, NULL, (PBYTE)Value, &Size) == ERROR_SUCCESS &&
           !_wcsicmp(Value, L"TESTUI.DLL"), "Configuration File is %S\n", Value);
        RegCloseKey(hKey);
    }

    Size = sizeof(Path);
    if (GetPrinterDriverDirectoryW(NULL, NULL, 1, (PBYTE)Path, Size, &Size))
    {
        StringCchCatW(Path, ARRAYSIZE(Path), L"\\3\\*.apd-*");
        hFind = FindFirstFileW(Path, &Find);
        ok(hFind == INVALID_HANDLE_VALUE, "%S was left behind\n", hFind == INVALID_HANDLE_VALUE ? L"" : Find.cFileName);
        if (hFind != INVALID_HANDLE_VALUE)
            FindClose(hFind);
    }

    Test->Info.pDataFile = DataFile;
    DeleteFileW(Fresh);
}

static VOID
TestPackageLock(PCWSTR InfPath, PCWSTR StoreInf)
{
    WCHAR Driver[MAX_PATH], Config[MAX_PATH], Data[MAX_PATH], Missing[MAX_PATH], Value[MAX_PATH];
    WCHAR SourceDir[MAX_PATH], Fresh[MAX_PATH], Gone[MAX_PATH];
    int DirLength = (int)(wcsrchr(StoreInf, L'\\') - StoreInf);
    LOCK_TEST Test = { { 0 } };
    DWORD Size;
    HRESULT hr;
    HKEY hKey;

    StringCchPrintfW(Driver, ARRAYSIZE(Driver), L"%.*s\\TESTDRV.DLL", DirLength, StoreInf);
    StringCchPrintfW(Config, ARRAYSIZE(Config), L"%.*s\\TESTUI.DLL", DirLength, StoreInf);
    StringCchPrintfW(Data, ARRAYSIZE(Data), L"%.*s\\TESTPKG.GPD", DirLength, StoreInf);
    StringCchPrintfW(Missing, ARRAYSIZE(Missing), L"%.*s\\TESTNONE.INF", DirLength, StoreInf);

    Test.UploadInf = InfPath;
    RunWhileLocked(&Test, "UploadPrinterDriverPackageW");
    ok(Test.Error == (DWORD)S_OK, "UploadPrinterDriverPackageW returned 0x%lx\n", Test.Error);

    Test.UploadInf = NULL;
    Test.Info.cVersion = 3;
    Test.Info.pName = (PWSTR)LOCK_DRIVER_NAME;
    Test.Info.pDriverPath = Driver;
    Test.Info.pConfigFile = Config;
    Test.Info.pDataFile = Data;

    Test.Info.pszInfPath = Missing;
    ok(!AddPrinterDriverExW(NULL, 8, (PBYTE)&Test.Info, APD_COPY_ALL_FILES | APD_COPY_FROM_DIRECTORY),
       "AddPrinterDriverExW succeeded for the package %S\n", Missing);
    hKey = OpenDriverKey(LOCK_DRIVER_NAME);
    ok(hKey == NULL, "Driver %S is registered for a package that does not exist\n", LOCK_DRIVER_NAME);
    if (hKey)
        RegCloseKey(hKey);

    Test.Info.pszInfPath = (PWSTR)StoreInf;
    StringCchPrintfW(SourceDir, ARRAYSIZE(SourceDir), L"%.*s", (int)(wcsrchr(InfPath, L'\\') - InfPath), InfPath);
    StringCchPrintfW(Fresh, ARRAYSIZE(Fresh), L"%s\\TESTROLL.DAT", SourceDir);
    StringCchPrintfW(Gone, ARRAYSIZE(Gone), L"%.*s\\TESTGONE.DLL", DirLength, StoreInf);
    if (WriteTestFile(SourceDir, L"TESTROLL.DAT", "rollback\r\n", 10))
    {
        Test.Info.pDataFile = Fresh;
        Test.Info.pConfigFile = Gone;
        ok(!AddPrinterDriverExW(NULL, 8, (PBYTE)&Test.Info, APD_COPY_ALL_FILES | APD_COPY_FROM_DIRECTORY),
           "AddPrinterDriverExW succeeded although %S does not exist\n", Gone);
        hKey = OpenDriverKey(LOCK_DRIVER_NAME);
        ok(hKey == NULL, "Driver %S is registered without %S\n", LOCK_DRIVER_NAME, Gone);
        if (hKey)
            RegCloseKey(hKey);
        ok(!DriverFileExists(L"TESTROLL.DAT"), "TESTROLL.DAT was left in the driver directory\n");
        Test.Info.pDataFile = Data;
        Test.Info.pConfigFile = Config;
        DeleteFileW(Fresh);
    }
    else
    {
        skip("Cannot write %S (%lu)\n", Fresh, GetLastError());
    }

    RunWhileLocked(&Test, "AddPrinterDriverExW");
    ok(Test.Error == ERROR_SUCCESS, "AddPrinterDriverExW failed with %lu\n", Test.Error);
    hKey = OpenDriverKey(LOCK_DRIVER_NAME);
    ok(hKey != NULL, "Driver %S is not registered\n", LOCK_DRIVER_NAME);
    if (hKey)
    {
        Size = sizeof(Value);
        ok(RegQueryValueExW(hKey, L"InfPath", NULL, NULL, (PBYTE)Value, &Size) == ERROR_SUCCESS &&
           !_wcsicmp(Value, StoreInf), "InfPath is %S\n", Value);
        RegCloseKey(hKey);

        hr = DeletePrinterDriverPackageW(NULL, StoreInf, NULL);
        ok(hr == HRESULT_FROM_WIN32(ERROR_PRINTER_DRIVER_PACKAGE_IN_USE), "DeletePrinterDriverPackageW returned 0x%lx\n", hr);
    }

    TestDriverUpdate(&Test, SourceDir, Gone);
}

#define RACE_TIME 5000

typedef struct _RACE_TEST
{
    PCWSTR InfPath;
    PCWSTR StoreInf;
    LONG Installed;
    LONG Refused;
    LONG Broken;
    LONG Deleted;
    LONG UploadFailed;
} RACE_TEST, *PRACE_TEST;

static const PCWSTR RaceFiles[] = { L"TESTDRV.DLL", L"TESTUI.DLL", L"TESTPKG.GPD", L"TESTPKG.HLP", L"TESTPKG.DAT", L"TESTREN.DAT" };

static UINT
CountDriverFiles(VOID)
{
    UINT i, Present = 0;

    for (i = 0; i < ARRAYSIZE(RaceFiles); i++)
    {
        if (DriverFileExists(RaceFiles[i]))
            Present++;
    }
    return Present;
}

static DWORD WINAPI
RaceInstallThread(PVOID Parameter)
{
    PRACE_TEST Test = Parameter;
    DWORD Start = GetTickCount();
    UINT Before, After;
    HRESULT hr;
    HKEY hKey;

    do
    {
        Before = CountDriverFiles();
        hr = InstallPrinterDriverFromPackageW(NULL, Test->StoreInf, TEST_DRIVER_NAME, NULL, IPDFP_COPY_ALL_FILES);
        After = CountDriverFiles();
        hKey = OpenDriverKey(TEST_DRIVER_NAME);
        if (hr == S_OK)
        {
            Test->Installed++;
            if (!hKey || After != ARRAYSIZE(RaceFiles))
                Test->Broken++;
        }
        else
        {
            Test->Refused++;
            if (hKey || After != Before)
                Test->Broken++;
        }
        if (hKey)
            RegCloseKey(hKey);
        DeleteTestDriver();
    } while (GetTickCount() - Start < RACE_TIME);

    return 0;
}

static DWORD WINAPI
RaceDeleteThread(PVOID Parameter)
{
    PRACE_TEST Test = Parameter;
    DWORD Start = GetTickCount();
    WCHAR StoreInf[MAX_PATH];
    ULONG Length;
    HRESULT hr;

    do
    {
        if (DeletePrinterDriverPackageW(NULL, Test->StoreInf, NULL) == S_OK)
            Test->Deleted++;
        Length = ARRAYSIZE(StoreInf);
        hr = UploadPrinterDriverPackageW(NULL, Test->InfPath, NULL, UPDP_SILENT_UPLOAD, NULL, StoreInf, &Length);
        if (hr != S_OK || _wcsicmp(StoreInf, Test->StoreInf) != 0)
            Test->UploadFailed++;
    } while (GetTickCount() - Start < RACE_TIME);

    return 0;
}

static VOID
TestConcurrentInstall(PCWSTR InfPath, PCWSTR StoreInf)
{
    static RACE_TEST Test;
    WCHAR Again[MAX_PATH];
    ULONG Length = ARRAYSIZE(Again);
    HANDLE Threads[2];
    HRESULT hr;
    UINT i;

    Test.InfPath = InfPath;
    Test.StoreInf = StoreInf;
    Threads[0] = CreateThread(NULL, 0, RaceInstallThread, &Test, 0, NULL);
    Threads[1] = CreateThread(NULL, 0, RaceDeleteThread, &Test, 0, NULL);
    for (i = 0; i < ARRAYSIZE(Threads); i++)
    {
        ok(Threads[i] != NULL, "CreateThread failed with %lu\n", GetLastError());
        if (Threads[i])
        {
            ok(WaitForSingleObject(Threads[i], 60000) == WAIT_OBJECT_0, "Thread %u did not finish\n", i);
            CloseHandle(Threads[i]);
        }
    }

    trace("%ld installed, %ld refused, %ld packages deleted\n", Test.Installed, Test.Refused, Test.Deleted);
    ok(Test.Broken == 0, "%ld of %ld installations were left half done\n", Test.Broken, Test.Installed + Test.Refused);
    ok(Test.UploadFailed == 0, "%ld uploads failed or gave another store INF\n", Test.UploadFailed);

    DeleteTestDriver();
    hr = UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_SILENT_UPLOAD, NULL, Again, &Length);
    ok(hr == S_OK && _wcsicmp(Again, StoreInf) == 0, "UploadPrinterDriverPackageW returned 0x%lx\n", hr);
}

#define OEM_RACE_ROUNDS 200

typedef struct _OEM_RACE_TEST
{
    PCWSTR InfPath;
    CRITICAL_SECTION NameLock;
    WCHAR Name[32];
    LONG Done;
    LONG Copied;
    LONG CopyFailed;
    LONG Uninstalled;
} OEM_RACE_TEST, *POEM_RACE_TEST;

static DWORD WINAPI
OemRaceCopyThread(PVOID Parameter)
{
    POEM_RACE_TEST Test = Parameter;
    DWORD Start = GetTickCount();
    WCHAR Published[MAX_PATH];
    PWSTR Component;
    UINT i;

    for (i = 0; i < OEM_RACE_ROUNDS && GetTickCount() - Start < 4 * RACE_TIME; i++)
    {
        if (!SetupCopyOEMInfW(Test->InfPath, NULL, 0, 0, Published, ARRAYSIZE(Published), NULL, &Component))
        {
            Test->CopyFailed++;
            continue;
        }
        Test->Copied++;
        EnterCriticalSection(&Test->NameLock);
        StringCchCopyW(Test->Name, ARRAYSIZE(Test->Name), Component);
        LeaveCriticalSection(&Test->NameLock);
    }
    InterlockedExchange(&Test->Done, 1);
    return 0;
}

static DWORD WINAPI
OemRaceUninstallThread(PVOID Parameter)
{
    POEM_RACE_TEST Test = Parameter;
    WCHAR Name[32];

    while (!Test->Done)
    {
        EnterCriticalSection(&Test->NameLock);
        StringCchCopyW(Name, ARRAYSIZE(Name), Test->Name);
        LeaveCriticalSection(&Test->NameLock);
        if (Name[0] && SetupUninstallOEMInfW(Name, 0, NULL))
            Test->Uninstalled++;
        else
            Sleep(1);
    }
    return 0;
}

static BOOL
IsInfRecorded(PCWSTR Name)
{
    WCHAR Path[MAX_PATH];
    HKEY hKey;

    StringCchPrintfW(Path, ARRAYSIZE(Path), L"SYSTEM\\DriverDatabase\\DriverInfFiles\\%s", Name);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, Path, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return FALSE;
    RegCloseKey(hKey);
    return TRUE;
}

/* Whoever holds the package lock sees a package that is published, staged and recorded, or none of the three */
static VOID
TestOemInfRace(VOID)
{
    static const PCWSTR Names[] = { L"lntprnrace.inf", L"TESTPLAIN.DLL", L"TESTPLAIN.GPD" };
    static const char Text[] = "LiberNT package test file\r\n";
    static const char Marker[] = "; lntprnrace\r\n";
    static char Inf[sizeof(Marker) + sizeof(PlainInf)];
    WCHAR Dir[MAX_PATH], InfPath[MAX_PATH], Pattern[MAX_PATH], Path[MAX_PATH], Published[MAX_PATH], Name[32];
    static OEM_RACE_TEST Test;
    HANDLE Namespace, Lock, Threads[2], hFind;
    UINT i, Checks = 0, Torn = 0;
    BOOL Exists, Stored, Recorded;
    WIN32_FIND_DATAW Find;
    DWORD Start;

    GetTempPathW(MAX_PATH, Dir);
    StringCchCatW(Dir, MAX_PATH, L"lntprnrace");
    CreateDirectoryW(Dir, NULL);
    StringCchPrintfW(InfPath, ARRAYSIZE(InfPath), L"%s\\%s", Dir, Names[0]);
    GetWindowsDirectoryW(Pattern, ARRAYSIZE(Pattern));
    StringCchCatW(Pattern, ARRAYSIZE(Pattern), L"\\System32\\DriverStore\\FileRepository\\lntprnrace.inf_*");

    memcpy(Inf, Marker, sizeof(Marker) - 1);
    memcpy(Inf + sizeof(Marker) - 1, PlainInf, sizeof(PlainInf) - 1);
    if (!WriteTestFile(Dir, Names[0], Inf, sizeof(Marker) - 1 + sizeof(PlainInf) - 1) ||
        !WriteTestFile(Dir, Names[1], Text, sizeof(Text) - 1) ||
        !WriteTestFile(Dir, Names[2], Text, sizeof(Text) - 1))
    {
        skip("Failed to create the package lntprnrace.inf (%lu)\n", GetLastError());
        goto Cleanup;
    }

    Test.InfPath = InfPath;
    InitializeCriticalSection(&Test.NameLock);
    Threads[0] = CreateThread(NULL, 0, OemRaceCopyThread, &Test, 0, NULL);
    Threads[1] = CreateThread(NULL, 0, OemRaceUninstallThread, &Test, 0, NULL);
    ok(Threads[0] != NULL && Threads[1] != NULL, "CreateThread failed with %lu\n", GetLastError());
    if (!Threads[0])
        InterlockedExchange(&Test.Done, 1);

    Start = GetTickCount();
    while (!Test.Done && GetTickCount() - Start < 60000)
    {
        if (!AcquirePackageLock(&Namespace, &Lock))
        {
            skip("Cannot take the package lock (%lu)\n", GetLastError());
            break;
        }
        Exists = FindPublishedInf(InfPath, Published);
        hFind = FindFirstFileW(Pattern, &Find);
        Stored = hFind != INVALID_HANDLE_VALUE;
        if (Stored)
            FindClose(hFind);
        EnterCriticalSection(&Test.NameLock);
        StringCchCopyW(Name, ARRAYSIZE(Name), Test.Name);
        LeaveCriticalSection(&Test.NameLock);
        Recorded = Exists ? IsInfRecorded(wcsrchr(Published, L'\\') + 1) : (Name[0] && IsInfRecorded(Name));
        ReleasePackageLock(Namespace, Lock);

        Checks++;
        if (Stored != Exists || Recorded != Exists)
        {
            if (!Torn)
                trace("Check %u: published %d, staged %d, recorded %d\n", Checks, Exists, Stored, Recorded);
            Torn++;
        }
        Sleep(1);
    }

    for (i = 0; i < ARRAYSIZE(Threads); i++)
    {
        if (Threads[i])
        {
            ok(WaitForSingleObject(Threads[i], 60000) == WAIT_OBJECT_0, "Thread %u did not finish\n", i);
            CloseHandle(Threads[i]);
        }
    }
    DeleteCriticalSection(&Test.NameLock);

    trace("%ld copied, %ld copies failed, %ld uninstalled, %u checks\n", Test.Copied, Test.CopyFailed, Test.Uninstalled, Checks);
    ok(Test.Copied > 0, "SetupCopyOEMInfW never succeeded\n");
    ok(Checks > 0, "The package was never looked at under the package lock\n");
    ok(Torn == 0, "%u of %u looks under the package lock found a package that was only partly there\n", Torn, Checks);

    Exists = FindPublishedInf(InfPath, Published);
    hFind = FindFirstFileW(Pattern, &Find);
    Stored = hFind != INVALID_HANDLE_VALUE;
    if (Stored)
        FindClose(hFind);
    ok(Stored == Exists, "After the race the package is %s but %s\n", Exists ? "published" : "not published", Stored ? "staged" : "not staged");
    if (Exists)
    {
        ok(IsInfRecorded(wcsrchr(Published, L'\\') + 1), "%S is published but not recorded\n", Published);
        ok(SetupUninstallOEMInfW(wcsrchr(Published, L'\\') + 1, 0, NULL), "SetupUninstallOEMInfW failed with %lu\n", GetLastError());
    }
    ok(!Test.Name[0] || !IsInfRecorded(Test.Name), "%S is recorded without its INF\n", Test.Name);
    hFind = FindFirstFileW(Pattern, &Find);
    ok(hFind == INVALID_HANDLE_VALUE, "%S is left in the store\n", hFind == INVALID_HANDLE_VALUE ? L"" : Find.cFileName);
    if (hFind != INVALID_HANDLE_VALUE)
        FindClose(hFind);

Cleanup:
    for (i = 0; i < ARRAYSIZE(Names); i++)
    {
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\%s", Dir, Names[i]);
        DeleteFileW(Path);
    }
    RemoveDirectoryW(Dir);
}

static VOID
TestStoreReplacement(PCWSTR Dir, PCWSTR InfPath, PCWSTR StoreInf)
{
    static const char Text[] = "LiberNT package test file\r\n";
    static const char Changed[] = "changed for the held store\r\n";
    WCHAR StoreDir[MAX_PATH], StoreFile[MAX_PATH], SourceFile[MAX_PATH], Backup[MAX_PATH], Again[MAX_PATH];
    WIN32_FIND_DATAW Find;
    HANDLE hHeld, hFind;
    ULONG Length;
    HRESULT hr;
    PWSTR Last;

    StringCchCopyW(StoreDir, ARRAYSIZE(StoreDir), StoreInf);
    Last = wcsrchr(StoreDir, L'\\');
    if (!Last)
    {
        skip("%S is not a path\n", StoreInf);
        return;
    }
    *Last = UNICODE_NULL;

    StringCchPrintfW(StoreFile, ARRAYSIZE(StoreFile), L"%s\\TESTDRV.DLL", StoreDir);
    hHeld = CreateFileW(StoreFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    ok(hHeld != INVALID_HANDLE_VALUE, "Opening %S failed with %lu\n", StoreFile, GetLastError());
    if (hHeld == INVALID_HANDLE_VALUE)
        return;

    StringCchPrintfW(StoreFile, ARRAYSIZE(StoreFile), L"%s\\TESTPKG.HLP", StoreDir);
    StringCchPrintfW(SourceFile, ARRAYSIZE(SourceFile), L"%s\\TESTPKG.GPD", Dir);
    ok(WriteTestFile(Dir, L"TESTPKG.HLP", Changed, sizeof(Changed) - 1), "Changing the source TESTPKG.HLP failed\n");

    Length = ARRAYSIZE(Again);
    hr = UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_UPLOAD_ALWAYS, NULL, Again, &Length);
    ok(hr == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED), "UploadPrinterDriverPackageW returned 0x%lx over a held package\n", hr);
    ok(GetFileAttributesW(StoreInf) != INVALID_FILE_ATTRIBUTES, "%S is gone after an upload over a held package\n", StoreInf);
    ok(FilesMatch(StoreFile, SourceFile), "%S was replaced by an upload over a held package\n", StoreFile);
    Length = ARRAYSIZE(Again);
    hr = UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_CHECK_DRIVERSTORE, NULL, Again, &Length);
    ok(hr == S_OK && _wcsicmp(Again, StoreInf) == 0, "UploadPrinterDriverPackageW returned 0x%lx for the held package\n", hr);
    CloseHandle(hHeld);

    StringCchPrintfW(SourceFile, ARRAYSIZE(SourceFile), L"%s\\TESTPKG.HLP", Dir);
    Length = ARRAYSIZE(Again);
    hr = UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_UPLOAD_ALWAYS, NULL, Again, &Length);
    ok(hr == S_OK && _wcsicmp(Again, StoreInf) == 0, "UploadPrinterDriverPackageW returned 0x%lx after the package was released\n", hr);
    ok(FilesMatch(StoreFile, SourceFile), "%S was not replaced after the package was released\n", StoreFile);

    /* The state a replacement leaves when its backup cannot be moved back */
    StringCchPrintfW(Backup, ARRAYSIZE(Backup), L"%s.stage-0-0.old", StoreDir);
    ok(WriteTestFile(StoreDir, L"TESTKEEP.DAT", Text, sizeof(Text) - 1), "Writing TESTKEEP.DAT failed\n");
    if (MoveFileW(StoreDir, Backup))
    {
        Length = ARRAYSIZE(Again);
        hr = UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_UPLOAD_ALWAYS, NULL, Again, &Length);
        ok(hr == S_OK && _wcsicmp(Again, StoreInf) == 0, "UploadPrinterDriverPackageW returned 0x%lx over a backup\n", hr);
        ok(GetFileAttributesW(Backup) == INVALID_FILE_ATTRIBUTES, "%S was left behind\n", Backup);
        StringCchPrintfW(StoreFile, ARRAYSIZE(StoreFile), L"%s\\TESTKEEP.DAT", StoreDir);
        ok(GetFileAttributesW(StoreFile) == INVALID_FILE_ATTRIBUTES, "%S of the backup is not in the package and was left in the store\n", StoreFile);
    }
    else
    {
        skip("Moving %S away failed with %lu\n", StoreDir, GetLastError());
    }

    /* The state an upload leaves when it cannot delete its staging directory */
    StringCchPrintfW(Backup, ARRAYSIZE(Backup), L"%s.stage-0-0", StoreDir);
    if (CreateDirectoryW(Backup, NULL) && WriteTestFile(Backup, L"TESTKEEP.DAT", Text, sizeof(Text) - 1))
    {
        Length = ARRAYSIZE(Again);
        hr = UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_UPLOAD_ALWAYS, NULL, Again, &Length);
        ok(hr == S_OK && _wcsicmp(Again, StoreInf) == 0, "UploadPrinterDriverPackageW returned 0x%lx over a staging directory\n", hr);
        ok(GetFileAttributesW(Backup) == INVALID_FILE_ATTRIBUTES, "%S was left behind\n", Backup);
        ok(GetFileAttributesW(StoreInf) != INVALID_FILE_ATTRIBUTES, "%S is gone after an upload over a staging directory\n", StoreInf);
    }
    else
    {
        skip("Creating %S failed with %lu\n", Backup, GetLastError());
        RemoveDirectoryW(Backup);
    }

    ok(WriteTestFile(Dir, L"TESTPKG.HLP", Text, sizeof(Text) - 1), "Restoring TESTPKG.HLP failed\n");
    Length = ARRAYSIZE(Again);
    hr = UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_UPLOAD_ALWAYS, NULL, Again, &Length);
    ok(hr == S_OK && _wcsicmp(Again, StoreInf) == 0, "UploadPrinterDriverPackageW returned 0x%lx\n", hr);
    StringCchPrintfW(StoreFile, ARRAYSIZE(StoreFile), L"%s\\TESTPKG.HLP", StoreDir);
    ok(FilesMatch(StoreFile, SourceFile), "%S was not replaced\n", StoreFile);

    StringCchPrintfW(StoreFile, ARRAYSIZE(StoreFile), L"%s.stage-*", StoreDir);
    hFind = FindFirstFileW(StoreFile, &Find);
    ok(hFind == INVALID_HANDLE_VALUE, "%S was left behind\n", hFind == INVALID_HANDLE_VALUE ? L"" : Find.cFileName);
    if (hFind != INVALID_HANDLE_VALUE)
        FindClose(hFind);
}

/* No model installs the section that copies TESTOPT.DAT, so a package is complete with and without the file */
static VOID
TestRemovedOptionalFile(PCWSTR Dir, PCWSTR InfPath, PCWSTR StoreInf)
{
    static const char Text[] = "LiberNT package test file\r\n";
    WCHAR SourceFile[MAX_PATH], StoreFile[MAX_PATH], Again[MAX_PATH];
    ULONG Length = ARRAYSIZE(Again);
    HRESULT hr;

    StringCchPrintfW(SourceFile, ARRAYSIZE(SourceFile), L"%s\\TESTOPT.DAT", Dir);
    StringCchPrintfW(StoreFile, ARRAYSIZE(StoreFile), L"%.*s\\TESTOPT.DAT", (int)(wcsrchr(StoreInf, L'\\') - StoreInf), StoreInf);
    ok(WriteTestFile(Dir, L"TESTOPT.DAT", Text, sizeof(Text) - 1), "Writing %S failed\n", SourceFile);

    hr = UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_UPLOAD_ALWAYS, NULL, Again, &Length);
    ok(hr == S_OK && _wcsicmp(Again, StoreInf) == 0, "UploadPrinterDriverPackageW returned 0x%lx with an optional file\n", hr);
    ok(GetFileAttributesW(StoreFile) != INVALID_FILE_ATTRIBUTES, "%S was not staged\n", StoreFile);

    ok(DeleteFileW(SourceFile), "Deleting %S failed with %lu\n", SourceFile, GetLastError());
    Length = ARRAYSIZE(Again);
    hr = UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_UPLOAD_ALWAYS, NULL, Again, &Length);
    ok(hr == S_OK && _wcsicmp(Again, StoreInf) == 0, "UploadPrinterDriverPackageW returned 0x%lx without the optional file\n", hr);
    ok(GetFileAttributesW(StoreFile) == INVALID_FILE_ATTRIBUTES, "%S was left in the store after its source was removed\n", StoreFile);
}

static VOID
TestHeldPackageDelete(PCWSTR InfPath, PCWSTR StoreInf)
{
    static const PCWSTR Names[] = { L"lntprnpkg.inf", L"TESTPKG.GPD", L"TESTDRV.DLL", L"TESTUI.DLL", L"TESTPKG.HLP", L"TESTPKG.DAT" };
    int DirLength = (int)(wcsrchr(StoreInf, L'\\') - StoreInf);
    WCHAR Path[MAX_PATH], Published[MAX_PATH];
    HANDLE hHeld;
    HRESULT hr;
    UINT i;

    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%.*s\\TESTPKG.HLP", DirLength, StoreInf);
    hHeld = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    ok(hHeld != INVALID_HANDLE_VALUE, "Opening %S failed with %lu\n", Path, GetLastError());
    if (hHeld == INVALID_HANDLE_VALUE)
        return;

    hr = DeletePrinterDriverPackageW(NULL, StoreInf, NULL);
    ok(FAILED(hr), "DeletePrinterDriverPackageW returned 0x%lx for a package with an open file\n", hr);
    for (i = 0; i < ARRAYSIZE(Names); i++)
    {
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"%.*s\\%s", DirLength, StoreInf, Names[i]);
        ok(GetFileAttributesW(Path) != INVALID_FILE_ATTRIBUTES, "%S was deleted from a package with an open file\n", Path);
    }
    ok(FindPublishedInf(InfPath, Published), "The published INF was deleted and the package with an open file was not\n");
    CloseHandle(hHeld);
}

static BOOL
SetTestDacl(PCWSTR Path, PCWSTR Sddl)
{
    PSECURITY_DESCRIPTOR Descriptor;
    BOOL Ret;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Descriptor, NULL))
        return FALSE;
    Ret = SetFileSecurityW(Path, DACL_SECURITY_INFORMATION, Descriptor);
    LocalFree(Descriptor);
    return Ret;
}

/* A file that grants only reading in a directory that grants only reading is deleted by nobody, and the directory above is still renamed */
static BOOL
BlockPackageDelete(PCWSTR PackageDir)
{
    static const char Text[] = "LiberNT package test file\r\n";
    WCHAR Dir[MAX_PATH], File[MAX_PATH];
    HANDLE hFile;

    StringCchPrintfW(Dir, ARRAYSIZE(Dir), L"%s\\TESTACL", PackageDir);
    StringCchPrintfW(File, ARRAYSIZE(File), L"%s\\TESTACL.DAT", Dir);
    if (!CreateDirectoryW(Dir, NULL) ||
        !WriteTestFile(Dir, L"TESTACL.DAT", Text, sizeof(Text) - 1) ||
        !SetTestDacl(File, L"D:P(A;;0x1200a9;;;WD)") ||
        !SetTestDacl(Dir, L"D:P(A;;0x1200a9;;;WD)"))
    {
        return FALSE;
    }

    hFile = CreateFileW(File, DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return TRUE;
    CloseHandle(hFile);
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
}

static VOID
UnblockPackageDelete(PCWSTR PackageDir)
{
    WCHAR Dir[MAX_PATH], File[MAX_PATH];

    StringCchPrintfW(Dir, ARRAYSIZE(Dir), L"%s\\TESTACL", PackageDir);
    StringCchPrintfW(File, ARRAYSIZE(File), L"%s\\TESTACL.DAT", Dir);
    SetTestDacl(Dir, L"D:(A;;FA;;;WD)");
    SetTestDacl(File, L"D:(A;;FA;;;WD)");
    DeleteFileW(File);
    RemoveDirectoryW(Dir);
}

static UINT
UnblockLeftovers(PCWSTR StoreDir)
{
    WCHAR Pattern[MAX_PATH], Path[MAX_PATH];
    WIN32_FIND_DATAW Find;
    HANDLE hFind;
    UINT Count = 0;

    StringCchPrintfW(Pattern, ARRAYSIZE(Pattern), L"%s.delete-*", StoreDir);
    hFind = FindFirstFileW(Pattern, &Find);
    if (hFind == INVALID_HANDLE_VALUE)
        return 0;
    do
    {
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"%.*s\\%s", (int)(wcsrchr(StoreDir, L'\\') - StoreDir), StoreDir, Find.cFileName);
        UnblockPackageDelete(Path);
        Count++;
    } while (FindNextFileW(hFind, &Find));
    FindClose(hFind);
    return Count;
}

static VOID
TestFailedPackageDelete(PCWSTR InfPath, PCWSTR StoreInf)
{
    WCHAR StoreDir[MAX_PATH], Published[MAX_PATH], Again[MAX_PATH];
    ULONG Length;
    HRESULT hr;
    PWSTR Last;
    BOOL Ret;
    UINT i;

    StringCchCopyW(StoreDir, ARRAYSIZE(StoreDir), StoreInf);
    Last = wcsrchr(StoreDir, L'\\');
    if (!Last || !FindPublishedInf(InfPath, Published))
    {
        skip("%S is not a published package\n", StoreInf);
        return;
    }
    *Last = UNICODE_NULL;

    for (i = 0; i < 2; i++)
    {
        PCSTR What = i ? "DeletePrinterDriverPackageW" : "SetupUninstallOEMInfW";

        if (!BlockPackageDelete(StoreDir))
        {
            skip("A file in %S cannot be protected from deletion (%lu)\n", StoreDir, GetLastError());
            UnblockPackageDelete(StoreDir);
            return;
        }

        if (i)
        {
            hr = DeletePrinterDriverPackageW(NULL, StoreInf, NULL);
            Ret = SUCCEEDED(hr);
        }
        else
        {
            Ret = SetupUninstallOEMInfW(wcsrchr(Published, L'\\') + 1, 0, NULL);
        }
        ok(!Ret, "%s succeeded for a package with a file that cannot be deleted\n", What);
        ok(GetFileAttributesW(Published) != INVALID_FILE_ATTRIBUTES, "%s deleted %S and left a part of its package\n", What, Published);
        ok(UnblockLeftovers(StoreDir) == 1, "%s left no directory for the part of the package it could not delete\n", What);

        Length = ARRAYSIZE(Again);
        hr = UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_UPLOAD_ALWAYS, NULL, Again, &Length);
        ok(hr == S_OK && _wcsicmp(Again, StoreInf) == 0, "UploadPrinterDriverPackageW returned 0x%lx after %s failed\n", hr, What);
        ok(GetFileAttributesW(StoreInf) != INVALID_FILE_ATTRIBUTES, "%S was not staged again after %s failed\n", StoreInf, What);
        ok(UnblockLeftovers(StoreDir) == 0, "The upload after %s failed left the partly deleted package behind\n", What);
    }
}

START_TEST(DriverPackage)
{
    WCHAR Dir[MAX_PATH], InfPath[MAX_PATH], StoreInf[MAX_PATH];
    PWSTR Dependent;
    ULONG Length;
    HRESULT hr;
    BOOL DatFound = FALSE;

    Length = ARRAYSIZE(StoreInf);
    hr = UploadPrinterDriverPackageW(NULL, NULL, NULL, 0, NULL, StoreInf, &Length);
    ok(hr == E_INVALIDARG, "UploadPrinterDriverPackageW returned 0x%lx\n", hr);
    hr = UploadPrinterDriverPackageW(NULL, L"C:\\x.inf", L"Invalid Env", 0, NULL, StoreInf, &Length);
    ok(hr == HRESULT_FROM_WIN32(ERROR_INVALID_ENVIRONMENT), "UploadPrinterDriverPackageW returned 0x%lx\n", hr);
    hr = InstallPrinterDriverFromPackageW(NULL, NULL, TEST_DRIVER_NAME, NULL, 0);
    ok(hr == HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED), "InstallPrinterDriverFromPackageW returned 0x%lx\n", hr);
    hr = InstallPrinterDriverFromPackageW(NULL, L"C:\\x.inf", TEST_DRIVER_NAME, NULL, 0x80);
    ok(hr == E_INVALIDARG, "InstallPrinterDriverFromPackageW returned 0x%lx\n", hr);
    hr = DeletePrinterDriverPackageW(NULL, NULL, NULL);
    ok(hr == E_INVALIDARG, "DeletePrinterDriverPackageW returned 0x%lx\n", hr);

    TestRefusedPackage(L"lntprnmiss", MissingInf, sizeof(MissingInf) - 1, L"TESTMISS.DAT", NULL, HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND));
    TestRefusedPackage(L"lntprnneed", NeedsMissingInf, sizeof(NeedsMissingInf) - 1, L"TESTNM.DAT", NULL, HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND));
    TestRefusedPackage(L"lntprnunl", UnlistedInf, sizeof(UnlistedInf) - 1, L"TESTUNL.DAT", NULL, HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND));
    TestRefusedPackage(L"lntprnbad",MalformedInf, sizeof(MalformedInf) - 1, L"TESTBAD.DAT", NULL, S_OK);
    TestRefusedPackage(L"lntprnesc", EscapeInf, sizeof(EscapeInf) - 1, L"TESTESC.DAT", NULL, S_OK);
    TestRefusedPackage(L"lntprnies", IncludeEscapeInf, sizeof(IncludeEscapeInf) - 1, L"TESTIES.DAT", L"lntprnout.inf", S_OK);
    TestRefusedPackage(L"lntprnsle", SlashEscapeInf, sizeof(SlashEscapeInf) - 1, L"TESTSLE.DAT", L"lntprnout.dll", S_OK);
    TestInstallPackage(L"lntprnplain", L"LiberNT Package Plain Printer", PlainInf, sizeof(PlainInf) - 1,
                       L"TESTPLAIN.DLL", L"TESTPLAIN.GPD", 1, NULL, NULL);
    TestInstallPackage(L"lntprntwo", L"LiberNT Package Two Needs Printer", TwoNeedsInf, sizeof(TwoNeedsInf) - 1,
                       L"TESTTWO.DLL", L"TESTTWO%u.DAT", 2, L"TESTTWO1.DAT", NULL);
    TestInstallPackage(L"lntprnbig",L"LiberNT Package Big Printer", BigInf, BuildBigInf(),
                       L"TESTBIG.DLL", L"TESTBIG%03u.DAT", BIG_SECTIONS * BIG_SECTION_FILES, L"TESTBIG139.DAT", NULL);
    TestInstallPackage(L"lntprninc", L"LiberNT Package Include Printer", IncludeInf, sizeof(IncludeInf) - 1,
                       L"TESTINC.DLL", L"TESTINC%u.DAT", 2, L"TESTINC1.DAT", L"lntprncmn.inf");
    TestInstallPackage(L"lntprnsub", L"LiberNT Package Subdir Include Printer", SubdirIncludeInf, sizeof(SubdirIncludeInf) - 1,
                       L"TESTINC.DLL", L"TESTINC%u.DAT", 2, L"TESTINC1.DAT", L"sub\\lntprncmn.inf");
    TestAbsoluteInclude();
    TestOtherEnvironment();
    TestMisplacedPackage(L"FileRepository-backup", L"lntprnsib", L"lntprnsib.inf");
    TestMisplacedPackage(L"FileRepository", L"lntprnbadh.inf_" TEST_STORE_ARCHITECTURE L"_0000000000000000", L"lntprnbadh.inf");
    TestIncompleteUpdate();
    TestJunctionPackage();
    TestSetupLock();
    TestOemInfRace();

    if (!CreateTestPackage(Dir, InfPath))
    {
        skip("Failed to create the test package (%lu)\n", GetLastError());
        return;
    }

    Length = ARRAYSIZE(StoreInf);
    hr = UploadPrinterDriverPackageW(NULL, L"C:\\does-not-exist\\none.inf", NULL, 0, NULL, StoreInf, &Length);
    ok(FAILED(hr), "UploadPrinterDriverPackageW returned 0x%lx\n", hr);

    Length = 1;
    hr = UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_SILENT_UPLOAD, NULL, StoreInf, &Length);
    ok(hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER), "UploadPrinterDriverPackageW returned 0x%lx\n", hr);
    ok(Length > 1, "Length is %lu\n", Length);

    Length = ARRAYSIZE(StoreInf);
    hr = UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_SILENT_UPLOAD, NULL, StoreInf, &Length);
    ok(hr == S_OK, "UploadPrinterDriverPackageW returned 0x%lx\n", hr);
    if (hr != S_OK)
    {
        skip("The package could not be uploaded\n");
        DeleteTestPackage(Dir);
        return;
    }
    ok(Length == wcslen(StoreInf) + 1, "Length is %lu for %S\n", Length, StoreInf);
    ok(wcsstr(StoreInf, L"\\DriverStore\\FileRepository\\") != NULL, "Store path is %S\n", StoreInf);
    ok(GetFileAttributesW(StoreInf) != INVALID_FILE_ATTRIBUTES, "%S does not exist\n", StoreInf);
    trace("Store INF: %S\n", StoreInf);

    {
        WCHAR Again[MAX_PATH];
        Length = ARRAYSIZE(Again);
        hr = UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_CHECK_DRIVERSTORE, NULL, Again, &Length);
        ok(hr == S_OK, "UploadPrinterDriverPackageW returned 0x%lx\n", hr);
        if (hr == S_OK)
            ok(_wcsicmp(Again, StoreInf) == 0, "Second upload returned %S\n", Again);

        ok(wcsstr(StoreInf, L"\\lntprnpkg.inf_" TEST_STORE_ARCHITECTURE L"_") != NULL,
           "%S is not a package of %S\n", StoreInf, TEST_ENVIRONMENT);
        Length = ARRAYSIZE(Again);
        hr = UploadPrinterDriverPackageW(NULL, InfPath, TEST_ENVIRONMENT, UPDP_CHECK_DRIVERSTORE, NULL, Again, &Length);
        ok(hr == S_OK, "UploadPrinterDriverPackageW(%S) returned 0x%lx\n", TEST_ENVIRONMENT, hr);
        if (hr == S_OK)
            ok(_wcsicmp(Again, StoreInf) == 0, "Upload for %S returned %S\n", TEST_ENVIRONMENT, Again);
    }

    TestSharedInf(InfPath, StoreInf);

    {
        WCHAR StoreDir[MAX_PATH], StoreFile[MAX_PATH], SourceFile[MAX_PATH], Again[MAX_PATH];
        static const char Changed[] = "changed in the store\r\n";
        PWSTR Last;

        StringCchCopyW(StoreDir, ARRAYSIZE(StoreDir), StoreInf);
        Last = wcsrchr(StoreDir, L'\\');
        if (Last)
            *Last = UNICODE_NULL;
        StringCchPrintfW(StoreFile, ARRAYSIZE(StoreFile), L"%s\\TESTPKG.DAT", StoreDir);
        ok(DeleteFileW(StoreFile), "Deleting %S failed with %lu\n", StoreFile, GetLastError());
        ok(WriteTestFile(StoreDir, L"TESTPKG.HLP", Changed, sizeof(Changed) - 1), "Changing TESTPKG.HLP failed\n");

        Length = ARRAYSIZE(Again);
        hr = UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_UPLOAD_ALWAYS, NULL, Again, &Length);
        ok(hr == S_OK, "UploadPrinterDriverPackageW returned 0x%lx\n", hr);
        if (hr == S_OK)
            ok(_wcsicmp(Again, StoreInf) == 0, "Forced upload returned %S\n", Again);
        ok(GetFileAttributesW(StoreFile) != INVALID_FILE_ATTRIBUTES, "%S was not copied again\n", StoreFile);
        StringCchPrintfW(StoreFile, ARRAYSIZE(StoreFile), L"%s\\TESTPKG.HLP", StoreDir);
        StringCchPrintfW(SourceFile, ARRAYSIZE(SourceFile), L"%s\\TESTPKG.HLP", Dir);
        ok(FilesMatch(StoreFile, SourceFile), "%S was not copied again\n", StoreFile);
    }

    {
        WCHAR StoreFile[MAX_PATH], Original[MAX_PATH], Removed[MAX_PATH], Again[MAX_PATH];
        static const char Text[] = "LiberNT package test file\r\n";
        static const char Changed[] = "changed in the source\r\n";
        PWSTR Last = wcsrchr(StoreInf, L'\\');
        WIN32_FIND_DATAW Find;
        HANDLE hFind;

        StringCchPrintfW(StoreFile, ARRAYSIZE(StoreFile), L"%.*s\\TESTPKG.HLP", (int)(Last - StoreInf), StoreInf);
        StringCchPrintfW(Original, ARRAYSIZE(Original), L"%s\\TESTPKG.GPD", Dir);
        StringCchPrintfW(Removed, ARRAYSIZE(Removed), L"%s\\TESTPKG.DAT", Dir);
        ok(WriteTestFile(Dir, L"TESTPKG.HLP", Changed, sizeof(Changed) - 1), "Changing the source TESTPKG.HLP failed\n");
        ok(DeleteFileW(Removed), "Deleting %S failed with %lu\n", Removed, GetLastError());

        Length = ARRAYSIZE(Again);
        hr = UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_UPLOAD_ALWAYS, NULL, Again, &Length);
        ok(hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), "UploadPrinterDriverPackageW returned 0x%lx\n", hr);
        ok(GetFileAttributesW(StoreInf) != INVALID_FILE_ATTRIBUTES, "%S is gone after a failed upload\n", StoreInf);
        ok(FilesMatch(StoreFile, Original), "%S was replaced by a failed upload\n", StoreFile);
        StringCchPrintfW(StoreFile, ARRAYSIZE(StoreFile), L"%.*s\\TESTPKG.DAT", (int)(Last - StoreInf), StoreInf);
        ok(FilesMatch(StoreFile, Original), "%S was lost in a failed upload\n", StoreFile);

        StringCchPrintfW(StoreFile, ARRAYSIZE(StoreFile), L"%.*s.stage-*", (int)(Last - StoreInf), StoreInf);
        hFind = FindFirstFileW(StoreFile, &Find);
        ok(hFind == INVALID_HANDLE_VALUE, "%S was left behind\n", hFind == INVALID_HANDLE_VALUE ? L"" : Find.cFileName);
        if (hFind != INVALID_HANDLE_VALUE)
            FindClose(hFind);

        ok(WriteTestFile(Dir, L"TESTPKG.HLP", Text, sizeof(Text) - 1), "Restoring TESTPKG.HLP failed\n");
        ok(WriteTestFile(Dir, L"TESTPKG.DAT", Text, sizeof(Text) - 1), "Restoring TESTPKG.DAT failed\n");
    }

    TestStoreReplacement(Dir, InfPath, StoreInf);
    TestRemovedOptionalFile(Dir, InfPath, StoreInf);

    hr = InstallPrinterDriverFromPackageW(NULL, StoreInf, BROKEN_DRIVER_NAME, NULL, 0);
    ok(hr == HRESULT_FROM_WIN32(ERROR_SECTION_NOT_FOUND), "InstallPrinterDriverFromPackageW returned 0x%lx\n", hr);
    {
        HKEY hBroken = OpenDriverKey(BROKEN_DRIVER_NAME);
        ok(hBroken == NULL, "Driver %S is registered\n", BROKEN_DRIVER_NAME);
        if (hBroken)
            RegCloseKey(hBroken);
    }

    hr = InstallPrinterDriverFromPackageW(NULL, StoreInf, NEEDS_DRIVER_NAME, NULL, IPDFP_COPY_ALL_FILES);
    ok(hr == S_OK, "InstallPrinterDriverFromPackageW returned 0x%lx\n", hr);
    {
        WCHAR Value[MAX_PATH * 2];
        DWORD Size = sizeof(Value);
        HKEY hNeeds = OpenDriverKey(NEEDS_DRIVER_NAME);

        ok(hNeeds != NULL, "Driver %S is not registered\n", NEEDS_DRIVER_NAME);
        if (hNeeds)
        {
            ZeroMemory(Value, sizeof(Value));
            ok(RegQueryValueExW(hNeeds, L"Dependent Files", NULL, NULL, (PBYTE)Value, &Size) == ERROR_SUCCESS,
               "No Dependent Files\n");
            for (Dependent = Value; *Dependent && _wcsicmp(Dependent, L"TESTPKG.DAT"); Dependent += wcslen(Dependent) + 1);
            ok(*Dependent != UNICODE_NULL, "TESTPKG.DAT from NEEDS_B is not a dependent file\n");
            Size = sizeof(Value);
            ok(RegQueryValueExW(hNeeds, L"InfPath", NULL, NULL, (PBYTE)Value, &Size) == ERROR_SUCCESS &&
               !_wcsicmp(Value, StoreInf), "InfPath is %S\n", Value);
            RegCloseKey(hNeeds);
        }
    }

    hr = InstallPrinterDriverFromPackageW(NULL, StoreInf, L"No Such Printer", NULL, 0);
    ok(hr == HRESULT_FROM_WIN32(ERROR_UNKNOWN_PRINTER_DRIVER), "InstallPrinterDriverFromPackageW returned 0x%lx\n", hr);

    {
        WCHAR Slashed[MAX_PATH], Value[MAX_PATH];
        DWORD Size = sizeof(Value);
        HKEY hNeeds;
        PWSTR Next;

        StringCchCopyW(Slashed, ARRAYSIZE(Slashed), StoreInf);
        for (Next = Slashed; *Next; Next++)
        {
            if (*Next == L'\\')
                *Next = L'/';
        }
        hr = InstallPrinterDriverFromPackageW(NULL, Slashed, NEEDS_DRIVER_NAME, NULL, IPDFP_COPY_ALL_FILES);
        ok(hr == S_OK, "InstallPrinterDriverFromPackageW(%S) returned 0x%lx\n", Slashed, hr);
        hNeeds = OpenDriverKey(NEEDS_DRIVER_NAME);
        ok(hNeeds != NULL, "Driver %S is not registered\n", NEEDS_DRIVER_NAME);
        if (hNeeds)
        {
            ok(RegQueryValueExW(hNeeds, L"InfPath", NULL, NULL, (PBYTE)Value, &Size) == ERROR_SUCCESS &&
               !_wcsicmp(Value, StoreInf), "InfPath is %S\n", Value);
            RegCloseKey(hNeeds);
        }
    }

    {
        WCHAR DriverDir[MAX_PATH];
        DWORD Size = sizeof(DriverDir);
        static const char Keep[] = "not the package file\r\n";

        if (GetPrinterDriverDirectoryW(NULL, NULL, 1, (PBYTE)DriverDir, Size, &Size))
            ok(WriteTestFile(DriverDir, L"TESTREN.DAT", Keep, sizeof(Keep) - 1), "Cannot write TESTREN.DAT\n");
    }

    hr = InstallPrinterDriverFromPackageW(NULL, StoreInf, TEST_DRIVER_NAME, NULL, IPDFP_COPY_ALL_FILES);
    ok(hr == S_OK, "InstallPrinterDriverFromPackageW returned 0x%lx\n", hr);

    ok(DriverFileExists(L"TESTDRV.DLL"), "TESTDRV.DLL was not copied\n");
    ok(DriverFileExists(L"TESTUI.DLL"), "TESTUI.DLL was not copied\n");
    ok(DriverFileExists(L"TESTPKG.GPD"), "TESTPKG.GPD was not copied\n");
    ok(DriverFileExists(L"TESTPKG.DAT"), "TESTPKG.DAT was not copied\n");

    ok(DriverFileExists(L"TESTREN.DAT"), "TESTREN.DAT was not copied\n");
    {
        WCHAR DriverDir[MAX_PATH], Installed[MAX_PATH], Packaged[MAX_PATH], Kept[MAX_PATH];
        DWORD Size = sizeof(DriverDir), Read = 0;
        WIN32_FIND_DATAW Find;
        HANDLE hFind, hKept;
        char Buffer[64] = "";

        if (GetPrinterDriverDirectoryW(NULL, NULL, 1, (PBYTE)DriverDir, Size, &Size))
        {
            StringCchPrintfW(Installed, ARRAYSIZE(Installed), L"%s\\3\\TESTREN.DAT", DriverDir);
            StringCchPrintfW(Packaged, ARRAYSIZE(Packaged), L"%s\\TESTPKG.DAT", Dir);
            ok(FilesMatch(Installed, Packaged), "TESTREN.DAT is not TESTPKG.DAT\n");

            StringCchPrintfW(Kept, ARRAYSIZE(Kept), L"%s\\TESTREN.DAT", DriverDir);
            hKept = CreateFileW(Kept, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            ok(hKept != INVALID_HANDLE_VALUE, "%S was deleted (%lu)\n", Kept, GetLastError());
            if (hKept != INVALID_HANDLE_VALUE)
            {
                ReadFile(hKept, Buffer, sizeof(Buffer) - 1, &Read, NULL);
                CloseHandle(hKept);
                ok(Read == 22 && !memcmp(Buffer, "not the package file", 20), "%S was overwritten\n", Kept);
            }
            DeleteFileW(Kept);

            StringCchPrintfW(Kept, ARRAYSIZE(Kept), L"%s\\pkgstage-*", DriverDir);
            hFind = FindFirstFileW(Kept, &Find);
            ok(hFind == INVALID_HANDLE_VALUE, "%S was left behind\n", hFind == INVALID_HANDLE_VALUE ? L"" : Find.cFileName);
            if (hFind != INVALID_HANDLE_VALUE)
                FindClose(hFind);
        }
    }

    {
        WCHAR Key[MAX_PATH], Value[MAX_PATH * 2];
        DWORD Size;
        HKEY hKey = NULL;

        StringCchPrintfW(Key, ARRAYSIZE(Key), L"%s\\%s", TEST_DRIVERS_KEY, TEST_DRIVER_NAME);
        ok(RegOpenKeyExW(HKEY_LOCAL_MACHINE, Key, 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS,
           "Driver %S is not registered\n", TEST_DRIVER_NAME);
        if (!hKey)
        {
            skip("The driver is not registered\n");
            DeleteTestDriver();
            DeletePrinterDriverPackageW(NULL, StoreInf, NULL);
            DeleteTestPackage(Dir);
            return;
        }
        Size = sizeof(Value);
        ok(RegQueryValueExW(hKey, L"Driver", NULL, NULL, (PBYTE)Value, &Size) == ERROR_SUCCESS &&
           !_wcsicmp(Value, L"TESTDRV.DLL"), "Driver is %S\n", Value);
        Size = sizeof(Value);
        ok(RegQueryValueExW(hKey, L"Configuration File", NULL, NULL, (PBYTE)Value, &Size) == ERROR_SUCCESS &&
           !_wcsicmp(Value, L"TESTUI.DLL"), "Configuration File is %S\n", Value);
        Size = sizeof(Value);
        ok(RegQueryValueExW(hKey, L"Data File", NULL, NULL, (PBYTE)Value, &Size) == ERROR_SUCCESS &&
           !_wcsicmp(Value, L"TESTPKG.GPD"), "Data File is %S\n", Value);
        Size = sizeof(Value);
        ok(RegQueryValueExW(hKey, L"Help File", NULL, NULL, (PBYTE)Value, &Size) == ERROR_SUCCESS &&
           !_wcsicmp(Value, L"TESTPKG.HLP"), "Help File is %S\n", Value);
        Size = sizeof(Value);
        ZeroMemory(Value, sizeof(Value));
        ok(RegQueryValueExW(hKey, L"Dependent Files", NULL, NULL, (PBYTE)Value, &Size) == ERROR_SUCCESS,
           "No Dependent Files\n");
        for (Dependent = Value; *Dependent; Dependent += wcslen(Dependent) + 1)
        {
            if (!_wcsicmp(Dependent, L"TESTPKG.DAT"))
                DatFound = TRUE;
        }
        ok(DatFound, "TESTPKG.DAT is not a dependent file\n");
        for (Dependent = Value; *Dependent && _wcsicmp(Dependent, L"TESTREN.DAT"); Dependent += wcslen(Dependent) + 1);
        ok(*Dependent != UNICODE_NULL, "TESTREN.DAT is not a dependent file\n");
        Size = sizeof(Value);
        ok(RegQueryValueExW(hKey, L"InfPath", NULL, NULL, (PBYTE)Value, &Size) == ERROR_SUCCESS &&
           !_wcsicmp(Value, StoreInf), "InfPath is %S\n", Value);
        RegCloseKey(hKey);
    }

    hr = DeletePrinterDriverPackageW(NULL, StoreInf, NULL);
    ok(hr == HRESULT_FROM_WIN32(ERROR_PRINTER_DRIVER_PACKAGE_IN_USE), "DeletePrinterDriverPackageW returned 0x%lx\n", hr);

    {
        WCHAR Other[MAX_PATH];
        PWSTR Last = wcsrchr(StoreInf, L'\\');

        if (Last && SUCCEEDED(StringCchPrintfW(Other, ARRAYSIZE(Other), L"%.*s\\.%s", (int)(Last - StoreInf), StoreInf, Last)))
        {
            hr = DeletePrinterDriverPackageW(NULL, Other, NULL);
            ok(hr == HRESULT_FROM_WIN32(ERROR_PRINTER_DRIVER_PACKAGE_IN_USE),
               "DeletePrinterDriverPackageW(%S) returned 0x%lx\n", Other, hr);
        }

        StringCchCopyW(Other, ARRAYSIZE(Other), StoreInf);
        _wcsupr(Other);
        hr = DeletePrinterDriverPackageW(NULL, Other, NULL);
        ok(hr == HRESULT_FROM_WIN32(ERROR_PRINTER_DRIVER_PACKAGE_IN_USE),
           "DeletePrinterDriverPackageW(%S) returned 0x%lx\n", Other, hr);

        hr = DeletePrinterDriverPackageW(NULL, InfPath, NULL);
        ok(hr == HRESULT_FROM_WIN32(ERROR_PRINTER_DRIVER_PACKAGE_IN_USE),
           "DeletePrinterDriverPackageW(%S) returned 0x%lx\n", InfPath, hr);
        ok(GetFileAttributesW(StoreInf) != INVALID_FILE_ATTRIBUTES, "%S was deleted while in use\n", StoreInf);

        if (Last && SUCCEEDED(StringCchPrintfW(Other, ARRAYSIZE(Other), L"%.*s\\TESTPKG.GPD", (int)(Last - StoreInf), StoreInf)))
        {
            hr = DeletePrinterDriverPackageW(NULL, Other, NULL);
            ok(FAILED(hr), "DeletePrinterDriverPackageW(%S) returned 0x%lx\n", Other, hr);
            ok(GetFileAttributesW(StoreInf) != INVALID_FILE_ATTRIBUTES, "%S was deleted through %S\n", StoreInf, Other);
        }
        if (Last && SUCCEEDED(StringCchPrintfW(Other, ARRAYSIZE(Other), L"%.*s", (int)(Last - StoreInf), StoreInf)))
        {
            hr = DeletePrinterDriverPackageW(NULL, Other, NULL);
            ok(FAILED(hr), "DeletePrinterDriverPackageW(%S) returned 0x%lx\n", Other, hr);
            ok(GetFileAttributesW(StoreInf) != INVALID_FILE_ATTRIBUTES, "%S was deleted through %S\n", StoreInf, Other);
        }
    }

    TestPackageLock(InfPath, StoreInf);

    DeleteTestDriver();
    TestConcurrentInstall(InfPath, StoreInf);

    {
        WCHAR Other[MAX_PATH];

        StringCchPrintfW(Other, ARRAYSIZE(Other), L"%s\\TESTPKG.GPD", Dir);
        if (CopyFileW(Other, StoreInf, FALSE))
        {
            hr = DeletePrinterDriverPackageW(NULL, StoreInf, NULL);
            ok(FAILED(hr), "DeletePrinterDriverPackageW returned 0x%lx for an INF that is not the one the directory is named after\n", hr);
            ok(GetFileAttributesW(StoreInf) != INVALID_FILE_ATTRIBUTES, "%S was deleted\n", StoreInf);
            ok(CopyFileW(InfPath, StoreInf, FALSE), "Restoring %S failed with %lu\n", StoreInf, GetLastError());
        }
        else
        {
            skip("Cannot replace %S (%lu)\n", StoreInf, GetLastError());
        }
    }

    TestHeldPackageDelete(InfPath, StoreInf);
    TestFailedPackageDelete(InfPath, StoreInf);

    hr = DeletePrinterDriverPackageW(NULL, StoreInf, NULL);
    ok(hr == S_OK, "DeletePrinterDriverPackageW returned 0x%lx\n", hr);
    ok(GetFileAttributesW(StoreInf) == INVALID_FILE_ATTRIBUTES, "%S still exists\n", StoreInf);

    DeleteTestPackage(Dir);
}
