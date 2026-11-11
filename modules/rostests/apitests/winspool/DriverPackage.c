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
#include <wingdi.h>
#include <winreg.h>
#include <winspool.h>
#include <strsafe.h>
#include <drvpkglock.h>

#define ERROR_SECTION_NOT_FOUND (APPLICATION_ERROR_MASK | ERROR_SEVERITY_ERROR | 0x101)

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
                                    L"TESTREN.DAT", L"TESTROLL.DAT" };
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

static const char IncludeInf[] =
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
    "\"LiberNT Package Include Printer\"=TESTINC,LiberNT_Package_Include\r\n"
    "\r\n"
    "[TESTINC]\r\n"
    "Include=lntprncmn.inf\r\n"
    "Needs=TESTINC_COMMON\r\n"
    "\r\n"
    "[DestinationDirs]\r\n"
    "DefaultDestDir=66000\r\n"
    "\r\n"
    "[SourceDisksNames]\r\n"
    "1=\"Disk\",,,\r\n"
    "\r\n"
    "[SourceDisksFiles]\r\n"
    "TESTINC.DLL=1\r\n"
    "TESTINC0.DAT=1\r\n"
    "TESTINC1.DAT=1\r\n";

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
    WCHAR SystemInfDir[MAX_PATH];
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
    if (Created && IncludeName)
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
    WCHAR Fresh[MAX_PATH], Path[MAX_PATH], Value[MAX_PATH] = L"";
    PWSTR DataFile = Test->Info.pDataFile, ConfigFile = Test->Info.pConfigFile;
    DWORD Size = sizeof(Path);
    WIN32_FIND_DATAW Find;
    HANDLE hFind;
    HKEY hKey;

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
    TestOtherEnvironment();

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

    hr = DeletePrinterDriverPackageW(NULL, StoreInf, NULL);
    ok(hr == S_OK, "DeletePrinterDriverPackageW returned 0x%lx\n", hr);
    ok(GetFileAttributesW(StoreInf) == INVALID_FILE_ATTRIBUTES, "%S still exists\n", StoreInf);

    DeleteTestPackage(Dir);
}
