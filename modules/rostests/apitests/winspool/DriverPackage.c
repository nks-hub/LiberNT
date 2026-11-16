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
#include <winnls.h>
#include <winioctl.h>
#include <wingdi.h>
#include <winreg.h>
#include <winspool.h>
#include <winver.h>
#include <wincrypt.h>
#include <mscat.h>
#include <mssip.h>
#include <lm.h>
#include <strsafe.h>
#include <versionhelpers.h>
#include <drvpkglock.h>
#include <wine/mssign.h>

#define ERROR_SECTION_NOT_FOUND (APPLICATION_ERROR_MASK | ERROR_SEVERITY_ERROR | 0x101)
#define ERROR_CLASS_MISMATCH (APPLICATION_ERROR_MASK | ERROR_SEVERITY_ERROR | 0x201)
#define ERROR_GENERAL_SYNTAX (APPLICATION_ERROR_MASK | ERROR_SEVERITY_ERROR | 3)
#define SP_COPY_NOOVERWRITE 0x0000008

BOOL WINAPI SetupCopyOEMInfW(PCWSTR SourceInfFileName, PCWSTR OEMSourceMediaLocation, DWORD OEMSourceMediaType, DWORD CopyStyle,
                             PWSTR DestinationInfFileName, DWORD DestinationInfFileNameSize, PDWORD RequiredSize,
                             PWSTR *DestinationInfFileNameComponent);
BOOL WINAPI SetupUninstallOEMInfW(PCWSTR InfFileName, DWORD Flags, PVOID Reserved);

#define TEST_CATALOG L"lntprn.cat"

/* Windows 11 installs a driver file whose version resource says 0.3 and whose DrvQueryDriverInfo tells that it runs in user mode */
static WCHAR TestDriverFile[MAX_PATH];

static BOOL
FindTestDriverFile(VOID)
{
    PWSTR Last;

    if (!GetModuleFileNameW(NULL, TestDriverFile, ARRAYSIZE(TestDriverFile)))
        return FALSE;
    Last = wcsrchr(TestDriverFile, L'\\');
    if (!Last)
        return FALSE;
    Last[1] = UNICODE_NULL;
    return SUCCEEDED(StringCchCatW(TestDriverFile, ARRAYSIZE(TestDriverFile), L"winspool_apitest_drv.dll")) &&
           GetFileAttributesW(TestDriverFile) != INVALID_FILE_ATTRIBUTES;
}

static BOOL
CopyTestDriverFile(PCWSTR Dir, PCWSTR Name)
{
    WCHAR Target[MAX_PATH];

    return SUCCEEDED(StringCchPrintfW(Target, ARRAYSIZE(Target), L"%s\\%s", Dir, Name)) && CopyFileW(TestDriverFile, Target, FALSE);
}

typedef struct _TEST_SIGNER
{
    WCHAR Container[32];
    HCRYPTPROV Provider;
    PCCERT_CONTEXT Cert;
} TEST_SIGNER, *PTEST_SIGNER;

static TEST_SIGNER TrustedSigner, UntrustedSigner;

/* A self-signed certificate with its key, made the way the setupapi devinst test of Wine makes its own */
static BOOL
CreateTestSigner(PTEST_SIGNER Signer, PCWSTR Container, PCSTR Subject)
{
    BYTE Name[128], KeyId[256], PublicKey[1024], Hash[20], Encoded[2048], Serial[16];
    PCERT_PUBLIC_KEY_INFO KeyInfo = (PCERT_PUBLIC_KEY_INFO)PublicKey;
    CRYPT_ALGORITHM_IDENTIFIER Algorithm = { (PSTR)szOID_RSA_SHA1RSA };
    CRYPT_KEY_PROV_INFO ProviderInfo = { 0 };
    CERT_AUTHORITY_KEY_ID_INFO Authority;
    CERT_EXTENSION Extension;
    CERT_INFO Info = { 0 };
    WCHAR ProviderNameW[128];
    char ProviderName[128];
    HCRYPTKEY hKey;
    DWORD Size;

    ZeroMemory(Signer, sizeof(*Signer));
    StringCchCopyW(Signer->Container, ARRAYSIZE(Signer->Container), Container);

    /* The container of a run that did not finish */
    CryptAcquireContextW(&Signer->Provider, Container, NULL, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
    Signer->Provider = 0;
    if (!CryptAcquireContextW(&Signer->Provider, Container, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET) ||
        !CryptGenKey(Signer->Provider, AT_SIGNATURE, CRYPT_EXPORTABLE, &hKey))
    {
        return FALSE;
    }
    CryptDestroyKey(hKey);

    Size = sizeof(Name);
    if (!CertStrToNameA(X509_ASN_ENCODING, Subject, CERT_X500_NAME_STR, NULL, Name, &Size, NULL))
        return FALSE;
    Authority.CertIssuer.cbData = Size;
    Authority.CertIssuer.pbData = Name;

    Size = sizeof(PublicKey);
    if (!CryptExportPublicKeyInfo(Signer->Provider, AT_SIGNATURE, X509_ASN_ENCODING, KeyInfo, &Size))
        return FALSE;
    Size = sizeof(Hash);
    if (!CryptHashPublicKeyInfo(Signer->Provider, CALG_MD5, 0, X509_ASN_ENCODING, KeyInfo, Hash, &Size))
        return FALSE;
    Authority.KeyId.cbData = Size;
    Authority.KeyId.pbData = Hash;

    if (!CryptGenRandom(Signer->Provider, sizeof(Serial), Serial))
        return FALSE;
    Authority.CertSerialNumber.cbData = sizeof(Serial);
    Authority.CertSerialNumber.pbData = Serial;

    Size = sizeof(KeyId);
    if (!CryptEncodeObject(X509_ASN_ENCODING, X509_AUTHORITY_KEY_ID, &Authority, KeyId, &Size))
        return FALSE;
    Extension.pszObjId = (PSTR)szOID_AUTHORITY_KEY_IDENTIFIER;
    Extension.fCritical = TRUE;
    Extension.Value.cbData = Size;
    Extension.Value.pbData = KeyId;

    Info.dwVersion = CERT_V3;
    Info.SerialNumber = Authority.CertSerialNumber;
    Info.SignatureAlgorithm = Algorithm;
    Info.Issuer = Authority.CertIssuer;
    Info.Subject = Authority.CertIssuer;
    Info.SubjectPublicKeyInfo = *KeyInfo;
    Info.cExtension = 1;
    Info.rgExtension = &Extension;
    GetSystemTimeAsFileTime(&Info.NotBefore);
    Info.NotAfter = Info.NotBefore;
    Info.NotBefore.dwHighDateTime -= 0x100;
    Info.NotAfter.dwHighDateTime += 0x100;

    Size = sizeof(Encoded);
    if (!CryptSignAndEncodeCertificate(Signer->Provider, AT_SIGNATURE, X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED, &Info,
                                       &Algorithm, NULL, Encoded, &Size))
    {
        return FALSE;
    }
    Signer->Cert = CertCreateCertificateContext(X509_ASN_ENCODING, Encoded, Size);
    if (!Signer->Cert)
        return FALSE;

    Size = sizeof(ProviderName);
    if (!CryptGetProvParam(Signer->Provider, PP_NAME, (PBYTE)ProviderName, &Size, 0))
        return FALSE;
    MultiByteToWideChar(CP_ACP, 0, ProviderName, -1, ProviderNameW, ARRAYSIZE(ProviderNameW));
    ProviderInfo.pwszContainerName = Signer->Container;
    ProviderInfo.pwszProvName = ProviderNameW;
    ProviderInfo.dwProvType = PROV_RSA_FULL;
    ProviderInfo.dwKeySpec = AT_SIGNATURE;
    return CertSetCertificateContextProperty(Signer->Cert, CERT_KEY_PROV_INFO_PROP_ID, 0, &ProviderInfo);
}

static VOID
DeleteTestSigner(PTEST_SIGNER Signer)
{
    HCRYPTPROV Deleted;

    if (Signer->Cert)
        CertFreeCertificateContext(Signer->Cert);
    if (Signer->Provider)
    {
        CryptReleaseContext(Signer->Provider, 0);
        CryptAcquireContextW(&Deleted, Signer->Container, NULL, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
    }
    ZeroMemory(Signer, sizeof(*Signer));
}

/* Puts the certificate of the trusted signer into a store of the machine, or takes it out */
static BOOL
TrustTestSigner(PCWSTR StoreName, BOOL Trust)
{
    HCERTSTORE Store = CertOpenStore(CERT_STORE_PROV_SYSTEM_REGISTRY_W, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE, StoreName);
    PCCERT_CONTEXT Found;
    BOOL Ret = TRUE;

    if (!Store)
        return FALSE;
    if (Trust)
    {
        Ret = CertAddCertificateContextToStore(Store, TrustedSigner.Cert, CERT_STORE_ADD_REPLACE_EXISTING, NULL);
    }
    else
    {
        while ((Found = CertFindCertificateInStore(Store, X509_ASN_ENCODING, 0, CERT_FIND_EXISTING, TrustedSigner.Cert, NULL)) != NULL)
            CertDeleteCertificateFromStore(Found);
    }
    CertCloseStore(Store, 0);
    return Ret;
}

static VOID
AddCatalogMember(HANDLE hCatalog, PCWSTR File)
{
    SIP_SUBJECTINFO Subject = { sizeof(Subject) };
    PSIP_INDIRECT_DATA Data;
    WCHAR Tag[2 * 64 + 1];
    DWORD Size = 0, i;
    GUID Type;

    if (!CryptSIPRetrieveSubjectGuidForCatalogFile(File, NULL, &Type))
        return;
    Subject.pgSubjectType = &Type;
    Subject.pwsFileName = File;
    Subject.DigestAlgorithm.pszObjId = (PSTR)szOID_OIWSEC_sha1;
    if (!CryptSIPCreateIndirectData(&Subject, &Size, NULL))
        return;
    Data = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size);
    if (!Data)
        return;

    if (CryptSIPCreateIndirectData(&Subject, &Size, Data) && Data->Digest.cbData <= 64)
    {
        for (i = 0; i < Data->Digest.cbData; i++)
            StringCchPrintfW(Tag + i * 2, 3, L"%02X", Data->Digest.pbData[i]);
        CryptCATPutMemberInfo(hCatalog, (PWSTR)File, Tag, &Type, 0, Size, (PBYTE)Data);
    }
    HeapFree(GetProcessHeap(), 0, Data);
}

static VOID
AddCatalogMembers(HANDLE hCatalog, PCWSTR Dir)
{
    WCHAR Path[MAX_PATH];
    WIN32_FIND_DATAW Find;
    HANDLE hFind;
    SIZE_T Length;

    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\*", Dir);
    hFind = FindFirstFileW(Path, &Find);
    if (hFind == INVALID_HANDLE_VALUE)
        return;

    do
    {
        Length = wcslen(Find.cFileName);
        if (!wcscmp(Find.cFileName, L".") || !wcscmp(Find.cFileName, L"..") ||
            (Length > 4 && !_wcsicmp(Find.cFileName + Length - 4, L".cat")) ||
            FAILED(StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\%s", Dir, Find.cFileName)))
        {
            continue;
        }

        if (Find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            AddCatalogMembers(hCatalog, Path);
        else
            AddCatalogMember(hCatalog, Path);
    } while (FindNextFileW(hFind, &Find));
    FindClose(hFind);
}

static BOOL
SignTestFile(PCWSTR File, PCCERT_CONTEXT Cert)
{
    static HRESULT (WINAPI *pSignerSign)(SIGNER_SUBJECT_INFO *, SIGNER_CERT *, SIGNER_SIGNATURE_INFO *, SIGNER_PROVIDER_INFO *,
                                         PCWSTR, CRYPT_ATTRIBUTES *, PVOID);
    SIGNER_ATTR_AUTHCODE Authcode = { sizeof(Authcode) };
    SIGNER_SIGNATURE_INFO Signature = { sizeof(Signature) };
    SIGNER_SUBJECT_INFO Subject = { sizeof(Subject) };
    SIGNER_CERT_STORE_INFO Store = { sizeof(Store) };
    SIGNER_FILE_INFO FileInfo = { sizeof(FileInfo) };
    SIGNER_CERT CertInfo = { sizeof(CertInfo) };
    HMODULE hSign;
    DWORD Index = 0;

    if (!pSignerSign)
    {
        hSign = LoadLibraryW(L"mssign32.dll");
        if (hSign)
            pSignerSign = (PVOID)GetProcAddress(hSign, "SignerSign");
        if (!pSignerSign)
            return FALSE;
    }

    Subject.dwSubjectChoice = 1;
    Subject.pdwIndex = &Index;
    Subject.pSignerFileInfo = &FileInfo;
    FileInfo.pwszFileName = File;
    CertInfo.dwCertChoice = SIGNER_CERT_STORE;
    CertInfo.pCertStoreInfo = &Store;
    Store.pSigningCert = Cert;
    Signature.algidHash = CALG_SHA_256;
    Signature.dwAttrChoice = SIGNER_AUTHCODE_ATTR;
    Signature.pAttrAuthcode = &Authcode;
    Authcode.pwszName = L"";
    Authcode.pwszInfo = L"";
    return pSignerSign(&Subject, &CertInfo, &Signature, NULL, NULL, NULL, NULL) == S_OK;
}

/* Makes the catalog of the files that are in the directory now; without a certificate it stays unsigned */
static BOOL
SignTestPackage(PCWSTR Dir, PCCERT_CONTEXT Cert)
{
    WCHAR Path[MAX_PATH];
    HANDLE hCatalog;
    BOOL Ret;

    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\" TEST_CATALOG, Dir);
    hCatalog = CryptCATOpen(Path, CRYPTCAT_OPEN_CREATENEW, 0, CRYPTCAT_VERSION_1, 0);
    if (hCatalog == INVALID_HANDLE_VALUE)
        return FALSE;
    AddCatalogMembers(hCatalog, Dir);
    Ret = CryptCATPersistStore(hCatalog);
    CryptCATClose(hCatalog);
    return Ret && (!Cert || SignTestFile(Path, Cert));
}

/* Windows 11 refuses a package without a signed catalog, so every package of the temporary directory is signed as it is uploaded */
static HRESULT WINAPI
UploadSignedPackage(LPCWSTR pszServer, LPCWSTR pszInfPath, LPCWSTR pszEnvironment, DWORD dwFlags, HWND hwnd,
                    LPWSTR pszDestInfPath, PULONG pcchDestInfPath)
{
    WCHAR Temp[MAX_PATH], Dir[MAX_PATH];
    PWSTR Last, Slash;

    if (pszInfPath && (dwFlags & (UPDP_UPLOAD_ALWAYS | UPDP_CHECK_DRIVERSTORE)) != UPDP_CHECK_DRIVERSTORE &&
        GetTempPathW(ARRAYSIZE(Temp), Temp) &&
        !_wcsnicmp(pszInfPath, Temp, wcslen(Temp)) && GetFileAttributesW(pszInfPath) != INVALID_FILE_ATTRIBUTES &&
        SUCCEEDED(StringCchCopyW(Dir, ARRAYSIZE(Dir), pszInfPath)))
    {
        Last = wcsrchr(Dir, L'\\');
        Slash = wcsrchr(Dir, L'/');
        if (Slash > Last)
            Last = Slash;
        if (Last)
        {
            *Last = UNICODE_NULL;
            ok(SignTestPackage(Dir, TrustedSigner.Cert), "Signing the package in %S failed with 0x%lx\n", Dir, GetLastError());
        }
    }
    return UploadPrinterDriverPackageW(pszServer, pszInfPath, pszEnvironment, dwFlags, hwnd, pszDestInfPath, pcchDestInfPath);
}

static HRESULT (WINAPI *UploadUnsignedPackage)(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, HWND, LPWSTR, PULONG) = UploadPrinterDriverPackageW;
#define UploadPrinterDriverPackageW UploadSignedPackage

/* The catalogs that UploadSignedPackage left in the package directories, and the directories that are empty without them */
static VOID
DeleteTestCatalogs(VOID)
{
    WCHAR Temp[MAX_PATH], Path[MAX_PATH];
    WIN32_FIND_DATAW Find;
    HANDLE hFind;

    if (!GetTempPathW(ARRAYSIZE(Temp), Temp))
        return;
    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%slntprn*", Temp);
    hFind = FindFirstFileW(Path, &Find);
    if (hFind == INVALID_HANDLE_VALUE)
        return;

    do
    {
        if (!(Find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            continue;
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s%s\\" TEST_CATALOG, Temp, Find.cFileName);
        DeleteFileW(Path);
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s%s", Temp, Find.cFileName);
        RemoveDirectoryW(Path);
    } while (FindNextFileW(hFind, &Find));
    FindClose(hFind);
}

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

static VOID
RemoveTestDriver(PCWSTR Name)
{
    DeletePrinterDriverExW(NULL, NULL, (PWSTR)Name, DPD_DELETE_UNUSED_FILES, 0);
}

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
    "CatalogFile=lntprn.cat\r\n"
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
    "CopyFiles=@TESTPKG.GPD,TESTPKG_FILES\r\n"
    "DataFile=TESTPKG.GPD\r\n"
    "DataSection=TESTPKG_DATA\r\n"
    "Needs=NEEDS_A\r\n"
    "\r\n"
    "[NEEDS_A]\r\n"
    "Needs=NEEDS_B\r\n"
    "\r\n"
    "[NEEDS_B]\r\n"
    "Needs=NEEDS_A\r\n"
    "CopyFiles=@TESTNEED.DAT\r\n"
    "\r\n"
    "[TESTBROKEN]\r\n"
    "CopyFiles=@TESTPKG.GPD,TESTPKG_FILES\r\n"
    "DataFile=TESTPKG.GPD\r\n"
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
    "TESTPKG.DAT=1\r\n"
    "TESTNEED.DAT=1\r\n";

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
    WCHAR Source[MAX_PATH], Target[MAX_PATH];
    static const char Text[] = "LiberNT package test file\r\n";

    GetTempPathW(MAX_PATH, Dir);
    StringCchCatW(Dir, MAX_PATH, L"lntprnpkg");
    CreateDirectoryW(Dir, NULL);
    StringCchPrintfW(InfPath, MAX_PATH, L"%s\\lntprnpkg.inf", Dir);

    StringCchCopyW(Source, ARRAYSIZE(Source), TestDriverFile);
    StringCchPrintfW(Target, ARRAYSIZE(Target), L"%s\\TESTDRV.DLL", Dir);
    if (!CopyFileW(Source, Target, FALSE))
        return FALSE;
    StringCchPrintfW(Target, ARRAYSIZE(Target), L"%s\\TESTUI.DLL", Dir);
    if (!CopyFileW(Source, Target, FALSE))
        return FALSE;

    return WriteTestFile(Dir, L"lntprnpkg.inf", TestInf, sizeof(TestInf) - 1) &&
           WriteTestFile(Dir, L"TESTPKG.GPD", Text, sizeof(Text) - 1) &&
           WriteTestFile(Dir, L"TESTPKG.HLP", Text, sizeof(Text) - 1) &&
           WriteTestFile(Dir, L"TESTPKG.DAT", Text, sizeof(Text) - 1) &&
           WriteTestFile(Dir, L"TESTNEED.DAT", Text, sizeof(Text) - 1);
}

static VOID
DeleteTestPackage(PCWSTR Dir)
{
    static const PCWSTR Names[] = { L"lntprnpkg.inf", L"TESTPKG.GPD", L"TESTDRV.DLL", L"TESTUI.DLL",
                                    L"TESTPKG.HLP", L"TESTPKG.DAT", L"TESTNEED.DAT" };
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

/* The whole files: the test INFs have the same first 253 bytes */
static BOOL
FilesMatch(PCWSTR First, PCWSTR Second)
{
    char A[4096], B[4096];
    DWORD ReadA = 0, ReadB = 0, Total = 0;
    HANDLE hA, hB;
    BOOL Same = FALSE;

    hA = CreateFileW(First, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    hB = CreateFileW(Second, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    while (hA != INVALID_HANDLE_VALUE && hB != INVALID_HANDLE_VALUE &&
           ReadFile(hA, A, sizeof(A), &ReadA, NULL) && ReadFile(hB, B, sizeof(B), &ReadB, NULL) &&
           ReadA == ReadB && memcmp(A, B, ReadA) == 0)
    {
        if (!ReadA)
        {
            Same = Total != 0;
            break;
        }
        Total += ReadA;
    }
    if (hA != INVALID_HANDLE_VALUE)
        CloseHandle(hA);
    if (hB != INVALID_HANDLE_VALUE)
        CloseHandle(hB);
    return Same;
}

static VOID
DeleteTestDriver(VOID)
{
    static const PCWSTR Names[] = { L"TESTDRV.DLL", L"TESTUI.DLL", L"TESTPKG.GPD", L"TESTPKG.HLP", L"TESTPKG.DAT",
                                    L"TESTREN.DAT", L"TESTROLL.DAT", L"TESTROLL.DAT.apd-new", L"TESTROLL.DAT.apd-old" };
    static const PCWSTR Drivers[] = { TEST_DRIVER_NAME, NEEDS_DRIVER_NAME, BROKEN_DRIVER_NAME, LOCK_DRIVER_NAME };
    WCHAR Dir[MAX_PATH], Path[MAX_PATH];
    DWORD Size = sizeof(Dir);
    UINT i;

    for (i = 0; i < ARRAYSIZE(Drivers); i++)
        RemoveTestDriver(Drivers[i]);

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
    "CatalogFile=lntprn.cat\r\n"
    "\r\n"
    "[Manufacturer]\r\n"
    "\"LiberNT\"=Models,NTamd64,NTx86,NTarm64\r\n"
    "\r\n"
    "[Models.NTamd64]\r\n"
    "\"LiberNT Package Missing Printer\"=TESTMISS,LiberNT_Package_Missing\r\n"
    "[Models.NTx86]\r\n"
    "\"LiberNT Package Missing Printer\"=TESTMISS,LiberNT_Package_Missing\r\n"
    "[Models.NTarm64]\r\n"
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
    "CatalogFile=lntprn.cat\r\n"
    "\r\n"
    "[Manufacturer]\r\n"
    "\"LiberNT\"=Models,NTamd64,NTx86,NTarm64\r\n"
    "\r\n"
    "[Models.NTamd64]\r\n"
    "\"LiberNT Package Needs Missing Printer\"=TESTNM,LiberNT_Package_Needs_Missing\r\n"
    "[Models.NTx86]\r\n"
    "\"LiberNT Package Needs Missing Printer\"=TESTNM,LiberNT_Package_Needs_Missing\r\n"
    "[Models.NTarm64]\r\n"
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
    "CatalogFile=lntprn.cat\r\n"
    "\r\n"
    "[Manufacturer]\r\n"
    "\"LiberNT\"=Models,NTamd64,NTx86,NTarm64\r\n"
    "\r\n"
    "[Models.NTamd64]\r\n"
    "\"LiberNT Package Unlisted Printer\"=TESTUNL,LiberNT_Package_Unlisted\r\n"
    "[Models.NTx86]\r\n"
    "\"LiberNT Package Unlisted Printer\"=TESTUNL,LiberNT_Package_Unlisted\r\n"
    "[Models.NTarm64]\r\n"
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
    "CatalogFile=lntprn.cat\r\n"
    "\r\n"
    "[Manufacturer]\r\n"
    "\"LiberNT\"=Models,NTamd64,NTx86,NTarm64\r\n"
    "\r\n"
    "[Models.NTamd64]\r\n"
    "\"LiberNT Package Escape Printer\"=TESTESC,LiberNT_Package_Escape\r\n"
    "[Models.NTx86]\r\n"
    "\"LiberNT Package Escape Printer\"=TESTESC,LiberNT_Package_Escape\r\n"
    "[Models.NTarm64]\r\n"
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
    "CatalogFile=lntprn.cat\r\n"
    "\r\n"
    "[Manufacturer]\r\n"
    "\"LiberNT\"=Models,NTamd64,NTx86,NTarm64\r\n"
    "\r\n"
    "[Models.NTamd64]\r\n"
    "\"LiberNT Package Include Escape Printer\"=TESTIES,LiberNT_Package_Include_Escape\r\n"
    "[Models.NTx86]\r\n"
    "\"LiberNT Package Include Escape Printer\"=TESTIES,LiberNT_Package_Include_Escape\r\n"
    "[Models.NTarm64]\r\n"
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
    "CatalogFile=lntprn.cat\r\n"
    "\r\n"
    "[Manufacturer]\r\n"
    "\"LiberNT\"=Models,NTamd64,NTx86,NTarm64\r\n"
    "\r\n"
    "[Models.NTamd64]\r\n"
    "\"LiberNT Package Slash Escape Printer\"=TESTSLE,LiberNT_Package_Slash_Escape\r\n"
    "[Models.NTx86]\r\n"
    "\"LiberNT Package Slash Escape Printer\"=TESTSLE,LiberNT_Package_Slash_Escape\r\n"
    "[Models.NTarm64]\r\n"
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
TestRefusedPackage(PCWSTR Name, const char *Inf, DWORD InfSize, PCWSTR Present, PCWSTR Outside, HRESULT Expected, PCWSTR Unsupported)
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
        ok(Expected == E_FAIL ? FAILED(hr) : hr == Expected, "UploadPrinterDriverPackageW(%S) returned 0x%lx\n", InfName, hr);
        if (hr == S_OK && Unsupported)
        {
            hr = InstallPrinterDriverFromPackageW(NULL, StoreInf, Unsupported, NULL, 0);
            ok(hr == HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED), "InstallPrinterDriverFromPackageW(%S) returned 0x%lx\n", Unsupported, hr);
            hr = S_OK;
        }
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

            /* Windows 11 leaves the file it was not to stage next to its staging directory */
            GetWindowsDirectoryW(Path, ARRAYSIZE(Path));
            StringCchCatW(Path, ARRAYSIZE(Path), L"\\System32\\DriverStore\\Temp\\");
            StringCchCatW(Path, ARRAYSIZE(Path), Outside);
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
    "CatalogFile=lntprn.cat\r\n"
    "\r\n"
    "[Manufacturer]\r\n"
    "\"LiberNT\"=Models,NTamd64,NTx86,NTarm64\r\n"
    "\r\n"
    "[Models.NTamd64]\r\n"
    "\"LiberNT Package Plain Printer\"=TESTPLAIN,LiberNT_Package_Plain\r\n"
    "[Models.NTx86]\r\n"
    "\"LiberNT Package Plain Printer\"=TESTPLAIN,LiberNT_Package_Plain\r\n"
    "[Models.NTarm64]\r\n"
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
    "CatalogFile=lntprn.cat\r\n"
    "\r\n"
    "[Manufacturer]\r\n"
    "\"LiberNT\"=Models,NTamd64,NTx86,NTarm64\r\n"
    "\r\n"
    "[Models.NTamd64]\r\n"
    "\"LiberNT Package Two Needs Printer\"=TESTTWO,LiberNT_Package_Two_Needs\r\n"
    "[Models.NTx86]\r\n"
    "\"LiberNT Package Two Needs Printer\"=TESTTWO,LiberNT_Package_Two_Needs\r\n"
    "[Models.NTarm64]\r\n"
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
                   "CatalogFile=lntprn.cat\r\n"
                   "\r\n"
                   "[Manufacturer]\r\n"
                   "\"LiberNT\"=Models,NTamd64,NTx86,NTarm64\r\n"
                   "\r\n"
                   "[Models.NTamd64]\r\n"
                   "\"LiberNT Package Big Printer\"=TESTBIG,LiberNT_Package_Big\r\n"
                   "[Models.NTx86]\r\n"
                   "\"LiberNT Package Big Printer\"=TESTBIG,LiberNT_Package_Big\r\n"
                   "[Models.NTarm64]\r\n"
                   "\"LiberNT Package Big Printer\"=TESTBIG,LiberNT_Package_Big\r\n"
                   "\r\n"
                   "[TESTBIG]\r\n"
                   "DriverFile=TESTBIG.DLL\r\n"
                   "ConfigFile=TESTBIG.DLL\r\n"
                   "DataFile=TESTBIG000.DAT\r\n"
                   "CopyFiles=@TESTBIG.DLL");
    for (i = 0; i < BIG_SECTIONS; i++)
    {
        StringCchPrintfA(Line, ARRAYSIZE(Line), ",TESTBIG_F%02u", i);
        StringCchCatA(BigInf, ARRAYSIZE(BigInf), Line);
    }
    StringCchCatA(BigInf, ARRAYSIZE(BigInf), "\r\n");

    for (i = 0; i < BIG_SECTIONS; i++)
    {
        StringCchPrintfA(Line, ARRAYSIZE(Line), "\r\n[TESTBIG_F%02u]\r\n", i);
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
    "CatalogFile=lntprn.cat\r\n" \
    "\r\n" \
    "[Manufacturer]\r\n" \
    "\"LiberNT\"=Models,NTamd64,NTx86,NTarm64\r\n" \
    "\r\n" \
    "[Models.NTamd64]\r\n" \
    "\"" Model "\"=TESTINC,LiberNT_Package_Include\r\n" \
    "[Models.NTx86]\r\n" \
    "\"" Model "\"=TESTINC,LiberNT_Package_Include\r\n" \
    "[Models.NTarm64]\r\n" \
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
                   PCWSTR FilePattern, UINT FileCount, PCWSTR Dependent, PCWSTR IncludeName, HRESULT Expected)
{
    WCHAR Dir[MAX_PATH], InfName[MAX_PATH], InfPath[MAX_PATH], StoreInf[MAX_PATH], Path[MAX_PATH], File[MAX_PATH];
    WCHAR IncludeDir[MAX_PATH];
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

    StringCchCopyW(Path, ARRAYSIZE(Path), TestDriverFile);
    StringCchPrintfW(File, ARRAYSIZE(File), L"%s\\%s", Dir, DriverFile);
    Created = CopyFileW(Path, File, FALSE) && WriteTestFile(Dir, InfName, Inf, InfSize);
    for (i = 0; Created && i < FileCount; i++)
    {
        StringCchPrintfW(File, ARRAYSIZE(File), FilePattern, i);
        Created = WriteTestFile(Dir, File, Text, sizeof(Text) - 1);
    }

    IncludeDir[0] = UNICODE_NULL;
    if (Created && IncludeName && wcschr(IncludeName, L'\\'))
    {
        StringCchPrintfW(IncludeDir, ARRAYSIZE(IncludeDir), L"%s\\%.*s", Dir, (int)(wcschr(IncludeName, L'\\') - IncludeName), IncludeName);
        Created = CreateDirectoryW(IncludeDir, NULL) && WriteTestFile(Dir, IncludeName, IncludedInf, sizeof(IncludedInf) - 1);
    }
    else if (Created && IncludeName)
    {
        Created = WriteTestFile(Dir, IncludeName, IncludedInf, sizeof(IncludedInf) - 1);
    }

    if (Created)
    {
        hr = UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_SILENT_UPLOAD, NULL, StoreInf, &Length);
        ok(hr == S_OK, "UploadPrinterDriverPackageW(%S) returned 0x%lx\n", InfName, hr);
        if (hr == S_OK)
        {
            hr = InstallPrinterDriverFromPackageW(NULL, StoreInf, DriverName, NULL, 0);
            ok(hr == Expected, "InstallPrinterDriverFromPackageW(%S) returned 0x%lx\n", DriverName, hr);
            for (i = 0; i < FileCount; i++)
            {
                StringCchPrintfW(File, ARRAYSIZE(File), FilePattern, i);
                ok(DriverFileExists(File) == (Expected == S_OK), "%S of %S was %s\n", File, DriverName,
                   Expected == S_OK ? "not installed" : "installed");
            }
            hKey = OpenDriverKey(DriverName);
            ok((hKey != NULL) == (Expected == S_OK), "Driver %S is %s\n", DriverName, hKey ? "registered" : "not registered");
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

            RemoveTestDriver(DriverName);
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
    }
    if (IncludeDir[0])
        RemoveDirectoryW(IncludeDir);
    DeleteFileW(InfPath);
    RemoveDirectoryW(Dir);
}

/* The INF outside the package has all that the driver needs, so only a refusal stops the installation */
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

    StringCchCopyW(Path, ARRAYSIZE(Path), TestDriverFile);
    StringCchPrintfW(StoreInf, ARRAYSIZE(StoreInf), L"%s\\TESTINC.DLL", Dir);
    if (SUCCEEDED(StringCchPrintfA(Inf, ARRAYSIZE(Inf), AbsoluteIncludeInf, Outside)) &&
        CopyFileW(Path, StoreInf, FALSE) &&
        WriteTestFile(Dir, L"lntprnabs.inf", Inf, (DWORD)strlen(Inf)) &&
        WriteTestFile(Dir, L"TESTINC0.DAT", Text, sizeof(Text) - 1) &&
        WriteTestFile(Temp, L"lntprnabsc.inf", SystemIncludedInf, sizeof(SystemIncludedInf) - 1))
    {
        hr = InstallPrinterDriverFromPackageW(NULL, InfPath, ABSOLUTE_DRIVER_NAME, NULL, 0);
        ok(hr == E_INVALIDARG, "InstallPrinterDriverFromPackageW returned 0x%lx for an INF that is not in the store\n", hr);
        hKey = OpenDriverKey(ABSOLUTE_DRIVER_NAME);
        ok(hKey == NULL, "Driver %S is registered\n", ABSOLUTE_DRIVER_NAME);
        if (hKey)
            RegCloseKey(hKey);

        /* Windows 11 uploads the package and returns ERROR_NOT_FOUND when it is to include a rooted path */
        hr = UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_SILENT_UPLOAD, NULL, StoreInf, &Length);
        ok(hr == S_OK, "UploadPrinterDriverPackageW returned 0x%lx for an INF that includes %S\n", hr, Outside);
        if (hr == S_OK)
        {
            hr = InstallPrinterDriverFromPackageW(NULL, StoreInf, ABSOLUTE_DRIVER_NAME, NULL, 0);
            ok(hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND), "InstallPrinterDriverFromPackageW returned 0x%lx for an INF that includes %S\n", hr, Outside);
            hKey = OpenDriverKey(ABSOLUTE_DRIVER_NAME);
            ok(hKey == NULL, "Driver %S is registered\n", ABSOLUTE_DRIVER_NAME);
            if (hKey)
                RegCloseKey(hKey);
            hr = DeletePrinterDriverPackageW(NULL, StoreInf, NULL);
            ok(hr == S_OK, "DeletePrinterDriverPackageW returned 0x%lx\n", hr);
        }
    }
    else
    {
        skip("Failed to create the package lntprnabs.inf (%lu)\n", GetLastError());
    }

    RemoveTestDriver(ABSOLUTE_DRIVER_NAME);
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
    "CatalogFile=lntprn.cat\r\n"
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
    WCHAR Dir[MAX_PATH], InfPath[MAX_PATH], StoreInf[MAX_PATH], Path[MAX_PATH];
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
        CopyTestDriverFile(Dir, L"bin\\" OTHER_DRIVER_FILE) &&
        WriteTestFile(Dir, L"TESTCROSS.GPD", Text, sizeof(Text) - 1))
    {
        hr = UploadPrinterDriverPackageW(NULL, InfPath, OTHER_ENVIRONMENT, UPDP_SILENT_UPLOAD, NULL, StoreInf, &Length);
        ok(hr == S_OK, "UploadPrinterDriverPackageW(%S) returned 0x%lx\n", OTHER_ENVIRONMENT, hr);
        if (hr == S_OK)
        {
            ok(wcsstr(StoreInf, L"\\lntprncross.inf_" OTHER_STORE_ARCHITECTURE L"_") != NULL,
               "%S is not a package of %S\n", StoreInf, OTHER_ENVIRONMENT);

            /* The driver file of the test is one of this machine; Windows 11 does not install it for another */
            hr = InstallPrinterDriverFromPackageW(NULL, StoreInf, CROSS_DRIVER_NAME, OTHER_ENVIRONMENT, 0);
            ok(hr == HRESULT_FROM_WIN32(ERROR_EXE_MACHINE_TYPE_MISMATCH), "InstallPrinterDriverFromPackageW(%S) returned 0x%lx\n",
               OTHER_ENVIRONMENT, hr);

            hKey = OpenDriverKey(CROSS_DRIVER_NAME);
            ok(hKey == NULL, "Driver %S is registered for %S\n", CROSS_DRIVER_NAME, TEST_ENVIRONMENT);
            if (hKey)
                RegCloseKey(hKey);

            hKey = NULL;
            ok(RegOpenKeyExW(HKEY_LOCAL_MACHINE, OTHER_DRIVER_KEY, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS,
               "Driver %S is registered for %S\n", CROSS_DRIVER_NAME, OTHER_ENVIRONMENT);
            if (hKey)
                RegCloseKey(hKey);

            hr = DeletePrinterDriverPackageW(NULL, StoreInf, TEST_ENVIRONMENT);
            ok(FAILED(hr), "DeletePrinterDriverPackageW(%S) returned 0x%lx for a package of %S\n",
               TEST_ENVIRONMENT, hr, OTHER_ENVIRONMENT);
            ok(GetFileAttributesW(StoreInf) != INVALID_FILE_ATTRIBUTES, "%S was deleted\n", StoreInf);

            RegDeleteKeyW(HKEY_LOCAL_MACHINE, OTHER_DRIVER_KEY);
            RemoveTestDriver(CROSS_DRIVER_NAME);
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
    "CatalogFile=lntprn.cat\r\n"
    "\r\n"
    "[Manufacturer]\r\n"
    "\"LiberNT\"=Models,NTamd64,NTx86,NTarm64\r\n"
    "\r\n"
    "[Models.NTamd64]\r\n"
    "\"LiberNT Package Junction Printer\"=TESTJNC,LiberNT_Package_Junction\r\n"
    "[Models.NTx86]\r\n"
    "\"LiberNT Package Junction Printer\"=TESTJNC,LiberNT_Package_Junction\r\n"
    "[Models.NTarm64]\r\n"
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
TestLinkedInf(PCWSTR InfPath, HRESULT Expected, PCSTR What)
{
    static const PCWSTR Names[] = { L"TESTPLAIN.DLL", L"TESTPLAIN.GPD" };
    WCHAR StoreInf[MAX_PATH], Dir[MAX_PATH], Path[MAX_PATH];
    ULONG Length = ARRAYSIZE(StoreInf);
    DWORD Size = sizeof(Dir);
    HRESULT hr;
    HKEY hKey;
    UINT i;

    hr = UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_SILENT_UPLOAD, NULL, StoreInf, &Length);
    ok(hr == Expected, "UploadPrinterDriverPackageW returned 0x%lx for %s\n", hr, What);
    if (hr == S_OK)
    {
        hr = DeletePrinterDriverPackageW(NULL, StoreInf, NULL);
        ok(hr == S_OK, "DeletePrinterDriverPackageW returned 0x%lx for the package uploaded from %s\n", hr, What);
    }

    hr = InstallPrinterDriverFromPackageW(NULL, InfPath, L"LiberNT Package Plain Printer", NULL, 0);
    ok(FAILED(hr), "InstallPrinterDriverFromPackageW returned 0x%lx for %s\n", hr, What);
    hKey = OpenDriverKey(L"LiberNT Package Plain Printer");
    ok(hKey == NULL, "A driver was registered from %s\n", What);
    if (hKey)
        RegCloseKey(hKey);

    RemoveTestDriver(L"LiberNT Package Plain Printer");
    if (GetPrinterDriverDirectoryW(NULL, NULL, 1, (PBYTE)Dir, Size, &Size))
    {
        for (i = 0; i < ARRAYSIZE(Names); i++)
        {
            StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\3\\%s", Dir, Names[i]);
            DeleteFileW(Path);
        }
    }
}

/* The INF takes TESTJNC.DLL from a directory of the package that is a junction to a directory outside of it. Windows 11 follows */
/* a junction and a link to a directory, and stages the file under the name of the junction; an INF that is a link it refuses */
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
        !CopyTestDriverFile(Outside, L"TESTJNC.DLL"))
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
        ok(hr == S_OK, "UploadPrinterDriverPackageW returned 0x%lx for a file behind a junction\n", hr);
        if (hr == S_OK)
        {
            StringCchPrintfW(Path, ARRAYSIZE(Path), L"%.*s\\link\\TESTJNC.DLL", (int)(wcsrchr(StoreInf, L'\\') - StoreInf), StoreInf);
            ok(GetFileAttributesW(Path) != INVALID_FILE_ATTRIBUTES, "%S was not staged\n", Path);

            hr = InstallPrinterDriverFromPackageW(NULL, StoreInf, L"LiberNT Package Junction Printer", NULL, 0);
            ok(hr == S_OK, "InstallPrinterDriverFromPackageW returned 0x%lx for a file behind a junction\n", hr);
            hKey = OpenDriverKey(L"LiberNT Package Junction Printer");
            ok(hKey != NULL, "No driver was registered with a file behind a junction\n");
            if (hKey)
                RegCloseKey(hKey);
            ok(DriverFileExists(L"TESTJNC.DLL"), "TESTJNC.DLL was not installed\n");
            RemoveTestDriver(L"LiberNT Package Junction Printer");
            hr = DeletePrinterDriverPackageW(NULL, StoreInf, NULL);
            ok(hr == S_OK, "DeletePrinterDriverPackageW returned 0x%lx\n", hr);
        }

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
            TestLinkedInf(Path, S_OK, "a package directory that is a junction");
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
            TestLinkedInf(Link, (HRESULT)ERROR_GENERAL_SYNTAX, "an INF that is a link");
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

/* Windows 11 gives a path that begins with the path of the store back as it is and stages nothing; it deletes no package there */
static VOID
TestMisplacedPackage(PCWSTR Parent, PCWSTR Directory, PCWSTR InfName)
{
    static const PCWSTR Names[] = { L"TESTPLAIN.DLL", L"TESTPLAIN.GPD" };
    static const char Text[] = "LiberNT package test file\r\n";
    WCHAR Root[MAX_PATH], Dir[MAX_PATH], InfPath[MAX_PATH], StoreInf[MAX_PATH], Path[MAX_PATH];
    ULONG Length = ARRAYSIZE(StoreInf);
    HRESULT hr;
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
            ok(_wcsicmp(StoreInf, InfPath) == 0 && Length == wcslen(InfPath) + 1, "%S was uploaded as %S, length %lu\n", InfPath, StoreInf, Length);
            if (_wcsicmp(StoreInf, InfPath) != 0)
                DeletePrinterDriverPackageW(NULL, StoreInf, NULL);
        }
        Length = ARRAYSIZE(StoreInf);
        hr = UploadPrinterDriverPackageW(NULL, InfPath, OTHER_ENVIRONMENT, UPDP_CHECK_DRIVERSTORE, NULL, StoreInf, &Length);
        ok(hr == S_OK && _wcsicmp(StoreInf, InfPath) == 0 && Length == wcslen(InfPath) + 1,
           "The lookup of %S for %S returned 0x%lx, %S and the length %lu\n", InfPath, OTHER_ENVIRONMENT, hr, StoreInf, Length);

        hr = DeletePrinterDriverPackageW(NULL, InfPath, NULL);
        ok(hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND), "DeletePrinterDriverPackageW(%S) returned 0x%lx\n", InfPath, hr);
        ok(GetFileAttributesW(InfPath) != INVALID_FILE_ATTRIBUTES, "%S was deleted\n", InfPath);
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

static const char NoSectionInf[] =
    "[Version]\r\n"
    "Signature=\"$Windows NT$\"\r\n"
    "Class=Printer\r\n"
    "ClassGUID={4D36E979-E325-11CE-BFC1-08002BE10318}\r\n"
    "Provider=LiberNT\r\n"
    "DriverVer=11/06/2026,1.0.0.0\r\n"
    "CatalogFile=lntprn.cat\r\n"
    "\r\n"
    "[Manufacturer]\r\n"
    "\"LiberNT\"=Models,NTamd64,NTx86,NTarm64\r\n"
    "\r\n"
    "[Models.NTamd64]\r\n"
    "\"LiberNT Package No Section Printer\"=TESTNOSEC,LiberNT_Package_No_Section\r\n"
    "[Models.NTx86]\r\n"
    "\"LiberNT Package No Section Printer\"=TESTNOSEC,LiberNT_Package_No_Section\r\n"
    "[Models.NTarm64]\r\n"
    "\"LiberNT Package No Section Printer\"=TESTNOSEC,LiberNT_Package_No_Section\r\n"
    "\r\n"
    "[TESTNOSEC]\r\n"
    "CopyFiles=@TESTNOSEC.DLL,@TESTNOSEC.GPD,TESTNOSEC_MISSING\r\n"
    "DriverFile=TESTNOSEC.DLL\r\n"
    "ConfigFile=TESTNOSEC.DLL\r\n"
    "DataFile=TESTNOSEC.GPD\r\n"
    "\r\n"
    "[DestinationDirs]\r\n"
    "DefaultDestDir=66000\r\n"
    "\r\n"
    "[SourceDisksNames]\r\n"
    "1=\"Disk\",,,\r\n"
    "\r\n"
    "[SourceDisksFiles]\r\n"
    "TESTNOSEC.DLL=1\r\n"
    "TESTNOSEC.GPD=1\r\n";

/* Windows 11 uploads, publishes and installs a signed package whose CopyFiles names a section that no INF of it has */
static VOID
TestMissingCopyFilesSection(VOID)
{
    static const PCWSTR Names[] = { L"lntprnnosec.inf", L"TESTNOSEC.DLL", L"TESTNOSEC.GPD" };
    static const PCWSTR DriverName = L"LiberNT Package No Section Printer";
    static const char Text[] = "LiberNT package test file\r\n";
    WCHAR Dir[MAX_PATH], InfPath[MAX_PATH], StoreInf[MAX_PATH], Path[MAX_PATH], File[MAX_PATH];
    ULONG Length = ARRAYSIZE(StoreInf);
    HRESULT hr;
    HKEY hKey;
    UINT i;

    GetTempPathW(MAX_PATH, Dir);
    StringCchCatW(Dir, MAX_PATH, L"lntprnnosec");
    CreateDirectoryW(Dir, NULL);
    StringCchPrintfW(InfPath, ARRAYSIZE(InfPath), L"%s\\%s", Dir, Names[0]);
    StringCchCopyW(Path, ARRAYSIZE(Path), TestDriverFile);
    StringCchPrintfW(File, ARRAYSIZE(File), L"%s\\%s", Dir, Names[1]);

    if (CopyFileW(Path, File, FALSE) &&
        WriteTestFile(Dir, Names[0], NoSectionInf, sizeof(NoSectionInf) - 1) &&
        WriteTestFile(Dir, Names[2], Text, sizeof(Text) - 1))
    {
        hr = UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_SILENT_UPLOAD, NULL, StoreInf, &Length);
        ok(hr == S_OK, "UploadPrinterDriverPackageW(lntprnnosec.inf) returned 0x%lx\n", hr);
        if (hr == S_OK)
        {
            ok(GetFileAttributesW(StoreInf) != INVALID_FILE_ATTRIBUTES, "%S does not exist\n", StoreInf);
            ok(FindPublishedInf(InfPath, Path), "lntprnnosec.inf is not published\n");

            hr = InstallPrinterDriverFromPackageW(NULL, StoreInf, DriverName, NULL, 0);
            ok(hr == S_OK, "InstallPrinterDriverFromPackageW returned 0x%lx\n", hr);
            hKey = OpenDriverKey(DriverName);
            ok(hKey != NULL, "Driver %S is not registered\n", DriverName);
            if (hKey)
                RegCloseKey(hKey);
            ok(DriverFileExists(Names[1]), "%S was not installed\n", Names[1]);
            RemoveTestDriver(DriverName);

            hr = DeletePrinterDriverPackageW(NULL, StoreInf, NULL);
            ok(hr == S_OK, "DeletePrinterDriverPackageW(%S) returned 0x%lx\n", StoreInf, hr);
            ok(GetFileAttributesW(StoreInf) == INVALID_FILE_ATTRIBUTES, "%S still exists\n", StoreInf);
            ok(!FindPublishedInf(InfPath, Path), "%S is still published\n", Path);
        }
    }
    else
    {
        skip("Failed to create the package lntprnnosec.inf (%lu)\n", GetLastError());
    }

    for (i = 0; i < ARRAYSIZE(Names); i++)
    {
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\%s", Dir, Names[i]);
        DeleteFileW(Path);
    }
    RemoveDirectoryW(Dir);
}

/* Every environment has a package of its own, staged from the same INF and deleted only for the environment its directory is named */
/* after. Windows 11 takes the published INF for its package only for the environment of the machine */
static VOID
TestSharedInf(PCWSTR InfPath, PCWSTR StoreInf)
{
    WCHAR Published[MAX_PATH], Other[MAX_PATH];
    ULONG Length = ARRAYSIZE(Other);
    HANDLE hFile;
    HRESULT hr;

    if (!FindPublishedInf(InfPath, Published))
    {
        skip("%S is not published\n", InfPath);
        return;
    }

    /* A published INF that is open without delete sharing cannot be deleted, and then the package is not deleted either */
    if (IsReactOS())
    {
        hFile = CreateFileW(Published, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        ok(hFile != INVALID_HANDLE_VALUE, "%S cannot be opened (%lu)\n", Published, GetLastError());
        if (hFile != INVALID_HANDLE_VALUE)
        {
            hr = DeletePrinterDriverPackageW(NULL, StoreInf, NULL);
            ok(FAILED(hr), "DeletePrinterDriverPackageW returned 0x%lx while the published INF could not be deleted\n", hr);
            ok(GetFileAttributesW(StoreInf) != INVALID_FILE_ATTRIBUTES, "%S was deleted and %S was not\n", StoreInf, Published);
            CloseHandle(hFile);
            ok(GetFileAttributesW(Published) != INVALID_FILE_ATTRIBUTES, "%S was deleted\n", Published);
        }
    }

    hr = UploadPrinterDriverPackageW(NULL, Published, NULL, UPDP_SILENT_UPLOAD, NULL, Other, &Length);
    ok(hr == S_OK && _wcsicmp(Other, StoreInf) == 0, "UploadPrinterDriverPackageW(%S) returned 0x%lx and %S\n", Published, hr, Other);
    Length = ARRAYSIZE(Other);
    hr = UploadPrinterDriverPackageW(NULL, Published, OTHER_ENVIRONMENT, UPDP_SILENT_UPLOAD, NULL, Other, &Length);
    ok(hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND), "UploadPrinterDriverPackageW(%S, %S) returned 0x%lx\n", Published, OTHER_ENVIRONMENT, hr);
    hr = DeletePrinterDriverPackageW(NULL, Published, NULL);
    ok(hr == E_INVALIDARG, "DeletePrinterDriverPackageW(%S) returned 0x%lx\n", Published, hr);
    hr = DeletePrinterDriverPackageW(NULL, StoreInf, OTHER_ENVIRONMENT);
    ok(hr == E_INVALIDARG, "DeletePrinterDriverPackageW(%S, %S) returned 0x%lx\n", StoreInf, OTHER_ENVIRONMENT, hr);
    ok(GetFileAttributesW(StoreInf) != INVALID_FILE_ATTRIBUTES, "%S was deleted for %S\n", StoreInf, OTHER_ENVIRONMENT);

    Length = ARRAYSIZE(Other);
    hr = UploadPrinterDriverPackageW(NULL, StoreInf, OTHER_ENVIRONMENT, UPDP_SILENT_UPLOAD, NULL, Other, &Length);
    ok(hr == S_OK && _wcsicmp(Other, StoreInf) == 0, "UploadPrinterDriverPackageW(%S, %S) returned 0x%lx and %S\n", StoreInf, OTHER_ENVIRONMENT, hr, Other);

    Length = ARRAYSIZE(Other);
    hr = UploadPrinterDriverPackageW(NULL, InfPath, OTHER_ENVIRONMENT, UPDP_SILENT_UPLOAD, NULL, Other, &Length);
    ok(hr == S_OK, "UploadPrinterDriverPackageW(%S) returned 0x%lx\n", OTHER_ENVIRONMENT, hr);
    if (hr != S_OK)
        return;
    ok(wcsstr(Other, L"\\lntprnpkg.inf_" OTHER_STORE_ARCHITECTURE L"_") != NULL, "%S is not a package of %S\n", Other, OTHER_ENVIRONMENT);
    if (_wcsicmp(Other, StoreInf) == 0)
        return;

    hr = DeletePrinterDriverPackageW(NULL, Other, NULL);
    ok(hr == E_INVALIDARG, "DeletePrinterDriverPackageW(%S) returned 0x%lx for %S\n", Other, hr, TEST_ENVIRONMENT);
    hr = DeletePrinterDriverPackageW(NULL, Other, OTHER_ENVIRONMENT);
    ok(hr == S_OK, "DeletePrinterDriverPackageW(%S) returned 0x%lx\n", OTHER_ENVIRONMENT, hr);
    ok(GetFileAttributesW(Other) == INVALID_FILE_ATTRIBUTES, "%S still exists\n", Other);
    ok(GetFileAttributesW(StoreInf) != INVALID_FILE_ATTRIBUTES, "%S was deleted with the package of %S\n", StoreInf, OTHER_ENVIRONMENT);
    ok(FindPublishedInf(InfPath, Published), "The published INF was deleted with the package of %S\n", OTHER_ENVIRONMENT);
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
    "CatalogFile=lntprn.cat\r\n"
    "\r\n"
    "[Manufacturer]\r\n"
    "\"LiberNT\"=Models,NTamd64,NTx86,NTarm64\r\n"
    "\r\n"
    "[Models.NTamd64]\r\n"
    "\"LiberNT Package Update Printer\"=TESTUPD,LiberNT_Package_Update\r\n"
    "[Models.NTx86]\r\n"
    "\"LiberNT Package Update Printer\"=TESTUPD,LiberNT_Package_Update\r\n"
    "[Models.NTarm64]\r\n"
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
        CopyTestDriverFile(Dir, L"TESTUPD.DLL") &&
        WriteTestFile(Dir, L"TESTUPD.GPD", Text, sizeof(Text) - 1) &&
        WriteTestFile(DriverDir, L"TESTUPD.DAT", Installed, sizeof(Installed) - 1))
    {
        hr = InstallPrinterDriverFromPackageW(NULL, InfPath, L"LiberNT Package Update Printer", NULL, IPDFP_COPY_ALL_FILES);
        ok(hr == E_INVALIDARG, "InstallPrinterDriverFromPackageW returned 0x%lx for an INF that is not in the store\n", hr);

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

    RemoveTestDriver(L"LiberNT Package Update Printer");
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
        /* TestConcurrentInstall signs the package once, as signing here would add a check per round */
        Length = ARRAYSIZE(StoreInf);
        hr = UploadUnsignedPackage(NULL, Test->InfPath, NULL, UPDP_SILENT_UPLOAD, NULL, StoreInf, &Length);
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
    StringCchCopyW(Again, ARRAYSIZE(Again), InfPath);
    *wcsrchr(Again, L'\\') = UNICODE_NULL;
    ok(SignTestPackage(Again, TrustedSigner.Cert), "Signing the package in %S failed with 0x%lx\n", Again, GetLastError());
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

#define STANDARD_USER L"LntPkgTest"
#define STANDARD_PASSWORD L"Lnt!Pkg#2026q"

typedef struct _OEM_INF_RESULT
{
    BOOL Result;
    DWORD Error;
    DWORD Required;
    WCHAR Published[MAX_PATH];
    PWSTR Component;
} OEM_INF_RESULT, *POEM_INF_RESULT;

static VOID
CopyOemInf(PCWSTR InfPath, DWORD Style, POEM_INF_RESULT Out)
{
    Out->Required = 0xdeadbeef;
    Out->Component = NULL;
    StringCchCopyW(Out->Published, ARRAYSIZE(Out->Published), L"untouched");
    SetLastError(0xdeadbeef);
    Out->Result = SetupCopyOEMInfW(InfPath, NULL, 0, Style, Out->Published, ARRAYSIZE(Out->Published), &Out->Required, &Out->Component);
    Out->Error = GetLastError();
}

/* Windows 11 22621 tells a standard user about a published INF and refuses with ERROR_ACCESS_DENIED to publish a new one */
static VOID
TestStandardUserOemInf(VOID)
{
    static const PCWSTR Names[] = { L"lntprnstd.inf", L"lntprnstdnew.inf", L"TESTPLAIN.DLL", L"TESTPLAIN.GPD" };
    static const char Text[] = "LiberNT package test file\r\n";
    static const char Marker[] = "; lntprnstd\r\n", NewMarker[] = "; lntprnstd new\r\n";
    static char Inf[sizeof(NewMarker) + sizeof(PlainInf)];
    WCHAR Dir[MAX_PATH], InfPath[MAX_PATH], NewInfPath[MAX_PATH], Path[MAX_PATH], Pattern[MAX_PATH];
    SECURITY_ATTRIBUTES Security = { sizeof(Security), NULL, FALSE };
    OEM_INF_RESULT Admin, NoOverwrite, Again, New;
    USER_INFO_1 UserInfo = { 0 };
    WIN32_FIND_DATAW Find;
    HANDLE hToken = NULL, hFind;
    NET_API_STATUS Status;
    BOOL Created, Readable = FALSE;
    UINT i;

    GetTempPathW(MAX_PATH, Dir);
    StringCchCatW(Dir, MAX_PATH, L"lntprnstd");
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;OICI;GA;;;WD)", SDDL_REVISION_1, &Security.lpSecurityDescriptor, NULL))
    {
        CreateDirectoryW(Dir, &Security);
        LocalFree(Security.lpSecurityDescriptor);
    }
    StringCchPrintfW(InfPath, ARRAYSIZE(InfPath), L"%s\\%s", Dir, Names[0]);
    StringCchPrintfW(NewInfPath, ARRAYSIZE(NewInfPath), L"%s\\%s", Dir, Names[1]);
    GetWindowsDirectoryW(Pattern, ARRAYSIZE(Pattern));
    StringCchCatW(Pattern, ARRAYSIZE(Pattern), L"\\System32\\DriverStore\\FileRepository\\lntprnstdnew.inf_*");

    memcpy(Inf, Marker, sizeof(Marker) - 1);
    memcpy(Inf + sizeof(Marker) - 1, PlainInf, sizeof(PlainInf) - 1);
    Created = WriteTestFile(Dir, Names[0], Inf, sizeof(Marker) - 1 + sizeof(PlainInf) - 1);
    memcpy(Inf, NewMarker, sizeof(NewMarker) - 1);
    memcpy(Inf + sizeof(NewMarker) - 1, PlainInf, sizeof(PlainInf) - 1);
    if (!Created ||
        !WriteTestFile(Dir, Names[1], Inf, sizeof(NewMarker) - 1 + sizeof(PlainInf) - 1) ||
        !WriteTestFile(Dir, Names[2], Text, sizeof(Text) - 1) ||
        !WriteTestFile(Dir, Names[3], Text, sizeof(Text) - 1))
    {
        skip("Failed to create the package lntprnstd.inf (%lu)\n", GetLastError());
        goto Cleanup;
    }

    ok(SignTestPackage(Dir, TrustedSigner.Cert), "Signing the package in %S failed with 0x%lx\n", Dir, GetLastError());
    CopyOemInf(InfPath, 0, &Admin);
    if (!Admin.Result)
    {
        skip("lntprnstd.inf cannot be published (%lu)\n", Admin.Error);
        goto Cleanup;
    }

    NetUserDel(NULL, STANDARD_USER);
    UserInfo.usri1_name = STANDARD_USER;
    UserInfo.usri1_password = STANDARD_PASSWORD;
    UserInfo.usri1_priv = USER_PRIV_USER;
    UserInfo.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    Status = NetUserAdd(NULL, 1, (PBYTE)&UserInfo, NULL);
    if (Status != NERR_Success ||
        !LogonUserW(STANDARD_USER, L".", STANDARD_PASSWORD, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken))
    {
        skip("No standard user to call SetupCopyOEMInfW as (NetUserAdd %lu, LogonUserW %lu)\n", Status, GetLastError());
    }
    else if (!ImpersonateLoggedOnUser(hToken))
    {
        skip("ImpersonateLoggedOnUser failed with %lu\n", GetLastError());
    }
    else
    {
        Readable = GetFileAttributesW(InfPath) != INVALID_FILE_ATTRIBUTES && GetFileAttributesW(Admin.Published) != INVALID_FILE_ATTRIBUTES;
        if (Readable)
        {
            CopyOemInf(InfPath, SP_COPY_NOOVERWRITE, &NoOverwrite);
            CopyOemInf(InfPath, 0, &Again);
            CopyOemInf(NewInfPath, 0, &New);
        }
        RevertToSelf();

        if (!Readable)
        {
            skip("The standard user cannot read %S or %S\n", InfPath, Admin.Published);
        }
        else
        {
            ok(!NoOverwrite.Result && NoOverwrite.Error == ERROR_FILE_EXISTS,
               "SP_COPY_NOOVERWRITE returned %d with error %lu for a published INF\n", NoOverwrite.Result, NoOverwrite.Error);
            ok(!_wcsicmp(NoOverwrite.Published, Admin.Published) && NoOverwrite.Required == wcslen(Admin.Published) + 1,
               "SP_COPY_NOOVERWRITE returned %S and size %lu\n", NoOverwrite.Published, NoOverwrite.Required);
            ok(NoOverwrite.Component && !_wcsicmp(NoOverwrite.Component, Admin.Component),
               "SP_COPY_NOOVERWRITE returned the component %S\n", NoOverwrite.Component ? NoOverwrite.Component : L"(null)");

            ok(Again.Result && Again.Error == ERROR_SUCCESS, "A published INF returned %d with error %lu\n", Again.Result, Again.Error);
            ok(!_wcsicmp(Again.Published, Admin.Published) && Again.Required == wcslen(Admin.Published) + 1,
               "A published INF returned %S and size %lu\n", Again.Published, Again.Required);
            ok(Again.Component && !_wcsicmp(Again.Component, Admin.Component),
               "A published INF returned the component %S\n", Again.Component ? Again.Component : L"(null)");

            ok(!New.Result && New.Error == ERROR_ACCESS_DENIED, "A new INF returned %d with error %lu\n", New.Result, New.Error);
            ok(!wcscmp(New.Published, L"untouched") && New.Required == 0xdeadbeef && !New.Component,
               "A new INF returned %S and size %lu\n", New.Published, New.Required);
            ok(!FindPublishedInf(NewInfPath, Path), "The standard user published %S\n", Path);
            hFind = FindFirstFileW(Pattern, &Find);
            ok(hFind == INVALID_HANDLE_VALUE, "The standard user staged %S\n", hFind == INVALID_HANDLE_VALUE ? L"" : Find.cFileName);
            if (hFind != INVALID_HANDLE_VALUE)
                FindClose(hFind);
        }
    }

    if (hToken)
        CloseHandle(hToken);
    NetUserDel(NULL, STANDARD_USER);
    if (FindPublishedInf(NewInfPath, Path))
        SetupUninstallOEMInfW(wcsrchr(Path, L'\\') + 1, 0, NULL);
    ok(SetupUninstallOEMInfW(Admin.Component, 0, NULL), "SetupUninstallOEMInfW failed with %lu\n", GetLastError());

Cleanup:
    for (i = 0; i < ARRAYSIZE(Names); i++)
    {
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\%s", Dir, Names[i]);
        DeleteFileW(Path);
    }
    RemoveDirectoryW(Dir);
}

/* Windows 11 stages a package once. For an INF that the store has, an upload with any flags returns the package and leaves it as */
/* it is, whatever has become of the source. The test changes the source alone and only reads the store */
static VOID
TestStoreReplacement(PCWSTR Dir, PCWSTR InfPath, PCWSTR StoreInf)
{
    static const DWORD Flags[] = { 0, UPDP_SILENT_UPLOAD, UPDP_UPLOAD_ALWAYS, UPDP_SILENT_UPLOAD | UPDP_UPLOAD_ALWAYS,
                                   UPDP_UPLOAD_ALWAYS | UPDP_CHECK_DRIVERSTORE, 8 };
    static const char Text[] = "LiberNT package test file\r\n";
    static const char Changed[] = "changed in the source\r\n";
    WCHAR StoreFile[MAX_PATH], Original[MAX_PATH], Removed[MAX_PATH], Again[MAX_PATH];
    PCWSTR Last = wcsrchr(StoreInf, L'\\');
    WIN32_FIND_DATAW Find;
    HANDLE hFind;
    ULONG Length;
    HRESULT hr;
    UINT i;

    StringCchPrintfW(Original, ARRAYSIZE(Original), L"%s\\TESTPKG.GPD", Dir);
    StringCchPrintfW(Removed, ARRAYSIZE(Removed), L"%s\\TESTPKG.DAT", Dir);
    ok(WriteTestFile(Dir, L"TESTPKG.HLP", Changed, sizeof(Changed) - 1), "Changing the source TESTPKG.HLP failed\n");
    ok(DeleteFileW(Removed), "Deleting %S failed with %lu\n", Removed, GetLastError());
    ok(WriteTestFile(Dir, L"TESTOPT.DAT", Text, sizeof(Text) - 1), "Writing the source TESTOPT.DAT failed\n");

    for (i = 0; i < ARRAYSIZE(Flags); i++)
    {
        Length = ARRAYSIZE(Again);
        Again[0] = UNICODE_NULL;
        hr = UploadUnsignedPackage(NULL, InfPath, NULL, Flags[i], NULL, Again, &Length);
        ok(hr == S_OK && _wcsicmp(Again, StoreInf) == 0, "UploadPrinterDriverPackageW with the flags 0x%lx returned 0x%lx and %S\n", Flags[i], hr, Again);
        ok(Length == wcslen(StoreInf) + 1, "UploadPrinterDriverPackageW with the flags 0x%lx returned the length %lu\n", Flags[i], Length);
    }

    StringCchPrintfW(StoreFile, ARRAYSIZE(StoreFile), L"%.*s\\TESTPKG.HLP", (int)(Last - StoreInf), StoreInf);
    ok(FilesMatch(StoreFile, Original), "%S was replaced by an upload over the staged package\n", StoreFile);
    StringCchPrintfW(StoreFile, ARRAYSIZE(StoreFile), L"%.*s\\TESTPKG.DAT", (int)(Last - StoreInf), StoreInf);
    ok(FilesMatch(StoreFile, Original), "%S was lost in an upload over the staged package\n", StoreFile);
    StringCchPrintfW(StoreFile, ARRAYSIZE(StoreFile), L"%.*s\\TESTOPT.DAT", (int)(Last - StoreInf), StoreInf);
    ok(GetFileAttributesW(StoreFile) == INVALID_FILE_ATTRIBUTES, "%S was staged by an upload over the staged package\n", StoreFile);

    StringCchPrintfW(StoreFile, ARRAYSIZE(StoreFile), L"%.*s.stage-*", (int)(Last - StoreInf), StoreInf);
    hFind = FindFirstFileW(StoreFile, &Find);
    ok(hFind == INVALID_HANDLE_VALUE, "%S was left behind\n", hFind == INVALID_HANDLE_VALUE ? L"" : Find.cFileName);
    if (hFind != INVALID_HANDLE_VALUE)
        FindClose(hFind);

    ok(WriteTestFile(Dir, L"TESTPKG.HLP", Text, sizeof(Text) - 1), "Restoring TESTPKG.HLP failed\n");
    ok(WriteTestFile(Dir, L"TESTPKG.DAT", Text, sizeof(Text) - 1), "Restoring TESTPKG.DAT failed\n");
    StringCchPrintfW(Removed, ARRAYSIZE(Removed), L"%s\\TESTOPT.DAT", Dir);
    DeleteFileW(Removed);
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

#define SIGNED_INF(Driver, Config, Data, Help) \
    "[Version]\r\n" \
    "Signature=\"$Windows NT$\"\r\n" \
    "Class=Printer\r\n" \
    "ClassGUID={4D36E979-E325-11CE-BFC1-08002BE10318}\r\n" \
    "Provider=LiberNT\r\n" \
    "DriverVer=11/06/2026,1.0.0.0\r\n" \
    "CatalogFile=lntprn.cat\r\n" \
    "\r\n" \
    "[Manufacturer]\r\n" \
    "\"LiberNT\"=Models,NTamd64,NTx86,NTarm64\r\n" \
    "\r\n" \
    "[Models.NTamd64]\r\n" \
    "\"LiberNT Package Signed Printer\"=TESTSIG,LiberNT_Package_Signed\r\n" \
    "[Models.NTx86]\r\n" \
    "\"LiberNT Package Signed Printer\"=TESTSIG,LiberNT_Package_Signed\r\n" \
    "[Models.NTarm64]\r\n" \
    "\"LiberNT Package Signed Printer\"=TESTSIG,LiberNT_Package_Signed\r\n" \
    "\r\n" \
    "[TESTSIG]\r\n" \
    "CopyFiles=@TESTSIG.DLL,@TESTSIG.DAT\r\n" \
    "DriverFile=" Driver "\r\n" \
    "ConfigFile=" Config "\r\n" \
    "DataFile=" Data "\r\n" \
    Help \
    "\r\n" \
    "[DestinationDirs]\r\n" \
    "DefaultDestDir=66000\r\n" \
    "\r\n" \
    "[SourceDisksNames]\r\n" \
    "1=\"Disk\",,,\r\n" \
    "\r\n" \
    "[SourceDisksFiles]\r\n" \
    "TESTSIG.DLL=1\r\n" \
    "TESTSIG.DAT=1\r\n"

#define SIGNED_DRIVER_NAME L"LiberNT Package Signed Printer"

static const char SignedInf[] = SIGNED_INF("TESTSIG.DLL", "TESTSIG.DLL", "TESTSIG.DAT", "");

static BOOL
CreateSignedPackage(PCWSTR Name, const char *Inf, DWORD InfSize, PWSTR Dir, PWSTR InfPath)
{
    static const char Text[] = "LiberNT package test file\r\n";
    WCHAR Source[MAX_PATH], Target[MAX_PATH], InfName[MAX_PATH];

    GetTempPathW(MAX_PATH, Dir);
    StringCchCatW(Dir, MAX_PATH, Name);
    CreateDirectoryW(Dir, NULL);
    StringCchPrintfW(InfName, ARRAYSIZE(InfName), L"%s.inf", Name);
    StringCchPrintfW(InfPath, MAX_PATH, L"%s\\%s", Dir, InfName);

    StringCchCopyW(Source, ARRAYSIZE(Source), TestDriverFile);
    StringCchPrintfW(Target, ARRAYSIZE(Target), L"%s\\TESTSIG.DLL", Dir);
    return CopyFileW(Source, Target, FALSE) && WriteTestFile(Dir, InfName, Inf, InfSize) &&
           WriteTestFile(Dir, L"TESTSIG.DAT", Text, sizeof(Text) - 1);
}

static VOID
DeleteSignedPackage(PCWSTR Name, PCWSTR Dir)
{
    static const PCWSTR Names[] = { L"TESTSIG.DLL", L"TESTSIG.DAT", TEST_CATALOG };
    WCHAR Path[MAX_PATH];
    UINT i;

    for (i = 0; i < ARRAYSIZE(Names); i++)
    {
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\%s", Dir, Names[i]);
        DeleteFileW(Path);
    }
    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\%s.inf", Dir, Name);
    DeleteFileW(Path);
    RemoveDirectoryW(Dir);
}

static VOID
TestRefusedSignature(PCWSTR InfPath, HRESULT Expected, PCSTR What)
{
    WCHAR StoreInf[MAX_PATH];
    ULONG Length = ARRAYSIZE(StoreInf);
    HRESULT hr;

    hr = UploadUnsignedPackage(NULL, InfPath, NULL, UPDP_SILENT_UPLOAD, NULL, StoreInf, &Length);
    ok(hr == Expected, "UploadPrinterDriverPackageW returned 0x%lx for a package %s\n", hr, What);
    if (hr == S_OK)
        DeletePrinterDriverPackageW(NULL, StoreInf, NULL);

    Length = ARRAYSIZE(StoreInf);
    hr = UploadUnsignedPackage(NULL, InfPath, NULL, UPDP_CHECK_DRIVERSTORE, NULL, StoreInf, &Length);
    ok(hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND), "The driver store lookup returned 0x%lx after the upload of a package %s\n", hr, What);
}

/* The results are those of Windows 11 22621 */
static VOID
TestPackageSignature(VOID)
{
    static const char Changed[] = "changed after the catalog was made\r\n";
    static const char Text[] = "LiberNT package test file\r\n";
    WCHAR Dir[MAX_PATH], InfPath[MAX_PATH], StoreInf[MAX_PATH], Again[MAX_PATH], Path[MAX_PATH], StoreFile[MAX_PATH];
    ULONG Length;
    HRESULT hr;

    if (!CreateSignedPackage(L"lntprnsig", SignedInf, sizeof(SignedInf) - 1, Dir, InfPath))
    {
        skip("Failed to create the package lntprnsig (%lu)\n", GetLastError());
        DeleteSignedPackage(L"lntprnsig", Dir);
        return;
    }
    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\TESTSIG.DAT", Dir);

    TestRefusedSignature(InfPath, HRESULT_FROM_WIN32(ERROR_CANCELLED), "without its catalog");

    ok(SignTestPackage(Dir, NULL), "Making the catalog failed with 0x%lx\n", GetLastError());
    TestRefusedSignature(InfPath, TRUST_E_NOSIGNATURE, "with an unsigned catalog");

    ok(SignTestPackage(Dir, UntrustedSigner.Cert), "Signing the catalog failed with 0x%lx\n", GetLastError());
    TestRefusedSignature(InfPath, CERT_E_UNTRUSTEDROOT, "signed by a certificate that is in no store");

    ok(SignTestPackage(Dir, TrustedSigner.Cert), "Signing the catalog failed with 0x%lx\n", GetLastError());
    ok(TrustTestSigner(L"TrustedPublisher", FALSE), "Removing the trusted publisher failed with 0x%lx\n", GetLastError());
    TestRefusedSignature(InfPath, SPAPI_E_AUTHENTICODE_TRUST_NOT_ESTABLISHED, "signed by a root that is not a trusted publisher");
    ok(TrustTestSigner(L"TrustedPublisher", TRUE), "Adding the trusted publisher failed with 0x%lx\n", GetLastError());

    ok(TrustTestSigner(L"Root", FALSE), "Removing the root failed with 0x%lx\n", GetLastError());
    TestRefusedSignature(InfPath, CERT_E_UNTRUSTEDROOT, "signed by a trusted publisher that is not a root");
    ok(TrustTestSigner(L"Root", TRUE), "Adding the root failed with 0x%lx\n", GetLastError());

    ok(WriteTestFile(Dir, L"TESTSIG.DAT", Changed, sizeof(Changed) - 1), "Changing TESTSIG.DAT failed\n");
    TestRefusedSignature(InfPath, SPAPI_E_FILE_HASH_NOT_IN_CATALOG, "with a file changed after the catalog was made");
    ok(WriteTestFile(Dir, L"TESTSIG.DAT", Text, sizeof(Text) - 1), "Restoring TESTSIG.DAT failed\n");

    /* A buffer of less than MAX_PATH characters is refused before anything is staged, and its length is left alone */
    Length = MAX_PATH - 1;
    hr = UploadUnsignedPackage(NULL, InfPath, NULL, UPDP_SILENT_UPLOAD, NULL, StoreInf, &Length);
    ok(hr == E_INVALIDARG && Length == MAX_PATH - 1, "UploadPrinterDriverPackageW returned 0x%lx and the length %lu for a short buffer\n", hr, Length);
    Length = MAX_PATH;
    hr = UploadUnsignedPackage(NULL, InfPath, NULL, UPDP_SILENT_UPLOAD, NULL, NULL, &Length);
    ok(hr == E_INVALIDARG, "UploadPrinterDriverPackageW returned 0x%lx without a buffer\n", hr);
    Length = ARRAYSIZE(StoreInf);
    hr = UploadUnsignedPackage(NULL, InfPath, NULL, UPDP_CHECK_DRIVERSTORE, NULL, StoreInf, &Length);
    ok(hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND), "The driver store lookup returned 0x%lx after refused buffers\n", hr);

    /* An INF of another class */
    {
        static char NetInf[sizeof(SignedInf)];
        char *Class;

        CopyMemory(NetInf, SignedInf, sizeof(SignedInf));
        Class = strstr(NetInf, "Class=Printer");
        if (Class)
            CopyMemory(Class, "Class=Net;;;;", 13);
        ok(WriteTestFile(Dir, L"lntprnsig.inf", NetInf, sizeof(NetInf) - 1), "Changing lntprnsig.inf failed\n");
        ok(SignTestPackage(Dir, TrustedSigner.Cert), "Signing the catalog failed with 0x%lx\n", GetLastError());
        TestRefusedSignature(InfPath, (HRESULT)ERROR_CLASS_MISMATCH, "of the class Net");
        ok(WriteTestFile(Dir, L"lntprnsig.inf", SignedInf, sizeof(SignedInf) - 1), "Restoring lntprnsig.inf failed\n");
        ok(SignTestPackage(Dir, TrustedSigner.Cert), "Signing the catalog failed with 0x%lx\n", GetLastError());
    }

    Length = ARRAYSIZE(StoreInf);
    hr = UploadUnsignedPackage(NULL, InfPath, NULL, UPDP_SILENT_UPLOAD, NULL, StoreInf, &Length);
    ok(hr == S_OK, "UploadPrinterDriverPackageW returned 0x%lx for a signed package\n", hr);
    if (hr == S_OK)
    {
        StringCchPrintfW(StoreFile, ARRAYSIZE(StoreFile), L"%.*s\\" TEST_CATALOG, (int)(wcsrchr(StoreInf, L'\\') - StoreInf), StoreInf);
        ok(GetFileAttributesW(StoreFile) != INVALID_FILE_ATTRIBUTES, "%S is not in the store\n", StoreFile);

        /* Windows 11 stages a package once: it returns S_OK and keeps the package it has, whatever the source is now */
        StringCchPrintfW(StoreFile, ARRAYSIZE(StoreFile), L"%.*s\\TESTSIG.DAT", (int)(wcsrchr(StoreInf, L'\\') - StoreInf), StoreInf);
        ok(WriteTestFile(Dir, L"TESTSIG.DAT", Changed, sizeof(Changed) - 1), "Changing TESTSIG.DAT failed\n");
        Length = ARRAYSIZE(Again);
        hr = UploadUnsignedPackage(NULL, InfPath, NULL, UPDP_UPLOAD_ALWAYS, NULL, Again, &Length);
        ok(hr == S_OK && _wcsicmp(Again, StoreInf) == 0, "UploadPrinterDriverPackageW returned 0x%lx over a staged package\n", hr);
        ok(WriteTestFile(Dir, L"TESTSIG.DAT", Text, sizeof(Text) - 1), "Restoring TESTSIG.DAT failed\n");
        ok(FilesMatch(StoreFile, Path), "%S was replaced by an upload over a staged package\n", StoreFile);
        Length = ARRAYSIZE(Again);
        hr = UploadUnsignedPackage(NULL, InfPath, NULL, UPDP_CHECK_DRIVERSTORE, NULL, Again, &Length);
        ok(hr == S_OK && _wcsicmp(Again, StoreInf) == 0, "The driver store lookup returned 0x%lx after the second upload\n", hr);
        ok(Length == ARRAYSIZE(Again), "The driver store lookup changed the length to %lu\n", Length);

        hr = DeletePrinterDriverPackageW(NULL, StoreInf, NULL);
        ok(hr == S_OK, "DeletePrinterDriverPackageW returned 0x%lx\n", hr);
    }

    DeleteSignedPackage(L"lntprnsig", Dir);
}

/* Takes the export table from the file, so that it has no DrvQueryDriverInfo */
static BOOL
RemoveExports(PCWSTR Path)
{
    static const BYTE Empty[2 * sizeof(DWORD)];
    IMAGE_DOS_HEADER Dos;
    DWORD Done, Offset;
    BOOL Ret = FALSE;
    HANDLE hFile;
    WORD Magic;

    hFile = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    if (ReadFile(hFile, &Dos, sizeof(Dos), &Done, NULL) && Done == sizeof(Dos) && Dos.e_magic == IMAGE_DOS_SIGNATURE)
    {
        Offset = Dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
        if (SetFilePointer(hFile, Offset, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER &&
            ReadFile(hFile, &Magic, sizeof(Magic), &Done, NULL) && Done == sizeof(Magic))
        {
            Offset += Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, DataDirectory)
                                                             : FIELD_OFFSET(IMAGE_OPTIONAL_HEADER32, DataDirectory);
            Ret = SetFilePointer(hFile, Offset, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER &&
                  WriteFile(hFile, Empty, sizeof(Empty), &Done, NULL) && Done == sizeof(Empty);
        }
    }
    CloseHandle(hFile);
    return Ret;
}

/* Writes the major part of the file version into the version resource of the file */
static BOOL
SetFileVersion(PCWSTR Path, DWORD VersionMS)
{
    static const BYTE Signature[] = { 0xBD, 0x04, 0xEF, 0xFE };
    static BYTE Data[16384];
    DWORD Size = 0, Done, i;
    BOOL Ret = FALSE;
    HANDLE hFile;

    hFile = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    if (ReadFile(hFile, Data, sizeof(Data), &Size, NULL))
    {
        for (i = 0; i + sizeof(VS_FIXEDFILEINFO) <= Size && memcmp(Data + i, Signature, sizeof(Signature)) != 0; i += sizeof(DWORD));
        Ret = i + sizeof(VS_FIXEDFILEINFO) <= Size &&
              SetFilePointer(hFile, i + FIELD_OFFSET(VS_FIXEDFILEINFO, dwFileVersionMS), NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER &&
              WriteFile(hFile, &VersionMS, sizeof(VersionMS), &Done, NULL) && Done == sizeof(VersionMS);
    }
    CloseHandle(hFile);
    return Ret;
}

typedef enum _BLOCKED_FILE
{
    BlockedSystemFile,
    BlockedNoExport,
    BlockedVersion2,
    BlockedVersion4,
} BLOCKED_FILE;

/* Windows 11 22621 blocks a driver file whose version resource does not say 0.3 before it adds the driver: one that says 0.2 as a */
/* kernel mode driver, every other, as version.dll or one that says 0.4, as a blocked driver. One that says 0.3 it adds, loads and */
/* asks through DrvQueryDriverInfo whether it runs in user mode; a file without the export it takes for a kernel mode driver and */
/* deletes the driver again, leaving the files it copied in the driver directory. Measured with an empty driver directory */
static VOID
TestBlockedDriverFile(PCWSTR Name, BLOCKED_FILE Kind, HRESULT Expected, PCSTR What)
{
    WCHAR Dir[MAX_PATH], InfPath[MAX_PATH], StoreInf[MAX_PATH], Source[MAX_PATH], Target[MAX_PATH];
    ULONG Length = ARRAYSIZE(StoreInf);
    DWORD Size = sizeof(Source);
    HRESULT hr;
    HKEY hKey;

    GetSystemDirectoryW(Source, ARRAYSIZE(Source));
    StringCchCatW(Source, ARRAYSIZE(Source), L"\\version.dll");
    if (!CreateSignedPackage(Name, SignedInf, sizeof(SignedInf) - 1, Dir, InfPath) ||
        FAILED(StringCchPrintfW(Target, ARRAYSIZE(Target), L"%s\\TESTSIG.DLL", Dir)) ||
        !(Kind == BlockedSystemFile ? CopyFileW(Source, Target, FALSE) :
          Kind == BlockedNoExport ? RemoveExports(Target) : SetFileVersion(Target, Kind == BlockedVersion2 ? 2 : 4)))
    {
        skip("Failed to create the package %S (%lu)\n", Name, GetLastError());
        DeleteSignedPackage(Name, Dir);
        return;
    }

    hr = UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_SILENT_UPLOAD, NULL, StoreInf, &Length);
    ok(hr == S_OK, "UploadPrinterDriverPackageW returned 0x%lx for a package with %s as its driver file\n", hr, What);
    if (hr == S_OK)
    {
        hr = InstallPrinterDriverFromPackageW(NULL, StoreInf, SIGNED_DRIVER_NAME, NULL, 0);
        ok(hr == Expected, "InstallPrinterDriverFromPackageW returned 0x%lx for %s\n", hr, What);
        hKey = OpenDriverKey(SIGNED_DRIVER_NAME);
        ok(hKey == NULL, "Driver %S is registered with %s as its driver file\n", SIGNED_DRIVER_NAME, What);
        if (hKey)
        {
            RegCloseKey(hKey);
            RemoveTestDriver(SIGNED_DRIVER_NAME);
        }
        hr = DeletePrinterDriverPackageW(NULL, StoreInf, NULL);
        ok(hr == S_OK, "DeletePrinterDriverPackageW returned 0x%lx\n", hr);
    }
    if (GetPrinterDriverDirectoryW(NULL, NULL, 1, (PBYTE)Source, Size, &Size))
    {
        StringCchPrintfW(Target, ARRAYSIZE(Target), L"%s\\3\\TESTSIG.DLL", Source);
        DeleteFileW(Target);
        StringCchPrintfW(Target, ARRAYSIZE(Target), L"%s\\3\\TESTSIG.DAT", Source);
        DeleteFileW(Target);
    }
    DeleteSignedPackage(Name, Dir);
}

#if !defined(_M_IX86)
/* On a 64-bit machine Windows 11 22621 does not look for a model in a section without the decoration of the architecture */
static VOID
TestUndecoratedModels(VOID)
{
    static char Inf[sizeof(SignedInf)];
    WCHAR Dir[MAX_PATH], InfPath[MAX_PATH], StoreInf[MAX_PATH];
    ULONG Length = ARRAYSIZE(StoreInf);
    char *Line;
    HRESULT hr;
    HKEY hKey;

    CopyMemory(Inf, SignedInf, sizeof(SignedInf));
    Line = strstr(Inf, "=Models,NTamd64,NTx86,NTarm64");
    if (Line)
        CopyMemory(Line, "=Models;;;;;;;;;;;;;;;;;;;;;;", 29);
    Line = strstr(Inf, "[Models.NTamd64]");
    if (Line)
        CopyMemory(Line, "[Models]\r\n;;;;;;", 16);

    if (!CreateSignedPackage(L"lntprnund", Inf, sizeof(Inf) - 1, Dir, InfPath))
    {
        skip("Failed to create the package lntprnund (%lu)\n", GetLastError());
        DeleteSignedPackage(L"lntprnund", Dir);
        return;
    }

    hr = UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_SILENT_UPLOAD, NULL, StoreInf, &Length);
    ok(hr == S_OK, "UploadPrinterDriverPackageW returned 0x%lx for an INF with an undecorated models section\n", hr);
    if (hr == S_OK)
    {
        hr = InstallPrinterDriverFromPackageW(NULL, StoreInf, SIGNED_DRIVER_NAME, NULL, 0);
        ok(hr == HRESULT_FROM_WIN32(ERROR_UNKNOWN_PRINTER_DRIVER), "InstallPrinterDriverFromPackageW returned 0x%lx for an undecorated model\n", hr);
        hKey = OpenDriverKey(SIGNED_DRIVER_NAME);
        ok(hKey == NULL, "Driver %S is registered from an undecorated models section\n", SIGNED_DRIVER_NAME);
        if (hKey)
        {
            RegCloseKey(hKey);
            RemoveTestDriver(SIGNED_DRIVER_NAME);
        }
        hr = DeletePrinterDriverPackageW(NULL, StoreInf, NULL);
        ok(hr == S_OK, "DeletePrinterDriverPackageW returned 0x%lx\n", hr);
    }
    DeleteSignedPackage(L"lntprnund", Dir);
}
#endif

static const struct
{
    PCWSTR Name;
    PCSTR Directive;
    const char *Inf;
    DWORD InfSize;
    PCWSTR Stale;
} StaleFiles[] =
{
#define STALE_INF(Driver, Config, Data, Help) SIGNED_INF(Driver, Config, Data, Help), sizeof(SIGNED_INF(Driver, Config, Data, Help)) - 1
    { L"lntprnstdr", "DriverFile", STALE_INF("TESTSTALE.DLL", "TESTSIG.DLL", "TESTSIG.DAT", ""), L"TESTSTALE.DLL" },
    { L"lntprnstcf", "ConfigFile", STALE_INF("TESTSIG.DLL", "TESTSTALE.DLL", "TESTSIG.DAT", ""), L"TESTSTALE.DLL" },
    { L"lntprnstda", "DataFile", STALE_INF("TESTSIG.DLL", "TESTSIG.DLL", "TESTSTALE.DAT", ""), L"TESTSTALE.DAT" },
    { L"lntprnsthl", "HelpFile", STALE_INF("TESTSIG.DLL", "TESTSIG.DLL", "TESTSIG.DAT", "HelpFile=TESTSTALE.HLP\r\n"), L"TESTSTALE.HLP" },
#undef STALE_INF
};

/* Windows 11 22621 does not take a file that the package names and does not have from the driver directory */
static VOID
TestStaleDriverFile(VOID)
{
    WCHAR Dir[MAX_PATH], InfPath[MAX_PATH], StoreInf[MAX_PATH], DriverDir[MAX_PATH], Stale[MAX_PATH], Source[MAX_PATH];
    DWORD Size = sizeof(DriverDir);
    ULONG Length;
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

    for (i = 0; i < ARRAYSIZE(StaleFiles); i++)
    {
        if (!CreateSignedPackage(StaleFiles[i].Name, StaleFiles[i].Inf, StaleFiles[i].InfSize, Dir, InfPath))
        {
            skip("Failed to create the package %S (%lu)\n", StaleFiles[i].Name, GetLastError());
            DeleteSignedPackage(StaleFiles[i].Name, Dir);
            continue;
        }

        Length = ARRAYSIZE(StoreInf);
        hr = UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_SILENT_UPLOAD, NULL, StoreInf, &Length);
        ok(hr == S_OK, "UploadPrinterDriverPackageW returned 0x%lx for a package without its %s\n", hr, StaleFiles[i].Directive);
        if (hr == S_OK)
        {
            hr = InstallPrinterDriverFromPackageW(NULL, StoreInf, SIGNED_DRIVER_NAME, NULL, 0);
            ok(hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), "InstallPrinterDriverFromPackageW returned 0x%lx without the %s\n",
               hr, StaleFiles[i].Directive);

            StringCchPrintfW(Stale, ARRAYSIZE(Stale), L"%s\\%s", DriverDir, StaleFiles[i].Stale);
            StringCchPrintfW(Source, ARRAYSIZE(Source), L"%s\\TESTSIG.DLL", Dir);
            ok(CopyFileW(Source, Stale, FALSE), "Writing %S failed with %lu\n", Stale, GetLastError());
            hr = InstallPrinterDriverFromPackageW(NULL, StoreInf, SIGNED_DRIVER_NAME, NULL, 0);
            ok(hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND),
               "InstallPrinterDriverFromPackageW returned 0x%lx with a %s of that name in the driver directory\n", hr, StaleFiles[i].Directive);
            hKey = OpenDriverKey(SIGNED_DRIVER_NAME);
            ok(hKey == NULL, "Driver %S is registered with a %s that is not of its package\n", SIGNED_DRIVER_NAME, StaleFiles[i].Directive);
            if (hKey)
            {
                RegCloseKey(hKey);
                RemoveTestDriver(SIGNED_DRIVER_NAME);
            }
            DeleteFileW(Stale);
            StringCchPrintfW(Stale, ARRAYSIZE(Stale), L"%s\\TESTSIG.DLL", DriverDir);
            DeleteFileW(Stale);
            StringCchPrintfW(Stale, ARRAYSIZE(Stale), L"%s\\TESTSIG.DAT", DriverDir);
            DeleteFileW(Stale);

            hr = DeletePrinterDriverPackageW(NULL, StoreInf, NULL);
            ok(hr == S_OK, "DeletePrinterDriverPackageW returned 0x%lx\n", hr);
        }
        DeleteSignedPackage(StaleFiles[i].Name, Dir);
    }
}

/* The files of the directory of a staged package are those named, and no other */
static VOID
CheckStagedFiles(PCWSTR StoreInf, const PCWSTR *Names, UINT Count, PCSTR What)
{
    WCHAR Path[MAX_PATH];
    int DirLength = (int)(wcsrchr(StoreInf, L'\\') - StoreInf);
    WIN32_FIND_DATAW Find;
    HANDLE hFind;
    UINT i, Files = 0;

    for (i = 0; i < Count; i++)
    {
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"%.*s\\%s", DirLength, StoreInf, Names[i]);
        ok(GetFileAttributesW(Path) != INVALID_FILE_ATTRIBUTES, "%S is not staged for %s\n", Names[i], What);
    }

    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%.*s\\*", DirLength, StoreInf);
    hFind = FindFirstFileW(Path, &Find);
    if (hFind == INVALID_HANDLE_VALUE)
        return;
    do
    {
        if (Find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            ok(!wcscmp(Find.cFileName, L".") || !wcscmp(Find.cFileName, L".."), "The directory %S is staged for %s\n", Find.cFileName, What);
            continue;
        }
        Files++;
        for (i = 0; i < Count && _wcsicmp(Find.cFileName, Names[i]) != 0; i++);
        ok(i < Count, "%S is staged for %s\n", Find.cFileName, What);
    } while (FindNextFileW(hFind, &Find));
    FindClose(hFind);
    ok(Files == Count, "%u files are staged for %s, not %u\n", Files, What, Count);
}

static const char StagedInf[] =
    "[Version]\r\n"
    "Signature=\"$Windows NT$\"\r\n"
    "Class=Printer\r\n"
    "ClassGUID={4D36E979-E325-11CE-BFC1-08002BE10318}\r\n"
    "Provider=LiberNT\r\n"
    "DriverVer=11/06/2026,1.0.0.0\r\n"
    "CatalogFile=lntprn.cat\r\n"
    "\r\n"
    "[Manufacturer]\r\n"
    "\"LiberNT\"=Models,NTamd64,NTx86,NTarm64\r\n"
    "\r\n"
    "[Models.NTamd64]\r\n"
    "\"LiberNT Package Staged Printer\"=TESTSTG,LiberNT_Package_Staged\r\n"
    "[Models.NTx86]\r\n"
    "\"LiberNT Package Staged Printer\"=TESTSTG,LiberNT_Package_Staged\r\n"
    "[Models.NTarm64]\r\n"
    "\"LiberNT Package Staged Printer\"=TESTSTG,LiberNT_Package_Staged\r\n"
    "\r\n"
    "[TESTSTG]\r\n"
    "CopyFiles=@TESTSTG.DLL,TESTSTG_FILES\r\n"
    "DataSection=TESTSTG_DATA\r\n"
    "Include=lntprnstgi.inf\r\n"
    "Needs=TESTSTG_NEEDED,TESTSTG_INCLUDED\r\n"
    "\r\n"
    "[TESTSTG_FILES]\r\n"
    "TESTSTG.DAT\r\n"
    "TESTSTGR.DAT,TESTSTGS.DAT\r\n"
    "\r\n"
    "[TESTSTG_DATA]\r\n"
    "CopyFiles=@TESTSTGD.DAT\r\n"
    "DriverFile=TESTSTG.DLL\r\n"
    "ConfigFile=TESTSTG.DLL\r\n"
    "DataFile=TESTSTG.DAT\r\n"
    "\r\n"
    "[TESTSTG_NEEDED]\r\n"
    "CopyFiles=@TESTSTGN.DAT\r\n"
    "Needs=TESTSTG_NEEDED_MORE\r\n"
    "\r\n"
    "[TESTSTG_NEEDED_MORE]\r\n"
    "CopyFiles=@TESTSTGM.DAT\r\n"
    "\r\n"
    "[TESTSTG_UNUSED]\r\n"
    "CopyFiles=@TESTSTGU.DAT\r\n"
    "\r\n"
    "[DestinationDirs]\r\n"
    "DefaultDestDir=66000\r\n"
    "\r\n"
    "[SourceDisksNames]\r\n"
    "1=\"Disk\",,,\r\n"
    "\r\n"
    "[SourceDisksFiles]\r\n"
    "TESTSTG.DLL=1\r\n"
    "TESTSTG.DAT=1\r\n"
    "TESTSTGS.DAT=1\r\n"
    "TESTSTGD.DAT=1\r\n"
    "TESTSTGN.DAT=1\r\n"
    "TESTSTGM.DAT=1\r\n"
    "TESTSTGU.DAT=1\r\n"
    "TESTSTGX.DAT=1\r\n";

static const char StagedIncludedInf[] =
    "[Version]\r\n"
    "Signature=\"$Windows NT$\"\r\n"
    "\r\n"
    "[TESTSTG_INCLUDED]\r\n"
    "CopyFiles=@TESTSTGI.DAT\r\n";

/* Windows 11 22621 stages the INF, its catalog and what the CopyFiles lists of the install sections of the models copy, under the */
/* name of the source, with the sections of the INF that they need. It stages neither the CopyFiles of a DataSection or of a */
/* section that no model installs, nor an INF of the package that Include names or what its sections copy, nor any other file */
static VOID
TestStagedFiles(VOID)
{
    static const PCWSTR Staged[] = { L"lntprnstg.inf", TEST_CATALOG, L"TESTSTG.DLL", L"TESTSTG.DAT", L"TESTSTGS.DAT", L"TESTSTGN.DAT", L"TESTSTGM.DAT" };
    static const PCWSTR Left[] = { L"TESTSTGD.DAT", L"TESTSTGU.DAT", L"TESTSTGI.DAT", L"TESTSTGX.DAT", L"lntprnstgi.inf" };
    static const char Text[] = "LiberNT package test file\r\n";
    WCHAR Dir[MAX_PATH], InfPath[MAX_PATH], StoreInf[MAX_PATH], Path[MAX_PATH];
    ULONG Length = ARRAYSIZE(StoreInf);
    BOOL Created;
    HRESULT hr;
    UINT i;

    GetTempPathW(MAX_PATH, Dir);
    StringCchCatW(Dir, MAX_PATH, L"lntprnstg");
    CreateDirectoryW(Dir, NULL);
    StringCchPrintfW(InfPath, ARRAYSIZE(InfPath), L"%s\\lntprnstg.inf", Dir);

    Created = WriteTestFile(Dir, L"lntprnstg.inf", StagedInf, sizeof(StagedInf) - 1) && CopyTestDriverFile(Dir, L"TESTSTG.DLL") &&
              WriteTestFile(Dir, L"lntprnstgi.inf", StagedIncludedInf, sizeof(StagedIncludedInf) - 1);
    for (i = 3; Created && i < ARRAYSIZE(Staged); i++)
        Created = WriteTestFile(Dir, Staged[i], Text, sizeof(Text) - 1);
    for (i = 0; Created && i + 1 < ARRAYSIZE(Left); i++)
        Created = WriteTestFile(Dir, Left[i], Text, sizeof(Text) - 1);

    if (Created)
    {
        hr = UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_SILENT_UPLOAD, NULL, StoreInf, &Length);
        ok(hr == S_OK, "UploadPrinterDriverPackageW(lntprnstg.inf) returned 0x%lx\n", hr);
        if (hr == S_OK)
        {
            CheckStagedFiles(StoreInf, Staged, ARRAYSIZE(Staged), "lntprnstg.inf");
            hr = DeletePrinterDriverPackageW(NULL, StoreInf, NULL);
            ok(hr == S_OK, "DeletePrinterDriverPackageW returned 0x%lx\n", hr);
        }
    }
    else
    {
        skip("Failed to create the package lntprnstg.inf (%lu)\n", GetLastError());
    }

    for (i = 0; i < ARRAYSIZE(Staged) + ARRAYSIZE(Left); i++)
    {
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\%s", Dir, i < ARRAYSIZE(Staged) ? Staged[i] : Left[i - ARRAYSIZE(Staged)]);
        DeleteFileW(Path);
    }
    RemoveDirectoryW(Dir);
}

#define INCLUDED_DRIVER_NAME L"LiberNT Package Included Printer"
#define INCLUDING_DRIVER_NAME L"LiberNT Package Including Printer"

#define STORE_INF(Models, Driver, Section, Rest) \
    "[Version]\r\n" \
    "Signature=\"$Windows NT$\"\r\n" \
    "Class=Printer\r\n" \
    "ClassGUID={4D36E979-E325-11CE-BFC1-08002BE10318}\r\n" \
    "Provider=LiberNT\r\n" \
    "DriverVer=11/06/2026,1.0.0.0\r\n" \
    "CatalogFile=lntprn.cat\r\n" \
    "\r\n" \
    "[Manufacturer]\r\n" \
    "\"LiberNT " Models "\"=" Models ",NTamd64,NTx86,NTarm64\r\n" \
    "\r\n" \
    "[" Models ".NTamd64]\r\n" \
    "\"" Driver "\"=" Section ",LiberNT_" Section "\r\n" \
    "[" Models ".NTx86]\r\n" \
    "\"" Driver "\"=" Section ",LiberNT_" Section "\r\n" \
    "[" Models ".NTarm64]\r\n" \
    "\"" Driver "\"=" Section ",LiberNT_" Section "\r\n" \
    "\r\n" \
    "[" Section "]\r\n" \
    "CopyFiles=@" Section ".DLL,@" Section ".DAT\r\n" \
    "DriverFile=" Section ".DLL\r\n" \
    "ConfigFile=" Section ".DLL\r\n" \
    "DataFile=" Section ".DAT\r\n" \
    Rest \
    "\r\n" \
    "[DestinationDirs]\r\n" \
    "DefaultDestDir=66000\r\n" \
    "\r\n" \
    "[SourceDisksNames]\r\n" \
    "1=\"Disk\",,,\r\n" \
    "\r\n" \
    "[SourceDisksFiles]\r\n" \
    Section ".DLL=1\r\n" \
    Section ".DAT=1\r\n"

static const char IncludedStoreInf[] =
    STORE_INF("ModelsA", "LiberNT Package Included Printer", "TESTINA",
              "\r\n[TESTINA_SHARED]\r\nCopyFiles=@TESTINA.DAT\r\n"
              "\r\n[TESTINA_OTHER]\r\nCopyFiles=@TESTINB.DAT\r\n"
              "\r\n[TESTINA_GONE]\r\nCopyFiles=@TESTGONE.DAT\r\n"
              "\r\n[TESTINA_UNUSED]\r\nCopyFiles=@TESTINA.DAT\r\n");
static const char IncludingStoreInf[] = STORE_INF("ModelsB", "LiberNT Package Including Printer", "TESTINB", "Include=%S\r\n%s");

/* Windows 11 22621 includes the INF that another package of the store is published as and follows Needs to a section of that INF. */
/* What the section copies is staged from the including package, which is not uploaded without the file, and is installed from the */
/* included package, which has to have the file too */
static VOID
TestStoreInclude(VOID)
{
    static const struct
    {
        PCSTR Needs;
        HRESULT Upload;
        HRESULT Install;
    } Cases[] =
    {
        { "Needs=TESTINA_GONE\r\n", __HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), S_OK },
        { "Needs=TESTINA_OTHER\r\n", S_OK, __HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) },
        { "", S_OK, S_OK },
        { "Needs=TESTINA_SHARED\r\n", __HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), S_OK },
        { "Needs=TESTINA_SHARED\r\n;both\r\n", S_OK, S_OK },
    };
    static const PCWSTR IncludedNames[] = { L"lntprnina.inf", TEST_CATALOG, L"TESTINA.DLL", L"TESTINA.DAT" };
    static const PCWSTR IncludingNames[] = { L"lntprninb.inf", TEST_CATALOG, L"TESTINB.DLL", L"TESTINB.DAT", L"TESTINA.DAT" };
    static const char Text[] = "LiberNT package test file\r\n";
    static const char Other[] = "the file of the including package\r\n";
    static char Inf[sizeof(IncludingStoreInf) + MAX_PATH];
    WCHAR Temp[MAX_PATH], DirA[MAX_PATH], DirB[MAX_PATH], InfA[MAX_PATH], InfB[MAX_PATH], StoreA[MAX_PATH], StoreB[MAX_PATH];
    WCHAR Published[MAX_PATH], Path[MAX_PATH], DriverDir[MAX_PATH] = L"";
    static WCHAR Value[1024];
    DWORD Size = sizeof(DriverDir);
    PWSTR Entry;
    ULONG Length;
    HRESULT hr;
    HKEY hKey;
    UINT i;

    GetTempPathW(ARRAYSIZE(Temp), Temp);
    StringCchPrintfW(DirA, ARRAYSIZE(DirA), L"%slntprnina", Temp);
    StringCchPrintfW(DirB, ARRAYSIZE(DirB), L"%slntprninb", Temp);
    StringCchPrintfW(InfA, ARRAYSIZE(InfA), L"%s\\lntprnina.inf", DirA);
    StringCchPrintfW(InfB, ARRAYSIZE(InfB), L"%s\\lntprninb.inf", DirB);
    CreateDirectoryW(DirA, NULL);
    CreateDirectoryW(DirB, NULL);
    GetPrinterDriverDirectoryW(NULL, NULL, 1, (PBYTE)DriverDir, Size, &Size);

    Length = ARRAYSIZE(StoreA);
    if (!WriteTestFile(DirA, L"lntprnina.inf", IncludedStoreInf, sizeof(IncludedStoreInf) - 1) || !CopyTestDriverFile(DirA, L"TESTINA.DLL") ||
        !WriteTestFile(DirA, L"TESTINA.DAT", Text, sizeof(Text) - 1) ||
        !CopyTestDriverFile(DirB, L"TESTINB.DLL") || !WriteTestFile(DirB, L"TESTINB.DAT", Text, sizeof(Text) - 1))
    {
        skip("Failed to create the packages lntprnina.inf and lntprninb.inf (%lu)\n", GetLastError());
    }
    else if ((hr = UploadPrinterDriverPackageW(NULL, InfA, NULL, UPDP_SILENT_UPLOAD, NULL, StoreA, &Length)) != S_OK ||
             !FindPublishedInf(InfA, Published))
    {
        ok(FALSE, "lntprnina.inf is not uploaded and published (0x%lx)\n", hr);
        if (hr == S_OK)
            DeletePrinterDriverPackageW(NULL, StoreA, NULL);
    }
    else
    {
        for (i = 0; i < ARRAYSIZE(Cases); i++)
        {
            StringCchPrintfA(Inf, ARRAYSIZE(Inf), IncludingStoreInf, wcsrchr(Published, L'\\') + 1, Cases[i].Needs);
            ok(WriteTestFile(DirB, L"lntprninb.inf", Inf, (DWORD)strlen(Inf)), "Writing lntprninb.inf failed\n");
            /* The last case has the file of the included package in the including one too */
            if (strstr(Cases[i].Needs, "both"))
                ok(WriteTestFile(DirB, L"TESTINA.DAT", Other, sizeof(Other) - 1), "Writing TESTINA.DAT failed\n");

            Length = ARRAYSIZE(StoreB);
            hr = UploadPrinterDriverPackageW(NULL, InfB, NULL, UPDP_SILENT_UPLOAD, NULL, StoreB, &Length);
            ok(hr == Cases[i].Upload, "UploadPrinterDriverPackageW returned 0x%lx for %s\n", hr, Cases[i].Needs);
            if (hr != S_OK)
                continue;
            CheckStagedFiles(StoreB, IncludingNames, strstr(Cases[i].Needs, "both") ? 5 : 4, Cases[i].Needs);

            hr = InstallPrinterDriverFromPackageW(NULL, StoreB, INCLUDING_DRIVER_NAME, NULL, 0);
            ok(hr == Cases[i].Install, "InstallPrinterDriverFromPackageW returned 0x%lx for %s\n", hr, Cases[i].Needs);
            hKey = OpenDriverKey(INCLUDING_DRIVER_NAME);
            ok((hKey != NULL) == (Cases[i].Install == S_OK), "Driver %S is %s for %s\n", INCLUDING_DRIVER_NAME,
               hKey ? "registered" : "not registered", Cases[i].Needs);
            if (hKey)
            {
                Size = sizeof(Value) - 2 * sizeof(WCHAR);
                ZeroMemory(Value, sizeof(Value));
                RegQueryValueExW(hKey, L"Dependent Files", NULL, NULL, (PBYTE)Value, &Size);
                for (Entry = Value; *Entry && _wcsicmp(Entry, L"TESTINA.DAT"); Entry += wcslen(Entry) + 1);
                ok((*Entry != UNICODE_NULL) == (strstr(Cases[i].Needs, "SHARED") != NULL), "TESTINA.DAT is %s for %s\n",
                   *Entry ? "a dependent file" : "no dependent file", Cases[i].Needs);
                ok(DriverFileExists(L"TESTINA.DAT") == (strstr(Cases[i].Needs, "SHARED") != NULL), "TESTINA.DAT is %s for %s\n",
                   *Entry ? "installed" : "not installed", Cases[i].Needs);
                if (strstr(Cases[i].Needs, "SHARED"))
                    ok(DriverFileIs(L"TESTINA.DAT", Text), "TESTINA.DAT is not the file of the included package\n");
                RegCloseKey(hKey);
                RemoveTestDriver(INCLUDING_DRIVER_NAME);
            }
            hr = DeletePrinterDriverPackageW(NULL, StoreB, NULL);
            ok(hr == S_OK, "DeletePrinterDriverPackageW returned 0x%lx for %s\n", hr, Cases[i].Needs);
        }

        hr = DeletePrinterDriverPackageW(NULL, StoreA, NULL);
        ok(hr == S_OK, "DeletePrinterDriverPackageW(%S) returned 0x%lx\n", StoreA, hr);
    }

    for (i = 0; i < ARRAYSIZE(IncludingNames); i++)
    {
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\%s", DirA, IncludedNames[i < ARRAYSIZE(IncludedNames) ? i : 0]);
        DeleteFileW(Path);
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\%s", DirB, IncludingNames[i]);
        DeleteFileW(Path);
        if (DriverDir[0])
        {
            StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\3\\%s", DriverDir, IncludedNames[i < ARRAYSIZE(IncludedNames) ? i : 0]);
            DeleteFileW(Path);
            StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\3\\%s", DriverDir, IncludingNames[i]);
            DeleteFileW(Path);
        }
    }
    RemoveDirectoryW(DirA);
    RemoveDirectoryW(DirB);
}

#define DELETE_DRIVER_A L"LiberNT Package Delete A Printer"
#define DELETE_DRIVER_B L"LiberNT Package Delete B Printer"
#define DELETE_PRINTER L"LiberNT Package Delete Test Printer"

#define DELETE_MODELS \
    "\"LiberNT Package Delete A Printer\"=TESTDELA,LiberNT_Package_Delete_A\r\n" \
    "\"LiberNT Package Delete B Printer\"=TESTDELB,LiberNT_Package_Delete_B\r\n"

static const char DeleteInf[] =
    "[Version]\r\n"
    "Signature=\"$Windows NT$\"\r\n"
    "Class=Printer\r\n"
    "ClassGUID={4D36E979-E325-11CE-BFC1-08002BE10318}\r\n"
    "Provider=LiberNT\r\n"
    "DriverVer=11/06/2026,1.0.0.0\r\n"
    "CatalogFile=lntprn.cat\r\n"
    "\r\n"
    "[Manufacturer]\r\n"
    "\"LiberNT\"=Models,NTamd64,NTx86,NTarm64\r\n"
    "\r\n"
    "[Models.NTamd64]\r\n"
    DELETE_MODELS
    "[Models.NTx86]\r\n"
    DELETE_MODELS
    "[Models.NTarm64]\r\n"
    DELETE_MODELS
    "\r\n"
    "[TESTDELA]\r\n"
    "CopyFiles=TESTDELA_FILES\r\n"
    "DriverFile=TESTDELA.DLL\r\n"
    "ConfigFile=TESTDELU.DLL\r\n"
    "DataFile=TESTDELA.GPD\r\n"
    "HelpFile=TESTDEL.HLP\r\n"
    "\r\n"
    "[TESTDELB]\r\n"
    "CopyFiles=TESTDELB_FILES\r\n"
    "DriverFile=TESTDELB.DLL\r\n"
    "ConfigFile=TESTDELU.DLL\r\n"
    "DataFile=TESTDELB.GPD\r\n"
    "HelpFile=TESTDEL.HLP\r\n"
    "\r\n"
    "[TESTDELA_FILES]\r\n"
    "TESTDELA.DLL\r\n"
    "TESTDELU.DLL\r\n"
    "TESTDELA.GPD\r\n"
    "TESTDEL.HLP\r\n"
    "TESTDELA.DAT\r\n"
    "TESTDEL.DAT\r\n"
    "\r\n"
    "[TESTDELB_FILES]\r\n"
    "TESTDELB.DLL\r\n"
    "TESTDELU.DLL\r\n"
    "TESTDELB.GPD\r\n"
    "TESTDEL.HLP\r\n"
    "TESTDEL.DAT\r\n"
    "\r\n"
    "[DestinationDirs]\r\n"
    "DefaultDestDir=66000\r\n"
    "\r\n"
    "[SourceDisksNames]\r\n"
    "1=\"Disk\",,,\r\n"
    "\r\n"
    "[SourceDisksFiles]\r\n"
    "TESTDELA.DLL=1\r\n"
    "TESTDELB.DLL=1\r\n"
    "TESTDELU.DLL=1\r\n"
    "TESTDELA.GPD=1\r\n"
    "TESTDELB.GPD=1\r\n"
    "TESTDEL.HLP=1\r\n"
    "TESTDELA.DAT=1\r\n"
    "TESTDEL.DAT=1\r\n";

/* The files of driver A, the files A and B share, and the files of B */
static const PCWSTR DeleteFiles[] = { L"TESTDELA.DLL", L"TESTDELA.GPD", L"TESTDELA.DAT", L"TESTDELU.DLL", L"TESTDEL.HLP",
                                      L"TESTDEL.DAT", L"TESTDELB.DLL", L"TESTDELB.GPD" };
#define DELETE_FILES_A 0x07
#define DELETE_FILES_SHARED 0x38
#define DELETE_FILES_B 0xC0

static DWORD
InstalledDeleteFiles(VOID)
{
    DWORD Mask = 0;
    UINT i;

    for (i = 0; i < ARRAYSIZE(DeleteFiles); i++)
    {
        if (DriverFileExists(DeleteFiles[i]))
            Mask |= 1 << i;
    }
    return Mask;
}

static DWORD
DeleteDriverError(PCWSTR Environment, PCWSTR Name, DWORD Flags, DWORD Version)
{
    SetLastError(0xdeadbeef);
    if (DeletePrinterDriverExW(NULL, (PWSTR)Environment, (PWSTR)Name, Flags, Version))
        return ERROR_SUCCESS;
    return GetLastError();
}

static BOOL
DriverRegistered(PCWSTR Name)
{
    HKEY hKey = OpenDriverKey(Name);

    if (hKey)
        RegCloseKey(hKey);
    return hKey != NULL;
}

static BOOL
InstallDeleteDriver(PCWSTR StoreInf, PCWSTR Name)
{
    HRESULT hr = InstallPrinterDriverFromPackageW(NULL, StoreInf, Name, NULL, 0);

    ok(hr == S_OK, "InstallPrinterDriverFromPackageW(%S) returned 0x%lx\n", Name, hr);
    return hr == S_OK;
}

typedef struct _IN_USE_DRIVER
{
    WCHAR Name[MAX_PATH];
    HANDLE hPrinter;
    BOOL Registered;
} IN_USE_DRIVER, *PIN_USE_DRIVER;

/* Windows 11 adds a printer with the driver of a printer it has and moves it to driver A; LiberNT adds no printer,
   so the driver of its setup printer is registered with the files of driver A */
static BOOL
UseDeleteDriver(PIN_USE_DRIVER InUse)
{
    PRINTER_INFO_2W Info = { 0 }, *Printers;
    DWORD Size = 0, Count = 0;
    DRIVER_INFO_3W Driver = { 0 };
    BOOL Found;

    ZeroMemory(InUse, sizeof(*InUse));
    EnumPrintersW(PRINTER_ENUM_LOCAL, NULL, 2, NULL, 0, &Size, &Count);
    Printers = Size ? HeapAlloc(GetProcessHeap(), 0, Size) : NULL;
    Found = Printers && EnumPrintersW(PRINTER_ENUM_LOCAL, NULL, 2, (PBYTE)Printers, Size, &Size, &Count) && Count &&
            SUCCEEDED(StringCchCopyW(InUse->Name, ARRAYSIZE(InUse->Name), Printers[0].pDriverName));
    HeapFree(GetProcessHeap(), 0, Printers);
    if (!Found)
    {
        skip("No printer to take the driver of (%lu)\n", GetLastError());
        return FALSE;
    }

    if (IsReactOS())
    {
        if (DriverRegistered(InUse->Name))
            return TRUE;
        Driver.cVersion = 3;
        Driver.pName = InUse->Name;
        Driver.pEnvironment = (PWSTR)TEST_ENVIRONMENT;
        Driver.pDriverPath = (PWSTR)L"TESTDELA.DLL";
        Driver.pDataFile = (PWSTR)L"TESTDELA.GPD";
        Driver.pConfigFile = (PWSTR)L"TESTDELU.DLL";
        InUse->Registered = AddPrinterDriverExW(NULL, 3, (PBYTE)&Driver, APD_COPY_NEW_FILES);
        ok(InUse->Registered, "AddPrinterDriverExW(%S) failed with %lu\n", InUse->Name, GetLastError());
        return InUse->Registered;
    }

    Info.pPrinterName = (PWSTR)DELETE_PRINTER;
    Info.pPortName = (PWSTR)L"PORTPROMPT:";
    Info.pDriverName = InUse->Name;
    Info.pPrintProcessor = (PWSTR)L"winprint";
    Info.pDatatype = (PWSTR)L"RAW";
    InUse->hPrinter = AddPrinterW(NULL, 2, (PBYTE)&Info);
    ok(InUse->hPrinter != NULL, "AddPrinterW(%S) failed with %lu\n", InUse->Name, GetLastError());
    if (!InUse->hPrinter)
        return FALSE;
    Info.pDriverName = (PWSTR)DELETE_DRIVER_A;
    ok(SetPrinterW(InUse->hPrinter, 2, (PBYTE)&Info, 0), "SetPrinterW failed with %lu\n", GetLastError());
    StringCchCopyW(InUse->Name, ARRAYSIZE(InUse->Name), DELETE_DRIVER_A);
    return TRUE;
}

static VOID
ReleaseDeleteDriver(PIN_USE_DRIVER InUse)
{
    WCHAR Key[MAX_PATH * 2];

    if (InUse->hPrinter)
    {
        ok(DeletePrinter(InUse->hPrinter), "DeletePrinter failed with %lu\n", GetLastError());
        ClosePrinter(InUse->hPrinter);
    }
    if (InUse->Registered && SUCCEEDED(StringCchPrintfW(Key, ARRAYSIZE(Key), L"%s\\%s", TEST_DRIVERS_KEY, InUse->Name)))
        ok(RegDeleteKeyW(HKEY_LOCAL_MACHINE, Key) == ERROR_SUCCESS, "Cannot delete the key of %S\n", InUse->Name);
}

static VOID
TestDeletePrinterDriverEx(VOID)
{
    WCHAR Dir[MAX_PATH], InfPath[MAX_PATH], StoreInf[MAX_PATH], Path[MAX_PATH], DriverDir[MAX_PATH];
    static const char Text[] = "LiberNT package test file\r\n";
    static const PCWSTR Copies[] = { L"TESTDELA.DLL", L"TESTDELB.DLL", L"TESTDELU.DLL" };
    static const PCWSTR Texts[] = { L"TESTDELA.GPD", L"TESTDELB.GPD", L"TESTDEL.HLP", L"TESTDELA.DAT", L"TESTDEL.DAT" };
    ULONG Length = ARRAYSIZE(StoreInf);
    IN_USE_DRIVER InUse;
    DWORD Error, Size, Files;
    HANDLE hFile;
    BOOL Created;
    HRESULT hr;
    UINT i;

    /* Windows 11 checks the flags and the name before the environment, and looks for the driver in every version */
    Error = DeleteDriverError(NULL, L"No Such Printer", 0, 0);
    ok(Error == ERROR_UNKNOWN_PRINTER_DRIVER, "Deleting an unknown driver gave %lu\n", Error);
    Error = DeleteDriverError(NULL, L"No Such Printer", DPD_DELETE_ALL_FILES, 0);
    ok(Error == ERROR_UNKNOWN_PRINTER_DRIVER, "Deleting an unknown driver with its files gave %lu\n", Error);
    Error = DeleteDriverError(NULL, L"No Such Printer", DPD_DELETE_SPECIFIC_VERSION, 2);
    ok(Error == ERROR_UNKNOWN_PRINTER_DRIVER, "Deleting version 2 of an unknown driver gave %lu\n", Error);
    Error = DeleteDriverError(OTHER_ENVIRONMENT, L"No Such Printer", 0, 0);
    ok(Error == ERROR_UNKNOWN_PRINTER_DRIVER, "Deleting an unknown driver of %S gave %lu\n", OTHER_ENVIRONMENT, Error);
    Error = DeleteDriverError(L"Invalid Env", L"No Such Printer", 0, 0);
    ok(Error == ERROR_INVALID_ENVIRONMENT, "Deleting in an invalid environment gave %lu\n", Error);
    Error = DeleteDriverError(NULL, L"", 0, 0);
    ok(Error == ERROR_INVALID_PARAMETER, "Deleting an empty name gave %lu\n", Error);
    Error = DeleteDriverError(L"Invalid Env", L"", 0, 0);
    ok(Error == ERROR_INVALID_PARAMETER, "Deleting an empty name in an invalid environment gave %lu\n", Error);
    Error = DeleteDriverError(NULL, L"No Such Printer", 0x8, 0);
    ok(Error == ERROR_INVALID_PARAMETER, "Deleting with flag 0x8 gave %lu\n", Error);
    Error = DeleteDriverError(L"Invalid Env", L"No Such Printer", 0x80000000, 0);
    ok(Error == ERROR_INVALID_PARAMETER, "Deleting with flag 0x80000000 in an invalid environment gave %lu\n", Error);
    SetLastError(0xdeadbeef);
    ok(!DeletePrinterDriverExW((PWSTR)L"", NULL, (PWSTR)L"No Such Printer", 0, 0) && GetLastError() == ERROR_UNKNOWN_PRINTER_DRIVER,
       "Deleting on the server \"\" gave %lu\n", GetLastError());
    SetLastError(0xdeadbeef);
    ok(!DeletePrinterDriverW(NULL, NULL, (PWSTR)L"No Such Printer") && GetLastError() == ERROR_UNKNOWN_PRINTER_DRIVER,
       "DeletePrinterDriverW of an unknown driver gave %lu\n", GetLastError());

    GetTempPathW(MAX_PATH, Dir);
    StringCchCatW(Dir, MAX_PATH, L"lntprndel");
    CreateDirectoryW(Dir, NULL);
    StringCchPrintfW(InfPath, ARRAYSIZE(InfPath), L"%s\\lntprndel.inf", Dir);
    Created = WriteTestFile(Dir, L"lntprndel.inf", DeleteInf, sizeof(DeleteInf) - 1);
    for (i = 0; Created && i < ARRAYSIZE(Copies); i++)
        Created = CopyTestDriverFile(Dir, Copies[i]);
    for (i = 0; Created && i < ARRAYSIZE(Texts); i++)
        Created = WriteTestFile(Dir, Texts[i], Text, sizeof(Text) - 1);

    hr = Created ? UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_SILENT_UPLOAD, NULL, StoreInf, &Length) : E_FAIL;
    ok(hr == S_OK, "UploadPrinterDriverPackageW(%S) returned 0x%lx\n", InfPath, hr);
    if (hr == S_OK && InstallDeleteDriver(StoreInf, DELETE_DRIVER_A) && InstallDeleteDriver(StoreInf, DELETE_DRIVER_B))
    {
        Files = InstalledDeleteFiles();
        ok(Files == 0xFF, "Installed files are 0x%lx\n", Files);

        /* A version that does not have the driver is deleted as nothing */
        Error = DeleteDriverError(OTHER_ENVIRONMENT, DELETE_DRIVER_A, 0, 0);
        ok(Error == ERROR_UNKNOWN_PRINTER_DRIVER, "Deleting A of %S gave %lu\n", OTHER_ENVIRONMENT, Error);
        Error = DeleteDriverError(NULL, DELETE_DRIVER_A, DPD_DELETE_SPECIFIC_VERSION, 2);
        ok(Error == ERROR_SUCCESS, "Deleting version 2 of A gave %lu\n", Error);
        Error = DeleteDriverError(NULL, DELETE_DRIVER_A, DPD_DELETE_SPECIFIC_VERSION | DPD_DELETE_ALL_FILES, 4);
        ok(Error == ERROR_SUCCESS, "Deleting version 4 of A and its files gave %lu\n", Error);
        Error = DeleteDriverError(NULL, DELETE_DRIVER_A, 0x10, 0);
        ok(Error == ERROR_INVALID_PARAMETER, "Deleting A with flag 0x10 gave %lu\n", Error);
        Files = InstalledDeleteFiles();
        ok(Files == 0xFF && DriverRegistered(DELETE_DRIVER_A), "Deleting nothing of A left 0x%lx\n", Files);

        if (UseDeleteDriver(&InUse))
        {
            Error = DeleteDriverError(NULL, InUse.Name, 0, 0);
            ok(Error == ERROR_PRINTER_DRIVER_IN_USE, "Deleting %S used by a printer gave %lu\n", InUse.Name, Error);
            Error = DeleteDriverError(NULL, InUse.Name, DPD_DELETE_UNUSED_FILES, 0);
            ok(Error == ERROR_PRINTER_DRIVER_IN_USE, "Deleting %S used by a printer and its unused files gave %lu\n", InUse.Name, Error);
            Error = DeleteDriverError(NULL, InUse.Name, DPD_DELETE_ALL_FILES | DPD_DELETE_SPECIFIC_VERSION, 3);
            ok(Error == ERROR_PRINTER_DRIVER_IN_USE, "Deleting version 3 of %S used by a printer gave %lu\n", InUse.Name, Error);
            Error = DeleteDriverError(NULL, InUse.Name, DPD_DELETE_SPECIFIC_VERSION, 2);
            ok(Error == ERROR_SUCCESS, "Deleting version 2 of %S used by a printer gave %lu\n", InUse.Name, Error);
            Error = DeleteDriverError(OTHER_ENVIRONMENT, InUse.Name, 0, 0);
            ok(Error == ERROR_UNKNOWN_PRINTER_DRIVER, "Deleting %S of %S used by a printer gave %lu\n", InUse.Name, OTHER_ENVIRONMENT, Error);
            Files = InstalledDeleteFiles();
            ok(Files == 0xFF && DriverRegistered(InUse.Name), "Deleting %S used by a printer left 0x%lx\n", InUse.Name, Files);
        }
        ReleaseDeleteDriver(&InUse);

        /* Windows 11 refuses to delete all files of A as B names some, also when the unused ones are asked for */
        Error = DeleteDriverError(NULL, DELETE_DRIVER_A, DPD_DELETE_ALL_FILES, 0);
        ok(Error == ERROR_PRINTER_DRIVER_IN_USE, "Deleting A and all its files gave %lu\n", Error);
        Error = DeleteDriverError(NULL, DELETE_DRIVER_A, DPD_DELETE_ALL_FILES | DPD_DELETE_UNUSED_FILES, 0);
        ok(Error == ERROR_PRINTER_DRIVER_IN_USE, "Deleting A, all its files and the unused ones gave %lu\n", Error);
        Files = InstalledDeleteFiles();
        ok(Files == 0xFF && DriverRegistered(DELETE_DRIVER_A), "Refusing to delete all files of A left 0x%lx\n", Files);

        Error = DeleteDriverError(NULL, DELETE_DRIVER_A, DPD_DELETE_UNUSED_FILES, 0);
        ok(Error == ERROR_SUCCESS, "Deleting A and its unused files gave %lu\n", Error);
        Files = InstalledDeleteFiles();
        ok(Files == (DELETE_FILES_SHARED | DELETE_FILES_B), "Deleting A and its unused files left 0x%lx\n", Files);
        ok(!DriverRegistered(DELETE_DRIVER_A), "A is still registered\n");
        Error = DeleteDriverError(NULL, DELETE_DRIVER_A, 0, 0);
        ok(Error == ERROR_UNKNOWN_PRINTER_DRIVER, "Deleting A again gave %lu\n", Error);

        SetLastError(0xdeadbeef);
        ok(DeletePrinterDriverW(NULL, NULL, (PWSTR)DELETE_DRIVER_B), "DeletePrinterDriverW(B) failed with %lu\n", GetLastError());
        Files = InstalledDeleteFiles();
        ok(Files == (DELETE_FILES_SHARED | DELETE_FILES_B), "DeletePrinterDriverW(B) left 0x%lx\n", Files);
        ok(!DriverRegistered(DELETE_DRIVER_B), "B is still registered\n");

        if (InstallDeleteDriver(StoreInf, DELETE_DRIVER_A) && InstallDeleteDriver(StoreInf, DELETE_DRIVER_B))
        {
            Error = DeleteDriverError(TEST_ENVIRONMENT, DELETE_DRIVER_B, DPD_DELETE_ALL_FILES | DPD_DELETE_SPECIFIC_VERSION, 3);
            ok(Error == ERROR_PRINTER_DRIVER_IN_USE, "Deleting version 3 of B and all its files gave %lu\n", Error);
            Error = DeleteDriverError(NULL, DELETE_DRIVER_B, DPD_DELETE_UNUSED_FILES | DPD_DELETE_SPECIFIC_VERSION, 3);
            ok(Error == ERROR_SUCCESS, "Deleting version 3 of B and its unused files gave %lu\n", Error);
            Files = InstalledDeleteFiles();
            ok(Files == (DELETE_FILES_A | DELETE_FILES_SHARED), "Deleting B and its unused files left 0x%lx\n", Files);

            /* The version goes with the flag that selects it, and all files of a driver alone go */
            Error = DeleteDriverError(TEST_ENVIRONMENT, DELETE_DRIVER_A, DPD_DELETE_ALL_FILES, 2);
            ok(Error == ERROR_SUCCESS, "Deleting A and all its files gave %lu\n", Error);
            Files = InstalledDeleteFiles();
            ok(Files == 0, "Deleting A and all its files left 0x%lx\n", Files);
        }

        /* An open file of the driver stays where it is */
        if (InstallDeleteDriver(StoreInf, DELETE_DRIVER_A) && InstallDeleteDriver(StoreInf, DELETE_DRIVER_B))
        {
            Size = sizeof(DriverDir);
            if (!GetPrinterDriverDirectoryW(NULL, NULL, 1, (PBYTE)DriverDir, Size, &Size))
                DriverDir[0] = UNICODE_NULL;
            StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\3\\TESTDELA.DAT", DriverDir);
            hFile = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            ok(hFile != INVALID_HANDLE_VALUE, "Cannot open %S (%lu)\n", Path, GetLastError());
            Error = DeleteDriverError(NULL, L"LIBERNT PACKAGE DELETE A PRINTER", DPD_DELETE_UNUSED_FILES, 0);
            ok(Error == ERROR_SUCCESS, "Deleting A in upper case and its unused files gave %lu\n", Error);
            if (hFile != INVALID_HANDLE_VALUE)
                CloseHandle(hFile);
            Files = InstalledDeleteFiles();
            ok(Files == (0x04 | DELETE_FILES_SHARED | DELETE_FILES_B), "Deleting A with an open file left 0x%lx\n", Files);
        }

        RemoveTestDriver(DELETE_DRIVER_A);
        RemoveTestDriver(DELETE_DRIVER_B);
    }
    if (hr == S_OK)
    {
        hr = DeletePrinterDriverPackageW(NULL, StoreInf, NULL);
        ok(hr == S_OK, "DeletePrinterDriverPackageW(%S) returned 0x%lx\n", StoreInf, hr);
    }

    Size = sizeof(DriverDir);
    if (!GetPrinterDriverDirectoryW(NULL, NULL, 1, (PBYTE)DriverDir, Size, &Size))
        DriverDir[0] = UNICODE_NULL;
    for (i = 0; i < ARRAYSIZE(DeleteFiles); i++)
    {
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\%s", Dir, DeleteFiles[i]);
        DeleteFileW(Path);
        if (DriverDir[0])
        {
            StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\3\\%s", DriverDir, DeleteFiles[i]);
            DeleteFileW(Path);
        }
    }
    DeleteFileW(InfPath);
    RemoveDirectoryW(Dir);
}

static VOID
TestDriverPackages(VOID)
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
    ok(hr == HRESULT_FROM_WIN32(ERROR_UNKNOWN_PRINTER_DRIVER), "InstallPrinterDriverFromPackageW returned 0x%lx without an INF\n", hr);
    hr = InstallPrinterDriverFromPackageW(NULL, L"C:\\x.inf", TEST_DRIVER_NAME, NULL, 0x80);
    ok(hr == E_INVALIDARG, "InstallPrinterDriverFromPackageW returned 0x%lx\n", hr);
    hr = DeletePrinterDriverPackageW(NULL, NULL, NULL);
    ok(hr == E_INVALIDARG, "DeletePrinterDriverPackageW returned 0x%lx\n", hr);

    TestRefusedPackage(L"lntprnmiss", MissingInf, sizeof(MissingInf) - 1, L"TESTMISS.DAT", NULL, HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), NULL);
    TestRefusedPackage(L"lntprnneed", NeedsMissingInf, sizeof(NeedsMissingInf) - 1, L"TESTNM.DAT", NULL, HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), NULL);
    TestRefusedPackage(L"lntprnunl", UnlistedInf, sizeof(UnlistedInf) - 1, L"TESTUNL.DAT", NULL, HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), NULL);
    TestRefusedPackage(L"lntprnbad",MalformedInf, sizeof(MalformedInf) - 1, L"TESTBAD.DAT", NULL, E_FAIL, NULL);
    /* Windows 11 tells of a file outside the package directory that its hash is not in the catalog */
    TestRefusedPackage(L"lntprnesc", EscapeInf, sizeof(EscapeInf) - 1, L"TESTESC.DAT", L"lntprnesc.dll", SPAPI_E_FILE_HASH_NOT_IN_CATALOG, NULL);
    TestRefusedPackage(L"lntprnsle", SlashEscapeInf, sizeof(SlashEscapeInf) - 1, L"TESTSLE.DAT", L"lntprnout.dll", SPAPI_E_FILE_HASH_NOT_IN_CATALOG, NULL);
    /* and uploads a package whatever its Include names; an INF outside the package it does not include when it installs */
    TestRefusedPackage(L"lntprnies", IncludeEscapeInf, sizeof(IncludeEscapeInf) - 1, L"TESTIES.DAT", L"lntprnout.inf", S_OK,
                       L"LiberNT Package Include Escape Printer");
    TestInstallPackage(L"lntprnplain", L"LiberNT Package Plain Printer", PlainInf, sizeof(PlainInf) - 1,
                       L"TESTPLAIN.DLL", L"TESTPLAIN.GPD", 1, NULL, NULL, S_OK);
    /* Windows 11 follows Needs only to a section of ntprint.inf, so the files that the sections of the package copy are missing */
    TestInstallPackage(L"lntprntwo", L"LiberNT Package Two Needs Printer", TwoNeedsInf, sizeof(TwoNeedsInf) - 1,
                       L"TESTTWO.DLL", L"TESTTWO%u.DAT", 2, NULL, NULL, HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND));
    TestInstallPackage(L"lntprnbig",L"LiberNT Package Big Printer", BigInf, BuildBigInf(),
                       L"TESTBIG.DLL", L"TESTBIG%03u.DAT", BIG_SECTIONS * BIG_SECTION_FILES, L"TESTBIG139.DAT", NULL, S_OK);
    /* It includes no INF but ntprint.inf: one of the package is not supported, one with a directory is a path that is not found */
    TestInstallPackage(L"lntprninc", L"LiberNT Package Include Printer", IncludeInf, sizeof(IncludeInf) - 1,
                       L"TESTINC.DLL", L"TESTINC%u.DAT", 2, NULL, L"lntprncmn.inf", HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED));
    TestInstallPackage(L"lntprnsub", L"LiberNT Package Subdir Include Printer", SubdirIncludeInf, sizeof(SubdirIncludeInf) - 1,
                       L"TESTINC.DLL", L"TESTINC%u.DAT", 2, NULL, L"sub\\lntprncmn.inf", HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND));
    TestAbsoluteInclude();
    TestOtherEnvironment();
    TestMisplacedPackage(L"FileRepository-backup", L"lntprnsib", L"lntprnsib.inf");
    TestMisplacedPackage(L"FileRepository", L"lntprnbadh.inf_" TEST_STORE_ARCHITECTURE L"_0000000000000000", L"lntprnbadh.inf");
    TestIncompleteUpdate();
    TestJunctionPackage();
    /* The lock that the package functions and the Setup API share is of this implementation */
    if (IsReactOS())
    {
        TestSetupLock();
        TestOemInfRace();
    }
    TestStandardUserOemInf();
    TestMissingCopyFilesSection();
    TestPackageSignature();
    TestStaleDriverFile();
    TestBlockedDriverFile(L"lntprnblk", BlockedSystemFile, HRESULT_FROM_WIN32(ERROR_PRINTER_DRIVER_BLOCKED), "version.dll");
    TestBlockedDriverFile(L"lntprnkm", BlockedNoExport, HRESULT_FROM_WIN32(ERROR_KM_DRIVER_BLOCKED), "a file without DrvQueryDriverInfo");
    TestBlockedDriverFile(L"lntprnv2", BlockedVersion2, HRESULT_FROM_WIN32(ERROR_KM_DRIVER_BLOCKED), "a file of the version 0.2");
    TestBlockedDriverFile(L"lntprnv4", BlockedVersion4, HRESULT_FROM_WIN32(ERROR_PRINTER_DRIVER_BLOCKED), "a file of the version 0.4");
    TestStagedFiles();
    TestStoreInclude();
    TestDeletePrinterDriverEx();
#if !defined(_M_IX86)
    TestUndecoratedModels();
#endif

    if (!CreateTestPackage(Dir, InfPath))
    {
        skip("Failed to create the test package (%lu)\n", GetLastError());
        return;
    }

    Length = ARRAYSIZE(StoreInf);
    hr = UploadPrinterDriverPackageW(NULL, L"C:\\does-not-exist\\none.inf", NULL, 0, NULL, StoreInf, &Length);
    ok(FAILED(hr), "UploadPrinterDriverPackageW returned 0x%lx\n", hr);

    Length = ARRAYSIZE(StoreInf);
    hr = UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_CHECK_DRIVERSTORE, NULL, StoreInf, &Length);
    ok(hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND), "UploadPrinterDriverPackageW returned 0x%lx for a package that is not in the store\n", hr);

    Length = 1;
    hr = UploadPrinterDriverPackageW(NULL, InfPath, NULL, UPDP_SILENT_UPLOAD, NULL, StoreInf, &Length);
    ok(hr == E_INVALIDARG, "UploadPrinterDriverPackageW returned 0x%lx for a buffer of one character\n", hr);
    ok(Length == 1, "Length is %lu\n", Length);

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

    /* Windows 11 takes the INF in the store alone; the INF that it was uploaded from is the same file elsewhere */
    {
        WCHAR Other[MAX_PATH];
        PWSTR Last = wcsrchr(StoreInf, L'\\');
        HKEY hNeeds;

        hr = InstallPrinterDriverFromPackageW(NULL, InfPath, NEEDS_DRIVER_NAME, NULL, 0);
        ok(hr == E_INVALIDARG, "InstallPrinterDriverFromPackageW(%S) returned 0x%lx\n", InfPath, hr);
        hr = InstallPrinterDriverFromPackageW(NULL, InfPath, L"No Such Printer", NULL, 0);
        ok(hr == E_INVALIDARG, "InstallPrinterDriverFromPackageW(%S) returned 0x%lx for an unknown driver\n", InfPath, hr);
        StringCchPrintfW(Other, ARRAYSIZE(Other), L"%.*s\\nosuch.inf", (int)(Last - StoreInf), StoreInf);
        hr = InstallPrinterDriverFromPackageW(NULL, Other, NEEDS_DRIVER_NAME, NULL, 0);
        ok(hr == E_INVALIDARG, "InstallPrinterDriverFromPackageW(%S) returned 0x%lx\n", Other, hr);
        StringCchPrintfW(Other, ARRAYSIZE(Other), L"%.*s", (int)(Last - StoreInf), StoreInf);
        hr = InstallPrinterDriverFromPackageW(NULL, Other, NEEDS_DRIVER_NAME, NULL, 0);
        ok(hr == E_INVALIDARG, "InstallPrinterDriverFromPackageW(%S) returned 0x%lx\n", Other, hr);

        /* Of the other ways to write the path, Windows 11 refuses "..", a relative path, a trailing dot and a short name */
        StringCchPrintfW(Other, ARRAYSIZE(Other), L"%.*s\\..%s", (int)(Last - StoreInf), StoreInf, wcsstr(StoreInf, L"\\lntprnpkg.inf_"));
        hr = InstallPrinterDriverFromPackageW(NULL, Other, NEEDS_DRIVER_NAME, NULL, 0);
        ok(hr == E_INVALIDARG, "InstallPrinterDriverFromPackageW(%S) returned 0x%lx\n", Other, hr);
        StringCchPrintfW(Other, ARRAYSIZE(Other), L"%s.", StoreInf);
        hr = InstallPrinterDriverFromPackageW(NULL, Other, NEEDS_DRIVER_NAME, NULL, 0);
        ok(hr == E_INVALIDARG, "InstallPrinterDriverFromPackageW(%S) returned 0x%lx\n", Other, hr);
        if (GetShortPathNameW(StoreInf, Other, ARRAYSIZE(Other)) && _wcsicmp(Other, StoreInf) != 0)
        {
            hr = InstallPrinterDriverFromPackageW(NULL, Other, NEEDS_DRIVER_NAME, NULL, 0);
            ok(hr == E_INVALIDARG, "InstallPrinterDriverFromPackageW(%S) returned 0x%lx\n", Other, hr);
        }
        GetCurrentDirectoryW(ARRAYSIZE(Other), Other);
        *Last = UNICODE_NULL;
        SetCurrentDirectoryW(StoreInf);
        *Last = L'\\';
        hr = InstallPrinterDriverFromPackageW(NULL, Last + 1, NEEDS_DRIVER_NAME, NULL, 0);
        ok(hr == E_INVALIDARG, "InstallPrinterDriverFromPackageW(%S) returned 0x%lx in the store directory\n", Last + 1, hr);
        SetCurrentDirectoryW(Other);

        hNeeds = OpenDriverKey(NEEDS_DRIVER_NAME);
        ok(hNeeds == NULL, "Driver %S is registered from an INF that is not in the store\n", NEEDS_DRIVER_NAME);
        if (hNeeds)
            RegCloseKey(hNeeds);

        /* The unknown driver tells that the path was taken: without a drive, in upper case and with "." after the drive */
        hr = InstallPrinterDriverFromPackageW(NULL, StoreInf + 2, L"No Such Printer", NULL, 0);
        ok(hr == HRESULT_FROM_WIN32(ERROR_UNKNOWN_PRINTER_DRIVER), "InstallPrinterDriverFromPackageW(%S) returned 0x%lx\n", StoreInf + 2, hr);
        StringCchCopyW(Other, ARRAYSIZE(Other), StoreInf);
        _wcsupr(Other);
        hr = InstallPrinterDriverFromPackageW(NULL, Other, L"No Such Printer", NULL, 0);
        ok(hr == HRESULT_FROM_WIN32(ERROR_UNKNOWN_PRINTER_DRIVER), "InstallPrinterDriverFromPackageW(%S) returned 0x%lx\n", Other, hr);
        StringCchPrintfW(Other, ARRAYSIZE(Other), L"%.3s.\\%s", StoreInf, StoreInf + 3);
        hr = InstallPrinterDriverFromPackageW(NULL, Other, L"No Such Printer", NULL, 0);
        ok(hr == HRESULT_FROM_WIN32(ERROR_UNKNOWN_PRINTER_DRIVER), "InstallPrinterDriverFromPackageW(%S) returned 0x%lx\n", Other, hr);

        /* A doubled backslash, after the drive or before the name, and "." as the directory of the INF are refused */
        StringCchPrintfW(Other, ARRAYSIZE(Other), L"%.3s\\%s", StoreInf, StoreInf + 3);
        hr = InstallPrinterDriverFromPackageW(NULL, Other, L"No Such Printer", NULL, 0);
        ok(hr == E_INVALIDARG, "InstallPrinterDriverFromPackageW(%S) returned 0x%lx\n", Other, hr);
        StringCchPrintfW(Other, ARRAYSIZE(Other), L"%.*s\\%s", (int)(Last - StoreInf), StoreInf, Last);
        hr = InstallPrinterDriverFromPackageW(NULL, Other, L"No Such Printer", NULL, 0);
        ok(hr == E_INVALIDARG, "InstallPrinterDriverFromPackageW(%S) returned 0x%lx\n", Other, hr);
        StringCchPrintfW(Other, ARRAYSIZE(Other), L"%.*s\\.%s", (int)(Last - StoreInf), StoreInf, Last);
        hr = InstallPrinterDriverFromPackageW(NULL, Other, L"No Such Printer", NULL, 0);
        ok(hr == E_INVALIDARG, "InstallPrinterDriverFromPackageW(%S) returned 0x%lx\n", Other, hr);
    }

    /* Windows 11 takes the published INF for its package under its full path with backslashes, and under no other */
    {
        WCHAR Published[MAX_PATH], Other[MAX_PATH], Value[MAX_PATH];
        DWORD Size = sizeof(Value);
        HKEY hNeeds;
        PWSTR Next;

        ok(FindPublishedInf(InfPath, Published), "%S is not published\n", InfPath);
        hr = InstallPrinterDriverFromPackageW(NULL, Published, L"No Such Printer", NULL, 0);
        ok(hr == HRESULT_FROM_WIN32(ERROR_UNKNOWN_PRINTER_DRIVER), "InstallPrinterDriverFromPackageW(%S) returned 0x%lx\n", Published, hr);
        StringCchCopyW(Other, ARRAYSIZE(Other), Published);
        for (Next = Other; *Next; Next++)
        {
            if (*Next == L'\\')
                *Next = L'/';
        }
        hr = InstallPrinterDriverFromPackageW(NULL, Other, NEEDS_DRIVER_NAME, NULL, 0);
        ok(hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND), "InstallPrinterDriverFromPackageW(%S) returned 0x%lx\n", Other, hr);
        Next = wcsrchr(Published, L'\\') + 1;
        hr = InstallPrinterDriverFromPackageW(NULL, Next, NEEDS_DRIVER_NAME, NULL, 0);
        ok(hr == E_INVALIDARG, "InstallPrinterDriverFromPackageW(%S) returned 0x%lx\n", Next, hr);

        hr = InstallPrinterDriverFromPackageW(NULL, Published, NEEDS_DRIVER_NAME, NULL, 0);
        ok(hr == S_OK, "InstallPrinterDriverFromPackageW(%S) returned 0x%lx\n", Published, hr);
        hNeeds = OpenDriverKey(NEEDS_DRIVER_NAME);
        ok(hNeeds != NULL && RegQueryValueExW(hNeeds, L"InfPath", NULL, NULL, (PBYTE)Value, &Size) == ERROR_SUCCESS &&
           !_wcsicmp(Value, StoreInf), "The driver installed from %S is not one of the package %S\n", Published, StoreInf);
        if (hNeeds)
            RegCloseKey(hNeeds);
        DeleteTestDriver();
    }

    TestSharedInf(InfPath, StoreInf);

    TestStoreReplacement(Dir, InfPath, StoreInf);

    /* Windows 11 passes over Needs of a section that no INF has, and installs for a flag it does not define */
    hr = InstallPrinterDriverFromPackageW(NULL, StoreInf, BROKEN_DRIVER_NAME, NULL, 0x80);
    ok(hr == S_OK, "InstallPrinterDriverFromPackageW returned 0x%lx\n", hr);
    {
        HKEY hBroken = OpenDriverKey(BROKEN_DRIVER_NAME);
        ok(hBroken != NULL, "Driver %S is not registered\n", BROKEN_DRIVER_NAME);
        if (hBroken)
            RegCloseKey(hBroken);
        RemoveTestDriver(BROKEN_DRIVER_NAME);
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
            ok(*Dependent != UNICODE_NULL, "TESTPKG.DAT is not a dependent file\n");
            /* Windows 11 does not follow Needs to a section of the package, here NEEDS_A and NEEDS_B */
            for (Dependent = Value; *Dependent && _wcsicmp(Dependent, L"TESTNEED.DAT"); Dependent += wcslen(Dependent) + 1);
            ok(*Dependent == UNICODE_NULL, "TESTNEED.DAT from NEEDS_B is a dependent file\n");
            ok(!DriverFileExists(L"TESTNEED.DAT"), "TESTNEED.DAT from NEEDS_B was installed\n");
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

        /* Windows 11 compares the path of the package as text: with "." as the directory of the INF it is not found */
        if (Last && SUCCEEDED(StringCchPrintfW(Other, ARRAYSIZE(Other), L"%.*s\\.%s", (int)(Last - StoreInf), StoreInf, Last)))
        {
            hr = DeletePrinterDriverPackageW(NULL, Other, NULL);
            ok(hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND), "DeletePrinterDriverPackageW(%S) returned 0x%lx\n", Other, hr);
        }

        StringCchCopyW(Other, ARRAYSIZE(Other), StoreInf);
        _wcsupr(Other);
        hr = DeletePrinterDriverPackageW(NULL, Other, NULL);
        ok(hr == HRESULT_FROM_WIN32(ERROR_PRINTER_DRIVER_PACKAGE_IN_USE),
           "DeletePrinterDriverPackageW(%S) returned 0x%lx\n", Other, hr);

        /* Windows 11 does not find a package under the path it was uploaded from */
        hr = DeletePrinterDriverPackageW(NULL, InfPath, NULL);
        ok(hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND), "DeletePrinterDriverPackageW(%S) returned 0x%lx\n", InfPath, hr);
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

    if (IsReactOS())
        TestPackageLock(InfPath, StoreInf);

    DeleteTestDriver();
    if (IsReactOS())
        TestConcurrentInstall(InfPath, StoreInf);

    /* What follows changes the package in the store and blocks its deletion, which is done to the store of this implementation alone */
    if (IsReactOS())
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

    if (IsReactOS())
    {
        TestHeldPackageDelete(InfPath, StoreInf);
        TestFailedPackageDelete(InfPath, StoreInf);
    }

    hr = DeletePrinterDriverPackageW(NULL, StoreInf, NULL);
    ok(hr == S_OK, "DeletePrinterDriverPackageW returned 0x%lx\n", hr);
    ok(GetFileAttributesW(StoreInf) == INVALID_FILE_ATTRIBUTES, "%S still exists\n", StoreInf);
    hr = DeletePrinterDriverPackageW(NULL, StoreInf, NULL);
    ok(hr == HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND), "DeletePrinterDriverPackageW returned 0x%lx for a package that is deleted\n", hr);

    DeleteTestPackage(Dir);
}

START_TEST(DriverPackage)
{
    if (!FindTestDriverFile())
    {
        skip("%S is not next to the test\n", TestDriverFile);
        return;
    }

    if (!CreateTestSigner(&TrustedSigner, L"LiberNT winspool apitest", "CN=LiberNT winspool apitest") ||
        !CreateTestSigner(&UntrustedSigner, L"LiberNT winspool apitest 2", "CN=LiberNT winspool apitest untrusted") ||
        !TrustTestSigner(L"Root", TRUE) || !TrustTestSigner(L"TrustedPublisher", TRUE))
    {
        skip("No trusted test certificate (0x%lx)\n", GetLastError());
    }
    else
    {
        TestDriverPackages();
        DeleteTestCatalogs();
    }

    if (TrustedSigner.Cert)
    {
        TrustTestSigner(L"TrustedPublisher", FALSE);
        TrustTestSigner(L"Root", FALSE);
    }
    DeleteTestSigner(&UntrustedSigner);
    DeleteTestSigner(&TrustedSigner);
}
