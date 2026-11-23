/*
 * PROJECT:     LiberNT Spooler API
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Printer driver packages in the driver store
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include "precomp.h"
#include <winnls.h>
#include <setupapi.h>
#include <drvpkglock.h>
#include <drvpkgenv.h>

HRESULT WINAPI DriverStoreAddDriverPackageW(PCWSTR InfPath, PVOID Reserved1, PVOID Reserved2,
                                            WORD Architecture, PWSTR ReturnPath, PDWORD ReturnLength);
HRESULT WINAPI DriverStoreDeleteDriverPackageW(PCWSTR InfPath, PVOID Reserved1, PVOID Reserved2);

#define DRIVERS_KEY L"SYSTEM\\CurrentControlSet\\Control\\Print\\Environments\\%s\\Drivers\\Version-3"

/* Windows 11 refuses an INF of another class with the Setup API error itself */
static BOOL
IsPrinterClassInf(PCWSTR InfPath)
{
    WCHAR Class[64];
    INFCONTEXT Context;
    BOOL Printer = TRUE;
    HINF hInf;

    hInf = SetupOpenInfFileW(InfPath, NULL, INF_STYLE_WIN4, NULL);
    if (hInf == INVALID_HANDLE_VALUE)
        return TRUE;
    if (SetupFindFirstLineW(hInf, L"Version", L"Class", &Context) &&
        SetupGetStringFieldW(&Context, 1, Class, ARRAYSIZE(Class), NULL))
    {
        Printer = _wcsicmp(Class, L"Printer") == 0;
    }
    SetupCloseInfFile(hInf);
    return Printer;
}

static const WCHAR StoreDirectory[] = L"\\System32\\DriverStore\\FileRepository";
static const WCHAR InfDirectory[] = L"\\INF\\";

/* Windows 11 compares the beginning of the path as text, without regard to case; gives the length of that beginning */
static SIZE_T
BeginsWithSystemPath(PCWSTR Full, PCWSTR Below)
{
    WCHAR Prefix[MAX_PATH];
    UINT Length = GetSystemWindowsDirectoryW(Prefix, ARRAYSIZE(Prefix));

    if (Length == 0 || Length >= ARRAYSIZE(Prefix) || FAILED(StringCchCatW(Prefix, ARRAYSIZE(Prefix), Below)) ||
        _wcsnicmp(Full, Prefix, wcslen(Prefix)) != 0)
    {
        return 0;
    }
    return wcslen(Prefix);
}

HRESULT WINAPI
UploadPrinterDriverPackageW(LPCWSTR pszServer, LPCWSTR pszInfPath, LPCWSTR pszEnvironment, DWORD dwFlags,
                            HWND hwnd, LPWSTR pszDestInfPath, PULONG pcchDestInfPath)
{
    WCHAR Source[MAX_PATH], StoreInf[MAX_PATH], Found[MAX_PATH];
    DWORD Length = ARRAYSIZE(StoreInf);
    HANDLE Namespace, Lock;
    PCWSTR Environment;
    WORD Architecture;
    BOOL Lookup = (dwFlags & (UPDP_UPLOAD_ALWAYS | UPDP_CHECK_DRIVERSTORE)) == UPDP_CHECK_DRIVERSTORE;
    BOOL Published;
    SIZE_T Prefix;
    HRESULT hr;

    TRACE("UploadPrinterDriverPackageW(%S, %S, %S, 0x%lx, %p, %p, %p)\n",
          pszServer, pszInfPath, pszEnvironment, dwFlags, hwnd, pszDestInfPath, pcchDestInfPath);

    UNREFERENCED_PARAMETER(hwnd);

    /* Windows 11 takes no buffer of less than MAX_PATH characters, also for a shorter path */
    /* It stages a package for flags it does not define as well */
    if (!pszInfPath || !pszDestInfPath || !pcchDestInfPath || *pcchDestInfPath < MAX_PATH)
        return E_INVALIDARG;

    hr = CheckLocalRequest(pszServer, pszEnvironment, &Environment, &Architecture);
    if (FAILED(hr))
        return hr;

    Length = GetFullPathNameW(pszInfPath, ARRAYSIZE(Source), Source, NULL);
    if (Length == 0 || Length >= ARRAYSIZE(Source))
        return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);

    /* Windows 11 gives a path that begins with the path of the store back as it is, for every flag and whatever is there */
    if (BeginsWithSystemPath(Source, StoreDirectory))
    {
        if (FAILED(StringCchCopyW(pszDestInfPath, *pcchDestInfPath, pszInfPath)))
            return E_INVALIDARG;
        *pcchDestInfPath = (ULONG)wcslen(pszDestInfPath) + 1;
        return S_OK;
    }

    /* A published INF stands for its package, but only for the environment of this machine */
    Prefix = BeginsWithSystemPath(Source, InfDirectory);
    Published = Prefix != 0 && !wcschr(Source + Prefix, L'\\');
    if (Published)
    {
        if (GetFileAttributesW(Source) == INVALID_FILE_ATTRIBUTES)
            return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
        if (_wcsicmp(Environment, wszCurrentEnvironment) != 0)
            return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
    }
    else if (!Lookup)
    {
        /* Windows 11 follows a junction and a link to a directory, and refuses an INF that is a link itself */
        Length = GetFileAttributesW(Source);
        if (Length != INVALID_FILE_ATTRIBUTES && (Length & FILE_ATTRIBUTE_REPARSE_POINT) && !(Length & FILE_ATTRIBUTE_DIRECTORY))
            return (HRESULT)ERROR_GENERAL_SYNTAX;
        if (!IsPrinterClassInf(pszInfPath))
            return (HRESULT)ERROR_CLASS_MISMATCH;
    }

    if (!AcquirePackageLock(&Namespace, &Lock))
        return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);

    /* Windows 11 stages a package once: for an INF that the store has it returns the package as it is, for every flag */
    Length = ARRAYSIZE(StoreInf);
    if (Published)
    {
        hr = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
        if (SetupGetInfDriverStoreLocationW(Source, NULL, NULL, Found, ARRAYSIZE(Found), NULL) &&
            SUCCEEDED(DriverStoreFindDriverPackageW(Found, NULL, NULL, Architecture, NULL, StoreInf, &Length)) &&
            _wcsicmp(Found, StoreInf) == 0)
        {
            hr = S_OK;
        }
    }
    else
    {
        hr = DriverStoreFindDriverPackageW(pszInfPath, NULL, NULL, Architecture, NULL, StoreInf, &Length);
        if (FAILED(hr) && !Lookup)
        {
            Length = ARRAYSIZE(StoreInf);
            hr = DriverStoreAddDriverPackageW(pszInfPath, NULL, NULL, Architecture, StoreInf, &Length);
        }
    }

    ReleasePackageLock(Namespace, Lock);
    if (FAILED(hr))
        return hr;

    /* Windows 11 leaves the length alone when it only looked the package up */
    StringCchCopyW(pszDestInfPath, *pcchDestInfPath, StoreInf);
    if (!Lookup)
        *pcchDestInfPath = (ULONG)wcslen(StoreInf) + 1;
    return S_OK;
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

/* Windows 11 deletes a package under the path of its INF in the store, compared as text, and for the environment its directory is */
/* named after. For a path that is not there it returns the error of the file system, E_INVALIDARG for a directory, a file that */
/* is no INF, a published INF and another environment, and ERROR_NOT_FOUND for any other INF, also the one it was uploaded from */
static HRESULT
CheckStoreInfPath(PCWSTR InfPath, WORD Architecture)
{
    PCWSTR Directory, Name, Decoration = L"";
    DWORD Attributes, i;
    SIZE_T Length;

    Attributes = GetFileAttributesW(InfPath);
    if (Attributes == INVALID_FILE_ATTRIBUTES)
        return HRESULT_FROM_WIN32(GetLastError());

    Length = wcslen(InfPath);
    if ((Attributes & FILE_ATTRIBUTE_DIRECTORY) || Length < 5 || _wcsicmp(InfPath + Length - 4, L".inf") != 0 ||
        BeginsWithSystemPath(InfPath, InfDirectory))
    {
        return E_INVALIDARG;
    }

    Length = BeginsWithSystemPath(InfPath, StoreDirectory);
    if (Length == 0 || InfPath[Length] != L'\\')
        return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
    Directory = InfPath + Length + 1;
    Name = wcschr(Directory, L'\\');
    if (!Name || wcschr(Name + 1, L'\\'))
        return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
    Name++;
    Length = wcslen(Name);
    if (_wcsnicmp(Directory, Name, Length) != 0 || Directory[Length] != L'_')
        return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);

    for (i = 0; i < ARRAYSIZE(EnvironmentArchitectures); i++)
    {
        if (EnvironmentArchitectures[i].Architecture == Architecture)
            Decoration = EnvironmentArchitectures[i].Decoration;
    }
    Directory += Length + 1;
    Length = wcslen(Decoration);
    if (_wcsnicmp(Directory, Decoration, Length) != 0 || Directory[Length] != L'_')
        return E_INVALIDARG;
    return S_OK;
}

HRESULT WINAPI
DeletePrinterDriverPackageW(LPCWSTR pszServer, LPCWSTR pszInfPath, LPCWSTR pszEnvironment)
{
    WCHAR Found[MAX_PATH];
    DWORD Length = ARRAYSIZE(Found);
    HANDLE Namespace, Lock;
    PCWSTR Environment;
    WORD Architecture;
    HRESULT hr;

    TRACE("DeletePrinterDriverPackageW(%S, %S, %S)\n", pszServer, pszInfPath, pszEnvironment);

    if (!pszInfPath)
        return E_INVALIDARG;

    hr = CheckLocalRequest(pszServer, pszEnvironment, &Environment, &Architecture);
    if (FAILED(hr))
        return hr;

    hr = CheckStoreInfPath(pszInfPath, Architecture);
    if (FAILED(hr))
        return hr;

    if (!AcquirePackageLock(&Namespace, &Lock))
        return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);

    /* A directory of the store whose INF is not the one it is named after is no package */
    if (FAILED(DriverStoreFindDriverPackageW(pszInfPath, NULL, NULL, Architecture, NULL, Found, &Length)) || _wcsicmp(Found, pszInfPath) != 0)
        hr = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
    else
        hr = IsDriverPackageInUse(Found, Environment, Architecture);

    if (hr == S_OK)
        hr = HRESULT_FROM_WIN32(ERROR_PRINTER_DRIVER_PACKAGE_IN_USE);
    else if (hr == S_FALSE)
        hr = DriverStoreDeleteDriverPackageW(Found, NULL, NULL);

    ReleasePackageLock(Namespace, Lock);
    return hr;
}

HRESULT WINAPI
InstallPrinterDriverFromPackageW(LPCWSTR pszServer, LPCWSTR pszInfPath, LPCWSTR pszDriverName,
                                 LPCWSTR pszEnvironment, DWORD dwFlags)
{
    HRESULT hr;

    TRACE("InstallPrinterDriverFromPackageW(%S, %S, %S, %S, 0x%lx)\n",
          pszServer, pszInfPath, pszDriverName, pszEnvironment, dwFlags);

    RpcTryExcept
    {
        hr = (HRESULT)_RpcInstallPrinterDriverFromPackage((WINSPOOL_HANDLE)pszServer, pszInfPath, pszDriverName,
                                                          pszEnvironment, dwFlags);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        hr = HRESULT_FROM_WIN32(RpcExceptionCode());
        ERR("_RpcInstallPrinterDriverFromPackage failed with exception code 0x%lx!\n", hr);
    }
    RpcEndExcept;

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

    if (!pszDestInfPath || !pcchDestInfPath || *pcchDestInfPath < MAX_PATH)
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
