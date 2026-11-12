/*
 * PROJECT:     LiberNT Spooler API
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Printer driver packages in the driver store
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include "precomp.h"
#include <winnls.h>
#include <drvpkglock.h>
#include <drvpkgenv.h>

HRESULT WINAPI DriverStoreAddDriverPackageW(PCWSTR InfPath, PVOID Reserved1, PVOID Reserved2,
                                            WORD Architecture, PWSTR ReturnPath, PDWORD ReturnLength);
HRESULT WINAPI DriverStoreDeleteDriverPackageW(PCWSTR InfPath, PVOID Reserved1, PVOID Reserved2);

#define DRIVERS_KEY L"SYSTEM\\CurrentControlSet\\Control\\Print\\Environments\\%s\\Drivers\\Version-3"

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
    if ((dwFlags & UPDP_UPLOAD_ALWAYS) || (FAILED(hr) && !(dwFlags & UPDP_CHECK_DRIVERSTORE)))
    {
        Length = ARRAYSIZE(StoreInf);
        hr = DriverStoreAddDriverPackageW(pszInfPath, NULL, NULL, Architecture, StoreInf, &Length);
    }

    ReleasePackageLock(Namespace, Lock);
    if (FAILED(hr))
        return hr;

    return ReturnString(StoreInf, pszDestInfPath, pcchDestInfPath);
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

HRESULT WINAPI
InstallPrinterDriverFromPackageW(LPCWSTR pszServer, LPCWSTR pszInfPath, LPCWSTR pszDriverName,
                                 LPCWSTR pszEnvironment, DWORD dwFlags)
{
    WCHAR InfPath[MAX_PATH];
    DWORD Length;
    HRESULT hr;

    TRACE("InstallPrinterDriverFromPackageW(%S, %S, %S, %S, 0x%lx)\n",
          pszServer, pszInfPath, pszDriverName, pszEnvironment, dwFlags);

    /* The spooler does not have the current directory of the caller */
    if (pszInfPath)
    {
        Length = GetFullPathNameW(pszInfPath, ARRAYSIZE(InfPath), InfPath, NULL);
        if (Length == 0 || Length >= ARRAYSIZE(InfPath))
            return E_INVALIDARG;
        pszInfPath = InfPath;
    }

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
