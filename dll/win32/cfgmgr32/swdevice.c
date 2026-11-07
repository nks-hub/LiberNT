/*
 * PROJECT:     LiberNT Configuration Manager
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Software devices (SwDeviceCreate and related functions)
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include "cfgmgr32_private.h"
#include <devpkey.h>
#include <newdev.h>
#include <swdevice.h>

WINE_DEFAULT_DEBUG_CHANNEL(cfgmgr32);

/*
 * A software device is a root-enumerated device node with the instance ID
 * SWD\<enumerator>\<instance>. Its driver is installed through newdev.dll,
 * which is loaded at run time because setupapi and newdev import cfgmgr32.
 */
typedef struct _SW_DEVICE
{
    WCHAR InstanceId[MAX_DEVICE_ID_LEN];
    DEVINST DevInst;
    SW_DEVICE_LIFETIME Lifetime;
    ULONG Capabilities;
    PWSTR HardwareIds;
    PWSTR CompatibleIds;
    PWSTR Description;
    PWSTR Location;
    GUID ContainerId;
    BOOL HasContainerId;
    ULONG PropertyCount;
    DEVPROPERTY *Properties;
    SW_DEVICE_CREATE_CALLBACK Callback;
    PVOID Context;
    HANDLE Thread;
    DWORD ThreadId;
    BOOL Reopened;
} SW_DEVICE, *PSW_DEVICE;

typedef HDEVINFO (WINAPI *PFN_SETUPDICREATEDEVICEINFOLIST)(const GUID *, HWND);
typedef BOOL (WINAPI *PFN_SETUPDIOPENDEVICEINFOW)(HDEVINFO, PCWSTR, HWND, DWORD, PSP_DEVINFO_DATA);
typedef BOOL (WINAPI *PFN_SETUPDIDESTROYDEVICEINFOLIST)(HDEVINFO);
typedef BOOL (WINAPI *PFN_DIINSTALLDEVICE)(HWND, HDEVINFO, PSP_DEVINFO_DATA, PSP_DRVINFO_DATA_W, DWORD, PBOOL);

static SIZE_T
MultiSzSize(_In_opt_ PCZZWSTR pszz)
{
    PCWSTR p = pszz;

    if (!p)
        return 0;
    while (*p)
        p += wcslen(p) + 1;
    return (p - pszz + 1) * sizeof(WCHAR);
}

static PVOID
DupBuffer(_In_opt_ const VOID *Buffer, _In_ SIZE_T Size)
{
    PVOID Copy;

    if (!Buffer || !Size)
        return NULL;
    Copy = HeapAlloc(GetProcessHeap(), 0, Size);
    if (Copy)
        memcpy(Copy, Buffer, Size);
    return Copy;
}

static VOID
FreeProperties(_In_ ULONG Count, _In_opt_ DEVPROPERTY *Properties)
{
    ULONG i;

    if (!Properties)
        return;
    for (i = 0; i < Count; i++)
        HeapFree(GetProcessHeap(), 0, Properties[i].Buffer);
    HeapFree(GetProcessHeap(), 0, Properties);
}

static HRESULT
CopyProperties(_In_ ULONG Count, _In_reads_opt_(Count) const DEVPROPERTY *Source, _Out_ DEVPROPERTY **Copy)
{
    DEVPROPERTY *Properties;
    ULONG i;

    *Copy = NULL;
    if (!Count)
        return S_OK;
    if (!Source)
        return E_INVALIDARG;

    Properties = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Count * sizeof(*Properties));
    if (!Properties)
        return E_OUTOFMEMORY;

    for (i = 0; i < Count; i++)
    {
        Properties[i] = Source[i];
        Properties[i].Buffer = NULL;
        if (Source[i].BufferSize)
        {
            if (!Source[i].Buffer)
            {
                FreeProperties(Count, Properties);
                return E_INVALIDARG;
            }
            Properties[i].Buffer = DupBuffer(Source[i].Buffer, Source[i].BufferSize);
            if (!Properties[i].Buffer)
            {
                FreeProperties(Count, Properties);
                return E_OUTOFMEMORY;
            }
        }
    }

    *Copy = Properties;
    return S_OK;
}

static VOID
FreeSwDevice(_In_ PSW_DEVICE Device)
{
    HeapFree(GetProcessHeap(), 0, Device->HardwareIds);
    HeapFree(GetProcessHeap(), 0, Device->CompatibleIds);
    HeapFree(GetProcessHeap(), 0, Device->Description);
    HeapFree(GetProcessHeap(), 0, Device->Location);
    FreeProperties(Device->PropertyCount, Device->Properties);
    HeapFree(GetProcessHeap(), 0, Device);
}

static HRESULT
CrToHresult(_In_ CONFIGRET Cr)
{
    return Cr == CR_SUCCESS ? S_OK : HRESULT_FROM_WIN32(CM_MapCrToWin32Err(Cr, ERROR_GEN_FAILURE));
}

static HRESULT
ApplyProperties(_In_ DEVINST DevInst, _In_ ULONG Count, _In_reads_opt_(Count) const DEVPROPERTY *Properties)
{
    CONFIGRET Cr;
    ULONG i;

    for (i = 0; i < Count; i++)
    {
        if (Properties[i].CompKey.Store != DEVPROP_STORE_SYSTEM)
            return E_INVALIDARG;

        Cr = CM_Set_DevNode_PropertyW(DevInst, &Properties[i].CompKey.Key, Properties[i].Type,
                                      Properties[i].Buffer, Properties[i].BufferSize, 0);
        if (Cr != CR_SUCCESS)
        {
            ERR("Setting property %s %lu failed (CR %lu)\n", debugstr_guid(&Properties[i].CompKey.Key.fmtid),
                Properties[i].CompKey.Key.pid, Cr);
            return CrToHresult(Cr);
        }
    }
    return S_OK;
}

/* Installs the best driver for the device, or the null driver when none is required */
static HRESULT
InstallSwDeviceDriver(_In_ PSW_DEVICE Device)
{
    PFN_SETUPDICREATEDEVICEINFOLIST pSetupDiCreateDeviceInfoList;
    PFN_SETUPDIOPENDEVICEINFOW pSetupDiOpenDeviceInfoW;
    PFN_SETUPDIDESTROYDEVICEINFOLIST pSetupDiDestroyDeviceInfoList;
    PFN_DIINSTALLDEVICE pDiInstallDevice;
    BOOL HasIds = (Device->HardwareIds && *Device->HardwareIds) ||
                  (Device->CompatibleIds && *Device->CompatibleIds);
    BOOL DriverRequired = (Device->Capabilities & SWDeviceCapabilitiesDriverRequired) != 0;
    SP_DEVINFO_DATA DevInfoData = { sizeof(DevInfoData) };
    HMODULE hSetupApi, hNewDev;
    HDEVINFO DevInfo;
    HRESULT hr = S_OK;

    /* Nothing can match a device without IDs; SwDeviceCreate requires them with DriverRequired */
    if (!HasIds)
        return S_OK;

    hSetupApi = LoadLibraryW(L"setupapi.dll");
    hNewDev = LoadLibraryW(L"newdev.dll");
    if (!hSetupApi || !hNewDev)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto done;
    }

    pSetupDiCreateDeviceInfoList = (PFN_SETUPDICREATEDEVICEINFOLIST)GetProcAddress(hSetupApi, "SetupDiCreateDeviceInfoList");
    pSetupDiOpenDeviceInfoW = (PFN_SETUPDIOPENDEVICEINFOW)GetProcAddress(hSetupApi, "SetupDiOpenDeviceInfoW");
    pSetupDiDestroyDeviceInfoList = (PFN_SETUPDIDESTROYDEVICEINFOLIST)GetProcAddress(hSetupApi, "SetupDiDestroyDeviceInfoList");
    pDiInstallDevice = (PFN_DIINSTALLDEVICE)GetProcAddress(hNewDev, "DiInstallDevice");
    if (!pSetupDiCreateDeviceInfoList || !pSetupDiOpenDeviceInfoW || !pSetupDiDestroyDeviceInfoList || !pDiInstallDevice)
    {
        hr = HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
        goto done;
    }

    DevInfo = pSetupDiCreateDeviceInfoList(NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto done;
    }

    if (!pSetupDiOpenDeviceInfoW(DevInfo, Device->InstanceId, NULL, 0, &DevInfoData))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
    }
    else if (!pDiInstallDevice(NULL, DevInfo, &DevInfoData, NULL, 0, NULL))
    {
        DWORD Error = GetLastError();

        /*
         * The device is created also when no driver installs. A device that
         * requires one shows a problem, as a device without a needed driver.
         */
        WARN("No driver installed for %s (error %lu)\n", debugstr_w(Device->InstanceId), Error);
        if (DriverRequired)
            CM_Set_DevNode_Problem(Device->DevInst, CM_PROB_FAILED_INSTALL, CM_SET_DEVNODE_PROBLEM_OVERRIDE);
    }

    pSetupDiDestroyDeviceInfoList(DevInfo);

done:
    if (hNewDev)
        FreeLibrary(hNewDev);
    if (hSetupApi)
        FreeLibrary(hSetupApi);
    return hr;
}

/*
 * Windows removes a software device when the process holding its handle ends.
 * The PnP manager service watches that process. Every device made here also
 * records its owner in a volatile key; a later SwDeviceCreate of the same
 * instance removes the device when that process is gone and the service
 * missed it, so a crashed client does not block its own restart.
 */
#define SW_DEVICE_OWNERS L"SYSTEM\\CurrentControlSet\\Control\\SoftwareDevices"

static VOID
OwnerKeyName(_In_ PCWSTR InstanceId, _Out_writes_(MAX_DEVICE_ID_LEN) PWSTR Name)
{
    ULONG i;

    for (i = 0; i < MAX_DEVICE_ID_LEN - 1 && InstanceId[i]; i++)
        Name[i] = (InstanceId[i] == L'\\') ? L'#' : InstanceId[i];
    Name[i] = UNICODE_NULL;
}

static BOOL
GetProcessStart(_In_ HANDLE Process, _Out_ PULONGLONG Start)
{
    FILETIME Creation, Exit, Kernel, User;

    if (!GetProcessTimes(Process, &Creation, &Exit, &Kernel, &User))
        return FALSE;
    *Start = ((ULONGLONG)Creation.dwHighDateTime << 32) | Creation.dwLowDateTime;
    return TRUE;
}

/* ProcessId 0 records a device that outlives its closed handle */
static VOID
RecordOwner(_In_ PCWSTR InstanceId, _In_ DWORD ProcessId, _In_ SW_DEVICE_LIFETIME Lifetime)
{
    WCHAR Name[MAX_DEVICE_ID_LEN];
    ULONGLONG Start = 0;
    DWORD Value = Lifetime;
    HKEY Owners, Key;

    if ((ProcessId && !GetProcessStart(GetCurrentProcess(), &Start)) ||
        RegCreateKeyExW(HKEY_LOCAL_MACHINE, SW_DEVICE_OWNERS, 0, NULL, REG_OPTION_VOLATILE,
                        KEY_CREATE_SUB_KEY, NULL, &Owners, NULL))
    {
        return;
    }
    OwnerKeyName(InstanceId, Name);
    if (!RegCreateKeyExW(Owners, Name, 0, NULL, REG_OPTION_VOLATILE, KEY_SET_VALUE, NULL, &Key, NULL))
    {
        RegSetValueExW(Key, L"ProcessId", 0, REG_DWORD, (const BYTE *)&ProcessId, sizeof(ProcessId));
        RegSetValueExW(Key, L"ProcessStart", 0, REG_QWORD, (const BYTE *)&Start, sizeof(Start));
        RegSetValueExW(Key, L"Lifetime", 0, REG_DWORD, (const BYTE *)&Value, sizeof(Value));
        RegCloseKey(Key);
    }
    RegCloseKey(Owners);
}

static VOID
ForgetOwner(_In_ PCWSTR InstanceId)
{
    WCHAR Name[MAX_DEVICE_ID_LEN];
    HKEY Owners;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, SW_DEVICE_OWNERS, 0, DELETE | KEY_ENUMERATE_SUB_KEYS, &Owners))
        return;
    OwnerKeyName(InstanceId, Name);
    RegDeleteKeyW(Owners, Name);
    RegCloseKey(Owners);
}

typedef enum _SW_DEVICE_OWNER
{
    SwOwnerUnknown,     /* Not made by SwDeviceCreate during this boot */
    SwOwnerInUse,       /* A handle is open */
    SwOwnerEnded,       /* The process holding the handle ended */
    SwOwnerReleased,    /* No handle is open and the device stays */
} SW_DEVICE_OWNER;

static SW_DEVICE_OWNER
GetOwner(_In_ PCWSTR InstanceId)
{
    WCHAR Path[ARRAYSIZE(SW_DEVICE_OWNERS) + 1 + MAX_DEVICE_ID_LEN];
    DWORD ProcessId, Lifetime, Size;
    ULONGLONG Recorded, Start;
    HANDLE Process;
    BOOL Ended;
    HKEY Key;
    LONG Error;

    wcscpy(Path, SW_DEVICE_OWNERS L"\\");
    OwnerKeyName(InstanceId, Path + wcslen(Path));
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, Path, 0, KEY_QUERY_VALUE, &Key))
        return SwOwnerUnknown;
    Size = sizeof(ProcessId);
    Error = RegQueryValueExW(Key, L"ProcessId", NULL, NULL, (BYTE *)&ProcessId, &Size);
    if (!Error)
    {
        Size = sizeof(Recorded);
        Error = RegQueryValueExW(Key, L"ProcessStart", NULL, NULL, (BYTE *)&Recorded, &Size);
    }
    if (!Error)
    {
        Size = sizeof(Lifetime);
        Error = RegQueryValueExW(Key, L"Lifetime", NULL, NULL, (BYTE *)&Lifetime, &Size);
    }
    RegCloseKey(Key);
    if (Error)
        return SwOwnerUnknown;
    if (!ProcessId)
        return SwOwnerReleased;

    /* A reused process ID has another start time */
    Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, ProcessId);
    if (Process == NULL)
    {
        Ended = GetLastError() == ERROR_INVALID_PARAMETER;
    }
    else
    {
        Ended = !GetProcessStart(Process, &Start) || Start != Recorded ||
                WaitForSingleObject(Process, 0) == WAIT_OBJECT_0;
        CloseHandle(Process);
    }
    if (!Ended)
        return SwOwnerInUse;
    return Lifetime == SWDeviceLifetimeParentPresent ? SwOwnerReleased : SwOwnerEnded;
}

/*
 * Creates the device node, or takes over one that no handle holds, and
 * records this process as its owner. The lock keeps two SwDeviceCreate
 * calls from taking over the same node.
 */
static HRESULT
ClaimSwDeviceNode(_In_ PSW_DEVICE Device)
{
    DEVINST Root;
    CONFIGRET Cr;
    HANDLE Lock;
    DWORD Wait;

    Cr = CM_Locate_DevNodeW(&Root, NULL, CM_LOCATE_DEVNODE_NORMAL);
    if (Cr != CR_SUCCESS)
        return CrToHresult(Cr);

    Lock = CreateMutexW(NULL, FALSE, L"Global\\SoftwareDeviceOwners");
    if (!Lock)
        return HRESULT_FROM_WIN32(GetLastError());
    Wait = WaitForSingleObject(Lock, INFINITE);
    if (Wait != WAIT_OBJECT_0 && Wait != WAIT_ABANDONED)
    {
        CloseHandle(Lock);
        return HRESULT_FROM_WIN32(ERROR_GEN_FAILURE);
    }

    /* PnP installs the driver later, after the IDs and properties are in place */
    Cr = CM_Create_DevNodeW(&Device->DevInst, Device->InstanceId, Root,
                            CM_CREATE_DEVNODE_NORMAL | CM_CREATE_DEVNODE_DO_NOT_INSTALL);
    if (Cr == CR_ALREADY_SUCH_DEVINST)
    {
        switch (GetOwner(Device->InstanceId))
        {
            case SwOwnerReleased:
                /* A device that outlived its handle is opened again as it is */
                Cr = CM_Locate_DevNodeW(&Device->DevInst, Device->InstanceId, CM_LOCATE_DEVNODE_NORMAL);
                Device->Reopened = (Cr == CR_SUCCESS);
                break;

            case SwOwnerEnded:
                if (CfgmgrRemoveSoftwareDevice(Device->InstanceId) == CR_SUCCESS)
                {
                    TRACE("Removed %s left by an ended process\n", debugstr_w(Device->InstanceId));
                    Cr = CM_Create_DevNodeW(&Device->DevInst, Device->InstanceId, Root,
                                            CM_CREATE_DEVNODE_NORMAL | CM_CREATE_DEVNODE_DO_NOT_INSTALL);
                }
                break;

            default:
                break;
        }
    }
    if (Cr == CR_SUCCESS)
        RecordOwner(Device->InstanceId, GetCurrentProcessId(), SWDeviceLifetimeHandle);

    ReleaseMutex(Lock);
    CloseHandle(Lock);

    if (Cr != CR_SUCCESS)
    {
        /* The node may belong to another handle; it is not ours to remove */
        Device->DevInst = 0;
        return Cr == CR_ALREADY_SUCH_DEVINST ? HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) : CrToHresult(Cr);
    }

    /* A new handle has the handle lifetime */
    if (CfgmgrWatchSoftwareDevice(Device->InstanceId, GetCurrentProcessId()) != CR_SUCCESS)
        WARN("%s stays after this process ends\n", debugstr_w(Device->InstanceId));
    return S_OK;
}

static HRESULT
CreateSwDeviceNode(_In_ PSW_DEVICE Device)
{
    CONFIGRET Cr;
    HRESULT hr;

    hr = ClaimSwDeviceNode(Device);
    if (FAILED(hr))
        return hr;

    if (Device->HardwareIds && *Device->HardwareIds)
    {
        Cr = CM_Set_DevNode_Registry_PropertyW(Device->DevInst, CM_DRP_HARDWAREID, Device->HardwareIds,
                                               (ULONG)MultiSzSize(Device->HardwareIds), 0);
        if (Cr != CR_SUCCESS)
            return CrToHresult(Cr);
    }
    if (Device->CompatibleIds && *Device->CompatibleIds)
    {
        Cr = CM_Set_DevNode_Registry_PropertyW(Device->DevInst, CM_DRP_COMPATIBLEIDS, Device->CompatibleIds,
                                               (ULONG)MultiSzSize(Device->CompatibleIds), 0);
        if (Cr != CR_SUCCESS)
            return CrToHresult(Cr);
    }
    if (Device->Description)
    {
        Cr = CM_Set_DevNode_Registry_PropertyW(Device->DevInst, CM_DRP_DEVICEDESC, Device->Description,
                                               (ULONG)((wcslen(Device->Description) + 1) * sizeof(WCHAR)), 0);
        if (Cr != CR_SUCCESS)
            return CrToHresult(Cr);
    }
    if (Device->Location)
    {
        Cr = CM_Set_DevNode_Registry_PropertyW(Device->DevInst, CM_DRP_LOCATION_INFORMATION, Device->Location,
                                               (ULONG)((wcslen(Device->Location) + 1) * sizeof(WCHAR)), 0);
        if (Cr != CR_SUCCESS)
            return CrToHresult(Cr);
    }
    if (Device->HasContainerId)
    {
        Cr = CM_Set_DevNode_PropertyW(Device->DevInst, &DEVPKEY_Device_ContainerId, DEVPROP_TYPE_GUID,
                                      (const BYTE *)&Device->ContainerId, sizeof(GUID), 0);
        if (Cr != CR_SUCCESS)
            return CrToHresult(Cr);
    }

    hr = ApplyProperties(Device->DevInst, Device->PropertyCount, Device->Properties);
    if (FAILED(hr))
        return hr;

    /* A device opened again keeps the driver it runs with */
    if (Device->Reopened)
    {
        ULONG Status, Problem;

        if (CM_Get_DevNode_Status(&Status, &Problem, Device->DevInst, 0) == CR_SUCCESS &&
            (Status & DN_DRIVER_LOADED))
        {
            return S_OK;
        }
    }
    return InstallSwDeviceDriver(Device);
}

static DWORD
WINAPI
SwDeviceCreateThread(_In_ PVOID Parameter)
{
    PSW_DEVICE Device = Parameter;
    SW_DEVICE_CREATE_CALLBACK Callback = Device->Callback;
    PVOID Context = Device->Context;
    HRESULT hr;

    hr = CreateSwDeviceNode(Device);
    if (FAILED(hr))
    {
        ERR("Creating software device %s failed (0x%08lx)\n", debugstr_w(Device->InstanceId), hr);

        /* A half-created device would block the next creation with the same instance ID */
        if (Device->DevInst && Device->Reopened)
        {
            CfgmgrWatchSoftwareDevice(Device->InstanceId, 0);
            RecordOwner(Device->InstanceId, 0, SWDeviceLifetimeParentPresent);
        }
        else if (Device->DevInst)
        {
            CfgmgrRemoveSoftwareDevice(Device->InstanceId);
            ForgetOwner(Device->InstanceId);
        }
        Device->DevInst = 0;
    }

    /* The callback may close the handle; nothing touches Device afterwards */
    Callback((HSWDEVICE)Device, hr, Context, SUCCEEDED(hr) ? Device->InstanceId : NULL);
    return 0;
}

HRESULT
WINAPI
SwDeviceCreate(
    _In_ PCWSTR pszEnumeratorName,
    _In_ PCWSTR pszParentDeviceInstance,
    _In_ const SW_DEVICE_CREATE_INFO *pCreateInfo,
    _In_ ULONG cPropertyCount,
    _In_reads_opt_(cPropertyCount) const DEVPROPERTY *pProperties,
    _In_ SW_DEVICE_CREATE_CALLBACK pCallback,
    _In_opt_ PVOID pContext,
    _Out_ PHSWDEVICE phSwDevice)
{
    WCHAR RootId[MAX_DEVICE_ID_LEN];
    DEVINST Root, Parent;
    PSW_DEVICE Device;
    HRESULT hr;

    TRACE("%s %s %p %lu %p %p %p %p\n", debugstr_w(pszEnumeratorName), debugstr_w(pszParentDeviceInstance),
          pCreateInfo, cPropertyCount, pProperties, pCallback, pContext, phSwDevice);

    if (!phSwDevice)
        return E_POINTER;
    *phSwDevice = NULL;

    if (!pszEnumeratorName || !*pszEnumeratorName || wcschr(pszEnumeratorName, L'\\') ||
        !pszParentDeviceInstance || !pCreateInfo || pCreateInfo->cbSize < sizeof(*pCreateInfo) ||
        !pCreateInfo->pszInstanceId || !*pCreateInfo->pszInstanceId || wcschr(pCreateInfo->pszInstanceId, L'\\') ||
        !pCallback ||
        ((pCreateInfo->CapabilityFlags & SWDeviceCapabilitiesDriverRequired) &&
         !(pCreateInfo->pszzHardwareIds && *pCreateInfo->pszzHardwareIds) &&
         !(pCreateInfo->pszzCompatibleIds && *pCreateInfo->pszzCompatibleIds)) ||
        (pCreateInfo->CapabilityFlags & ~(SWDeviceCapabilitiesRemovable | SWDeviceCapabilitiesSilentInstall |
                                          SWDeviceCapabilitiesNoDisplayInUI | SWDeviceCapabilitiesDriverRequired)))
    {
        return E_INVALIDARG;
    }

    /* PnP creates device nodes below the root device only */
    if (CM_Locate_DevNodeW(&Root, NULL, CM_LOCATE_DEVNODE_NORMAL) != CR_SUCCESS ||
        CM_Get_Device_IDW(Root, RootId, ARRAYSIZE(RootId), 0) != CR_SUCCESS ||
        CM_Locate_DevNodeW(&Parent, (DEVINSTID_W)pszParentDeviceInstance, CM_LOCATE_DEVNODE_NORMAL) != CR_SUCCESS)
    {
        return HRESULT_FROM_WIN32(ERROR_NO_SUCH_DEVINST);
    }
    if (Parent != Root)
    {
        FIXME("Software devices below %s are not supported\n", debugstr_w(pszParentDeviceInstance));
        return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
    }

    Device = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Device));
    if (!Device)
        return E_OUTOFMEMORY;

    if (_snwprintf(Device->InstanceId, ARRAYSIZE(Device->InstanceId) - 1, L"SWD\\%s\\%s",
                   pszEnumeratorName, pCreateInfo->pszInstanceId) < 0)
    {
        FreeSwDevice(Device);
        return E_INVALIDARG;
    }

    Device->Lifetime = SWDeviceLifetimeHandle;
    Device->Capabilities = pCreateInfo->CapabilityFlags;
    Device->Callback = pCallback;
    Device->Context = pContext;
    Device->HardwareIds = DupBuffer(pCreateInfo->pszzHardwareIds, MultiSzSize(pCreateInfo->pszzHardwareIds));
    Device->CompatibleIds = DupBuffer(pCreateInfo->pszzCompatibleIds, MultiSzSize(pCreateInfo->pszzCompatibleIds));
    if (pCreateInfo->pszDeviceDescription)
        Device->Description = DupBuffer(pCreateInfo->pszDeviceDescription,
                                        (wcslen(pCreateInfo->pszDeviceDescription) + 1) * sizeof(WCHAR));
    if (pCreateInfo->pszDeviceLocation)
        Device->Location = DupBuffer(pCreateInfo->pszDeviceLocation,
                                     (wcslen(pCreateInfo->pszDeviceLocation) + 1) * sizeof(WCHAR));
    if (pCreateInfo->pContainerId)
    {
        Device->ContainerId = *pCreateInfo->pContainerId;
        Device->HasContainerId = TRUE;
    }
    if (pCreateInfo->pSecurityDescriptor)
        FIXME("Security descriptor of %s ignored\n", debugstr_w(Device->InstanceId));

    hr = CopyProperties(cPropertyCount, pProperties, &Device->Properties);
    if (FAILED(hr))
    {
        FreeSwDevice(Device);
        return hr;
    }
    Device->PropertyCount = cPropertyCount;

    /*
     * As on Windows the creation finishes asynchronously and reports through
     * the callback, which may close the handle before SwDeviceCreate returns.
     * The thread starts once Device is complete, and nothing here touches
     * Device after that.
     */
    Device->Thread = CreateThread(NULL, 0, SwDeviceCreateThread, Device, CREATE_SUSPENDED, &Device->ThreadId);
    if (!Device->Thread)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        FreeSwDevice(Device);
        return hr;
    }

    *phSwDevice = (HSWDEVICE)Device;
    if (ResumeThread(Device->Thread) == (DWORD)-1)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        TerminateThread(Device->Thread, 0);
        CloseHandle(Device->Thread);
        FreeSwDevice(Device);
        *phSwDevice = NULL;
        return hr;
    }
    return S_OK;
}

VOID
WINAPI
SwDeviceClose(
    _In_ HSWDEVICE hSwDevice)
{
    PSW_DEVICE Device = (PSW_DEVICE)hSwDevice;

    TRACE("%p\n", hSwDevice);

    if (!Device)
        return;

    /* Let a pending creation finish, unless the callback itself closes the handle */
    if (Device->Thread)
    {
        if (Device->ThreadId != GetCurrentThreadId())
            WaitForSingleObject(Device->Thread, INFINITE);
        CloseHandle(Device->Thread);
    }

    /* The device leaves with its handle; its registry keys stay for the next creation */
    if (Device->Lifetime == SWDeviceLifetimeHandle && Device->DevInst)
    {
        CONFIGRET Cr = CfgmgrRemoveSoftwareDevice(Device->InstanceId);
        if (Cr != CR_SUCCESS)
            WARN("Removing %s failed (CR %lu)\n", debugstr_w(Device->InstanceId), Cr);
        ForgetOwner(Device->InstanceId);
    }
    else if (Device->DevInst)
    {
        /* A device that stays can be opened again by the next SwDeviceCreate */
        CfgmgrWatchSoftwareDevice(Device->InstanceId, 0);
        RecordOwner(Device->InstanceId, 0, SWDeviceLifetimeParentPresent);
    }

    FreeSwDevice(Device);
}

HRESULT
WINAPI
SwDeviceSetLifetime(
    _In_ HSWDEVICE hSwDevice,
    _In_ SW_DEVICE_LIFETIME Lifetime)
{
    PSW_DEVICE Device = (PSW_DEVICE)hSwDevice;

    if (!Device || (Lifetime != SWDeviceLifetimeHandle && Lifetime != SWDeviceLifetimeParentPresent))
        return E_INVALIDARG;

    Device->Lifetime = Lifetime;

    /* Only a device with the handle lifetime leaves with this process */
    if (Device->DevInst)
    {
        CONFIGRET Cr = CfgmgrWatchSoftwareDevice(Device->InstanceId,
                                                 Lifetime == SWDeviceLifetimeHandle ? GetCurrentProcessId() : 0);
        if (Cr != CR_SUCCESS)
            return CrToHresult(Cr);
        RecordOwner(Device->InstanceId, GetCurrentProcessId(), Lifetime);
    }
    return S_OK;
}

HRESULT
WINAPI
SwDeviceGetLifetime(
    _In_ HSWDEVICE hSwDevice,
    _Out_ PSW_DEVICE_LIFETIME pLifetime)
{
    PSW_DEVICE Device = (PSW_DEVICE)hSwDevice;

    if (!Device || !pLifetime)
        return E_INVALIDARG;

    *pLifetime = Device->Lifetime;
    return S_OK;
}

HRESULT
WINAPI
SwDevicePropertySet(
    _In_ HSWDEVICE hSwDevice,
    _In_ ULONG cPropertyCount,
    _In_reads_(cPropertyCount) const DEVPROPERTY *pProperties)
{
    PSW_DEVICE Device = (PSW_DEVICE)hSwDevice;

    if (!Device || !Device->DevInst || (cPropertyCount && !pProperties))
        return E_INVALIDARG;

    return ApplyProperties(Device->DevInst, cPropertyCount, pProperties);
}

/* Device interfaces of software devices need a bus driver that registers them; LiberNT has none yet */
HRESULT
WINAPI
SwDeviceInterfaceRegister(
    _In_ HSWDEVICE hSwDevice,
    _In_ const GUID *pInterfaceClassGuid,
    _In_opt_ PCWSTR pszReferenceString,
    _In_ ULONG cPropertyCount,
    _In_reads_opt_(cPropertyCount) const DEVPROPERTY *pProperties,
    _In_ BOOL fEnabled,
    _Out_opt_ PWSTR *ppszDeviceInterfaceId)
{
    FIXME("%p %s %s not supported\n", hSwDevice, debugstr_guid(pInterfaceClassGuid), debugstr_w(pszReferenceString));
    if (ppszDeviceInterfaceId)
        *ppszDeviceInterfaceId = NULL;
    return E_NOTIMPL;
}

VOID
WINAPI
SwMemFree(
    _In_ PVOID pMem)
{
    HeapFree(GetProcessHeap(), 0, pMem);
}

HRESULT
WINAPI
SwDeviceInterfaceSetState(
    _In_ HSWDEVICE hSwDevice,
    _In_ PCWSTR pszDeviceInterfaceId,
    _In_ BOOL fEnabled)
{
    FIXME("%p %s not supported\n", hSwDevice, debugstr_w(pszDeviceInterfaceId));
    return E_NOTIMPL;
}

HRESULT
WINAPI
SwDeviceInterfacePropertySet(
    _In_ HSWDEVICE hSwDevice,
    _In_ PCWSTR pszDeviceInterfaceId,
    _In_ ULONG cPropertyCount,
    _In_reads_(cPropertyCount) const DEVPROPERTY *pProperties)
{
    FIXME("%p %s not supported\n", hSwDevice, debugstr_w(pszDeviceInterfaceId));
    return E_NOTIMPL;
}
