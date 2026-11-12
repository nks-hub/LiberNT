/*
 * PROJECT:     LiberNT API Tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Tests for software devices (SwDeviceCreate and related functions)
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include <apitest.h>
#include <windows.h>
#include <cfgmgr32.h>
#include <initguid.h>
#include <devpkey.h>
#include <sddl.h>
#include <swdevice.h>
#include <stdio.h>
#include <string.h>

#define TEST_ENUMERATOR L"LntSwTest"
#define TEST_HARDWARE_ID L"LntSwTestNoDriver\0"
#define OWNER_PARENT_ID L"SWD\\" TEST_ENUMERATOR L"\\OwnerParent"
#define OWNER_READY_EVENT L"LntSwTestOwnerReady"

typedef struct _CREATED
{
    HANDLE Event;
    HRESULT Result;
    WCHAR InstanceId[MAX_DEVICE_ID_LEN];
} CREATED;

static VOID WINAPI
Created(HSWDEVICE hSwDevice, HRESULT CreateResult, PVOID Context, PCWSTR DeviceInstanceId)
{
    CREATED *State = Context;

    UNREFERENCED_PARAMETER(hSwDevice);
    State->Result = CreateResult;
    if (DeviceInstanceId)
        lstrcpynW(State->InstanceId, DeviceInstanceId, MAX_DEVICE_ID_LEN);
    SetEvent(State->Event);
}

static VOID WINAPI
CreatedAndClosed(HSWDEVICE hSwDevice, HRESULT CreateResult, PVOID Context, PCWSTR DeviceInstanceId)
{
    SwDeviceClose(hSwDevice);
    Created(NULL, CreateResult, Context, DeviceInstanceId);
}

static HRESULT
CreateBelow(PCWSTR Parent, PCWSTR Enumerator, PCWSTR Instance, ULONG Capabilities, PSECURITY_DESCRIPTOR Security, CREATED *State,
            HSWDEVICE *Device)
{
    SW_DEVICE_CREATE_INFO Info = { sizeof(Info) };
    HRESULT hr;

    Info.pszInstanceId = Instance;
    Info.pszzHardwareIds = TEST_HARDWARE_ID;
    Info.pszDeviceDescription = L"LiberNT software device test";
    Info.CapabilityFlags = Capabilities;
    Info.pSecurityDescriptor = Security;
    ZeroMemory(State->InstanceId, sizeof(State->InstanceId));
    State->Result = E_PENDING;
    ResetEvent(State->Event);
    hr = SwDeviceCreate(Enumerator, Parent, &Info, 0, NULL, Created, State, Device);
    if (SUCCEEDED(hr) && WaitForSingleObject(State->Event, 30000) != WAIT_OBJECT_0)
        hr = HRESULT_FROM_WIN32(WAIT_TIMEOUT);
    return hr;
}

static HRESULT
CreateIn(PCWSTR Enumerator, PCWSTR Instance, ULONG Capabilities, PSECURITY_DESCRIPTOR Security, CREATED *State, HSWDEVICE *Device)
{
    return CreateBelow(L"HTREE\\ROOT\\0", Enumerator, Instance, Capabilities, Security, State, Device);
}

static HRESULT
Create(PCWSTR Instance, ULONG Capabilities, PSECURITY_DESCRIPTOR Security, CREATED *State, HSWDEVICE *Device)
{
    return CreateIn(TEST_ENUMERATOR, Instance, Capabilities, Security, State, Device);
}

static BOOL
IsPresent(PCWSTR InstanceId)
{
    DEVINST DevInst;

    return CM_Locate_DevNodeW(&DevInst, (DEVINSTID_W)InstanceId, CM_LOCATE_DEVNODE_NORMAL) == CR_SUCCESS;
}

static BOOL
WaitGone(PCWSTR InstanceId)
{
    DWORD Start = GetTickCount();

    while (IsPresent(InstanceId) && GetTickCount() - Start < 10000)
        Sleep(200);
    return !IsPresent(InstanceId);
}

static BOOL
GetParentId(PCWSTR InstanceId, PWSTR Parent)
{
    DEVINST DevInst, ParentInst;

    Parent[0] = UNICODE_NULL;
    return CM_Locate_DevNodeW(&DevInst, (DEVINSTID_W)InstanceId, CM_LOCATE_DEVNODE_NORMAL) == CR_SUCCESS &&
           CM_Get_Parent(&ParentInst, DevInst, 0) == CR_SUCCESS &&
           CM_Get_Device_IDW(ParentInst, Parent, MAX_DEVICE_ID_LEN, 0) == CR_SUCCESS;
}

static BOOL
GetContainer(PCWSTR InstanceId, GUID *Container)
{
    DEVPROPTYPE Type = DEVPROP_TYPE_EMPTY;
    ULONG Size = sizeof(*Container);
    DEVINST DevInst;

    ZeroMemory(Container, sizeof(*Container));
    return CM_Locate_DevNodeW(&DevInst, (DEVINSTID_W)InstanceId, CM_LOCATE_DEVNODE_NORMAL) == CR_SUCCESS &&
           CM_Get_DevNode_PropertyW(DevInst, &DEVPKEY_Device_ContainerId, &Type, (PBYTE)Container, &Size, 0) == CR_SUCCESS &&
           Type == DEVPROP_TYPE_GUID;
}

static void
test_Lifetime(CREATED *State)
{
    HSWDEVICE Device;
    WCHAR InstanceId[MAX_DEVICE_ID_LEN];
    HRESULT hr;

    hr = Create(L"Lifetime", SWDeviceCapabilitiesSilentInstall, NULL, State, &Device);
    ok(hr == S_OK, "SwDeviceCreate returned 0x%08lx\n", hr);
    if (FAILED(hr))
        return;
    ok(State->Result == S_OK, "The creation reported 0x%08lx\n", State->Result);
    lstrcpyW(InstanceId, State->InstanceId);
    ok(IsPresent(InstanceId), "%S is not present\n", InstanceId);

    hr = SwDeviceSetLifetime(Device, SWDeviceLifetimeParentPresent);
    ok(hr == S_OK, "SwDeviceSetLifetime returned 0x%08lx\n", hr);
    SwDeviceClose(Device);
    ok(IsPresent(InstanceId), "%S left with its handle\n", InstanceId);

    hr = Create(L"Lifetime", SWDeviceCapabilitiesSilentInstall, NULL, State, &Device);
    ok(hr == S_OK, "SwDeviceCreate of the persistent device returned 0x%08lx\n", hr);
    if (FAILED(hr))
        return;
    ok(State->Result == S_OK, "Opening the persistent device reported 0x%08lx\n", State->Result);

    hr = SwDeviceSetLifetime(Device, SWDeviceLifetimeHandle);
    ok(hr == S_OK, "SwDeviceSetLifetime returned 0x%08lx\n", hr);
    SwDeviceClose(Device);
    ok(WaitGone(InstanceId), "%S stayed after its handle closed\n", InstanceId);
}

static void
test_SimilarIds(CREATED *State)
{
    static const WCHAR First[] = L"SWD\\" TEST_ENUMERATOR L"#Owner\\Key";
    static const WCHAR Second[] = L"SWD\\" TEST_ENUMERATOR L"\\Owner#Key";
    HSWDEVICE FirstDevice, SecondDevice;
    HRESULT hr;

    hr = CreateIn(TEST_ENUMERATOR L"#Owner", L"Key", SWDeviceCapabilitiesSilentInstall, NULL, State, &FirstDevice);
    ok(hr == S_OK, "SwDeviceCreate returned 0x%08lx\n", hr);
    if (FAILED(hr))
        return;
    ok(State->Result == S_OK, "The creation reported 0x%08lx\n", State->Result);
    ok(!_wcsicmp(State->InstanceId, First), "The first device is %S\n", State->InstanceId);

    hr = Create(L"Owner#Key", SWDeviceCapabilitiesSilentInstall, NULL, State, &SecondDevice);
    ok(hr == S_OK, "SwDeviceCreate returned 0x%08lx\n", hr);
    if (FAILED(hr))
    {
        SwDeviceClose(FirstDevice);
        WaitGone(First);
        return;
    }
    ok(State->Result == S_OK, "The creation reported 0x%08lx\n", State->Result);
    ok(!_wcsicmp(State->InstanceId, Second), "The second device is %S\n", State->InstanceId);
    ok(IsPresent(First), "%S is not present\n", First);
    ok(IsPresent(Second), "%S is not present\n", Second);

    hr = SwDeviceSetLifetime(FirstDevice, SWDeviceLifetimeParentPresent);
    ok(hr == S_OK, "SwDeviceSetLifetime returned 0x%08lx\n", hr);
    SwDeviceClose(FirstDevice);
    SwDeviceClose(SecondDevice);
    ok(WaitGone(Second), "%S stayed after its handle closed\n", Second);
    ok(IsPresent(First), "%S left with the handle of %S\n", First, Second);

    hr = CreateIn(TEST_ENUMERATOR L"#Owner", L"Key", SWDeviceCapabilitiesSilentInstall, NULL, State, &FirstDevice);
    ok(hr == S_OK, "SwDeviceCreate of the persistent device returned 0x%08lx\n", hr);
    if (FAILED(hr))
        return;
    ok(State->Result == S_OK, "Opening the persistent device after %S closed reported 0x%08lx\n", Second, State->Result);

    hr = SwDeviceSetLifetime(FirstDevice, SWDeviceLifetimeHandle);
    ok(hr == S_OK, "SwDeviceSetLifetime returned 0x%08lx\n", hr);
    SwDeviceClose(FirstDevice);
    ok(WaitGone(First), "%S stayed after its handle closed\n", First);
}

static void
test_DriverRequired(CREATED *State)
{
    HSWDEVICE Device;
    ULONG Status = 0, Problem = 0;
    DEVINST DevInst;
    HRESULT hr;

    hr = Create(L"DriverRequired", SWDeviceCapabilitiesSilentInstall | SWDeviceCapabilitiesDriverRequired,
                NULL, State, &Device);
    ok(hr == S_OK, "SwDeviceCreate returned 0x%08lx\n", hr);
    if (FAILED(hr))
        return;
    trace("DriverRequired without a driver reported 0x%08lx\n", State->Result);
    ok(State->Result == S_OK, "The creation reported 0x%08lx\n", State->Result);
    if (CM_Locate_DevNodeW(&DevInst, State->InstanceId, CM_LOCATE_DEVNODE_NORMAL) == CR_SUCCESS)
    {
        CM_Get_DevNode_Status(&Status, &Problem, DevInst, 0);
        trace("Status 0x%lx, problem %lu\n", Status, Problem);
        ok(Status & DN_HAS_PROBLEM, "A device without its required driver has no problem\n");
    }
    else
    {
        ok(0, "The device without its required driver is not present\n");
    }
    SwDeviceClose(Device);
    WaitGone(State->InstanceId);
}

static void
test_DriverRequiredNoIds(CREATED *State)
{
    SW_DEVICE_CREATE_INFO Info = { sizeof(Info) };
    HSWDEVICE Device;
    HRESULT hr;

    Info.pszInstanceId = L"DriverRequiredNoIds";
    Info.pszzHardwareIds = L"";
    Info.pszDeviceDescription = L"LiberNT software device test";
    Info.CapabilityFlags = SWDeviceCapabilitiesSilentInstall | SWDeviceCapabilitiesDriverRequired;
    ZeroMemory(State->InstanceId, sizeof(State->InstanceId));
    State->Result = E_PENDING;
    ResetEvent(State->Event);
    hr = SwDeviceCreate(TEST_ENUMERATOR, L"HTREE\\ROOT\\0", &Info, 0, NULL, Created, State, &Device);
    ok(hr == S_OK, "SwDeviceCreate without IDs returned 0x%08lx\n", hr);
    if (FAILED(hr))
        return;
    ok(WaitForSingleObject(State->Event, 30000) == WAIT_OBJECT_0, "The creation did not complete\n");
    ok(State->Result == S_OK, "The creation without IDs reported 0x%08lx\n", State->Result);
    ok(IsPresent(State->InstanceId), "%S is not present\n", State->InstanceId);
    SwDeviceClose(Device);
    WaitGone(State->InstanceId);
}

static void
test_Capabilities(CREATED *State)
{
    static const struct
    {
        ULONG Flags;
        BOOL Ids;
    } Tests[] =
    {
        { SWDeviceCapabilitiesNone, FALSE },
        { SWDeviceCapabilitiesRemovable, FALSE },
        { SWDeviceCapabilitiesNoDisplayInUI, FALSE },
        { SWDeviceCapabilitiesRemovable | SWDeviceCapabilitiesNoDisplayInUI, FALSE },
        { SWDeviceCapabilitiesSilentInstall, TRUE },
        { SWDeviceCapabilitiesSilentInstall | SWDeviceCapabilitiesRemovable, TRUE },
        { SWDeviceCapabilitiesSilentInstall | SWDeviceCapabilitiesNoDisplayInUI, TRUE },
        { SWDeviceCapabilitiesSilentInstall | SWDeviceCapabilitiesRemovable | SWDeviceCapabilitiesNoDisplayInUI, TRUE },
        { SWDeviceCapabilitiesDriverRequired, FALSE },
        { SWDeviceCapabilitiesDriverRequired | SWDeviceCapabilitiesRemovable, FALSE },
        { SWDeviceCapabilitiesDriverRequired | SWDeviceCapabilitiesSilentInstall, TRUE },
        { SWDeviceCapabilitiesDriverRequired | SWDeviceCapabilitiesSilentInstall | SWDeviceCapabilitiesRemovable, TRUE },
    };
    static const GUID SystemContainer = { 0, 0, 0, { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } };
    SW_DEVICE_CREATE_INFO Info = { sizeof(Info) };
    ULONG i, Flags, Status, Problem, Capabilities, Policy, Default, Size, Expected, Try;
    GUID Root, Container;
    WCHAR Instance[32];
    HSWDEVICE Device;
    DEVINST DevInst;
    CONFIGRET Cr;
    BOOL Found;
    HRESULT hr;

    Found = GetContainer(L"HTREE\\ROOT\\0", &Root);
    ok(Found && IsEqualGUID(&Root, &SystemContainer), "The container of the root device is %d, {%08lx-...}\n", Found, Root.Data1);

    Info.pszInstanceId = Instance;
    Info.pszDeviceDescription = L"LiberNT software device test";
    for (i = 0; i < ARRAYSIZE(Tests); i++)
    {
        Flags = Tests[i].Flags;
        _snwprintf(Instance, ARRAYSIZE(Instance), L"Capabilities%lu", Flags);
        Info.pszzHardwareIds = Tests[i].Ids ? TEST_HARDWARE_ID : L"";
        Info.CapabilityFlags = Flags;
        ZeroMemory(State->InstanceId, sizeof(State->InstanceId));
        State->Result = E_PENDING;
        ResetEvent(State->Event);
        hr = SwDeviceCreate(TEST_ENUMERATOR, L"HTREE\\ROOT\\0", &Info, 0, NULL, Created, State, &Device);
        ok(hr == S_OK, "SwDeviceCreate with the capabilities 0x%lx returned 0x%08lx\n", Flags, hr);
        if (FAILED(hr))
            continue;
        ok(WaitForSingleObject(State->Event, 30000) == WAIT_OBJECT_0, "The creation with the capabilities 0x%lx did not complete\n", Flags);
        ok(State->Result == S_OK, "The creation with the capabilities 0x%lx reported 0x%08lx\n", Flags, State->Result);

        Cr = CM_Locate_DevNodeW(&DevInst, State->InstanceId, CM_LOCATE_DEVNODE_NORMAL);
        ok(Cr == CR_SUCCESS, "CM_Locate_DevNodeW of %S returned CR %lu\n", State->InstanceId, Cr);
        if (Cr == CR_SUCCESS)
        {
            Status = Problem = 0;
            Cr = CM_Get_DevNode_Status(&Status, &Problem, DevInst, 0);
            Expected = ((Flags & SWDeviceCapabilitiesRemovable) ? DN_REMOVABLE : 0) |
                       ((Flags & SWDeviceCapabilitiesNoDisplayInUI) ? DN_NO_SHOW_IN_DM : 0);
            ok(Cr == CR_SUCCESS && (Status & (DN_REMOVABLE | DN_NO_SHOW_IN_DM)) == Expected,
               "With the capabilities 0x%lx the status is CR %lu, 0x%08lx\n", Flags, Cr, Status);
            if (Flags & SWDeviceCapabilitiesDriverRequired)
            {
                ok((Status & (DN_STARTED | DN_HAS_PROBLEM)) == DN_HAS_PROBLEM && Problem == CM_PROB_FAILED_INSTALL,
                   "With the capabilities 0x%lx and no driver the status is 0x%08lx, problem %lu\n", Flags, Status, Problem);
            }
            else
            {
                /* Windows 11 starts the device some time after the callback */
                for (Try = 0; Try < 100 && !(Status & DN_STARTED); Try++)
                {
                    Sleep(100);
                    CM_Get_DevNode_Status(&Status, &Problem, DevInst, 0);
                }
                ok((Status & (DN_STARTED | DN_HAS_PROBLEM)) == DN_STARTED,
                   "With the capabilities 0x%lx and no driver the status is 0x%08lx, problem %lu\n", Flags, Status, Problem);
            }

            Capabilities = 0;
            Size = sizeof(Capabilities);
            Cr = CM_Get_DevNode_Registry_PropertyW(DevInst, CM_DRP_CAPABILITIES, NULL, &Capabilities, &Size, 0);
            Expected = CM_DEVCAP_UNIQUEID | CM_DEVCAP_SURPRISEREMOVALOK |
                       ((Flags & SWDeviceCapabilitiesDriverRequired) ? 0 : CM_DEVCAP_RAWDEVICEOK) |
                       ((Flags & SWDeviceCapabilitiesRemovable) ? CM_DEVCAP_REMOVABLE : 0) |
                       ((Flags & SWDeviceCapabilitiesSilentInstall) ? CM_DEVCAP_SILENTINSTALL : 0);
            ok(Cr == CR_SUCCESS && Capabilities == Expected,
               "With the capabilities 0x%lx the device reports CR %lu, 0x%lx instead of 0x%lx\n", Flags, Cr, Capabilities, Expected);

            Found = GetContainer(State->InstanceId, &Container);
            ok(Found && (!IsEqualGUID(&Container, &Root)) == ((Flags & SWDeviceCapabilitiesRemovable) != 0),
               "With the capabilities 0x%lx the container is %d, {%08lx-...}\n", Flags, Found, Container.Data1);

            Policy = Default = 0;
            Size = sizeof(Policy);
            Cr = CM_Get_DevNode_Registry_PropertyW(DevInst, CM_DRP_REMOVAL_POLICY, NULL, &Policy, &Size, 0);
            Expected = (Flags & SWDeviceCapabilitiesRemovable) ? CM_REMOVAL_POLICY_EXPECT_ORDERLY_REMOVAL
                                                               : CM_REMOVAL_POLICY_EXPECT_NO_REMOVAL;
            ok(Cr == CR_SUCCESS && Policy == Expected, "With the capabilities 0x%lx the removal policy is CR %lu, %lu\n", Flags, Cr, Policy);
            Size = sizeof(Default);
            Cr = CM_Get_DevNode_Registry_PropertyW(DevInst, CM_DRP_REMOVAL_POLICY_HW_DEFAULT, NULL, &Default, &Size, 0);
            ok(Cr == CR_SUCCESS && Default == Expected,
               "With the capabilities 0x%lx the default removal policy is CR %lu, %lu\n", Flags, Cr, Default);
        }

        SwDeviceClose(Device);
        ok(WaitGone(State->InstanceId), "%S stayed after its handle closed\n", State->InstanceId);
    }
}

/* Windows 11 looks up the module of the callback and refuses a callback that has none */
static void
test_CallbackOutsideModule(void)
{
    SW_DEVICE_CREATE_INFO Info = { sizeof(Info) };
    HSWDEVICE Device = (HSWDEVICE)(ULONG_PTR)1;
    PVOID Page;
    HRESULT hr;

    Page = VirtualAlloc(NULL, 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!Page)
    {
        skip("VirtualAlloc failed (%lu)\n", GetLastError());
        return;
    }

    Info.pszInstanceId = L"NoModule";
    Info.pszzHardwareIds = TEST_HARDWARE_ID;
    Info.pszDeviceDescription = L"LiberNT software device test";
    Info.CapabilityFlags = SWDeviceCapabilitiesSilentInstall;
    hr = SwDeviceCreate(TEST_ENUMERATOR, L"HTREE\\ROOT\\0", &Info, 0, NULL, (SW_DEVICE_CREATE_CALLBACK)(ULONG_PTR)Page, NULL, &Device);
    ok(hr == HRESULT_FROM_WIN32(ERROR_MOD_NOT_FOUND), "SwDeviceCreate with a callback outside of every module returned 0x%08lx\n", hr);
    ok(Device == NULL, "SwDeviceCreate with a callback outside of every module returned the device %p\n", Device);
    ok(!IsPresent(L"SWD\\" TEST_ENUMERATOR L"\\NoModule"), "A device was created for a callback outside of every module\n");

    /* A creation that started calls into the page */
    if (FAILED(hr))
        VirtualFree(Page, 0, MEM_RELEASE);
}

static BYTE *HookedPage;
static PVOID (NTAPI *OriginalPcToFileHeader)(PVOID, PVOID *);

static PVOID NTAPI
HookedPcToFileHeader(PVOID PcValue, PVOID *BaseOfImage)
{
    if ((BYTE *)PcValue >= HookedPage && (BYTE *)PcValue < HookedPage + 0x1000)
        PcValue = (PVOID)(ULONG_PTR)Created;
    return OriginalPcToFileHeader(PcValue, BaseOfImage);
}

static ULONG_PTR *
FindKernelBaseImport(PCSTR Function)
{
    BYTE *Image = (BYTE *)GetModuleHandleW(L"kernelbase.dll");
    IMAGE_IMPORT_DESCRIPTOR *Import;
    IMAGE_THUNK_DATA *Name, *Slot;
    IMAGE_NT_HEADERS *Headers;
    ULONG Rva;

    if (!Image)
        return NULL;
    Headers = (IMAGE_NT_HEADERS *)(Image + ((IMAGE_DOS_HEADER *)Image)->e_lfanew);
    Rva = Headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!Rva)
        return NULL;
    for (Import = (IMAGE_IMPORT_DESCRIPTOR *)(Image + Rva); Import->Name; Import++)
    {
        if (_stricmp((PCSTR)(Image + Import->Name), "ntdll.dll") || !Import->OriginalFirstThunk)
            continue;
        Name = (IMAGE_THUNK_DATA *)(Image + Import->OriginalFirstThunk);
        Slot = (IMAGE_THUNK_DATA *)(Image + Import->FirstThunk);
        for (; Name->u1.AddressOfData; Name++, Slot++)
        {
            if (!IMAGE_SNAP_BY_ORDINAL(Name->u1.Ordinal) &&
                !strcmp((PCSTR)((IMAGE_IMPORT_BY_NAME *)(Image + Name->u1.AddressOfData))->Name, Function))
            {
                return (ULONG_PTR *)&Slot->u1.Function;
            }
        }
    }
    return NULL;
}

static BOOL
WriteImport(ULONG_PTR *Slot, ULONG_PTR Value)
{
    DWORD Protection;

    if (!VirtualProtect(Slot, sizeof(*Slot), PAGE_READWRITE, &Protection))
        return FALSE;
    *Slot = Value;
    return VirtualProtect(Slot, sizeof(*Slot), Protection, &Protection);
}

/* Windows 11 refuses a callback in code mapped by hand unless the RtlPcToFileHeader import of kernelbase finds it in a module */
static void
test_CallbackInMappedCode(CREATED *State)
{
    static const WCHAR InstanceId[] = L"SWD\\" TEST_ENUMERATOR L"\\MappedCode";
#if defined(_M_AMD64)
    BYTE Code[] = { 0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0 };
    const ULONG TargetOffset = 2;
#elif defined(_M_IX86)
    BYTE Code[] = { 0xB8, 0, 0, 0, 0, 0xFF, 0xE0 };
    const ULONG TargetOffset = 1;
#elif defined(_M_ARM64)
    BYTE Code[] = { 0x50, 0x00, 0x00, 0x58, 0x00, 0x02, 0x1F, 0xD6, 0, 0, 0, 0, 0, 0, 0, 0 };
    const ULONG TargetOffset = 8;
#else
    BYTE Code[sizeof(ULONG_PTR)];
    const ULONG TargetOffset = ~0u;
#endif
    SW_DEVICE_CREATE_INFO Info = { sizeof(Info) };
    ULONG_PTR Target = (ULONG_PTR)Created, *Slot;
    HSWDEVICE Device = NULL;
    DWORD Protection;
    HRESULT hr;

    if (TargetOffset == ~0u)
    {
        skip("No code to jump to the callback on this architecture\n");
        return;
    }
    HookedPage = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!HookedPage)
    {
        skip("VirtualAlloc failed (%lu)\n", GetLastError());
        return;
    }
    memcpy(Code + TargetOffset, &Target, sizeof(Target));
    memcpy(HookedPage, Code, sizeof(Code));
    if (!VirtualProtect(HookedPage, 0x1000, PAGE_EXECUTE_READ, &Protection))
    {
        skip("VirtualProtect failed (%lu)\n", GetLastError());
        return;
    }
    FlushInstructionCache(GetCurrentProcess(), HookedPage, sizeof(Code));

    Info.pszInstanceId = L"MappedCode";
    Info.pszzHardwareIds = TEST_HARDWARE_ID;
    Info.pszDeviceDescription = L"LiberNT software device test";
    Info.CapabilityFlags = SWDeviceCapabilitiesSilentInstall;
    ZeroMemory(State->InstanceId, sizeof(State->InstanceId));
    State->Result = E_PENDING;
    ResetEvent(State->Event);

    hr = SwDeviceCreate(TEST_ENUMERATOR, L"HTREE\\ROOT\\0", &Info, 0, NULL, (SW_DEVICE_CREATE_CALLBACK)(ULONG_PTR)HookedPage, State, &Device);
    ok(hr == HRESULT_FROM_WIN32(ERROR_MOD_NOT_FOUND), "SwDeviceCreate with a callback in mapped code returned 0x%08lx\n", hr);
    if (SUCCEEDED(hr))
    {
        WaitForSingleObject(State->Event, 30000);
        SwDeviceClose(Device);
        WaitGone(InstanceId);
        return;
    }

    Slot = FindKernelBaseImport("RtlPcToFileHeader");
    if (!Slot)
    {
        skip("kernelbase does not import RtlPcToFileHeader\n");
        return;
    }
    OriginalPcToFileHeader = (PVOID)*Slot;
    if (!WriteImport(Slot, (ULONG_PTR)HookedPcToFileHeader))
    {
        skip("The import cannot be written (%lu)\n", GetLastError());
        return;
    }
    hr = SwDeviceCreate(TEST_ENUMERATOR, L"HTREE\\ROOT\\0", &Info, 0, NULL, (SW_DEVICE_CREATE_CALLBACK)(ULONG_PTR)HookedPage, State, &Device);
    ok(hr == S_OK, "SwDeviceCreate with a callback in mapped code that kernelbase finds in a module returned 0x%08lx\n", hr);
    if (SUCCEEDED(hr))
    {
        ok(WaitForSingleObject(State->Event, 30000) == WAIT_OBJECT_0, "The callback in mapped code was not called\n");
        ok(State->Result == S_OK, "The creation reported 0x%08lx\n", State->Result);
        ok(!_wcsicmp(State->InstanceId, InstanceId), "The callback in mapped code read %S\n", State->InstanceId);
        SwDeviceClose(Device);
        ok(WaitGone(InstanceId), "%S stayed after its handle closed\n", InstanceId);
    }
    WriteImport(Slot, (ULONG_PTR)OriginalPcToFileHeader);
}

static void
test_CloseInCallback(CREATED *State)
{
    static const WCHAR InstanceId[] = L"SWD\\" TEST_ENUMERATOR L"\\CloseInCallback";
    SW_DEVICE_CREATE_INFO Info = { sizeof(Info) };
    HSWDEVICE Device;
    HRESULT hr;

    Info.pszInstanceId = L"CloseInCallback";
    Info.pszzHardwareIds = TEST_HARDWARE_ID;
    Info.pszDeviceDescription = L"LiberNT software device test";
    Info.CapabilityFlags = SWDeviceCapabilitiesSilentInstall;
    ZeroMemory(State->InstanceId, sizeof(State->InstanceId));
    State->Result = E_PENDING;
    ResetEvent(State->Event);
    hr = SwDeviceCreate(TEST_ENUMERATOR, L"HTREE\\ROOT\\0", &Info, 0, NULL, CreatedAndClosed, State, &Device);
    ok(hr == S_OK, "SwDeviceCreate returned 0x%08lx\n", hr);
    if (FAILED(hr))
        return;
    ok(WaitForSingleObject(State->Event, 30000) == WAIT_OBJECT_0, "The creation did not complete\n");
    ok(State->Result == S_OK, "The creation reported 0x%08lx\n", State->Result);
    ok(!_wcsicmp(State->InstanceId, InstanceId), "The callback read %S after closing its device\n", State->InstanceId);
    ok(WaitGone(InstanceId), "%S stayed after its callback closed it\n", InstanceId);
}

static void
test_SecurityDescriptor(CREATED *State)
{
    PSECURITY_DESCRIPTOR Security = NULL, NoOwner = NULL;
    HSWDEVICE Device;
    HRESULT hr;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:SYG:SYD:P(A;;GA;;;SY)(A;;GR;;;BA)", SDDL_REVISION_1,
                                                              &Security, NULL) ||
        !ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GR;;;BA)", SDDL_REVISION_1,
                                                              &NoOwner, NULL))
    {
        skip("No security descriptor (%lu)\n", GetLastError());
        LocalFree(Security);
        return;
    }

    hr = Create(L"SecurityNoOwner", SWDeviceCapabilitiesSilentInstall, NoOwner, State, &Device);
    ok(hr == E_INVALIDARG, "SwDeviceCreate without an owner returned 0x%08lx\n", hr);
    if (SUCCEEDED(hr))
    {
        SwDeviceClose(Device);
        WaitGone(State->InstanceId);
    }

    hr = Create(L"Security", SWDeviceCapabilitiesSilentInstall, Security, State, &Device);
    ok(hr == S_OK, "SwDeviceCreate returned 0x%08lx\n", hr);
    if (SUCCEEDED(hr))
    {
        ok(State->Result == S_OK, "The creation reported 0x%08lx\n", State->Result);
        SwDeviceClose(Device);
        WaitGone(State->InstanceId);
    }
    LocalFree(NoOwner);
    LocalFree(Security);
}

static void
test_PropertyCountOverflow(CREATED *State)
{
    static const DEVPROPKEY Key = { { 0x4c6e7453, 0x7754, 0x4465, { 0x76, 0x69, 0x63, 0x65, 0x54, 0x65, 0x73, 0x74 } }, 2 };
    SW_DEVICE_CREATE_INFO Info = { sizeof(Info) };
    DEVPROPERTY Properties[2];
    HSWDEVICE Device = NULL;
    DWORD Exception = 0;
    ULONG Value = 1;
    HRESULT hr = S_OK;

    ZeroMemory(Properties, sizeof(Properties));
    Properties[0].CompKey.Key = Key;
    Properties[0].CompKey.Store = DEVPROP_STORE_SYSTEM;
    Properties[0].Type = DEVPROP_TYPE_UINT32;
    Properties[0].BufferSize = sizeof(Value);
    Properties[0].Buffer = &Value;
    Properties[1] = Properties[0];
    Properties[1].Buffer = NULL;

    Info.pszInstanceId = L"PropertyCount";
    Info.pszzHardwareIds = TEST_HARDWARE_ID;
    Info.pszDeviceDescription = L"LiberNT software device test";
    Info.CapabilityFlags = SWDeviceCapabilitiesSilentInstall;
    ZeroMemory(State->InstanceId, sizeof(State->InstanceId));
    State->Result = E_PENDING;
    ResetEvent(State->Event);

    /* The size of this many properties does not fit in 32 bits */
    _SEH2_TRY
    {
        hr = SwDeviceCreate(TEST_ENUMERATOR, L"HTREE\\ROOT\\0", &Info, MAXDWORD / sizeof(DEVPROPERTY) + 1, Properties,
                            Created, State, &Device);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Exception = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

    ok(Exception == 0, "SwDeviceCreate raised 0x%08lx\n", Exception);
    trace("SwDeviceCreate with an overflowing property count returned 0x%08lx\n", hr);
    ok(FAILED(hr), "SwDeviceCreate with an overflowing property count returned 0x%08lx\n", hr);
    if (SUCCEEDED(hr) && Device)
    {
        WaitForSingleObject(State->Event, 30000);
        SwDeviceClose(Device);
        WaitGone(L"SWD\\" TEST_ENUMERATOR L"\\PropertyCount");
    }
}

static void
test_Interface(CREATED *State)
{
    static const GUID Class = { 0x4c6e7449, 0x6e74, 0x6572, { 0x66, 0x61, 0x63, 0x65, 0x54, 0x65, 0x73, 0x74 } };
    static const DEVPROPKEY Key = { { 0x4c6e7453, 0x7754, 0x4465, { 0x76, 0x69, 0x63, 0x65, 0x54, 0x65, 0x73, 0x74 } }, 3 };
    static const WCHAR FriendlyName[] = L"LiberNT software device test interface";
    DEVPROP_BOOLEAN Enabled = DEVPROP_FALSE;
    DEVPROPERTY Properties[2];
    PWSTR InterfaceId = NULL;
    ULONG Value = 0x1234, Read = 0, Size;
    DEVPROPTYPE Type = DEVPROP_TYPE_EMPTY;
    WCHAR Name[64] = L"";
    HSWDEVICE Device;
    CONFIGRET Cr;
    HRESULT hr;

    hr = Create(L"Interface", SWDeviceCapabilitiesSilentInstall, NULL, State, &Device);
    ok(hr == S_OK, "SwDeviceCreate returned 0x%08lx\n", hr);
    if (FAILED(hr))
        return;
    ok(State->Result == S_OK, "The creation reported 0x%08lx\n", State->Result);

    ZeroMemory(Properties, sizeof(Properties));
    Properties[0].CompKey.Key = Key;
    Properties[0].CompKey.Store = DEVPROP_STORE_SYSTEM;
    Properties[0].Type = DEVPROP_TYPE_UINT32;
    Properties[0].BufferSize = sizeof(Value);
    Properties[0].Buffer = &Value;
    Properties[1].CompKey.Key = DEVPKEY_DeviceInterface_FriendlyName;
    Properties[1].CompKey.Store = DEVPROP_STORE_SYSTEM;
    Properties[1].Type = DEVPROP_TYPE_STRING;
    Properties[1].BufferSize = sizeof(FriendlyName);
    Properties[1].Buffer = (PVOID)FriendlyName;

    hr = SwDeviceInterfaceRegister(Device, &Class, L"Ref", 2, Properties, FALSE, &InterfaceId);
    ok(hr == S_OK, "SwDeviceInterfaceRegister returned 0x%08lx\n", hr);
    ok(InterfaceId != NULL, "SwDeviceInterfaceRegister returned no interface\n");
    if (SUCCEEDED(hr) && InterfaceId)
    {
        trace("The interface is %S\n", InterfaceId);
        ok(!wcsncmp(InterfaceId, L"\\\\?\\", 4), "The interface %S does not start with \\\\?\\\n", InterfaceId);

        Size = sizeof(Read);
        Cr = CM_Get_Device_Interface_PropertyW(InterfaceId, &Key, &Type, (PBYTE)&Read, &Size, 0);
        ok(Cr == CR_SUCCESS && Type == DEVPROP_TYPE_UINT32 && Read == Value,
           "The registered property is CR %lu, type 0x%lx, value 0x%lx\n", Cr, Type, Read);

        Size = sizeof(Name);
        Cr = CM_Get_Device_Interface_PropertyW(InterfaceId, &DEVPKEY_DeviceInterface_FriendlyName, &Type, (PBYTE)Name, &Size, 0);
        ok(Cr == CR_SUCCESS && Type == DEVPROP_TYPE_STRING && !wcscmp(Name, FriendlyName),
           "The friendly name is CR %lu, type 0x%lx, %S\n", Cr, Type, Name);

        Value = 0x5678;
        hr = SwDeviceInterfacePropertySet(Device, InterfaceId, 1, Properties);
        ok(hr == S_OK, "SwDeviceInterfacePropertySet returned 0x%08lx\n", hr);
        Size = sizeof(Read);
        Cr = CM_Get_Device_Interface_PropertyW(InterfaceId, &Key, &Type, (PBYTE)&Read, &Size, 0);
        ok(Cr == CR_SUCCESS && Type == DEVPROP_TYPE_UINT32 && Read == Value,
           "The property set again is CR %lu, type 0x%lx, value 0x%lx\n", Cr, Type, Read);

        hr = SwDeviceInterfaceSetState(Device, InterfaceId, TRUE);
        trace("SwDeviceInterfaceSetState returned 0x%08lx\n", hr);
        Size = sizeof(Enabled);
        Cr = CM_Get_Device_Interface_PropertyW(InterfaceId, &DEVPKEY_DeviceInterface_Enabled, &Type, (PBYTE)&Enabled, &Size, 0);
        ok(Cr == CR_SUCCESS, "Reading the state of the interface returned CR %lu\n", Cr);
        ok((hr == S_OK) == (Enabled == DEVPROP_TRUE),
           "SwDeviceInterfaceSetState returned 0x%08lx and the interface is %s\n", hr, Enabled == DEVPROP_TRUE ? "enabled" : "disabled");

        SwMemFree(InterfaceId);
    }

    SwDeviceClose(Device);
    WaitGone(State->InstanceId);
}

static BOOL
IsInterfacePresent(const GUID *Class, PCWSTR InterfaceId)
{
    WCHAR List[2048];
    PCWSTR Entry;
    CONFIGRET Cr;

    List[0] = UNICODE_NULL;
    Cr = CM_Get_Device_Interface_ListW((LPGUID)Class, NULL, List, ARRAYSIZE(List), CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
    if (Cr != CR_SUCCESS)
    {
        trace("CM_Get_Device_Interface_ListW returned CR %lu\n", Cr);
        return FALSE;
    }
    for (Entry = List; *Entry; Entry += wcslen(Entry) + 1)
    {
        if (wcslen(Entry) > 4 && !_wcsicmp(Entry + 4, InterfaceId + 4))
            return TRUE;
    }
    return FALSE;
}

/* Windows 11 lists an interface some time after the call that enabled it has returned */
static BOOL
WaitInterface(BOOL Present, const GUID *Class, PCWSTR InterfaceId)
{
    ULONG Try;

    for (Try = 0; Try < 50; Try++)
    {
        if (IsInterfacePresent(Class, InterfaceId) == Present)
            return TRUE;
        Sleep(100);
    }
    return FALSE;
}

static void
test_InterfaceState(CREATED *State)
{
    static const GUID Class = { 0x4c6e7449, 0x6e74, 0x6572, { 0x66, 0x61, 0x63, 0x65, 0x53, 0x74, 0x61, 0x74 } };
    DEVPROP_BOOLEAN Enabled = DEVPROP_FALSE;
    DEVPROPTYPE Type = DEVPROP_TYPE_EMPTY;
    PWSTR InterfaceId = NULL;
    WCHAR Copy[MAX_PATH];
    HSWDEVICE Device;
    HANDLE File;
    ULONG Size;
    CONFIGRET Cr;
    HRESULT hr;

    hr = Create(L"InterfaceState", SWDeviceCapabilitiesSilentInstall, NULL, State, &Device);
    ok(hr == S_OK, "SwDeviceCreate returned 0x%08lx\n", hr);
    if (FAILED(hr))
        return;
    ok(State->Result == S_OK, "The creation reported 0x%08lx\n", State->Result);

    hr = SwDeviceInterfaceRegister(Device, &Class, L"State", 0, NULL, TRUE, &InterfaceId);
    ok(hr == S_OK, "SwDeviceInterfaceRegister of an enabled interface returned 0x%08lx\n", hr);
    ok(InterfaceId != NULL, "SwDeviceInterfaceRegister returned no interface\n");
    if (FAILED(hr) || !InterfaceId || wcslen(InterfaceId) <= 4 || wcslen(InterfaceId) >= ARRAYSIZE(Copy))
    {
        SwDeviceClose(Device);
        WaitGone(State->InstanceId);
        return;
    }
    lstrcpyW(Copy, InterfaceId);
    SwMemFree(InterfaceId);

    ok(WaitInterface(TRUE, &Class, Copy), "%S registered enabled is not present\n", Copy);
    Size = sizeof(Enabled);
    Cr = CM_Get_Device_Interface_PropertyW(Copy, &DEVPKEY_DeviceInterface_Enabled, &Type, (PBYTE)&Enabled, &Size, 0);
    ok(Cr == CR_SUCCESS && Enabled == DEVPROP_TRUE, "The interface registered enabled is CR %lu, enabled %d\n", Cr, Enabled);

    File = CreateFileW(Copy, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    trace("Opening the enabled interface %s (error %lu)\n", File != INVALID_HANDLE_VALUE ? "succeeded" : "failed", GetLastError());
    if (File != INVALID_HANDLE_VALUE)
        CloseHandle(File);

    hr = SwDeviceInterfaceSetState(Device, Copy, TRUE);
    trace("Enabling the enabled interface returned 0x%08lx\n", hr);
    ok(WaitInterface(TRUE, &Class, Copy), "%S enabled twice is not present\n", Copy);

    hr = SwDeviceInterfaceSetState(Device, Copy, FALSE);
    ok(hr == S_OK, "Disabling the interface returned 0x%08lx\n", hr);
    ok(WaitInterface(FALSE, &Class, Copy), "%S is present after it was disabled\n", Copy);
    Size = sizeof(Enabled);
    Cr = CM_Get_Device_Interface_PropertyW(Copy, &DEVPKEY_DeviceInterface_Enabled, &Type, (PBYTE)&Enabled, &Size, 0);
    ok(Cr == CR_SUCCESS && Enabled == DEVPROP_FALSE, "The disabled interface is CR %lu, enabled %d\n", Cr, Enabled);

    hr = SwDeviceInterfaceSetState(Device, Copy, FALSE);
    trace("Disabling the disabled interface returned 0x%08lx\n", hr);
    ok(WaitInterface(FALSE, &Class, Copy), "%S disabled twice is present\n", Copy);

    hr = SwDeviceInterfaceSetState(Device, Copy, TRUE);
    ok(hr == S_OK, "Enabling the interface again returned 0x%08lx\n", hr);
    ok(WaitInterface(TRUE, &Class, Copy), "%S is not present after it was enabled again\n", Copy);

    hr = SwDeviceInterfaceSetState(Device, L"\\\\?\\SWD#" TEST_ENUMERATOR L"#NoSuchDevice#{4c6e7449-6e74-6572-6661-636553746174}", TRUE);
    ok(hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND), "Enabling an interface that was never registered returned 0x%08lx\n", hr);

    SwDeviceClose(Device);
    ok(WaitGone(State->InstanceId), "%S stayed after its handle closed\n", State->InstanceId);
    ok(WaitInterface(FALSE, &Class, Copy), "%S is present after its device was closed\n", Copy);
}

static void
test_DevNodeProperty(CREATED *State)
{
    static const DEVPROPKEY Key = { { 0x4c6e7453, 0x7754, 0x4465, { 0x76, 0x69, 0x63, 0x65, 0x54, 0x65, 0x73, 0x74 } }, 4 };
    static const WCHAR Text[] = L"Text";
    static const BYTE Bytes[16] = { 0 };
    ULONG Value = 0x1234, Read, Size;
    DEVPROPTYPE Type;
    HSWDEVICE Device;
    DEVINST DevInst;
    CONFIGRET Cr;
    HRESULT hr;

    hr = Create(L"Property", SWDeviceCapabilitiesSilentInstall, NULL, State, &Device);
    ok(hr == S_OK, "SwDeviceCreate returned 0x%08lx\n", hr);
    if (FAILED(hr))
        return;
    ok(State->Result == S_OK, "The creation reported 0x%08lx\n", State->Result);
    Cr = CM_Locate_DevNodeW(&DevInst, State->InstanceId, CM_LOCATE_DEVNODE_NORMAL);
    ok(Cr == CR_SUCCESS, "CM_Locate_DevNodeW returned CR %lu\n", Cr);
    if (Cr != CR_SUCCESS)
        goto Done;

    Cr = CM_Set_DevNode_PropertyW(DevInst, &Key, DEVPROP_TYPE_NULL, NULL, 0, 0);
    ok(Cr == CR_SUCCESS, "Creating a property without a value returned CR %lu\n", Cr);
    Type = DEVPROP_TYPE_EMPTY;
    Read = 0;
    Size = sizeof(Read);
    Cr = CM_Get_DevNode_PropertyW(DevInst, &Key, &Type, (PBYTE)&Read, &Size, 0);
    ok(Cr == CR_SUCCESS && Type == DEVPROP_TYPE_NULL && Size == 0,
       "The new property without a value is CR %lu, type 0x%lx, size %lu\n", Cr, Type, Size);
    Type = DEVPROP_TYPE_EMPTY;
    Size = 0;
    Cr = CM_Get_DevNode_PropertyW(DevInst, &Key, &Type, NULL, &Size, 0);
    trace("The property without a value read without a buffer is CR %lu, type 0x%lx, size %lu\n", Cr, Type, Size);

    Cr = CM_Set_DevNode_PropertyW(DevInst, &Key, DEVPROP_TYPE_UINT32, (const BYTE *)&Value, sizeof(Value), 0);
    ok(Cr == CR_SUCCESS, "Setting a value returned CR %lu\n", Cr);
    Type = DEVPROP_TYPE_EMPTY;
    Read = 0;
    Size = sizeof(Read);
    Cr = CM_Get_DevNode_PropertyW(DevInst, &Key, &Type, (PBYTE)&Read, &Size, 0);
    ok(Cr == CR_SUCCESS && Type == DEVPROP_TYPE_UINT32 && Size == sizeof(Read) && Read == Value,
       "The value is CR %lu, type 0x%lx, size %lu, 0x%lx\n", Cr, Type, Size, Read);

    Cr = CM_Set_DevNode_PropertyW(DevInst, &Key, DEVPROP_TYPE_NULL, NULL, 0, 0);
    ok(Cr == CR_SUCCESS, "Removing the value of a property returned CR %lu\n", Cr);
    Type = DEVPROP_TYPE_EMPTY;
    Size = sizeof(Read);
    Cr = CM_Get_DevNode_PropertyW(DevInst, &Key, &Type, (PBYTE)&Read, &Size, 0);
    ok(Cr == CR_SUCCESS && Type == DEVPROP_TYPE_NULL && Size == 0,
       "The property that lost its value is CR %lu, type 0x%lx, size %lu\n", Cr, Type, Size);

    Cr = CM_Set_DevNode_PropertyW(DevInst, &Key, DEVPROP_TYPE_EMPTY, NULL, 0, 0);
    ok(Cr == CR_SUCCESS, "Deleting the property returned CR %lu\n", Cr);
    Type = DEVPROP_TYPE_EMPTY;
    Size = sizeof(Read);
    Cr = CM_Get_DevNode_PropertyW(DevInst, &Key, &Type, (PBYTE)&Read, &Size, 0);
    trace("The deleted property is CR %lu, type 0x%lx, size %lu\n", Cr, Type, Size);
    ok(Cr != CR_SUCCESS, "The deleted property is still there, type 0x%lx, size %lu\n", Type, Size);

    Cr = CM_Set_DevNode_PropertyW(DevInst, &Key, 0xffffffff, (const BYTE *)&Value, sizeof(Value), 0);
    trace("Setting a property of type 0xffffffff returned CR %lu\n", Cr);
    ok(Cr != CR_SUCCESS, "A property of type 0xffffffff was set\n");
    Cr = CM_Set_DevNode_PropertyW(DevInst, &Key, DEVPROP_TYPE_UINT32 | DEVPROP_TYPEMOD_LIST, (const BYTE *)&Value, sizeof(Value), 0);
    trace("Setting a list of UINT32 returned CR %lu\n", Cr);
    ok(Cr != CR_SUCCESS, "A list of UINT32 was set\n");
    Cr = CM_Set_DevNode_PropertyW(DevInst, &Key, DEVPROP_TYPE_NULL, (const BYTE *)&Value, sizeof(Value), 0);
    trace("Setting a property without a value from %lu bytes returned CR %lu\n", (ULONG)sizeof(Value), Cr);
    Type = DEVPROP_TYPE_EMPTY;
    Size = sizeof(Read);
    Cr = CM_Get_DevNode_PropertyW(DevInst, &Key, &Type, (PBYTE)&Read, &Size, 0);
    trace("After the rejected types the property is CR %lu, type 0x%lx, size %lu\n", Cr, Type, Size);
    CM_Set_DevNode_PropertyW(DevInst, &Key, DEVPROP_TYPE_EMPTY, NULL, 0, 0);

    Cr = CM_Set_DevNode_PropertyW(DevInst, &Key, DEVPROP_TYPE_UINT32, NULL, 0, 0);
    trace("Setting a UINT32 without a buffer returned CR %lu\n", Cr);
    ok(Cr != CR_SUCCESS, "A UINT32 without a buffer was set\n");
    Cr = CM_Set_DevNode_PropertyW(DevInst, &Key, DEVPROP_TYPE_UINT32, Bytes, 1, 0);
    trace("Setting a UINT32 from 1 byte returned CR %lu\n", Cr);
    ok(Cr != CR_SUCCESS, "A UINT32 of 1 byte was set\n");
    Cr = CM_Set_DevNode_PropertyW(DevInst, &Key, DEVPROP_TYPE_UINT32, Bytes, 8, 0);
    trace("Setting a UINT32 from 8 bytes returned CR %lu\n", Cr);
    ok(Cr != CR_SUCCESS, "A UINT32 of 8 bytes was set\n");
    Cr = CM_Set_DevNode_PropertyW(DevInst, &Key, DEVPROP_TYPE_UINT32 | DEVPROP_TYPEMOD_ARRAY, Bytes, 6, 0);
    trace("Setting an array of UINT32 from 6 bytes returned CR %lu\n", Cr);
    ok(Cr != CR_SUCCESS, "An array of UINT32 of 6 bytes was set\n");
    Cr = CM_Set_DevNode_PropertyW(DevInst, &Key, DEVPROP_TYPE_STRING, (const BYTE *)Text, sizeof(Text) - 1, 0);
    trace("Setting a string of an odd size returned CR %lu\n", Cr);
    ok(Cr != CR_SUCCESS, "A string of an odd size was set\n");
    Cr = CM_Set_DevNode_PropertyW(DevInst, &Key, DEVPROP_TYPE_STRING, (const BYTE *)Text, sizeof(Text) - sizeof(WCHAR), 0);
    trace("Setting a string without a terminator returned CR %lu\n", Cr);
    ok(Cr != CR_SUCCESS, "A string without a terminator was set\n");
    Cr = CM_Set_DevNode_PropertyW(DevInst, &Key, DEVPROP_TYPE_GUID, Bytes, sizeof(GUID) - 1, 0);
    trace("Setting a GUID from %lu bytes returned CR %lu\n", (ULONG)sizeof(GUID) - 1, Cr);
    ok(Cr != CR_SUCCESS, "A GUID of a wrong size was set\n");
    Type = DEVPROP_TYPE_EMPTY;
    Size = sizeof(Read);
    Cr = CM_Get_DevNode_PropertyW(DevInst, &Key, &Type, (PBYTE)&Read, &Size, 0);
    trace("After the rejected values the property is CR %lu, type 0x%lx, size %lu\n", Cr, Type, Size);
    ok(Cr != CR_SUCCESS, "A rejected value left a property of type 0x%lx, size %lu\n", Type, Size);
    Cr = CM_Set_DevNode_PropertyW(DevInst, &Key, DEVPROP_TYPE_BOOLEAN, Bytes, 1, 0);
    ok(Cr == CR_SUCCESS, "Setting a BOOLEAN from 1 byte returned CR %lu\n", Cr);
    CM_Set_DevNode_PropertyW(DevInst, &Key, DEVPROP_TYPE_EMPTY, NULL, 0, 0);

Done:
    SwDeviceClose(Device);
    WaitGone(State->InstanceId);
}

/* Windows 11 creates a software device below any device that is present and started, and removes it with that device */
static void
test_Parent(CREATED *State)
{
    static const WCHAR ParentId[] = L"SWD\\" TEST_ENUMERATOR L"\\Parent";
    static const WCHAR ChildId[] = L"SWD\\" TEST_ENUMERATOR L"\\Child";
    static const WCHAR RemovableId[] = L"SWD\\" TEST_ENUMERATOR L"\\RemovableChild";
    static const WCHAR KeptId[] = L"SWD\\" TEST_ENUMERATOR L"\\KeptChild";
    SW_DEVICE_LIFETIME Lifetime = SWDeviceLifetimeMax;
    HSWDEVICE Parent, Child = NULL, Device;
    WCHAR Found[MAX_DEVICE_ID_LEN];
    GUID ParentContainer, Container;
    HRESULT hr;

    hr = CreateBelow(L"", TEST_ENUMERATOR, L"NoParent", SWDeviceCapabilitiesSilentInstall, NULL, State, &Device);
    ok(hr == E_INVALIDARG, "SwDeviceCreate below an empty parent returned 0x%08lx\n", hr);
    if (SUCCEEDED(hr))
        SwDeviceClose(Device);

    hr = Create(L"Parent", SWDeviceCapabilitiesSilentInstall, NULL, State, &Parent);
    ok(hr == S_OK && State->Result == S_OK, "Creating the parent returned 0x%08lx and reported 0x%08lx\n", hr, State->Result);
    if (FAILED(hr))
        return;

    hr = CreateBelow(ParentId, TEST_ENUMERATOR, L"Child", SWDeviceCapabilitiesSilentInstall, NULL, State, &Child);
    ok(hr == S_OK && State->Result == S_OK, "Creating a device below %S returned 0x%08lx and reported 0x%08lx\n", ParentId, hr, State->Result);
    if (FAILED(hr))
        Child = NULL;
    if (SUCCEEDED(hr) && State->Result == S_OK)
    {
        ok(!_wcsicmp(State->InstanceId, ChildId), "The device below %S is %S\n", ParentId, State->InstanceId);
        ok(GetParentId(ChildId, Found) && !_wcsicmp(Found, ParentId), "The parent of %S is %S\n", ChildId, Found);
        ok(GetContainer(ParentId, &ParentContainer) && GetContainer(ChildId, &Container) && IsEqualGUID(&Container, &ParentContainer),
           "%S is in the container {%08lx-...} and its parent in {%08lx-...}\n", ChildId, Container.Data1, ParentContainer.Data1);

        hr = CreateBelow(ParentId, TEST_ENUMERATOR, L"RemovableChild", SWDeviceCapabilitiesSilentInstall | SWDeviceCapabilitiesRemovable,
                         NULL, State, &Device);
        ok(hr == S_OK && State->Result == S_OK, "Creating a removable device below %S returned 0x%08lx and reported 0x%08lx\n",
           ParentId, hr, State->Result);
        if (SUCCEEDED(hr))
        {
            ok(GetContainer(RemovableId, &Container) && !IsEqualGUID(&Container, &ParentContainer),
               "The removable %S is in the container {%08lx-...} of its parent\n", RemovableId, Container.Data1);
            SwDeviceClose(Device);
            ok(WaitGone(RemovableId), "%S stayed after its handle closed\n", RemovableId);
            ok(IsPresent(ParentId) && IsPresent(ChildId), "%S or %S left with the handle of %S\n", ParentId, ChildId, RemovableId);
        }

        hr = CreateBelow(ParentId, TEST_ENUMERATOR, L"KeptChild", SWDeviceCapabilitiesSilentInstall, NULL, State, &Device);
        ok(hr == S_OK && State->Result == S_OK, "Creating a second device below %S returned 0x%08lx and reported 0x%08lx\n",
           ParentId, hr, State->Result);
        if (SUCCEEDED(hr))
        {
            hr = SwDeviceSetLifetime(Device, SWDeviceLifetimeParentPresent);
            ok(hr == S_OK, "SwDeviceSetLifetime returned 0x%08lx\n", hr);
            SwDeviceClose(Device);
            ok(IsPresent(KeptId), "%S with the lifetime of its parent left with its handle\n", KeptId);
        }
    }

    SwDeviceClose(Parent);
    ok(WaitGone(ParentId), "%S stayed after its handle closed\n", ParentId);
    ok(WaitGone(ChildId), "%S stayed after its parent was removed\n", ChildId);
    ok(WaitGone(KeptId), "%S with the lifetime of its parent stayed after its parent was removed\n", KeptId);
    if (Child)
    {
        hr = SwDeviceGetLifetime(Child, &Lifetime);
        ok(hr == S_OK && Lifetime == SWDeviceLifetimeHandle, "The handle of the removed %S answers 0x%08lx, lifetime %d\n", ChildId, hr, Lifetime);
        SwDeviceClose(Child);
    }
}

static BOOL
FindStartedRootDevice(PWSTR InstanceId)
{
    ULONG Status, Problem;
    DEVINST Root, Child;

    if (CM_Locate_DevNodeW(&Root, NULL, CM_LOCATE_DEVNODE_NORMAL) != CR_SUCCESS || CM_Get_Child(&Child, Root, 0) != CR_SUCCESS)
        return FALSE;
    do
    {
        if (CM_Get_Device_IDW(Child, InstanceId, MAX_DEVICE_ID_LEN, 0) == CR_SUCCESS && !_wcsnicmp(InstanceId, L"ROOT\\", 5) &&
            CM_Get_DevNode_Status(&Status, &Problem, Child, 0) == CR_SUCCESS && (Status & DN_STARTED))
        {
            return TRUE;
        }
    } while (CM_Get_Sibling(&Child, Child, 0) == CR_SUCCESS);
    return FALSE;
}

static void
test_RootDeviceParent(CREATED *State)
{
    static const WCHAR InstanceId[] = L"SWD\\" TEST_ENUMERATOR L"\\BelowRootDevice";
    WCHAR Parent[MAX_DEVICE_ID_LEN], Found[MAX_DEVICE_ID_LEN];
    HSWDEVICE Device;
    HRESULT hr;

    if (!FindStartedRootDevice(Parent))
    {
        skip("No started device of the root enumerator\n");
        return;
    }
    hr = CreateBelow(Parent, TEST_ENUMERATOR, L"BelowRootDevice", SWDeviceCapabilitiesSilentInstall, NULL, State, &Device);
    ok(hr == S_OK && State->Result == S_OK, "Creating a device below %S returned 0x%08lx and reported 0x%08lx\n", Parent, hr, State->Result);
    if (FAILED(hr))
        return;
    if (State->Result == S_OK)
        ok(GetParentId(InstanceId, Found) && !_wcsicmp(Found, Parent), "The parent of %S is %S instead of %S\n", InstanceId, Found, Parent);
    SwDeviceClose(Device);
    ok(WaitGone(InstanceId), "%S stayed after its handle closed\n", InstanceId);
    ok(IsPresent(Parent), "%S left with the device below it\n", Parent);
}

/* Windows 11 accepts a parent that is not present, creates the device when the parent arrives and ends the wait when the handle closes */
static void
test_AbsentParent(CREATED *State)
{
    static const WCHAR ParentId[] = L"SWD\\" TEST_ENUMERATOR L"\\LateParent";
    static const WCHAR ChildId[] = L"SWD\\" TEST_ENUMERATOR L"\\Waiting";
    SW_DEVICE_CREATE_INFO Info = { sizeof(Info) };
    WCHAR Found[MAX_DEVICE_ID_LEN];
    HSWDEVICE Parent, Child;
    CREATED Waiting;
    HRESULT hr;

    Info.pszInstanceId = L"Waiting";
    Info.pszzHardwareIds = TEST_HARDWARE_ID;
    Info.pszDeviceDescription = L"LiberNT software device test";
    Info.CapabilityFlags = SWDeviceCapabilitiesSilentInstall;
    ZeroMemory(&Waiting, sizeof(Waiting));
    Waiting.Result = E_PENDING;
    Waiting.Event = CreateEventW(NULL, TRUE, FALSE, NULL);

    hr = SwDeviceCreate(TEST_ENUMERATOR, ParentId, &Info, 0, NULL, Created, &Waiting, &Child);
    ok(hr == S_OK, "SwDeviceCreate below a parent that is not present returned 0x%08lx\n", hr);
    if (SUCCEEDED(hr))
    {
        ok(WaitForSingleObject(Waiting.Event, 2000) == WAIT_TIMEOUT, "The creation below a parent that is not present reported 0x%08lx\n",
           Waiting.Result);
        ok(!IsPresent(ChildId), "%S is present without its parent\n", ChildId);

        hr = Create(L"LateParent", SWDeviceCapabilitiesSilentInstall, NULL, State, &Parent);
        ok(hr == S_OK && State->Result == S_OK, "Creating the parent returned 0x%08lx and reported 0x%08lx\n", hr, State->Result);
        if (SUCCEEDED(hr))
        {
            ok(WaitForSingleObject(Waiting.Event, 30000) == WAIT_OBJECT_0, "%S was not created after its parent arrived\n", ChildId);
            ok(Waiting.Result == S_OK && !_wcsicmp(Waiting.InstanceId, ChildId), "The creation after the parent arrived reported 0x%08lx, %S\n",
               Waiting.Result, Waiting.InstanceId);
            ok(GetParentId(ChildId, Found) && !_wcsicmp(Found, ParentId), "The parent of %S is %S\n", ChildId, Found);
        }
        SwDeviceClose(Child);
        ok(WaitGone(ChildId), "%S stayed after its handle closed\n", ChildId);
        if (SUCCEEDED(hr))
        {
            SwDeviceClose(Parent);
            ok(WaitGone(ParentId), "%S stayed after its handle closed\n", ParentId);
        }
    }

    Waiting.Result = E_PENDING;
    ResetEvent(Waiting.Event);
    hr = SwDeviceCreate(TEST_ENUMERATOR, L"SWD\\" TEST_ENUMERATOR L"\\NoSuchParent", &Info, 0, NULL, Created, &Waiting, &Child);
    ok(hr == S_OK, "SwDeviceCreate below a parent that never arrives returned 0x%08lx\n", hr);
    if (SUCCEEDED(hr))
    {
        ok(WaitForSingleObject(Waiting.Event, 2000) == WAIT_TIMEOUT, "The creation below a parent that never arrives reported 0x%08lx\n",
           Waiting.Result);
        SwDeviceClose(Child);
        ok(WaitForSingleObject(Waiting.Event, 10000) == WAIT_OBJECT_0 && Waiting.Result == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED),
           "Closing the handle of a creation that waits for its parent reported 0x%08lx\n", Waiting.Result);
        ok(!IsPresent(ChildId), "%S is present without its parent\n", ChildId);
    }
    CloseHandle(Waiting.Event);
}

static void
RunChild(void)
{
    CREATED State;
    HSWDEVICE Device;

    State.Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (SUCCEEDED(Create(L"ProcessEnd", SWDeviceCapabilitiesSilentInstall, NULL, &State, &Device)) &&
        State.Result == S_OK)
    {
        ExitProcess(0);
    }
    ExitProcess(1);
}

static BOOL
StartChild(PCWSTR Mode, PROCESS_INFORMATION *Process)
{
    WCHAR Path[MAX_PATH], CommandLine[MAX_PATH + 32];
    STARTUPINFOW Startup = { sizeof(Startup) };

    GetModuleFileNameW(NULL, Path, ARRAYSIZE(Path));
    _snwprintf(CommandLine, ARRAYSIZE(CommandLine), L"\"%s\" SwDevice %s", Path, Mode);
    if (!CreateProcessW(Path, CommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &Startup, Process))
    {
        skip("CreateProcessW failed (%lu)\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

static void
test_ProcessEnd(void)
{
    WCHAR InstanceId[] = L"SWD\\" TEST_ENUMERATOR L"\\ProcessEnd";
    PROCESS_INFORMATION Process;
    DWORD ExitCode = 1;

    if (!StartChild(L"child", &Process))
        return;
    WaitForSingleObject(Process.hProcess, 60000);
    GetExitCodeProcess(Process.hProcess, &ExitCode);
    CloseHandle(Process.hThread);
    CloseHandle(Process.hProcess);
    ok(ExitCode == 0, "The child failed to create its device\n");
    if (ExitCode == 0)
        ok(WaitGone(InstanceId), "%S stayed after the process holding its handle ended\n", InstanceId);
}

/* Holds a device below a parent of the test until the test ends this process */
static void
RunOwnerChild(void)
{
    HANDLE Ready = OpenEventW(EVENT_MODIFY_STATE, FALSE, OWNER_READY_EVENT);
    CREATED State;
    HSWDEVICE Device;

    State.Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (Ready && SUCCEEDED(CreateBelow(OWNER_PARENT_ID, TEST_ENUMERATOR, L"Replaced", SWDeviceCapabilitiesSilentInstall, NULL, &State, &Device)) &&
        State.Result == S_OK)
    {
        SetEvent(Ready);
        Sleep(INFINITE);
    }
    ExitProcess(1);
}

/* The end of a process must not take a device that was created with the instance ID of a device the process had owned */
static void
test_OwnerReplaced(CREATED *State)
{
    static const WCHAR ReplacedId[] = L"SWD\\" TEST_ENUMERATOR L"\\Replaced";
    HANDLE Ready = CreateEventW(NULL, TRUE, FALSE, OWNER_READY_EVENT), Wait[2];
    PROCESS_INFORMATION Process;
    DEVINST Root, DevInst;
    HSWDEVICE Parent, Device;
    CONFIGRET Cr;
    HRESULT hr;

    hr = Create(L"OwnerParent", SWDeviceCapabilitiesSilentInstall, NULL, State, &Parent);
    ok(hr == S_OK && State->Result == S_OK, "Creating the parent returned 0x%08lx and reported 0x%08lx\n", hr, State->Result);
    if (FAILED(hr) || !StartChild(L"owner", &Process))
    {
        if (SUCCEEDED(hr))
            SwDeviceClose(Parent);
        CloseHandle(Ready);
        return;
    }
    Wait[0] = Ready;
    Wait[1] = Process.hProcess;
    ok(WaitForMultipleObjects(2, Wait, FALSE, 60000) == WAIT_OBJECT_0, "The child failed to create %S\n", ReplacedId);

    SwDeviceClose(Parent);
    ok(WaitGone(OWNER_PARENT_ID), "%S stayed after its handle closed\n", OWNER_PARENT_ID);
    ok(WaitGone(ReplacedId), "%S stayed after its parent was removed\n", ReplacedId);

    Cr = CM_Locate_DevNodeW(&Root, NULL, CM_LOCATE_DEVNODE_NORMAL);
    if (Cr == CR_SUCCESS)
        Cr = CM_Create_DevNodeW(&DevInst, (DEVINSTID_W)ReplacedId, Root, CM_CREATE_DEVNODE_NORMAL | CM_CREATE_DEVNODE_DO_NOT_INSTALL);
    if (Cr != CR_SUCCESS)
        skip("CM_Create_DevNodeW cannot create %S (CR %lu)\n", ReplacedId, Cr);
    else
        ok(IsPresent(ReplacedId), "%S is not present after CM_Create_DevNodeW\n", ReplacedId);

    TerminateProcess(Process.hProcess, 0);
    WaitForSingleObject(Process.hProcess, 30000);
    CloseHandle(Process.hThread);
    CloseHandle(Process.hProcess);
    CloseHandle(Ready);
    if (Cr != CR_SUCCESS)
        return;

    Sleep(3000);
    ok(IsPresent(ReplacedId), "%S left when the process that had owned a device of that instance ID ended\n", ReplacedId);

    hr = Create(L"Replaced", SWDeviceCapabilitiesSilentInstall, NULL, State, &Device);
    ok(hr == S_OK && State->Result == S_OK, "Taking over %S returned 0x%08lx and reported 0x%08lx\n", ReplacedId, hr, State->Result);
    if (SUCCEEDED(hr))
        SwDeviceClose(Device);
    ok(WaitGone(ReplacedId), "%S stayed after its handle closed\n", ReplacedId);
}

typedef struct _CLOSE_LATER
{
    HSWDEVICE Device;
    DWORD Delay;
} CLOSE_LATER;

static DWORD WINAPI
CloseLater(PVOID Parameter)
{
    CLOSE_LATER *Close = Parameter;

    Sleep(Close->Delay);
    SwDeviceClose(Close->Device);
    return 0;
}

/* Windows 11 either creates the device before its parent leaves, and removes it with the parent, or keeps the creation waiting for the parent */
static void
test_ParentRemovalRace(CREATED *State)
{
    static const WCHAR ParentId[] = L"SWD\\" TEST_ENUMERATOR L"\\RaceParent";
    static const WCHAR ChildId[] = L"SWD\\" TEST_ENUMERATOR L"\\RaceChild";
    SW_DEVICE_CREATE_INFO Info = { sizeof(Info) };
    CLOSE_LATER Close;
    CREATED Racing;
    HSWDEVICE Child;
    HANDLE Thread;
    BOOL Reported;
    HRESULT hr;
    ULONG i;

    Info.pszInstanceId = L"RaceChild";
    Info.pszzHardwareIds = TEST_HARDWARE_ID;
    Info.pszDeviceDescription = L"LiberNT software device test";
    Info.CapabilityFlags = SWDeviceCapabilitiesSilentInstall;
    ZeroMemory(&Racing, sizeof(Racing));
    Racing.Event = CreateEventW(NULL, TRUE, FALSE, NULL);

    for (i = 0; i < 10; i++)
    {
        hr = Create(L"RaceParent", SWDeviceCapabilitiesSilentInstall, NULL, State, &Close.Device);
        ok(hr == S_OK && State->Result == S_OK, "Creating the parent returned 0x%08lx and reported 0x%08lx\n", hr, State->Result);
        if (FAILED(hr))
            break;

        Close.Delay = 2 * i * i;
        Racing.Result = E_PENDING;
        ResetEvent(Racing.Event);
        Thread = CreateThread(NULL, 0, CloseLater, &Close, 0, NULL);
        hr = SwDeviceCreate(TEST_ENUMERATOR, ParentId, &Info, 0, NULL, Created, &Racing, &Child);
        ok(hr == S_OK, "SwDeviceCreate below a parent that leaves after %lu ms returned 0x%08lx\n", Close.Delay, hr);
        WaitForSingleObject(Thread, INFINITE);
        CloseHandle(Thread);
        ok(WaitGone(ParentId), "%S stayed after its handle closed\n", ParentId);
        if (FAILED(hr))
            continue;

        Reported = WaitForSingleObject(Racing.Event, 2000) == WAIT_OBJECT_0;
        ok(!Reported || Racing.Result == S_OK, "The creation below a parent that left after %lu ms reported 0x%08lx\n", Close.Delay, Racing.Result);
        ok(WaitGone(ChildId), "%S stayed after its parent left %lu ms into its creation\n", ChildId, Close.Delay);
        SwDeviceClose(Child);
        if (!Reported)
        {
            ok(WaitForSingleObject(Racing.Event, 10000) == WAIT_OBJECT_0 && Racing.Result == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED),
               "Closing the handle of a creation that lost its parent after %lu ms reported 0x%08lx\n", Close.Delay, Racing.Result);
        }
        ok(!IsPresent(ChildId), "%S is present without its parent\n", ChildId);
    }
    CloseHandle(Racing.Event);
}

START_TEST(SwDevice)
{
    CREATED State;
    char **argv;

    if (winetest_get_mainargs(&argv) >= 3 && !strcmp(argv[2], "child"))
        RunChild();
    if (winetest_get_mainargs(&argv) >= 3 && !strcmp(argv[2], "owner"))
        RunOwnerChild();

    State.Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    test_Lifetime(&State);
    test_SimilarIds(&State);
    test_DriverRequired(&State);
    test_DriverRequiredNoIds(&State);
    test_Capabilities(&State);
    test_Parent(&State);
    test_RootDeviceParent(&State);
    test_AbsentParent(&State);
    test_CallbackOutsideModule();
    test_CallbackInMappedCode(&State);
    test_CloseInCallback(&State);
    test_SecurityDescriptor(&State);
    test_PropertyCountOverflow(&State);
    test_Interface(&State);
    test_InterfaceState(&State);
    test_DevNodeProperty(&State);
    test_ProcessEnd();
    test_OwnerReplaced(&State);
    test_ParentRemovalRace(&State);
    CloseHandle(State.Event);
}
