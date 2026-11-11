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

#define TEST_ENUMERATOR L"LntSwTest"
#define TEST_HARDWARE_ID L"LntSwTestNoDriver\0"

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
Create(PCWSTR Instance, ULONG Capabilities, PSECURITY_DESCRIPTOR Security, CREATED *State, HSWDEVICE *Device)
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
    hr = SwDeviceCreate(TEST_ENUMERATOR, L"HTREE\\ROOT\\0", &Info, 0, NULL, Created, State, Device);
    if (SUCCEEDED(hr) && WaitForSingleObject(State->Event, 30000) != WAIT_OBJECT_0)
        hr = HRESULT_FROM_WIN32(WAIT_TIMEOUT);
    return hr;
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

static void
test_DevNodeProperty(CREATED *State)
{
    static const DEVPROPKEY Key = { { 0x4c6e7453, 0x7754, 0x4465, { 0x76, 0x69, 0x63, 0x65, 0x54, 0x65, 0x73, 0x74 } }, 4 };
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

Done:
    SwDeviceClose(Device);
    WaitGone(State->InstanceId);
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

static void
test_ProcessEnd(void)
{
    WCHAR Path[MAX_PATH], CommandLine[MAX_PATH + 32];
    WCHAR InstanceId[] = L"SWD\\" TEST_ENUMERATOR L"\\ProcessEnd";
    STARTUPINFOW Startup = { sizeof(Startup) };
    PROCESS_INFORMATION Process;
    DWORD ExitCode = 1;

    GetModuleFileNameW(NULL, Path, ARRAYSIZE(Path));
    _snwprintf(CommandLine, ARRAYSIZE(CommandLine), L"\"%s\" SwDevice child", Path);
    if (!CreateProcessW(Path, CommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &Startup, &Process))
    {
        skip("CreateProcessW failed (%lu)\n", GetLastError());
        return;
    }
    WaitForSingleObject(Process.hProcess, 60000);
    GetExitCodeProcess(Process.hProcess, &ExitCode);
    CloseHandle(Process.hThread);
    CloseHandle(Process.hProcess);
    ok(ExitCode == 0, "The child failed to create its device\n");
    if (ExitCode == 0)
        ok(WaitGone(InstanceId), "%S stayed after the process holding its handle ended\n", InstanceId);
}

START_TEST(SwDevice)
{
    CREATED State;
    char **argv;

    if (winetest_get_mainargs(&argv) >= 3 && !strcmp(argv[2], "child"))
        RunChild();

    State.Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    test_Lifetime(&State);
    test_DriverRequired(&State);
    test_DriverRequiredNoIds(&State);
    test_CloseInCallback(&State);
    test_SecurityDescriptor(&State);
    test_PropertyCountOverflow(&State);
    test_Interface(&State);
    test_DevNodeProperty(&State);
    test_ProcessEnd();
    CloseHandle(State.Event);
}
