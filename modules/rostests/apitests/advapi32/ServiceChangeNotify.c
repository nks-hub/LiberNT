/*
 * PROJECT:     LiberNT API Tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Tests for service manager change notifications and subscriptions
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include "precomp.h"
#include <tlhelp32.h>
#include "svchlp.h"

#define TEST_SERVICE L"LntChangeNotifyTest"

typedef VOID (CALLBACK *PFN_SC_CALLBACK)(DWORD, PVOID);
typedef DWORD (WINAPI *PFN_SUBSCRIBE)(SC_HANDLE, SC_EVENT_TYPE, PFN_SC_CALLBACK, PVOID, PSC_NOTIFICATION_REGISTRATION *);
typedef VOID (WINAPI *PFN_UNSUBSCRIBE)(PSC_NOTIFICATION_REGISTRATION);

static PFN_SUBSCRIBE pSubscribe;
static PFN_UNSUBSCRIBE pUnsubscribe;
static volatile LONG Callbacks;
static HANDLE NotifyEvent;

static VOID CALLBACK
DatabaseChanged(DWORD Notify, PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    trace("Subscription callback 0x%lx\n", Notify);
    InterlockedIncrement(&Callbacks);
    SetEvent(NotifyEvent);
}

static SC_HANDLE
CreateTestService(SC_HANDLE Manager)
{
    WCHAR Path[MAX_PATH];

    GetSystemDirectoryW(Path, ARRAYSIZE(Path));
    StringCchCatW(Path, ARRAYSIZE(Path), L"\\svchost.exe");
    return CreateServiceW(Manager, TEST_SERVICE, TEST_SERVICE, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                          SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, Path, NULL, NULL, NULL, NULL, NULL);
}

static BOOL
WaitCallback(void)
{
    DWORD Start = GetTickCount();

    while (!Callbacks && GetTickCount() - Start < 10000)
        WaitForSingleObject(NotifyEvent, 500);
    return Callbacks != 0;
}

static void
test_Subscribe(SC_HANDLE Manager)
{
    PSC_NOTIFICATION_REGISTRATION Subscription = NULL;
    SC_HANDLE Service, Minimal;
    DWORD Error, i;

    Error = pSubscribe(Manager, SC_EVENT_DATABASE_CHANGE, DatabaseChanged, NULL, &Subscription);
    ok(Error == ERROR_SUCCESS, "SubscribeServiceChangeNotifications returned %lu\n", Error);
    if (Error != ERROR_SUCCESS)
        return;

    Callbacks = 0;
    Service = CreateTestService(Manager);
    ok(Service != NULL, "CreateServiceW failed (%lu)\n", GetLastError());
    if (Service)
    {
        ok(WaitCallback(), "No callback for the created service\n");

        Callbacks = 0;
        ok(DeleteService(Service), "DeleteService failed (%lu)\n", GetLastError());
        CloseServiceHandle(Service);
        ok(WaitCallback(), "No callback for the deleted service\n");
    }
    pUnsubscribe(Subscription);

    for (i = 0; i < 5; i++)
    {
        Error = pSubscribe(Manager, SC_EVENT_DATABASE_CHANGE, DatabaseChanged, NULL, &Subscription);
        ok(Error == ERROR_SUCCESS, "Subscription %lu returned %lu\n", i, Error);
        if (Error == ERROR_SUCCESS)
            pUnsubscribe(Subscription);
    }

    Minimal = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    ok(Minimal != NULL, "OpenSCManagerW failed (%lu)\n", GetLastError());
    if (Minimal)
    {
        Error = pSubscribe(Minimal, SC_EVENT_DATABASE_CHANGE, DatabaseChanged, NULL, &Subscription);
        ok(Error == ERROR_SUCCESS, "Subscription with SC_MANAGER_ENUMERATE_SERVICE returned %lu\n", Error);
        if (Error == ERROR_SUCCESS)
        {
            Callbacks = 0;
            Service = CreateTestService(Manager);
            if (Service)
            {
                ok(WaitCallback(), "No callback through the minimal handle\n");
                DeleteService(Service);
                CloseServiceHandle(Service);
            }
            pUnsubscribe(Subscription);
        }
        CloseServiceHandle(Minimal);
    }
}

static ULONG
CountThreads(void)
{
    THREADENTRY32 Entry = { sizeof(Entry) };
    HANDLE Snapshot;
    ULONG Count = 0;

    Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (Snapshot == INVALID_HANDLE_VALUE)
        return 0;
    if (Thread32First(Snapshot, &Entry))
    {
        do
        {
            if (Entry.th32OwnerProcessID == GetCurrentProcessId())
                Count++;
        } while (Thread32Next(Snapshot, &Entry));
    }
    CloseHandle(Snapshot);
    return Count;
}

static void
test_SubscribeCleanup(SC_HANDLE Manager)
{
    PSC_NOTIFICATION_REGISTRATION Subscription = NULL;
    ULONG Before, After, i;
    DWORD Error;

    Before = CountThreads();
    for (i = 0; i < 8; i++)
    {
        Error = pSubscribe(Manager, SC_EVENT_DATABASE_CHANGE, DatabaseChanged, NULL, &Subscription);
        ok(Error == ERROR_SUCCESS, "Subscription %lu returned %lu\n", i, Error);
        if (Error == ERROR_SUCCESS)
            pUnsubscribe(Subscription);
    }
    Sleep(8000);
    After = CountThreads();
    trace("Threads before %lu, after 8 subscriptions %lu\n", Before, After);
    ok(After < Before + 4, "8 ended subscriptions left %lu threads\n", After - Before);
}

/* A request ends without a result when its handle is closed */
static void
test_SubscribeHandleClosed(void)
{
    PSC_NOTIFICATION_REGISTRATION Subscriptions[8] = { NULL };
    SC_HANDLE Managers[8] = { NULL };
    ULONG Before, After, i;
    DWORD Error, Start;

    Before = CountThreads();
    for (i = 0; i < 8; i++)
    {
        Managers[i] = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
        ok(Managers[i] != NULL, "OpenSCManagerW %lu failed (%lu)\n", i, GetLastError());
        if (!Managers[i])
            continue;
        Error = pSubscribe(Managers[i], SC_EVENT_DATABASE_CHANGE, DatabaseChanged, NULL, &Subscriptions[i]);
        ok(Error == ERROR_SUCCESS, "Subscription %lu returned %lu\n", i, Error);
        if (Error != ERROR_SUCCESS)
            Subscriptions[i] = NULL;
    }
    for (i = 0; i < 8; i++)
    {
        if (Managers[i])
            CloseServiceHandle(Managers[i]);
    }

    for (Start = GetTickCount(); (After = CountThreads()) >= Before + 4 && GetTickCount() - Start < 15000; )
        Sleep(500);
    trace("Threads before %lu, after 8 subscriptions lost their handles %lu\n", Before, After);
    ok(After < Before + 4, "8 subscriptions whose handles were closed left %lu threads\n", After - Before);

    for (i = 0; i < 8; i++)
    {
        if (Subscriptions[i])
            pUnsubscribe(Subscriptions[i]);
    }
}

static volatile BOOL ApcFired;

static VOID CALLBACK
IgnoreNotify(PVOID Parameter)
{
    UNREFERENCED_PARAMETER(Parameter);
}

static void
test_Masks(SC_HANDLE Manager)
{
    SERVICE_NOTIFYW Notify = { SERVICE_NOTIFY_STATUS_CHANGE };
    SC_HANDLE Own, Service;
    DWORD Error;

    Notify.pfnNotifyCallback = IgnoreNotify;
    Own = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (Own)
    {
        Error = NotifyServiceStatusChangeW(Own, SERVICE_NOTIFY_CREATED | SERVICE_NOTIFY_RUNNING, &Notify);
        ok(Error == ERROR_INVALID_PARAMETER, "Mixed mask on a manager handle returned %lu\n", Error);
        Error = NotifyServiceStatusChangeW(Own, SERVICE_NOTIFY_RUNNING, &Notify);
        ok(Error == ERROR_INVALID_HANDLE, "State mask on a manager handle returned %lu\n", Error);
        Error = NotifyServiceStatusChangeW(Own, 0x00010000, &Notify);
        ok(Error == ERROR_INVALID_PARAMETER, "Unknown mask on a manager handle returned %lu\n", Error);
        Error = NotifyServiceStatusChangeW(Own, SERVICE_NOTIFY_CREATED | 0x00010000, &Notify);
        ok(Error == ERROR_SUCCESS, "Database mask with an unknown bit on a manager handle returned %lu\n", Error);
        CloseServiceHandle(Own);
    }

    Service = CreateTestService(Manager);
    ok(Service != NULL, "CreateServiceW failed (%lu)\n", GetLastError());
    if (Service)
    {
        Error = NotifyServiceStatusChangeW(Service, SERVICE_NOTIFY_CREATED, &Notify);
        ok(Error == ERROR_INVALID_HANDLE, "Database mask on a service handle returned %lu\n", Error);
        Error = NotifyServiceStatusChangeW(Service, SERVICE_NOTIFY_DELETED | SERVICE_NOTIFY_RUNNING, &Notify);
        ok(Error == ERROR_INVALID_PARAMETER, "Mixed mask on a service handle returned %lu\n", Error);
        Error = NotifyServiceStatusChangeW(Service, 0x00010000, &Notify);
        ok(Error == ERROR_INVALID_PARAMETER, "Unknown mask on a service handle returned %lu\n", Error);
        Error = NotifyServiceStatusChangeW(Service, SERVICE_NOTIFY_RUNNING | 0x00010000, &Notify);
        ok(Error == ERROR_SUCCESS, "State mask with an unknown bit on a service handle returned %lu\n", Error);
        DeleteService(Service);
        CloseServiceHandle(Service);
    }
    SleepEx(0, TRUE);
}

static VOID CALLBACK
ManagerNotified(PVOID Parameter)
{
    UNREFERENCED_PARAMETER(Parameter);
    ApcFired = TRUE;
}

static void
test_ServiceNames(void)
{
    SERVICE_NOTIFYW Notify = { SERVICE_NOTIFY_STATUS_CHANGE };
    SC_HANDLE Manager, Service;
    DWORD Error, Start;

    Manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!Manager)
        return;
    Notify.pfnNotifyCallback = ManagerNotified;
    ApcFired = FALSE;
    Error = NotifyServiceStatusChangeW(Manager, SERVICE_NOTIFY_CREATED, &Notify);
    ok(Error == ERROR_SUCCESS, "NotifyServiceStatusChangeW returned %lu\n", Error);
    if (Error == ERROR_SUCCESS)
    {
        Service = CreateTestService(Manager);
        ok(Service != NULL, "CreateServiceW failed (%lu)\n", GetLastError());
        for (Start = GetTickCount(); !ApcFired && GetTickCount() - Start < 10000; )
            SleepEx(500, TRUE);
        ok(ApcFired, "The notification did not come\n");
        if (ApcFired)
        {
            ok(Notify.dwNotificationTriggered & SERVICE_NOTIFY_CREATED, "Triggered 0x%lx\n",
               Notify.dwNotificationTriggered);
            ok(Notify.pszServiceNames && !_wcsicmp(Notify.pszServiceNames, L"/" TEST_SERVICE),
               "Service names %S\n", Notify.pszServiceNames ? Notify.pszServiceNames : L"(null)");
            if (Notify.pszServiceNames)
                LocalFree(Notify.pszServiceNames);
        }
        if (Service)
        {
            DeleteService(Service);
            CloseServiceHandle(Service);
        }
    }
    CloseServiceHandle(Manager);
}

static void
test_ServiceNamesA(void)
{
    SERVICE_NOTIFYA Notify = { SERVICE_NOTIFY_STATUS_CHANGE };
    SC_HANDLE Manager, Service;
    DWORD Error, Start;

    Manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!Manager)
        return;
    for (Start = GetTickCount(); GetTickCount() - Start < 5000; Sleep(50))
    {
        Service = OpenServiceW(Manager, TEST_SERVICE, SERVICE_QUERY_STATUS);
        if (!Service)
            break;
        CloseServiceHandle(Service);
    }
    Notify.pfnNotifyCallback = ManagerNotified;
    ApcFired = FALSE;
    Error = NotifyServiceStatusChangeA(Manager, SERVICE_NOTIFY_CREATED, &Notify);
    ok(Error == ERROR_SUCCESS, "NotifyServiceStatusChangeA returned %lu\n", Error);
    if (Error == ERROR_SUCCESS)
    {
        Service = CreateTestService(Manager);
        ok(Service != NULL, "CreateServiceW failed (%lu)\n", GetLastError());
        for (Start = GetTickCount(); !ApcFired && GetTickCount() - Start < 10000; )
            SleepEx(500, TRUE);
        ok(ApcFired, "The notification did not come\n");
        if (ApcFired)
        {
            ok(Notify.dwNotificationTriggered & SERVICE_NOTIFY_CREATED, "Triggered 0x%lx\n",
               Notify.dwNotificationTriggered);
            ok(Notify.pszServiceNames && !_stricmp(Notify.pszServiceNames, "/LntChangeNotifyTest"),
               "Service names %s\n", Notify.pszServiceNames ? Notify.pszServiceNames : "(null)");
            if (Notify.pszServiceNames)
            {
                ok(Notify.pszServiceNames[strlen(Notify.pszServiceNames) + 1] == 0, "The list has no second terminator\n");
                LocalFree(Notify.pszServiceNames);
            }
        }
        if (Service)
        {
            DeleteService(Service);
            CloseServiceHandle(Service);
        }
    }
    CloseServiceHandle(Manager);
}

static volatile LONG StatusApcs;

static VOID CALLBACK
ServiceNotified(PVOID Parameter)
{
    UNREFERENCED_PARAMETER(Parameter);
    InterlockedIncrement(&StatusApcs);
}

static void
test_ServiceStatus(SC_HANDLE Manager)
{
    const DWORD Mask = SERVICE_NOTIFY_RUNNING | SERVICE_NOTIFY_START_PENDING | SERVICE_NOTIFY_STOP_PENDING |
                       SERVICE_NOTIFY_STOPPED | SERVICE_NOTIFY_DELETE_PENDING;
    SERVICE_NOTIFYW Notify;
    SC_HANDLE Service;
    DWORD Error, Start, i;

    Service = CreateTestService(Manager);
    ok(Service != NULL, "CreateServiceW failed (%lu)\n", GetLastError());
    if (!Service)
        return;

    if (pSubscribe && pUnsubscribe)
    {
        PSC_NOTIFICATION_REGISTRATION Subscription = NULL;

        SC_HANDLE StatusOnly;

        Error = pSubscribe(Service, SC_EVENT_STATUS_CHANGE, DatabaseChanged, NULL, &Subscription);
        ok(Error == ERROR_SUCCESS, "Status subscription returned %lu\n", Error);
        if (Error == ERROR_SUCCESS)
            pUnsubscribe(Subscription);

        StatusOnly = OpenServiceW(Manager, TEST_SERVICE, SERVICE_QUERY_STATUS);
        ok(StatusOnly != NULL, "OpenServiceW failed (%lu)\n", GetLastError());
        if (StatusOnly)
        {
            Error = pSubscribe(StatusOnly, SC_EVENT_STATUS_CHANGE, DatabaseChanged, NULL, &Subscription);
            ok(Error == ERROR_SUCCESS, "Status subscription with SERVICE_QUERY_STATUS returned %lu\n", Error);
            if (Error == ERROR_SUCCESS)
                pUnsubscribe(Subscription);
            CloseServiceHandle(StatusOnly);
        }
    }

    for (i = 0; i < 1; i++)
    {
        ZeroMemory(&Notify, sizeof(Notify));
        Notify.dwVersion = SERVICE_NOTIFY_STATUS_CHANGE;
        Notify.pfnNotifyCallback = ServiceNotified;
        StatusApcs = 0;
        Error = NotifyServiceStatusChangeW(Service, Mask, &Notify);
        ok(Error == ERROR_SUCCESS, "Request %lu: NotifyServiceStatusChangeW returned %lu\n", i, Error);
        if (Error != ERROR_SUCCESS)
            break;
        for (Start = GetTickCount(); !StatusApcs && GetTickCount() - Start < 5000; )
            SleepEx(200, TRUE);
        ok(StatusApcs == 1, "Request %lu: %ld results\n", i, StatusApcs);
        ok(Notify.dwNotificationStatus == ERROR_SUCCESS, "Request %lu: status %lu\n", i, Notify.dwNotificationStatus);
        ok(Notify.dwNotificationTriggered == SERVICE_NOTIFY_STOPPED, "Request %lu: triggered 0x%lx\n", i,
           Notify.dwNotificationTriggered);
        ok(Notify.ServiceStatus.dwCurrentState == SERVICE_STOPPED, "Request %lu: state %lu\n", i,
           Notify.ServiceStatus.dwCurrentState);
        ok(Notify.pszServiceNames == NULL, "Request %lu: service names %p\n", i, Notify.pszServiceNames);
    }

    {
        SC_HANDLE Other;

        ZeroMemory(&Notify, sizeof(Notify));
        Notify.dwVersion = SERVICE_NOTIFY_STATUS_CHANGE;
        Notify.pfnNotifyCallback = ServiceNotified;
        StatusApcs = 0;
        Error = NotifyServiceStatusChangeW(Service, SERVICE_NOTIFY_RUNNING, &Notify);
        ok(Error == ERROR_SUCCESS, "Running request: NotifyServiceStatusChangeW returned %lu\n", Error);
        Other = CreateServiceW(Manager, TEST_SERVICE L"2", TEST_SERVICE L"2", SERVICE_ALL_ACCESS,
                               SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
                               L"C:\\Windows\\system32\\svchost.exe", NULL, NULL, NULL, NULL, NULL);
        ok(Other != NULL, "CreateServiceW failed (%lu)\n", GetLastError());
        SleepEx(1000, TRUE);
        ok(StatusApcs == 0, "Creating another service ended the request: status %lu, triggered 0x%lx\n",
           Notify.dwNotificationStatus, Notify.dwNotificationTriggered);
        if (Other)
        {
            DeleteService(Other);
            CloseServiceHandle(Other);
        }
        SleepEx(500, TRUE);
        ok(StatusApcs == 0, "Deleting another service ended the request: status %lu, triggered 0x%lx\n",
           Notify.dwNotificationStatus, Notify.dwNotificationTriggered);
    }

    ZeroMemory(&Notify, sizeof(Notify));
    Notify.dwVersion = SERVICE_NOTIFY_STATUS_CHANGE;
    Notify.pfnNotifyCallback = ServiceNotified;
    StatusApcs = 0;
    Error = NotifyServiceStatusChangeW(Service, SERVICE_NOTIFY_DELETE_PENDING, &Notify);
    ok(Error == ERROR_SUCCESS, "Delete request: NotifyServiceStatusChangeW returned %lu\n", Error);
    ok(DeleteService(Service), "DeleteService failed (%lu)\n", GetLastError());
    if (Error == ERROR_SUCCESS)
    {
        for (Start = GetTickCount(); !StatusApcs && GetTickCount() - Start < 5000; )
            SleepEx(200, TRUE);
        ok(StatusApcs == 1, "Delete request: %ld results\n", StatusApcs);
        ok(Notify.dwNotificationTriggered == SERVICE_NOTIFY_DELETE_PENDING, "Delete request: triggered 0x%lx\n",
           Notify.dwNotificationTriggered);
    }
    Error = NotifyServiceStatusChangeW(Service, Mask, &Notify);
    ok(Error == ERROR_SERVICE_MARKED_FOR_DELETE, "Request after delete returned %lu\n", Error);
    CloseServiceHandle(Service);
}

static SERVICE_STATUS_HANDLE StatusHandle;
static HANDLE StopEvent;

static VOID
ReportState(DWORD State)
{
    SERVICE_STATUS Status = { 0 };

    Status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    Status.dwCurrentState = State;
    if (State == SERVICE_RUNNING)
        Status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    SetServiceStatus(StatusHandle, &Status);
}

static VOID WINAPI
ServiceHandler(DWORD Control)
{
    if (Control == SERVICE_CONTROL_STOP)
        SetEvent(StopEvent);
}

static VOID WINAPI
ServiceMain(DWORD Argc, LPWSTR *Argv)
{
    UNREFERENCED_PARAMETER(Argc);

    StopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    StatusHandle = RegisterServiceCtrlHandlerW(Argv[0], ServiceHandler);
    if (!StatusHandle)
        return;
    ReportState(SERVICE_RUNNING);
    WaitForSingleObject(StopEvent, 60000);
    ReportState(SERVICE_STOPPED);
}

static BOOL
StartTestService(PCSTR NameA, PCWSTR NameW)
{
    SERVICE_TABLE_ENTRYW Table[] = { { (PWSTR)NameW, ServiceMain }, { NULL, NULL } };

    UNREFERENCED_PARAMETER(NameA);
    return StartServiceCtrlDispatcherW(Table);
}

static HANDLE GateEvent;
static volatile LONG StatusCalls, RunningSeen;

static VOID CALLBACK
StatusChanged(DWORD Notify, PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    trace("Status callback 0x%lx\n", Notify);
    if (Notify & SERVICE_NOTIFY_RUNNING)
        InterlockedExchange(&RunningSeen, 1);
    if (InterlockedIncrement(&StatusCalls) == 1)
        WaitForSingleObject(GateEvent, 30000);
}

static BOOL
WaitState(SC_HANDLE Service, DWORD State)
{
    SERVICE_STATUS Status = { 0 };
    DWORD Start = GetTickCount();

    while (QueryServiceStatus(Service, &Status) && Status.dwCurrentState != State && GetTickCount() - Start < 10000)
        Sleep(100);
    return Status.dwCurrentState == State;
}

/* The service is already running when the callback for an earlier change returns */
static void
test_ChangeDuringCallback(PCSTR NameA, PCWSTR NameW, void *Param)
{
    PSC_NOTIFICATION_REGISTRATION Subscription = NULL;
    SC_HANDLE Manager, Service;
    SERVICE_STATUS Status;
    DWORD Error, Start;

    UNREFERENCED_PARAMETER(NameA);
    UNREFERENCED_PARAMETER(Param);

    Manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!Manager)
    {
        skip("Cannot open the service manager (%lu)\n", GetLastError());
        return;
    }
    Service = register_serviceW(Manager, L"ServiceChangeNotify", NameW, NULL);
    if (!Service)
    {
        skip("Cannot create the test service (%lu)\n", GetLastError());
        CloseServiceHandle(Manager);
        return;
    }

    GateEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    Error = pSubscribe(Service, SC_EVENT_STATUS_CHANGE, StatusChanged, NULL, &Subscription);
    ok(Error == ERROR_SUCCESS, "Status subscription returned %lu\n", Error);
    if (Error == ERROR_SUCCESS)
    {
        ok(StartServiceW(Service, 0, NULL), "StartServiceW failed (%lu)\n", GetLastError());
        ok(WaitState(Service, SERVICE_RUNNING), "The service is not running\n");
        for (Start = GetTickCount(); !StatusCalls && GetTickCount() - Start < 5000; )
            Sleep(50);
        ok(StatusCalls != 0, "No callback for the started service\n");

        SetEvent(GateEvent);
        for (Start = GetTickCount(); !RunningSeen && GetTickCount() - Start < 5000; )
            Sleep(50);
        ok(RunningSeen, "No callback for SERVICE_RUNNING after %ld callbacks\n", StatusCalls);

        ControlService(Service, SERVICE_CONTROL_STOP, &Status);
        ok(WaitState(Service, SERVICE_STOPPED), "The service did not stop\n");
        pUnsubscribe(Subscription);
    }

    CloseHandle(GateEvent);
    DeleteService(Service);
    CloseServiceHandle(Service);
    CloseServiceHandle(Manager);
}

static volatile LONG DatabaseCalls, DatabaseSeen;

static VOID CALLBACK
DatabaseChangedGated(DWORD Notify, PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    trace("Database callback 0x%lx\n", Notify);
    InterlockedOr(&DatabaseSeen, Notify);
    if (InterlockedIncrement(&DatabaseCalls) == 1)
        WaitForSingleObject(GateEvent, 30000);
}

/* A second service is created before the callback for the first one returns */
static void
test_DatabaseChangeDuringCallback(SC_HANDLE Manager)
{
    PSC_NOTIFICATION_REGISTRATION Subscription = NULL;
    SC_HANDLE First, Second;
    WCHAR Path[MAX_PATH];
    DWORD Error, Start;

    /* A service deleted by an earlier test is reported when its last handle goes, which can be later */
    for (Start = GetTickCount(); GetTickCount() - Start < 5000; Sleep(50))
    {
        First = OpenServiceW(Manager, TEST_SERVICE, SERVICE_QUERY_STATUS);
        if (!First)
            break;
        CloseServiceHandle(First);
    }
    ok(GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST, "The test service of an earlier test is still there (%lu)\n", GetLastError());

    GateEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    DatabaseCalls = 0;
    DatabaseSeen = 0;
    Error = pSubscribe(Manager, SC_EVENT_DATABASE_CHANGE, DatabaseChangedGated, NULL, &Subscription);
    ok(Error == ERROR_SUCCESS, "Database subscription returned %lu\n", Error);
    if (Error != ERROR_SUCCESS)
    {
        CloseHandle(GateEvent);
        return;
    }

    First = CreateTestService(Manager);
    ok(First != NULL, "CreateServiceW failed (%lu)\n", GetLastError());
    for (Start = GetTickCount(); !DatabaseCalls && GetTickCount() - Start < 5000; )
        Sleep(50);
    ok(DatabaseCalls != 0, "No callback for the first service\n");

    GetSystemDirectoryW(Path, ARRAYSIZE(Path));
    StringCchCatW(Path, ARRAYSIZE(Path), L"\\svchost.exe");
    Second = CreateServiceW(Manager, TEST_SERVICE L"2", TEST_SERVICE L"2", SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                            SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, Path, NULL, NULL, NULL, NULL, NULL);
    ok(Second != NULL, "CreateServiceW failed (%lu)\n", GetLastError());

    SetEvent(GateEvent);
    for (Start = GetTickCount(); DatabaseCalls < 2 && GetTickCount() - Start < 5000; )
        Sleep(50);
    ok(DatabaseCalls >= 2, "No callback for the second service after %ld callbacks\n", DatabaseCalls);
    ok(!(DatabaseSeen & SERVICE_NOTIFY_DELETED), "A deleted service was reported (0x%lx), none was deleted\n", DatabaseSeen);

    pUnsubscribe(Subscription);
    if (First)
    {
        DeleteService(First);
        CloseServiceHandle(First);
    }
    if (Second)
    {
        DeleteService(Second);
        CloseServiceHandle(Second);
    }
    CloseHandle(GateEvent);
}

START_TEST(ServiceChangeNotify)
{
    HMODULE hSechost = LoadLibraryW(L"sechost.dll");
    SC_HANDLE Manager, Service;
    char **Argv;
    int Argc = winetest_get_mainargs(&Argv);

    if (Argc >= 3)
    {
        service_process(StartTestService, Argc, Argv);
        return;
    }

    pSubscribe = hSechost ? (PFN_SUBSCRIBE)GetProcAddress(hSechost, "SubscribeServiceChangeNotifications") : NULL;
    pUnsubscribe = hSechost ? (PFN_UNSUBSCRIBE)GetProcAddress(hSechost, "UnsubscribeServiceChangeNotifications") : NULL;

    Manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!Manager)
    {
        skip("Cannot open the service manager (%lu)\n", GetLastError());
        return;
    }

    Service = OpenServiceW(Manager, TEST_SERVICE, DELETE);
    if (Service)
    {
        DeleteService(Service);
        CloseServiceHandle(Service);
    }

    NotifyEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (pSubscribe && pUnsubscribe)
    {
        test_Subscribe(Manager);
        test_SubscribeCleanup(Manager);
        test_SubscribeHandleClosed();
        test_runner(test_ChangeDuringCallback, NULL);
        test_DatabaseChangeDuringCallback(Manager);
    }
    else
        skip("SubscribeServiceChangeNotifications is missing\n");
    test_ServiceNames();
    test_ServiceNamesA();
    test_ServiceStatus(Manager);
    test_Masks(Manager);

    CloseHandle(NotifyEvent);
    CloseServiceHandle(Manager);
}
