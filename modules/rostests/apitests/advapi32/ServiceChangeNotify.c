/*
 * PROJECT:     LiberNT API Tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Tests for service manager change notifications and subscriptions
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include "precomp.h"

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

/* Windows passes 0 to the callback, so only the calls count */
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
    SC_HANDLE Service;
    DWORD Error;

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

        /* The service goes away only when its last handle closes */
        Callbacks = 0;
        ok(DeleteService(Service), "DeleteService failed (%lu)\n", GetLastError());
        CloseServiceHandle(Service);
        ok(WaitCallback(), "No callback for the deleted service\n");
    }
    pUnsubscribe(Subscription);

    /* Unsubscribing ends the request, so a new subscription is accepted */
    Error = pSubscribe(Manager, SC_EVENT_DATABASE_CHANGE, DatabaseChanged, NULL, &Subscription);
    ok(Error == ERROR_SUCCESS, "Subscribing again returned %lu\n", Error);
    if (Error == ERROR_SUCCESS)
        pUnsubscribe(Subscription);
}

static volatile BOOL ApcFired;

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

    /* A handle of its own: closing it ends a request that never fires */
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

START_TEST(ServiceChangeNotify)
{
    HMODULE hSechost = LoadLibraryW(L"sechost.dll");
    SC_HANDLE Manager, Service;

    pSubscribe = hSechost ? (PFN_SUBSCRIBE)GetProcAddress(hSechost, "SubscribeServiceChangeNotifications") : NULL;
    pUnsubscribe = hSechost ? (PFN_UNSUBSCRIBE)GetProcAddress(hSechost, "UnsubscribeServiceChangeNotifications") : NULL;

    Manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!Manager)
    {
        skip("Cannot open the service manager (%lu)\n", GetLastError());
        return;
    }

    /* A test service left by an earlier run */
    Service = OpenServiceW(Manager, TEST_SERVICE, DELETE);
    if (Service)
    {
        DeleteService(Service);
        CloseServiceHandle(Service);
    }

    NotifyEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (pSubscribe && pUnsubscribe)
        test_Subscribe(Manager);
    else
        skip("SubscribeServiceChangeNotifications is missing\n");
    test_ServiceNames();

    CloseHandle(NotifyEvent);
    CloseServiceHandle(Manager);
}
