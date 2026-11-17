/*
 * PROJECT:     LiberNT Network Store Interface Service
 * PURPOSE:     Nsi service, running while the network store answers
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 */

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winsvc.h>
#include <ndk/iofuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/rtlfuncs.h>

static SERVICE_STATUS_HANDLE ServiceStatusHandle;
static SERVICE_STATUS ServiceStatus;
static HANDLE StopEvent;

static
VOID
ReportStatus(
    _In_ DWORD State,
    _In_ DWORD ExitCode)
{
    ServiceStatus.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
    ServiceStatus.dwCurrentState = State;
    ServiceStatus.dwControlsAccepted = (State == SERVICE_RUNNING) ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN) : 0;
    ServiceStatus.dwWin32ExitCode = ExitCode;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint = 0;
    ServiceStatus.dwWaitHint = (State == SERVICE_START_PENDING || State == SERVICE_STOP_PENDING) ? 5000 : 0;
    SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
}

static
DWORD
WINAPI
ControlHandler(
    _In_ DWORD Control,
    _In_ DWORD EventType,
    _In_ LPVOID EventData,
    _In_ LPVOID Context)
{
    UNREFERENCED_PARAMETER(EventType);
    UNREFERENCED_PARAMETER(EventData);
    UNREFERENCED_PARAMETER(Context);

    switch (Control)
    {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            ReportStatus(SERVICE_STOP_PENDING, NO_ERROR);
            SetEvent(StopEvent);
            return NO_ERROR;

        case SERVICE_CONTROL_INTERROGATE:
            SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
            return NO_ERROR;

        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

/* nsi.dll reaches the network store through the TCP/IP device, not through an RPC interface of this service */
static
DWORD
CheckNetworkStore(VOID)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Device\\Ip");
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK IoStatus;
    HANDLE File;
    NTSTATUS Status;

    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenFile(&File, SYNCHRONIZE, &Attributes, &IoStatus, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(Status))
        return RtlNtStatusToDosError(Status);

    NtClose(File);
    return NO_ERROR;
}

VOID
WINAPI
ServiceMain(
    _In_ DWORD Argc,
    _In_ LPWSTR *Argv)
{
    DWORD Error;

    UNREFERENCED_PARAMETER(Argc);
    UNREFERENCED_PARAMETER(Argv);

    ServiceStatusHandle = RegisterServiceCtrlHandlerExW(L"Nsi", ControlHandler, NULL);
    if (ServiceStatusHandle == NULL)
        return;

    ReportStatus(SERVICE_START_PENDING, NO_ERROR);

    StopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    Error = (StopEvent != NULL) ? CheckNetworkStore() : GetLastError();
    if (Error != NO_ERROR)
    {
        if (StopEvent != NULL)
        {
            CloseHandle(StopEvent);
            StopEvent = NULL;
        }
        ReportStatus(SERVICE_STOPPED, Error);
        return;
    }

    ReportStatus(SERVICE_RUNNING, NO_ERROR);
    WaitForSingleObject(StopEvent, INFINITE);

    CloseHandle(StopEvent);
    StopEvent = NULL;
    ReportStatus(SERVICE_STOPPED, NO_ERROR);
}
