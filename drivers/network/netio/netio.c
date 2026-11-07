/*
 * PROJECT:     NetIO driver
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     NT6 compatible NETIO.SYS driver: A BSD sockets like kernel
 *              internal interface for networking (TCP/IP, UDP/IP).
 * COPYRIGHT:   Copyright 2023-2025 Johannes Khoshnazar-Thoma <johannes@johannesthoma.com>
 */

/*
Copyright © 2025 Johannes Khoshnazar-Thoma <johannes@johannesthoma.com>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

/*
 * [NETIO] NETIO.SYS driver
 *
 * This files adds the NETIO.SYS driver to ReactOS. It is not
 * feature complete (meaning some functionality is unimplemented)
 * but does its job quite good for what it originally was written
 * for (which is getting WinDRBD working on ReactOS/Windows 2003 SP2).
 *
 * The driver re-uses parts of the AFD.SYS driver, namely those
 * functions that ease communitating with the transport device
 * interface (TDI). Other than that, following features are implemented
 * and should work:
 *
 *     * TCP/IP networking: connect, listen, accept, read, write
 *     * UDP/IP networking: write
 *
 * So in a nutshell TCP/IP support is completed, UDP support is
 * partially complete and ICMP support does not exist yet.
 * In particular the listen/accept mechanism allows one to write
 * kernel side TCP servers that one can connect to via the internet.
 */

#include <ntifs.h>
#include <netiodef.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <wsk.h>
#include <ndis.h>
#include <wdmsec.h>

/* If you want to see the DPRINT() output in your debugger,
 * remove the following line (or comment it out):
 * Note that DPRINT1() is always printed to the debugger. */
#define NDEBUG
#include <reactos/debug.h>

#include <tdi.h>
#include <tcpioctl.h>
#include <tdikrnl.h>
#include <tdiinfo.h>
#include <tdi_proto.h>
#include <tdiconn.h>

#define TAG_NETIO 'OIEN'

#ifndef TAG_AFD_TDI_CONNECTION_INFORMATION
#define TAG_AFD_TDI_CONNECTION_INFORMATION 'cTfA'
#endif

/* AFD Share Flags */
#define AFD_SHARE_UNIQUE    0x0L
#define AFD_SHARE_REUSE     0x1L
#define AFD_SHARE_WILDCARD  0x2L
#define AFD_SHARE_EXCLUSIVE 0x3L

/* Function trace */
// #define FUNCTION_TRACE DPRINT1("%s() ...\n", __FUNCTION__)
#define FUNCTION_TRACE do { } while (0)

#define NETIO_RECEIVE_COUNT 4
#define NETIO_RECEIVE_SIZE 65536

struct _WSK_SOCKET_INTERNAL;

/* One posted datagram receive; while the client retains the indication it stays lent out */
typedef struct _NETIO_RECEIVE
{
    WSK_DATAGRAM_INDICATION Indication;
    struct _WSK_SOCKET_INTERNAL *Socket;
    PIRP Irp;
    PMDL Mdl;
    volatile BOOLEAN InFlight;
    SOCKADDR_IN Remote;
    ULONG_PTR ConnInfo[(sizeof(TDI_CONNECTION_INFORMATION) + sizeof(TA_IP_ADDRESS) + sizeof(ULONG_PTR) - 1) / sizeof(ULONG_PTR)];
    DECLSPEC_ALIGN(8) UCHAR Control[64];
    UCHAR Data[NETIO_RECEIVE_SIZE];
} NETIO_RECEIVE, *PNETIO_RECEIVE;

/* What WSK_SET_STATIC_EVENT_CALLBACKS enabled for the sockets of one WSK client */
typedef struct _NETIO_WSK_CLIENT
{
    ULONG EventMask;
} NETIO_WSK_CLIENT, *PNETIO_WSK_CLIENT;

typedef struct _WSK_SOCKET_INTERNAL
{
    WSK_SOCKET Socket;

    ADDRESS_FAMILY family;      /* AF_INET or AF_INET6 */
    USHORT type;                /* SOCK_DGRAM, SOCK_STREAM, ... */
    ULONG proto;                /* IPPROTO_UDP, IPPROTO_TCP */
    ULONG WskFlags;             /* WSK_FLAG_LISTEN_SOCKET, ... */
    PVOID user_context;         /* parameter for callbacks, opaque */
    UNICODE_STRING TdiName;     /* \\Devices\\Tcp, \\Devices\\Udp */

    struct sockaddr LocalAddress;
    PFILE_OBJECT LocalAddressFile;
    HANDLE LocalAddressHandle;

    struct sockaddr RemoteAddress;      /* Remember latest remote connection */
    PFILE_OBJECT RemoteAddressFile;
    HANDLE RemoteAddressHandle;

    /* Those exist for connection oriented (TCP/IP) sockets only */
    PFILE_OBJECT ConnectionFile;        /* Returned by TdiOpenConnectionEndpointFile() */
    HANDLE ConnectionHandle;            /* Returned by TdiOpenConnectionEndpointFile() */
    BOOLEAN ConnectionFileAssociated;

    /* Incoming connection callback function */
    const WSK_CLIENT_LISTEN_DISPATCH *ListenDispatch;
    UINT CallbackMask;

    UINT Flags;                    /* SO_REUSEADDR, ... see ws2def.h */
    LONG RefCount;                 /* See ReferenceSocket/DereferenceSocket */

    PIRP ListenIrp;	           /* must be cancelled on close */
    volatile BOOLEAN ListenCancelled;
    HANDLE ListenThreadHandle;     /* needed to restart listening */
    PKTHREAD ListenThread;
    KEVENT StartListenEvent;
    volatile BOOLEAN ListenThreadShouldRun;

    /* AcceptSocket's keep a reference on their listen sockets so
     * that the Address file will be closed only if there are no
     * open connections any more.
     */
    struct _WSK_SOCKET_INTERNAL *ListenSocket;

    /* DereferenceSocket() only works at PASSIVE_LEVEL. If > PASSIVE_LEVEL,
     * it will put the socket on this list and wake the putsockets
     * thread.
     */
    struct _WSK_SOCKET_INTERNAL *NextSocketToDereference;
    ULONG NumSocketDereferences;

    /* Datagram sockets */
    const WSK_CLIENT_DATAGRAM_DISPATCH *DatagramDispatch;
    BOOLEAN ReceiveEvents;          /* WSK_EVENT_RECEIVE_FROM is enabled */
    BOOLEAN PktInfo;                /* IP_PKTINFO was requested */
    BOOLEAN ReceiveStarted;
    volatile BOOLEAN ReceiveClosing;
    LONG ReceivesBusy;              /* receives in flight or retained by the client */
    KEVENT ReceivesIdle;
    KSPIN_LOCK ReceiveLock;
    PNETIO_RECEIVE Receives[NETIO_RECEIVE_COUNT];
} WSK_SOCKET_INTERNAL, *PWSK_SOCKET_INTERNAL;

typedef struct _NETIO_CONTEXT
{
    PIRP UserIrp;
    PWSK_SOCKET_INTERNAL socket;
    PTDI_CONNECTION_INFORMATION TargetConnectionInfo;
    PTDI_CONNECTION_INFORMATION PeerAddrRet;
} NETIO_CONTEXT, *PNETIO_CONTEXT;

static void
ReferenceSocket(_In_ PWSK_SOCKET_INTERNAL Socket)
{
    FUNCTION_TRACE;

    InterlockedIncrement(&Socket->RefCount);
}

static void
DereferenceSocket(_In_ PWSK_SOCKET_INTERNAL Socket);

/* This function can be called several times on the same socket.
   In particular it will be called by WskClose and later by the
   DereferenceSocket() of the socket.
 */

static VOID
NetioStopReceives(_In_ PWSK_SOCKET_INTERNAL Socket);
static NTSTATUS
NetioStartReceives(_In_ PWSK_SOCKET_INTERNAL Socket);
static NTSTATUS
NetioSetAddressOption(_In_ PFILE_OBJECT AddressFile, _In_ ULONG Option, _In_ ULONG Value);

static
void SocketShutdown(_In_ PWSK_SOCKET_INTERNAL Socket)
{
    NTSTATUS status;

    FUNCTION_TRACE;

    NetioStopReceives(Socket);

    if (Socket->ListenSocket != NULL)
    {
        DereferenceSocket(Socket->ListenSocket);
        Socket->ListenSocket = NULL;
    }
    if (Socket->ListenThreadHandle != NULL)
    {
        Socket->ListenThreadShouldRun = FALSE;
        KeSetEvent(&Socket->StartListenEvent, IO_NO_INCREMENT, FALSE);
        status = KeWaitForSingleObject(Socket->ListenThread, Executive, KernelMode, FALSE, (PLARGE_INTEGER)NULL);
        if (!NT_SUCCESS(status))
        {
            DPRINT1("KeWaitForSingleObject failed with status 0x%08x!\n", status);
        }
        ObDereferenceObject(Socket->ListenThread);
        Socket->ListenThread = NULL;
        Socket->ListenThreadHandle = NULL;
    }
    if (Socket->ListenIrp != NULL)
    {
        Socket->ListenCancelled = TRUE;
        IoCancelIrp(Socket->ListenIrp);
        Socket->ListenIrp = NULL;
    }
    if (Socket->ConnectionFile != NULL)
    {
        if (Socket->ConnectionFileAssociated)
        {
            /* This fails with error STATUS_CONNECTION_ACTIVE on Windows 2003 */
            status = TdiDisassociateAddressFile(Socket->ConnectionFile);
            if (!NT_SUCCESS(status))
            {
                DPRINT1("Warning: TdiDisassociateAddressFile returned status %08x\n", status);
            }
            Socket->ConnectionFileAssociated = FALSE;
        }
        ObDereferenceObject(Socket->ConnectionFile);
        Socket->ConnectionFile = NULL;
    }
    if (Socket->ConnectionHandle != NULL)
    {
        ZwClose(Socket->ConnectionHandle);
        Socket->ConnectionHandle = NULL;
    }
}

static void
SocketDestroy(_In_ PWSK_SOCKET_INTERNAL Socket)
{
    SocketShutdown(Socket);

    /* Especially listen sockets must keep the LocalAddressFile
     * open when being closed and there are still accepted sockets
     * somewhere. Else the accepted socket I/O will fail with
     * STATUS_INVALID_DEVICE_STATE. So do not close the
     * address file in Shutdown only close it here when all AcceptSockets
     * are gone (AcceptSockets hold a reference to the listen socket).
     */

    if (Socket->LocalAddressFile != NULL)
    {
        ObDereferenceObject(Socket->LocalAddressFile);
        Socket->LocalAddressFile = NULL;
    }
    if (Socket->LocalAddressHandle != NULL)
    {
        ZwClose(Socket->LocalAddressHandle);
        Socket->LocalAddressHandle = NULL;
    }
    ExFreePoolWithTag(Socket, TAG_NETIO);
}

static void
DereferenceSocketSynchronous(_In_ PWSK_SOCKET_INTERNAL Socket)
{
    if (InterlockedDecrement(&Socket->RefCount) == 0)
    {
        SocketDestroy(Socket);
    }
}

static PWSK_SOCKET_INTERNAL SocketsToDereference = NULL;
static KSPIN_LOCK SocketsToDereferenceListLock = 0;
static volatile BOOLEAN DereferenceSocketsThreadShouldRun = FALSE;
static KEVENT DereferenceSocketsEvent;
static HANDLE DereferenceSocketsThreadHandle;

static VOID NTAPI DereferenceSocketsThread(_In_opt_ void *p)
{
    NTSTATUS status;
    PWSK_SOCKET_INTERNAL SocketToDereference;
    KIRQL OldIrql;
    ULONG NumSocketDereferences;

    FUNCTION_TRACE;

    while (DereferenceSocketsThreadShouldRun)
    {
        status = KeWaitForSingleObject(&DereferenceSocketsEvent, Executive, KernelMode, FALSE, NULL);
        if (!NT_SUCCESS(status))
        {
            DPRINT1("KeWaitForSingleObject failed with status 0x%08x!\n", status);
        }

        KeAcquireSpinLock(&SocketsToDereferenceListLock, &OldIrql);
        while (SocketsToDereference != NULL)
        {
            SocketToDereference = SocketsToDereference;
            SocketsToDereference = SocketToDereference->NextSocketToDereference;
            NumSocketDereferences = SocketToDereference->NumSocketDereferences;

            while (NumSocketDereferences > 0)
            {
                SocketToDereference->NumSocketDereferences--;
                NumSocketDereferences = SocketToDereference->NumSocketDereferences;

                KeReleaseSpinLock(&SocketsToDereferenceListLock, OldIrql);
                DereferenceSocketSynchronous(SocketToDereference);
                KeAcquireSpinLock(&SocketsToDereferenceListLock, &OldIrql);
            }
        }
        KeReleaseSpinLock(&SocketsToDereferenceListLock, OldIrql);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

static NTSTATUS StartSocketDereferenceThread(void)
{
    NTSTATUS status;

    KeInitializeSpinLock(&SocketsToDereferenceListLock);
    KeInitializeEvent(&DereferenceSocketsEvent, SynchronizationEvent, FALSE);
    DereferenceSocketsThreadShouldRun = TRUE;

    status = PsCreateSystemThread(&DereferenceSocketsThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, DereferenceSocketsThread, NULL);
    if (!NT_SUCCESS(status))
    {
        DPRINT1("Could not start put sockets thread, status is %x\n", status);
    }
    return status;
}

static void StopSocketDereferenceThread(void)
{
    DereferenceSocketsThreadShouldRun = FALSE;
    KeSetEvent(&DereferenceSocketsEvent, IO_NO_INCREMENT, FALSE);

    /* eventually it will terminate, no need to wait for that. */
}

static void
DereferenceSocket(_In_ PWSK_SOCKET_INTERNAL Socket)
{
    KIRQL OldIrql;

    FUNCTION_TRACE;

    /* We are doing calls like ZwClose, TdiDisassociateAddressFile, ...
       which require IRQL to be PASSIVE_LEVEL. So if we get here
       when IRQL is greater than PASSIVE_LEVEL, defer the DereferenceSocket()
       to a separate thread. */

    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
    {
        KeAcquireSpinLock(&SocketsToDereferenceListLock, &OldIrql);
        if (Socket->NumSocketDereferences == 0)
        {
            Socket->NextSocketToDereference = SocketsToDereference;
            SocketsToDereference = Socket;
            Socket->NumSocketDereferences = 1;
        }
        else
        {
            Socket->NumSocketDereferences++;
        }
        KeReleaseSpinLock(&SocketsToDereferenceListLock, OldIrql);

        KeSetEvent(&DereferenceSocketsEvent, IO_NO_INCREMENT, FALSE);

        return;
    }
    DereferenceSocketSynchronous(Socket);
}

NTSTATUS
WfpCreateDevice(
    _In_ PDRIVER_OBJECT DriverObject);

static PDEVICE_OBJECT NetioNsiDevice;
static PDRIVER_DISPATCH NetioWfpDispatch[IRP_MJ_MAXIMUM_FUNCTION + 1];

/*
 * \Device\Nsi exists so that drivers which filter NSI requests (wireguard.sys)
 * can attach to it. LiberNT's NSI provider lives in nsi.dll and does not send
 * requests to this device, so it only accepts opens and closes.
 */
static NTSTATUS NTAPI
NetioDispatch(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status;

    if (DeviceObject != NetioNsiDevice)
        return NetioWfpDispatch[Stack->MajorFunction](DeviceObject, Irp);

    switch (Stack->MajorFunction)
    {
        case IRP_MJ_CREATE:
        case IRP_MJ_CLEANUP:
        case IRP_MJ_CLOSE:
            Status = STATUS_SUCCESS;
            break;
        default:
            Status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static NTSTATUS
NetioCreateNsiDevice(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Device\\Nsi");
    NTSTATUS Status;
    ULONG i;

    Status = IoCreateDeviceSecure(DriverObject, 0, &Name, FILE_DEVICE_NETWORK, FILE_DEVICE_SECURE_OPEN, FALSE,
                                  &SDDL_DEVOBJ_SYS_ALL_ADM_ALL, NULL, &NetioNsiDevice);
    if (!NT_SUCCESS(Status))
        return Status;

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
    {
        NetioWfpDispatch[i] = DriverObject->MajorFunction[i];
        DriverObject->MajorFunction[i] = NetioDispatch;
    }
    NetioNsiDevice->Flags |= DO_BUFFERED_IO;
    NetioNsiDevice->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS Status;

    FUNCTION_TRACE;

    Status = WfpCreateDevice(DriverObject);
    if (!NT_SUCCESS(Status))
        return Status;
    return NetioCreateNsiDevice(DriverObject);
}

static NTSTATUS WSKAPI
WskSocket(
    _In_ PWSK_CLIENT Client,
    _In_ ADDRESS_FAMILY AddressFamily,
    _In_ USHORT SocketType,
    _In_ ULONG Protocol,
    _In_ ULONG Flags,
    _In_opt_ PVOID SocketContext,
    _In_opt_ const VOID * Dispatch,
    _In_opt_ PEPROCESS OwningProcess,
    _In_opt_ PETHREAD OwningThread,
    _In_opt_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _Inout_ PIRP Irp);

static NTSTATUS NTAPI
NetioComplete(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp, _In_ PVOID ContextParam)
{
    PNETIO_CONTEXT Context = (PNETIO_CONTEXT)ContextParam;
    PIRP UserIrp = Context->UserIrp;

    FUNCTION_TRACE;

    if (Irp->IoStatus.Status != STATUS_CANCELLED)
    {
        UserIrp->IoStatus.Status = Irp->IoStatus.Status;
        UserIrp->IoStatus.Information = Irp->IoStatus.Information;
    }

    if (Context->PeerAddrRet != NULL)
    {
        PSOCKADDR RemoteAddress =
            (PSOCKADDR)(&((PTRANSPORT_ADDRESS)Context->PeerAddrRet->RemoteAddress)->Address[0].AddressType);

        memcpy(&Context->socket->RemoteAddress, RemoteAddress, sizeof(Context->socket->RemoteAddress));
    }
    if (Irp->IoStatus.Status != STATUS_CANCELLED)
    {
        IoCompleteRequest(UserIrp, IO_NETWORK_INCREMENT);
    }

    DereferenceSocket(Context->socket);
    if (Context->TargetConnectionInfo != NULL)
    {
        ExFreePoolWithTag(Context->TargetConnectionInfo, TAG_AFD_TDI_CONNECTION_INFORMATION);
    }
    if (Context->PeerAddrRet != NULL)
    {
        ExFreePoolWithTag(Context->PeerAddrRet, TAG_AFD_TDI_CONNECTION_INFORMATION);
    }
    ExFreePoolWithTag(Context, TAG_NETIO);

    return STATUS_SUCCESS;
}

typedef struct _LISTEN_CONTEXT
{
    PWSK_SOCKET_INTERNAL ListenSocket;
    PWSK_SOCKET_INTERNAL AcceptSocket;
    PTDI_CONNECTION_INFORMATION RequestConnectionInfo, ReturnConnectionInfo;
} LISTEN_CONTEXT, *PLISTEN_CONTEXT;

static NTSTATUS NTAPI
CompletionFireEvent(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp, _In_ PVOID Context)
{
    PKEVENT Event = (PKEVENT)Context;

    FUNCTION_TRACE;

    KeSetEvent(Event, IO_NO_INCREMENT, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS CreateSocket(
    _In_ ADDRESS_FAMILY AddressFamily,
    _In_ USHORT SocketType,
    _In_ ULONG Protocol,
    _In_ ULONG Flags,
    _Outptr_ PWSK_SOCKET_INTERNAL *TheSocket)
{
    PIRP NewSocketIrp;
    KEVENT CompletionEvent;
    NTSTATUS Status;

    FUNCTION_TRACE;

    NewSocketIrp = IoAllocateIrp(1, FALSE);
    if (NewSocketIrp == NULL)
    {
        DPRINT1("Out of memory?\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    KeInitializeEvent(&CompletionEvent, NotificationEvent, FALSE);
    IoSetCompletionRoutine(NewSocketIrp, CompletionFireEvent, &CompletionEvent, TRUE, TRUE, TRUE);
    NewSocketIrp->Tail.Overlay.Thread = PsGetCurrentThread();

    Status = WskSocket(NULL, AddressFamily, SocketType, Protocol, Flags,
        NULL, NULL, NULL, NULL, NULL, NewSocketIrp);

    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
        Status = NewSocketIrp->IoStatus.Status;
    }

    if (NT_SUCCESS(Status))
    {
        *TheSocket = (PWSK_SOCKET_INTERNAL)NewSocketIrp->IoStatus.Information;
    }

    IoFreeIrp(NewSocketIrp);
    return Status;
}

static void QueueListening(_In_ PWSK_SOCKET_INTERNAL ListenSocket)
{
    FUNCTION_TRACE;

    KeSetEvent(&ListenSocket->StartListenEvent, IO_NO_INCREMENT, FALSE);
}

static NTSTATUS NTAPI
ListenComplete(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp, _In_ PVOID Context)
{
    PLISTEN_CONTEXT ListenContext = (PLISTEN_CONTEXT)Context;
    PWSK_SOCKET_INTERNAL ListenSocket = ListenContext->ListenSocket;
    PWSK_SOCKET_INTERNAL AcceptSocket = ListenContext->AcceptSocket;
    PWSK_CLIENT_LISTEN_DISPATCH ListenDispatch =
        (PWSK_CLIENT_LISTEN_DISPATCH)ListenSocket->ListenDispatch;

    /* A PTRANSPORT_ADDRESS address field has an additional
     * AddressLength field so the struct sockaddr_in starts
     * at the AddressType (the address family, 2 for AF_INET)
     * field.
     */

    PSOCKADDR RemoteAddress =
        (PSOCKADDR)(&((PTRANSPORT_ADDRESS)ListenContext->ReturnConnectionInfo->RemoteAddress)->Address[0].AddressType);
    PVOID AcceptSocketContext;
    const WSK_CLIENT_CONNECTION_DISPATCH *AcceptSocketDispatch;
    BOOLEAN Requeue = Irp->PendingReturned || NT_SUCCESS(Irp->IoStatus.Status);
    NTSTATUS Status;

    FUNCTION_TRACE;

    if (ListenSocket->CallbackMask & WSK_EVENT_ACCEPT &&
        ListenDispatch->WskAcceptEvent != NULL &&
        ListenSocket->ListenIrp != NULL &&
        !ListenSocket->ListenCancelled &&
        Irp->IoStatus.Status != STATUS_CANCELLED)
    {
        ListenSocket->ListenIrp = NULL;

        Status = ListenDispatch->WskAcceptEvent(ListenSocket->user_context,
                                                0,
                                                &ListenSocket->LocalAddress,
                                                RemoteAddress,
                                                &AcceptSocket->Socket,
                                                &AcceptSocketContext,
                                                &AcceptSocketDispatch);

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ListenDispatch->WskAcceptEvent returned non-successful status 0x%08x\n", Status);
        }
        else
        {
            memcpy(&AcceptSocket->RemoteAddress, RemoteAddress, sizeof(AcceptSocket->RemoteAddress));
        }
    }
    else
    {
        DereferenceSocket(AcceptSocket);	/* close the AcceptSocket */
    }
    ListenSocket->ListenIrp = NULL;

    DereferenceSocket(AcceptSocket);
    DereferenceSocket(ListenSocket);

    ExFreePoolWithTag(ListenContext->ReturnConnectionInfo, TAG_AFD_TDI_CONNECTION_INFORMATION);
    ExFreePoolWithTag(ListenContext->RequestConnectionInfo, TAG_AFD_TDI_CONNECTION_INFORMATION);
    ExFreePoolWithTag(ListenContext, TAG_NETIO);

    /* And wait for the next incoming connection.
     * This is done in a separate thread at IRQL = PASSIVE_LEVEL
     */

    if (Requeue)
        QueueListening(ListenSocket);

    return STATUS_SUCCESS;
}

static NTSTATUS
StartListening(_In_ PWSK_SOCKET_INTERNAL ListenSocket)
{
    PIRP tdiIrp;
    NTSTATUS status;
    PLISTEN_CONTEXT lc;
    PWSK_SOCKET_INTERNAL AcceptSocket;

    FUNCTION_TRACE;

    if (ListenSocket->LocalAddressHandle == NULL)
    {
        DPRINT1("LocalAddressHandle is not set, need to bind your socket before listening\n");
        return STATUS_INVALID_PARAMETER;
    }

    status = CreateSocket(ListenSocket->family, ListenSocket->type, ListenSocket->proto, WSK_FLAG_CONNECTION_SOCKET, &AcceptSocket);
    if (!NT_SUCCESS(status))
    {
        DPRINT1("Could not create AcceptSocket, status is 0x%08x\n", status);
        return status;
    }
    AcceptSocket->ListenSocket = ListenSocket;
    /* Dereferenced when the AcceptSocket is closed */
    ReferenceSocket(AcceptSocket->ListenSocket);

    status = STATUS_INSUFFICIENT_RESOURCES;
    lc = ExAllocatePoolUninitialized(NonPagedPool, sizeof(*lc), TAG_NETIO);
    if (lc == NULL)
    {
        goto err_out_free_accept_socket;
    }
    lc->ListenSocket = ListenSocket;
    lc->AcceptSocket = AcceptSocket;

    tdiIrp = NULL;

    status = TdiAssociateAddressFile(ListenSocket->LocalAddressHandle, AcceptSocket->ConnectionFile);
    if (!NT_SUCCESS(status))
    {
        goto err_out_free_lc;
    }
    AcceptSocket->ConnectionFileAssociated = TRUE;

    lc->RequestConnectionInfo = NULL;
    TdiBuildNullConnectionInfo(&lc->RequestConnectionInfo, TDI_ADDRESS_TYPE_IP);
    if (lc->RequestConnectionInfo == NULL)
    {
        goto err_out_free_lc_and_disassociate;
    }
    lc->RequestConnectionInfo->OptionsLength = 0;

    lc->ReturnConnectionInfo = NULL;
    TdiBuildNullConnectionInfo(&lc->ReturnConnectionInfo, TDI_ADDRESS_TYPE_IP);
    if (lc->ReturnConnectionInfo == NULL)
    {
        goto err_out_free_lc_and_req_conn_info;
    }
    lc->ReturnConnectionInfo->OptionsLength = 0;

    ReferenceSocket(ListenSocket);
    ReferenceSocket(AcceptSocket);

    ListenSocket->ListenCancelled = FALSE;
    /* pass the ConnectionFile from accept socket, not from ListenSocket ... */
    status = TdiListen(&tdiIrp, AcceptSocket->ConnectionFile, &lc->RequestConnectionInfo, &lc->ReturnConnectionInfo, ListenComplete, lc);

    if (tdiIrp == NULL)
    {
        ExFreePoolWithTag(lc->ReturnConnectionInfo, TAG_NETIO);
        DereferenceSocket(ListenSocket);
        DereferenceSocket(AcceptSocket);
        goto err_out_free_lc_and_req_conn_info;
    }
    if (status == STATUS_PENDING)
        ListenSocket->ListenIrp = tdiIrp;

    return STATUS_PENDING;

err_out_free_lc_and_req_conn_info:
    ExFreePoolWithTag(lc->RequestConnectionInfo, TAG_NETIO);

err_out_free_lc_and_disassociate:
    status = TdiDisassociateAddressFile(AcceptSocket->ConnectionFile);
    if (!NT_SUCCESS(status))
    {
        DPRINT1("Warning: TdiDisassociateAddressFile returned status %08x\n", status);
    }
    AcceptSocket->ConnectionFileAssociated = FALSE;

err_out_free_lc:
    ExFreePoolWithTag(lc, TAG_NETIO);

err_out_free_accept_socket:
    DereferenceSocket(AcceptSocket);

    return status;
}

static VOID NTAPI RequeueListenThread(_In_ PVOID p)
{
    PWSK_SOCKET_INTERNAL ListenSocket = (PWSK_SOCKET_INTERNAL)p;
    NTSTATUS status;

    FUNCTION_TRACE;

    while (ListenSocket->ListenThreadShouldRun)
    {
        status = KeWaitForSingleObject(&ListenSocket->StartListenEvent, Executive, KernelMode, FALSE, NULL);
        if (!NT_SUCCESS(status))
        {
            DPRINT1("KeWaitForSingleObject failed with status 0x%08x!\n", status);
        }
        if (!ListenSocket->ListenThreadShouldRun)
        {
            break;
        }
        StartListening(ListenSocket);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static NTSTATUS WSKAPI
WskControlSocket(
    _In_ PWSK_SOCKET SocketParam,
    _In_ WSK_CONTROL_SOCKET_TYPE RequestType,
    _In_ ULONG ControlCode,
    _In_ ULONG Level,
    _In_ SIZE_T InputSize,
    _In_reads_bytes_opt_(InputSize) PVOID InputBuffer,
    _In_ SIZE_T OutputSize,
    _Out_writes_bytes_opt_(OutputSize) PVOID OutputBuffer,
    _Out_opt_ SIZE_T * OutputSizeReturned,
    _Inout_opt_ PIRP Irp)
{
    PWSK_SOCKET_INTERNAL Socket = CONTAINING_RECORD(SocketParam, WSK_SOCKET_INTERNAL, Socket);
    NTSTATUS status = STATUS_NOT_IMPLEMENTED;

    FUNCTION_TRACE;

    if (Socket == NULL)
    {
        status = STATUS_INVALID_PARAMETER;
        goto err_out;
    }
    IoSetNextIrpStackLocation(Irp);

    switch (RequestType)
    {
        case WskSetOption:
            switch (Level)
            {
                case SOL_SOCKET:
                    switch (ControlCode)
                    {
                        case SO_REUSEADDR:     /* add more supported flags here */
                            if (InputBuffer == NULL)
                            {
                                DPRINT1("WskControlSocket: Need an InputBuffer for this operation\n");
                                status = STATUS_INVALID_PARAMETER;
                                break;
                            }
                            if (InputSize < sizeof(UINT))
                            {
                                DPRINT1("WskControlSocket: InputBuffer too small for this operation\n");
                                status = STATUS_INVALID_PARAMETER;
                                break;
                            }
                            UINT enable = *(PUINT)InputBuffer;
                            if (enable != 0)
                            {
                                Socket->Flags |= ControlCode;
                            }
                            else
                            {
                                Socket->Flags &= ~ControlCode;
                            }
                            status = STATUS_SUCCESS;
                            break;

                            /* Windows specific. This sets the mask for callback functions. */
                        case SO_WSK_EVENT_CALLBACK:
                            if (InputBuffer == NULL)
                            {
                                DPRINT1("WskControlSocket: Need an InputBuffer for this operation\n");
                                status = STATUS_INVALID_PARAMETER;
                                break;
                            }
                            if (InputSize < sizeof(WSK_EVENT_CALLBACK_CONTROL))
                            {
                                DPRINT1("WskControlSocket: InputBuffer too small for this operation\n");
                                status = STATUS_INVALID_PARAMETER;
                                break;
                            }
                            PWSK_EVENT_CALLBACK_CONTROL Control = (WSK_EVENT_CALLBACK_CONTROL *)InputBuffer;

                            if (((Socket->CallbackMask & WSK_EVENT_ACCEPT) == 0) &&
                                ((Control->EventMask & WSK_EVENT_ACCEPT) == WSK_EVENT_ACCEPT))
                            {
                                Socket->CallbackMask = Control->EventMask;
                                QueueListening(Socket);
                            }
                            else
                            {
                                Socket->CallbackMask = Control->EventMask;
                            }

                            status = STATUS_SUCCESS;
                            if (Socket->type == SOCK_DGRAM && (Control->EventMask & WSK_EVENT_RECEIVE_FROM) &&
                                !(Control->EventMask & WSK_EVENT_DISABLE))
                            {
                                Socket->ReceiveEvents = TRUE;
                                status = NetioStartReceives(Socket);
                            }
                            break;

                        default:
                            DPRINT1("WskControlSocket: ControlCode %d Not implemented\n", ControlCode);
                    }
                    break;
                case IPPROTO_IP:
                    if (ControlCode != IP_PKTINFO || Socket->type != SOCK_DGRAM)
                    {
                        DPRINT1("WskControlSocket: IPPROTO_IP option %d Not implemented\n", ControlCode);
                        break;
                    }
                    if (InputBuffer == NULL || InputSize < sizeof(ULONG))
                    {
                        status = STATUS_INVALID_PARAMETER;
                        break;
                    }
                    /* Before the bind the option is applied when the address file opens */
                    Socket->PktInfo = *(PULONG)InputBuffer != 0;
                    status = Socket->LocalAddressFile ?
                             NetioSetAddressOption(Socket->LocalAddressFile, AO_OPTION_IP_PKTINFO, Socket->PktInfo) :
                             STATUS_SUCCESS;
                    break;
                default:
                    DPRINT1("WskControlSocket: Level %d Not implemented\n", Level);
            }
            break;

        case WskGetOption:
        case WskIoctl:
        default:
            DPRINT1("WskControlSocket: Option %d Not implemented\n", RequestType);
    }

err_out:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);

    return STATUS_PENDING;
}

static NTSTATUS WSKAPI
WskCloseSocket(_In_ PWSK_SOCKET SocketParam, _Inout_ PIRP Irp)
{
    NTSTATUS status = STATUS_SUCCESS;
    PWSK_SOCKET_INTERNAL Socket = CONTAINING_RECORD(SocketParam, WSK_SOCKET_INTERNAL, Socket);

    IoSetNextIrpStackLocation(Irp);

    /* There might be a reference from (for example) a pending
     * receive. Shutdown the socket here explicitly. We expect
     * all pending I/O operations to be cancelled, then.
     */

    SocketShutdown(Socket);
    DereferenceSocket(Socket);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);

    return STATUS_PENDING;
}

static PTRANSPORT_ADDRESS
TdiTransportAddressFromSocketAddress(_In_ PSOCKADDR SocketAddress)
{
    PTRANSPORT_ADDRESS ta;
    ULONG Size;

    Size = FIELD_OFFSET(TRANSPORT_ADDRESS, Address) +
           FIELD_OFFSET(TA_ADDRESS, Address[sizeof(SocketAddress->sa_data)]);

    ta = ExAllocatePoolUninitialized(NonPagedPool, Size, TAG_NETIO);
    if (ta == NULL)
    {
        DPRINT1("TdiTransportAddressFromSocketAddress: Out of memory\n");
        return NULL;
    }

    ta->TAAddressCount = 1;
    ta->Address[0].AddressLength = sizeof(SocketAddress->sa_data);
    ta->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;	/* AF_INET */

    memcpy(&ta->Address[0].Address[0], &SocketAddress->sa_data, ta->Address[0].AddressLength);

    return ta;
}

static PTDI_CONNECTION_INFORMATION
TdiConnectionInfoFromSocketAddress(_In_ PSOCKADDR SocketAddress)
{
    PTRANSPORT_ADDRESS TargetAddress;
    PTDI_CONNECTION_INFORMATION ConnectionInformation = NULL;
    NTSTATUS status;

    TargetAddress = TdiTransportAddressFromSocketAddress(SocketAddress);
    if (TargetAddress == NULL)
        return NULL;

    status = TdiBuildConnectionInfo(&ConnectionInformation, TargetAddress);
    ExFreePoolWithTag(TargetAddress, TAG_NETIO);

    if (!NT_SUCCESS(status))
    {
        if (ConnectionInformation != NULL)
        {
            ExFreePoolWithTag(ConnectionInformation, TAG_AFD_TDI_CONNECTION_INFORMATION);
        }
        return NULL;
    }
    ConnectionInformation->OptionsLength = 0;
    return ConnectionInformation;
}

static NTSTATUS WSKAPI
WskBind(_In_ PWSK_SOCKET SocketParam, _In_ PSOCKADDR LocalAddress, _Reserved_ ULONG Flags, _Inout_ PIRP Irp)
{
    NTSTATUS status;
    PWSK_SOCKET_INTERNAL Socket = CONTAINING_RECORD(SocketParam, WSK_SOCKET_INTERNAL, Socket);

    PTRANSPORT_ADDRESS ta = TdiTransportAddressFromSocketAddress(LocalAddress);

    FUNCTION_TRACE;
    IoSetNextIrpStackLocation(Irp);

    if (ta == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto err_out;
    }
    if (Socket->LocalAddressHandle != NULL)
    {
        status = STATUS_INVALID_PARAMETER;
        goto err_out;
    }

    status = TdiOpenAddressFile(&Socket->TdiName,
                                ta, AFD_SHARE_REUSE, &Socket->LocalAddressHandle, &Socket->LocalAddressFile);

    ExFreePoolWithTag(ta, TAG_NETIO);

    if (NT_SUCCESS(status) && Socket->type == SOCK_DGRAM)
    {
        if (Socket->PktInfo)
            status = NetioSetAddressOption(Socket->LocalAddressFile, AO_OPTION_IP_PKTINFO, TRUE);
        if (NT_SUCCESS(status) && Socket->ReceiveEvents)
            status = NetioStartReceives(Socket);
    }

err_out:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);

    return STATUS_PENDING;
}

enum direction
{
    DIR_SEND,
    DIR_RECEIVE
};

static NTSTATUS
NetioDeferSend(
    _In_ PWSK_SOCKET SocketParam,
    _In_opt_ PWSK_BUF Buffer,
    _In_opt_ PWSK_BUF_LIST BufferList,
    _In_ ULONG Flags,
    _In_opt_ PSOCKADDR RemoteAddress,
    _In_ ULONG ControlInfoLength,
    _In_opt_ PCMSGHDR ControlInfo,
    _Inout_ PIRP Irp);

static NTSTATUS WSKAPI
WskSendTo(
    _In_ PWSK_SOCKET SocketParam,
    _In_ PWSK_BUF Buffer,
    _Reserved_ ULONG Flags,
    _In_opt_ PSOCKADDR RemoteAddress,
    _In_ ULONG ControlInfoLength,
    _In_reads_bytes_opt_(ControlInfoLength) PCMSGHDR ControlInfo,
    _Inout_ PIRP Irp)
{
    PIRP tdiIrp = NULL;
    PWSK_SOCKET_INTERNAL Socket = CONTAINING_RECORD(SocketParam, WSK_SOCKET_INTERNAL, Socket);
    PTDI_CONNECTION_INFORMATION TargetConnectionInfo;
    NTSTATUS status;
    void *BufferData;
    PNETIO_CONTEXT NetioContext;

    FUNCTION_TRACE;

    /* tcpip waits for each sent fragment, which it can only do at PASSIVE_LEVEL */
    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
        return NetioDeferSend(SocketParam, Buffer, NULL, Flags, RemoteAddress, ControlInfoLength, ControlInfo, Irp);

    IoSetNextIrpStackLocation(Irp);

    status = STATUS_INSUFFICIENT_RESOURCES;
    NetioContext = ExAllocatePoolUninitialized(NonPagedPool, sizeof(*NetioContext), TAG_NETIO);
    if (NetioContext == NULL)
    {
        goto err_out;
    }
    NetioContext->socket = Socket;
    NetioContext->UserIrp = Irp;

    TargetConnectionInfo = TdiConnectionInfoFromSocketAddress(RemoteAddress);
    if (TargetConnectionInfo == NULL)
    {
        goto err_out_free_nc;
    }
    NetioContext->TargetConnectionInfo = TargetConnectionInfo;
    NetioContext->PeerAddrRet = NULL;

    BufferData = MmGetSystemAddressForMdlSafe(Buffer->Mdl, NormalPagePriority);
    if (BufferData == NULL)
    {
        DPRINT1("Error mapping MDL\n");
        goto err_out_free_nc_and_tci;
    }

    IoMarkIrpPending(Irp);
    ReferenceSocket(Socket);

    /* This will create a tdiIrp */
    status = TdiSendDatagram(&tdiIrp, Socket->LocalAddressFile, ((char *)BufferData) + Buffer->Offset,
                        Buffer->Length, TargetConnectionInfo, NetioComplete, NetioContext);

    /* If allocating tdiIrp fails we get here.
     * Call the IoCompletion of the application's Irp so this Irp
     * gets freed.
     */
    if (!NT_SUCCESS(status))
    {
        DereferenceSocket(Socket);
        goto err_out_free_nc_and_tci;	/* caller has to clean up mdl mapping */
    }
    return STATUS_PENDING;

err_out_free_nc_and_tci:
    ExFreePoolWithTag(TargetConnectionInfo, TAG_AFD_TDI_CONNECTION_INFORMATION);

err_out_free_nc:
    ExFreePoolWithTag(NetioContext, TAG_NETIO);

err_out:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);

    return status;
}

static NTSTATUS WSKAPI
WskReceiveFrom(
    _In_ PWSK_SOCKET SocketParam,
    _In_ PWSK_BUF Buffer,
    _Reserved_ ULONG Flags,
    _Out_opt_ PSOCKADDR RemoteAddress,
    _Inout_ PULONG ControlLength,
    _Out_writes_bytes_opt_(*ControlLength) PCMSGHDR ControlInfo,
    _Out_opt_ PULONG ControlFlags, _Inout_ PIRP Irp)
{
    FUNCTION_TRACE;

    UNIMPLEMENTED;
    if (Irp != NULL)
    {
        Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
        IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);
    }
    return STATUS_NOT_IMPLEMENTED;
}

/* Datagram sockets */

static NTSTATUS
NetioSetAddressOption(
    _In_ PFILE_OBJECT AddressFile,
    _In_ ULONG Option,
    _In_ ULONG Value)
{
    PTCP_REQUEST_SET_INFORMATION_EX Request;
    ULONG Size = FIELD_OFFSET(TCP_REQUEST_SET_INFORMATION_EX, Buffer) + sizeof(ULONG);
    PDEVICE_OBJECT DeviceObject = IoGetRelatedDeviceObject(AddressFile);
    IO_STATUS_BLOCK Io;
    KEVENT Event;
    NTSTATUS Status;
    PIRP Irp;

    Request = ExAllocatePoolZero(NonPagedPool, Size, TAG_NETIO);
    if (Request == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    Request->ID.toi_entity.tei_entity = CL_TL_ENTITY;
    Request->ID.toi_entity.tei_instance = 0;
    Request->ID.toi_class = INFO_CLASS_PROTOCOL;
    Request->ID.toi_type = INFO_TYPE_ADDRESS_OBJECT;
    Request->ID.toi_id = Option;
    Request->BufferSize = sizeof(ULONG);
    RtlCopyMemory(Request->Buffer, &Value, sizeof(Value));

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    Irp = IoBuildDeviceIoControlRequest(IOCTL_TCP_SET_INFORMATION_EX, DeviceObject, Request, Size,
                                        NULL, 0, FALSE, &Event, &Io);
    if (Irp == NULL)
    {
        ExFreePoolWithTag(Request, TAG_NETIO);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    IoGetNextIrpStackLocation(Irp)->FileObject = AddressFile;
    Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = Io.Status;
    }
    ExFreePoolWithTag(Request, TAG_NETIO);
    return Status;
}

static VOID
NetioReceiveDone(
    _In_ PNETIO_RECEIVE Receive)
{
    PWSK_SOCKET_INTERNAL Socket = Receive->Socket;

    if (InterlockedDecrement(&Socket->ReceivesBusy) == 0)
        KeSetEvent(&Socket->ReceivesIdle, IO_NO_INCREMENT, FALSE);
}

static IO_COMPLETION_ROUTINE NetioReceiveComplete;

/* Posts the context's receive again; it stays with us when the socket is closing */
static VOID
NetioPostReceive(
    _In_ PNETIO_RECEIVE Receive)
{
    PWSK_SOCKET_INTERNAL Socket = Receive->Socket;
    PDEVICE_OBJECT DeviceObject = IoGetRelatedDeviceObject(Socket->LocalAddressFile);
    PTDI_CONNECTION_INFORMATION ConnInfo = (PTDI_CONNECTION_INFORMATION)Receive->ConnInfo;
    KIRQL OldIrql;

    KeAcquireSpinLock(&Socket->ReceiveLock, &OldIrql);
    if (Socket->ReceiveClosing)
    {
        KeReleaseSpinLock(&Socket->ReceiveLock, OldIrql);
        NetioReceiveDone(Receive);
        return;
    }
    Receive->InFlight = TRUE;
    KeReleaseSpinLock(&Socket->ReceiveLock, OldIrql);

    IoReuseIrp(Receive->Irp, STATUS_SUCCESS);
    TdiBuildNullConnectionInfoInPlace(ConnInfo, TDI_ADDRESS_TYPE_IP);
    /* tcpip writes IP_PKTINFO into the options when AO_OPTION_IP_PKTINFO is on */
    ConnInfo->Options = Socket->PktInfo ? Receive->Control : NULL;
    ConnInfo->OptionsLength = Socket->PktInfo ? sizeof(Receive->Control) : 0;
    TdiBuildReceiveDatagram(Receive->Irp, DeviceObject, Socket->LocalAddressFile, NetioReceiveComplete,
                            Receive, Receive->Mdl, NETIO_RECEIVE_SIZE, ConnInfo, ConnInfo, 0);
    IoCallDriver(DeviceObject, Receive->Irp);
}

static NTSTATUS NTAPI
NetioReceiveComplete(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_opt_ PVOID Context)
{
    PNETIO_RECEIVE Receive = Context;
    PWSK_SOCKET_INTERNAL Socket = Receive->Socket;
    PTDI_CONNECTION_INFORMATION ConnInfo = (PTDI_CONNECTION_INFORMATION)Receive->ConnInfo;
    PTA_IP_ADDRESS Source = (PTA_IP_ADDRESS)ConnInfo->RemoteAddress;
    NTSTATUS Status = Irp->IoStatus.Status;
    KIRQL OldIrql;

    UNREFERENCED_PARAMETER(DeviceObject);

    KeAcquireSpinLock(&Socket->ReceiveLock, &OldIrql);
    Receive->InFlight = FALSE;
    KeReleaseSpinLock(&Socket->ReceiveLock, OldIrql);

    if (NT_SUCCESS(Status) && !Socket->ReceiveClosing)
    {
        RtlZeroMemory(&Receive->Remote, sizeof(Receive->Remote));
        Receive->Remote.sin_family = AF_INET;
        Receive->Remote.sin_port = Source->Address[0].Address[0].sin_port;
        Receive->Remote.sin_addr.s_addr = Source->Address[0].Address[0].in_addr;

        Receive->Indication.Next = NULL;
        Receive->Indication.Buffer.Mdl = Receive->Mdl;
        Receive->Indication.Buffer.Offset = 0;
        Receive->Indication.Buffer.Length = (SIZE_T)Irp->IoStatus.Information;
        Receive->Indication.ControlInfoLength = Socket->PktInfo ? (ULONG)ConnInfo->OptionsLength : 0;
        Receive->Indication.ControlInfo = Receive->Indication.ControlInfoLength ? (PCMSGHDR)Receive->Control : NULL;
        Receive->Indication.RemoteAddress = (PSOCKADDR)&Receive->Remote;

        Status = Socket->DatagramDispatch->WskReceiveFromEvent(
            Socket->user_context,
            KeGetCurrentIrql() == DISPATCH_LEVEL ? WSK_FLAG_AT_DISPATCH_LEVEL : 0,
            &Receive->Indication);
        /* The client keeps the data until it calls WskRelease */
        if (Status == STATUS_PENDING)
            return STATUS_MORE_PROCESSING_REQUIRED;
        NetioPostReceive(Receive);
    }
    else if (Status == STATUS_BUFFER_OVERFLOW && !Socket->ReceiveClosing)
    {
        /* Larger than NETIO_RECEIVE_SIZE: the datagram is dropped */
        NetioPostReceive(Receive);
    }
    else
    {
        /* Cancelled on close, or the address file failed; reposting would only fail again */
        if (!Socket->ReceiveClosing)
            DPRINT1("Datagram receive failed with status 0x%08lx, receiving stops\n", Status);
        NetioReceiveDone(Receive);
    }
    return STATUS_MORE_PROCESSING_REQUIRED;
}

static VOID
NetioFreeReceives(
    _In_ PWSK_SOCKET_INTERNAL Socket)
{
    ULONG i;

    for (i = 0; i < NETIO_RECEIVE_COUNT; i++)
    {
        PNETIO_RECEIVE Receive = Socket->Receives[i];

        if (Receive == NULL)
            continue;
        if (Receive->Irp)
        {
            Receive->Irp->MdlAddress = NULL;
            IoFreeIrp(Receive->Irp);
        }
        if (Receive->Mdl)
            IoFreeMdl(Receive->Mdl);
        ExFreePoolWithTag(Receive, TAG_NETIO);
        Socket->Receives[i] = NULL;
    }
}

/* Starts the receive event loop of a bound datagram socket */
static NTSTATUS
NetioStartReceives(
    _In_ PWSK_SOCKET_INTERNAL Socket)
{
    PDEVICE_OBJECT DeviceObject;
    ULONG i;

    if (Socket->ReceiveStarted || Socket->LocalAddressFile == NULL ||
        Socket->DatagramDispatch == NULL || Socket->DatagramDispatch->WskReceiveFromEvent == NULL)
    {
        return STATUS_SUCCESS;
    }

    DeviceObject = IoGetRelatedDeviceObject(Socket->LocalAddressFile);
    for (i = 0; i < NETIO_RECEIVE_COUNT; i++)
    {
        PNETIO_RECEIVE Receive = ExAllocatePoolZero(NonPagedPool, sizeof(*Receive), TAG_NETIO);

        if (Receive == NULL)
            goto Fail;
        Socket->Receives[i] = Receive;
        Receive->Socket = Socket;
        Receive->Irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);
        Receive->Mdl = IoAllocateMdl(Receive->Data, NETIO_RECEIVE_SIZE, FALSE, FALSE, NULL);
        if (Receive->Irp == NULL || Receive->Mdl == NULL)
            goto Fail;
        MmBuildMdlForNonPagedPool(Receive->Mdl);
    }

    KeClearEvent(&Socket->ReceivesIdle);
    Socket->ReceivesBusy = NETIO_RECEIVE_COUNT;
    Socket->ReceiveStarted = TRUE;
    for (i = 0; i < NETIO_RECEIVE_COUNT; i++)
        NetioPostReceive(Socket->Receives[i]);
    return STATUS_SUCCESS;

Fail:
    NetioFreeReceives(Socket);
    return STATUS_INSUFFICIENT_RESOURCES;
}

/* Cancels the outstanding receives and waits for the client to release retained data */
static VOID
NetioStopReceives(
    _In_ PWSK_SOCKET_INTERNAL Socket)
{
    LARGE_INTEGER Timeout;
    KIRQL OldIrql;
    ULONG i;

    if (!Socket->ReceiveStarted)
        return;

    KeAcquireSpinLock(&Socket->ReceiveLock, &OldIrql);
    Socket->ReceiveClosing = TRUE;
    KeReleaseSpinLock(&Socket->ReceiveLock, OldIrql);

    Timeout.QuadPart = -1000000LL; /* 100 ms */
    do
    {
        /* A receive can be posted again just after a cancel; cancel until all are back */
        for (i = 0; i < NETIO_RECEIVE_COUNT; i++)
        {
            if (Socket->Receives[i]->InFlight)
                IoCancelIrp(Socket->Receives[i]->Irp);
        }
    } while (KeWaitForSingleObject(&Socket->ReceivesIdle, Executive, KernelMode, FALSE, &Timeout) == STATUS_TIMEOUT);

    NetioFreeReceives(Socket);
    Socket->ReceiveStarted = FALSE;
}

static NTSTATUS WSKAPI
WskReleaseUdp(_In_ PWSK_SOCKET SocketParam, _In_ PWSK_DATAGRAM_INDICATION DatagramIndication)
{
    PWSK_DATAGRAM_INDICATION Next;

    UNREFERENCED_PARAMETER(SocketParam);

    for (; DatagramIndication != NULL; DatagramIndication = Next)
    {
        Next = DatagramIndication->Next;
        NetioPostReceive(CONTAINING_RECORD(DatagramIndication, NETIO_RECEIVE, Indication));
    }
    return STATUS_SUCCESS;
}

static NTSTATUS WSKAPI
WskReleaseTcp(_In_ PWSK_SOCKET SocketParam, _In_ PWSK_DATA_INDICATION DataIndication)
{
    FUNCTION_TRACE;

    UNIMPLEMENTED;

    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS WSKAPI
WskGetLocalAddress(_In_ PWSK_SOCKET SocketParam, _Out_ PSOCKADDR LocalAddress, _Inout_ PIRP Irp)
{
    PWSK_SOCKET_INTERNAL Socket = CONTAINING_RECORD(SocketParam, WSK_SOCKET_INTERNAL, Socket);
    ULONG Size = FIELD_OFFSET(TDI_ADDRESS_INFO, Address) + sizeof(TA_IP_ADDRESS);
    PTDI_ADDRESS_INFO Info = NULL;
    PTA_IP_ADDRESS Address;
    NTSTATUS Status;
    PMDL Mdl = NULL;

    IoSetNextIrpStackLocation(Irp);

    if (Socket->LocalAddressFile == NULL)
    {
        Status = STATUS_INVALID_DEVICE_STATE;
        goto Done;
    }

    Info = ExAllocatePoolZero(NonPagedPool, Size, TAG_NETIO);
    Mdl = Info ? IoAllocateMdl(Info, Size, FALSE, FALSE, NULL) : NULL;
    if (Mdl == NULL)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Done;
    }
    _SEH2_TRY
    {
        MmProbeAndLockPages(Mdl, KernelMode, IoModifyAccess);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        IoFreeMdl(Mdl);
        Mdl = NULL;
    }
    _SEH2_END;
    if (Mdl == NULL)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Done;
    }

    /* The IRP owns the MDL and frees it on completion */
    Status = TdiQueryInformation(Socket->LocalAddressFile, TDI_QUERY_ADDRESS_INFO, Mdl);
    if (NT_SUCCESS(Status))
    {
        Address = (PTA_IP_ADDRESS)&Info->Address;
        if (Address->TAAddressCount < 1 || Address->Address[0].AddressType != TDI_ADDRESS_TYPE_IP)
        {
            Status = STATUS_INVALID_ADDRESS;
        }
        else
        {
            PSOCKADDR_IN Result = (PSOCKADDR_IN)LocalAddress;

            RtlZeroMemory(Result, sizeof(*Result));
            Result->sin_family = AF_INET;
            Result->sin_port = Address->Address[0].Address[0].sin_port;
            Result->sin_addr.s_addr = Address->Address[0].Address[0].in_addr;
        }
    }

Done:
    if (Info)
        ExFreePoolWithTag(Info, TAG_NETIO);
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);
    return STATUS_PENDING;
}

typedef struct _NETIO_SEND_BATCH
{
    PIRP UserIrp;
    PWSK_SOCKET_INTERNAL Socket;
    PTDI_CONNECTION_INFORMATION Target;
    LONG Pending;
    NTSTATUS Status;
    LONG_PTR Bytes;
} NETIO_SEND_BATCH, *PNETIO_SEND_BATCH;

typedef struct _NETIO_SEND_ITEM
{
    PNETIO_SEND_BATCH Batch;
    PVOID Copy;
} NETIO_SEND_ITEM, *PNETIO_SEND_ITEM;

static VOID
NetioSendItemDone(
    _In_ PNETIO_SEND_BATCH Batch)
{
    if (InterlockedDecrement(&Batch->Pending) != 0)
        return;
    Batch->UserIrp->IoStatus.Status = Batch->Status;
    Batch->UserIrp->IoStatus.Information = NT_SUCCESS(Batch->Status) ? Batch->Bytes : 0;
    IoCompleteRequest(Batch->UserIrp, IO_NETWORK_INCREMENT);
    ExFreePoolWithTag(Batch->Target, TAG_AFD_TDI_CONNECTION_INFORMATION);
    DereferenceSocket(Batch->Socket);
    ExFreePoolWithTag(Batch, TAG_NETIO);
}

static NTSTATUS NTAPI
NetioSendItemComplete(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_opt_ PVOID Context)
{
    PNETIO_SEND_ITEM Item = Context;
    PNETIO_SEND_BATCH Batch = Item->Batch;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (NT_SUCCESS(Irp->IoStatus.Status))
        InterlockedExchangeAddSizeT((volatile SIZE_T *)&Batch->Bytes, Irp->IoStatus.Information);
    else
        InterlockedCompareExchange(&Batch->Status, Irp->IoStatus.Status, STATUS_SUCCESS);
    if (Item->Copy)
        ExFreePoolWithTag(Item->Copy, TAG_NETIO);
    ExFreePoolWithTag(Item, TAG_NETIO);
    NetioSendItemDone(Batch);
    return STATUS_SUCCESS;
}

/* Sends each buffer as one datagram. Send-side control data (IP_PKTINFO) is not applied:
 * tcpip picks the source address by its routing. */
static NTSTATUS WSKAPI
WskSendMessages(
    _In_ PWSK_SOCKET SocketParam,
    _In_ PWSK_BUF_LIST BufferList,
    _Reserved_ ULONG Flags,
    _In_opt_ PSOCKADDR RemoteAddress,
    _In_ ULONG ControlInfoLength,
    _In_reads_bytes_opt_(ControlInfoLength) PCMSGHDR ControlInfo,
    _Inout_ PIRP Irp)
{
    PWSK_SOCKET_INTERNAL Socket = CONTAINING_RECORD(SocketParam, WSK_SOCKET_INTERNAL, Socket);
    PNETIO_SEND_BATCH Batch;
    PWSK_BUF_LIST Entry;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(ControlInfoLength);
    UNREFERENCED_PARAMETER(ControlInfo);

    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
        return NetioDeferSend(SocketParam, NULL, BufferList, Flags, RemoteAddress, ControlInfoLength, ControlInfo, Irp);

    IoSetNextIrpStackLocation(Irp);

    if (RemoteAddress == NULL || RemoteAddress->sa_family != AF_INET || Socket->LocalAddressFile == NULL)
    {
        Status = (Socket->LocalAddressFile == NULL) ? STATUS_INVALID_DEVICE_STATE : STATUS_INVALID_PARAMETER;
        goto Fail;
    }

    Batch = ExAllocatePoolZero(NonPagedPool, sizeof(*Batch), TAG_NETIO);
    if (Batch == NULL)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Fail;
    }
    Batch->Target = TdiConnectionInfoFromSocketAddress(RemoteAddress);
    if (Batch->Target == NULL)
    {
        ExFreePoolWithTag(Batch, TAG_NETIO);
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Fail;
    }
    Batch->UserIrp = Irp;
    Batch->Socket = Socket;
    Batch->Status = STATUS_SUCCESS;
    Batch->Pending = 1;
    ReferenceSocket(Socket);
    IoMarkIrpPending(Irp);

    for (Entry = BufferList; Entry != NULL; Entry = Entry->Next)
    {
        PNETIO_SEND_ITEM Item;
        PIRP TdiIrp = NULL;
        PUCHAR Data = NULL;
        PMDL Mdl = Entry->Buffer.Mdl;
        SIZE_T Offset = Entry->Buffer.Offset, Length = Entry->Buffer.Length;

        Item = ExAllocatePoolZero(NonPagedPool, sizeof(*Item), TAG_NETIO);
        if (Item == NULL)
        {
            InterlockedCompareExchange(&Batch->Status, STATUS_INSUFFICIENT_RESOURCES, STATUS_SUCCESS);
            break;
        }
        Item->Batch = Batch;

        if (Mdl != NULL && Offset + Length <= MmGetMdlByteCount(Mdl))
        {
            Data = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
            if (Data)
                Data += Offset;
        }
        else if (Mdl != NULL)
        {
            /* The datagram spans an MDL chain; tcpip takes one flat buffer */
            SIZE_T Copied = 0;

            Item->Copy = ExAllocatePoolWithTag(NonPagedPool, max(Length, 1), TAG_NETIO);
            for (; Item->Copy && Mdl && Copied < Length; Mdl = Mdl->Next)
            {
                PUCHAR Source = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
                SIZE_T Count = MmGetMdlByteCount(Mdl);

                if (Source == NULL)
                    break;
                if (Offset >= Count)
                {
                    Offset -= Count;
                    continue;
                }
                Count = min(Count - Offset, Length - Copied);
                RtlCopyMemory((PUCHAR)Item->Copy + Copied, Source + Offset, Count);
                Copied += Count;
                Offset = 0;
            }
            if (Item->Copy && Copied == Length)
                Data = Item->Copy;
        }

        if (Data == NULL && Length != 0)
        {
            if (Item->Copy)
                ExFreePoolWithTag(Item->Copy, TAG_NETIO);
            ExFreePoolWithTag(Item, TAG_NETIO);
            InterlockedCompareExchange(&Batch->Status, STATUS_INSUFFICIENT_RESOURCES, STATUS_SUCCESS);
            break;
        }

        InterlockedIncrement(&Batch->Pending);
        Status = TdiSendDatagram(&TdiIrp, Socket->LocalAddressFile, (PCHAR)Data, (UINT)Length,
                                 Batch->Target, NetioSendItemComplete, Item);
        if (TdiIrp == NULL)
        {
            /* The IRP was never sent, so its completion routine does not run */
            InterlockedCompareExchange(&Batch->Status, Status, STATUS_SUCCESS);
            if (Item->Copy)
                ExFreePoolWithTag(Item->Copy, TAG_NETIO);
            ExFreePoolWithTag(Item, TAG_NETIO);
            InterlockedDecrement(&Batch->Pending);
            break;
        }
    }

    NetioSendItemDone(Batch);
    return STATUS_PENDING;

Fail:
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);
    return STATUS_PENDING;
}

typedef struct _NETIO_DEFERRED_SEND
{
    WORK_QUEUE_ITEM WorkItem;
    PWSK_SOCKET Socket;
    WSK_BUF Buffer;
    PWSK_BUF_LIST BufferList;
    ULONG Flags;
    PSOCKADDR RemoteAddress;
    ULONG ControlInfoLength;
    PCMSGHDR ControlInfo;
    PIRP Irp;
} NETIO_DEFERRED_SEND, *PNETIO_DEFERRED_SEND;

static VOID NTAPI
NetioDeferredSendWorker(
    _In_ PVOID Context)
{
    PNETIO_DEFERRED_SEND Send = Context;
    PWSK_SOCKET_INTERNAL Socket = CONTAINING_RECORD(Send->Socket, WSK_SOCKET_INTERNAL, Socket);

    if (Send->BufferList)
        WskSendMessages(Send->Socket, Send->BufferList, Send->Flags, Send->RemoteAddress,
                        Send->ControlInfoLength, Send->ControlInfo, Send->Irp);
    else
        WskSendTo(Send->Socket, &Send->Buffer, Send->Flags, Send->RemoteAddress,
                  Send->ControlInfoLength, Send->ControlInfo, Send->Irp);

    DereferenceSocket(Socket);
    ExFreePoolWithTag(Send, TAG_NETIO);
}

/*
 * Runs a send that a client issued above PASSIVE_LEVEL (WSK allows up to
 * DISPATCH_LEVEL) in a system worker thread. The buffers, the address and the
 * control data stay valid until the IRP completes, as WSK requires.
 */
static NTSTATUS
NetioDeferSend(
    _In_ PWSK_SOCKET SocketParam,
    _In_opt_ PWSK_BUF Buffer,
    _In_opt_ PWSK_BUF_LIST BufferList,
    _In_ ULONG Flags,
    _In_opt_ PSOCKADDR RemoteAddress,
    _In_ ULONG ControlInfoLength,
    _In_opt_ PCMSGHDR ControlInfo,
    _Inout_ PIRP Irp)
{
    PNETIO_DEFERRED_SEND Send = ExAllocatePoolZero(NonPagedPool, sizeof(*Send), TAG_NETIO);

    if (Send == NULL)
    {
        IoSetNextIrpStackLocation(Irp);
        Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);
        return STATUS_PENDING;
    }

    Send->Socket = SocketParam;
    if (Buffer)
        Send->Buffer = *Buffer;
    Send->BufferList = BufferList;
    Send->Flags = Flags;
    Send->RemoteAddress = RemoteAddress;
    Send->ControlInfoLength = ControlInfoLength;
    Send->ControlInfo = ControlInfo;
    Send->Irp = Irp;
    ReferenceSocket(CONTAINING_RECORD(SocketParam, WSK_SOCKET_INTERNAL, Socket));
    ExInitializeWorkItem(&Send->WorkItem, NetioDeferredSendWorker, Send);
    ExQueueWorkItem(&Send->WorkItem, CriticalWorkQueue);
    return STATUS_PENDING;
}

static NTSTATUS WSKAPI
WskGetRemoteAddress(_In_ PWSK_SOCKET SocketParam, _Out_ PSOCKADDR RemoteAddress, _Inout_ PIRP Irp)
{
    FUNCTION_TRACE;

    PWSK_SOCKET_INTERNAL Socket = CONTAINING_RECORD(SocketParam, WSK_SOCKET_INTERNAL, Socket);
    NTSTATUS Status = STATUS_INVALID_PARAMETER;

    IoSetNextIrpStackLocation(Irp);
    if (Socket != NULL)
    {
        memcpy(RemoteAddress, &Socket->RemoteAddress, sizeof(*RemoteAddress));
        Status = STATUS_SUCCESS;
    }
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);

    return STATUS_PENDING;  /* Caller has to wait for his completion routine */
}

static NTSTATUS WSKAPI
WskSocketConnect(
    _In_ PWSK_CLIENT Client,
    _In_ USHORT SocketType,
    _In_ ULONG Protocol,
    _In_ PSOCKADDR LocalAddress,
    _In_ PSOCKADDR RemoteAddress,
    _In_ ULONG Flags,
    _In_opt_ PVOID SocketContext,
    _In_opt_ const WSK_CLIENT_CONNECTION_DISPATCH * Dispatch,
    _In_opt_ PEPROCESS OwningProcess,
    _In_opt_ PETHREAD OwningThread,
    _In_opt_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _Inout_ PIRP Irp)
{
    FUNCTION_TRACE;

    UNIMPLEMENTED;
    if (Irp != NULL)
    {
        Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
        IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);
    }
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS WSKAPI
WskControlClient(
    _In_ PWSK_CLIENT Client,
    _In_ ULONG ControlCode,
    _In_ SIZE_T InputSize,
    _In_reads_bytes_opt_(InputSize) PVOID InputBuffer,
    _In_ SIZE_T OutputSize,
    _Out_writes_bytes_opt_(OutputSize) PVOID OutputBuffer,
    _Out_opt_ SIZE_T * OutputSizeReturned, _Inout_opt_ PIRP Irp)
{
    /* Only IPv4 sockets exist (see WskSocket) */
    static const WSK_TRANSPORT Transports[] =
    {
        { 0, SOCK_STREAM, IPPROTO_TCP, AF_INET },
        { 0, SOCK_DGRAM, IPPROTO_UDP, AF_INET },
    };
    PNETIO_WSK_CLIENT ClientContext = (PNETIO_WSK_CLIENT)Client;
    NTSTATUS Status;

    FUNCTION_TRACE;

    if (OutputSizeReturned)
        *OutputSizeReturned = 0;

    switch (ControlCode)
    {
        case WSK_TRANSPORT_LIST_QUERY:
            if (OutputSizeReturned)
                *OutputSizeReturned = sizeof(Transports);
            if (OutputBuffer == NULL || OutputSize < sizeof(Transports))
            {
                Status = STATUS_BUFFER_OVERFLOW;
                break;
            }
            RtlCopyMemory(OutputBuffer, Transports, sizeof(Transports));
            Status = STATUS_SUCCESS;
            break;

        case WSK_SET_STATIC_EVENT_CALLBACKS:
            if (ClientContext == NULL || InputBuffer == NULL || InputSize < sizeof(WSK_EVENT_CALLBACK_CONTROL))
            {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
            ClientContext->EventMask = ((PWSK_EVENT_CALLBACK_CONTROL)InputBuffer)->EventMask;
            Status = STATUS_SUCCESS;
            break;

        case WSK_TDI_BEHAVIOR:
            /* Sockets always go to the TDI transports; there is no other path to choose */
            Status = (InputBuffer != NULL && InputSize >= sizeof(ULONG)) ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
            break;

        default:
            DPRINT1("WskControlClient: control code %lu not supported\n", ControlCode);
            Status = STATUS_NOT_SUPPORTED;
            break;
    }

    if (Irp != NULL)
    {
        Irp->IoStatus.Status = Status;
        Irp->IoStatus.Information = OutputSizeReturned ? *OutputSizeReturned : 0;
        IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);
    }
    return Status;
}

static WSK_PROVIDER_DATAGRAM_DISPATCH UdpDispatch = {
    .WskControlSocket = WskControlSocket,
    .WskCloseSocket = WskCloseSocket,
    .WskBind = WskBind,
    .WskSendTo = WskSendTo,
    .WskReceiveFrom = WskReceiveFrom,
    .WskRelease = WskReleaseUdp,
    .WskGetLocalAddress = WskGetLocalAddress,
    .WskSendMessages = WskSendMessages,
};

/* Connection oriented routines (TCP/IP) */

static NTSTATUS WSKAPI
WskConnect(_In_ PWSK_SOCKET SocketParam, _In_ PSOCKADDR RemoteAddress, _Reserved_ ULONG Flags, _Inout_ PIRP Irp)
{
    PTDI_CONNECTION_INFORMATION TargetConnectionInfo, PeerAddrRet;
    PIRP tdiIrp;
    PWSK_SOCKET_INTERNAL Socket = CONTAINING_RECORD(SocketParam, WSK_SOCKET_INTERNAL, Socket);
    NTSTATUS status, status2;
    PNETIO_CONTEXT NetioContext;

    FUNCTION_TRACE;

    IoSetNextIrpStackLocation(Irp);

    status = STATUS_INVALID_PARAMETER;
    if (Socket->LocalAddressHandle == NULL)
    {
        DPRINT1("LocalAddressHandle is not set, need to bind your socket before connecting\n");
        goto err_out;
    }

    status = STATUS_INSUFFICIENT_RESOURCES;
    NetioContext = ExAllocatePoolUninitialized(NonPagedPool, sizeof(*NetioContext), TAG_NETIO);
    if (NetioContext == NULL)
    {
        goto err_out;
    }
    NetioContext->socket = Socket;
    NetioContext->UserIrp = Irp;

    tdiIrp = NULL;

    status = TdiAssociateAddressFile(Socket->LocalAddressHandle, Socket->ConnectionFile);
    if (!NT_SUCCESS(status))
    {
        goto err_out_free_nc;
    }
    Socket->ConnectionFileAssociated = TRUE;

    TargetConnectionInfo = TdiConnectionInfoFromSocketAddress(RemoteAddress);
    if (TargetConnectionInfo == NULL)
    {
        goto err_out_free_nc_and_disassociate;
    }
    NetioContext->TargetConnectionInfo = TargetConnectionInfo;

    PeerAddrRet = NULL;
    TdiBuildNullConnectionInfo(&PeerAddrRet, TDI_ADDRESS_TYPE_IP);
    if (PeerAddrRet == NULL)
    {
        goto err_out_free_nc_and_tci;
    }
    PeerAddrRet->OptionsLength = 0;
    NetioContext->PeerAddrRet = PeerAddrRet;

    IoMarkIrpPending(Irp);
    ReferenceSocket(Socket);

    status = TdiConnect(&tdiIrp, Socket->ConnectionFile, TargetConnectionInfo, PeerAddrRet, NetioComplete, NetioContext);

    if (!NT_SUCCESS(status))
    {
        /* If allocating tdiIrp fails we get here.
         * Call the IoCompletion of the application's Irp so this Irp
         * gets freed.
         */
        ExFreePoolWithTag(PeerAddrRet, TAG_NETIO);
        DereferenceSocket(Socket);
        goto err_out_free_nc_and_tci;
    }
    return STATUS_PENDING;

err_out_free_nc_and_tci:
    ExFreePoolWithTag(TargetConnectionInfo, TAG_AFD_TDI_CONNECTION_INFORMATION);

err_out_free_nc_and_disassociate:
    status2 = TdiDisassociateAddressFile(Socket->ConnectionFile);
    if (!NT_SUCCESS(status2))
    {
        DPRINT1("Warning: TdiDisassociateAddressFile returned status %08x\n", status);
    }
    Socket->ConnectionFileAssociated = FALSE;

err_out_free_nc:
    ExFreePoolWithTag(NetioContext, TAG_NETIO);

err_out:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);

    return status;
}

static NTSTATUS WSKAPI
WskStreamIo(
    _In_ PWSK_SOCKET SocketParam,
    _In_ PWSK_BUF Buffer,
    _In_ ULONG Flags,
     _Inout_ PIRP Irp,
    _In_ enum direction Direction)
{
    PIRP tdiIrp = NULL;
    PWSK_SOCKET_INTERNAL Socket = CONTAINING_RECORD(SocketParam, WSK_SOCKET_INTERNAL, Socket);
    NTSTATUS status;
    void *BufferData;
    PNETIO_CONTEXT NetioContext;

    FUNCTION_TRACE;

    IoSetNextIrpStackLocation(Irp);
    status = STATUS_INSUFFICIENT_RESOURCES;

    NetioContext = ExAllocatePoolUninitialized(NonPagedPool, sizeof(*NetioContext), TAG_NETIO);
    if (NetioContext == NULL)
    {
        goto err_out;
    }
    NetioContext->socket = Socket;
    NetioContext->UserIrp = Irp;

    NetioContext->TargetConnectionInfo = NULL;
    NetioContext->PeerAddrRet = NULL;

    BufferData = MmGetSystemAddressForMdlSafe(Buffer->Mdl, NormalPagePriority);
    if (BufferData == NULL)
    {
        DPRINT1("Error mapping MDL\n");
        goto err_out_free_nc;
    }

    IoMarkIrpPending(Irp);
    ReferenceSocket(Socket);

    if (Direction == DIR_SEND)
    {
        /* This will create a tdiIrp */
        status = TdiSend(&tdiIrp, Socket->ConnectionFile, 0, ((char *)BufferData) + Buffer->Offset,
                    Buffer->Length, NetioComplete, NetioContext);
    }
    else
    {
        status = TdiReceive(&tdiIrp, Socket->ConnectionFile, 0, ((char *)BufferData) + Buffer->Offset,
                       Buffer->Length, NetioComplete, NetioContext);
    }

    /* If allocating tdiIrp fails we get here.
     * Call the IoCompletion of the application's Irp so this Irp
     * gets freed.
     */
    if (!NT_SUCCESS(status))
    {
        goto err_out_free_nc;	/* caller has to clean up mdl mapping */
    }
    return STATUS_PENDING;

err_out_free_nc:
    ExFreePoolWithTag(NetioContext, TAG_NETIO);

err_out:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);

    return status;
}

static NTSTATUS WSKAPI
WskSend(_In_ PWSK_SOCKET SocketParam, _In_ PWSK_BUF Buffer, _In_ ULONG Flags, _Inout_ PIRP Irp)
{
    FUNCTION_TRACE;

    return WskStreamIo(SocketParam, Buffer, Flags, Irp, DIR_SEND);
}

static NTSTATUS WSKAPI
WskReceive(_In_ PWSK_SOCKET SocketParam, _In_ PWSK_BUF Buffer, _In_ ULONG Flags, _Inout_ PIRP Irp)
{
    FUNCTION_TRACE;

    return WskStreamIo(SocketParam, Buffer, Flags, Irp, DIR_RECEIVE);
}

static NTSTATUS WSKAPI
WskDisconnect(_In_ PWSK_SOCKET SocketParam, _In_opt_ PWSK_BUF Buffer, _In_ ULONG Flags, _Inout_ PIRP Irp)
{
    PWSK_SOCKET_INTERNAL Socket = CONTAINING_RECORD(SocketParam, WSK_SOCKET_INTERNAL, Socket);

    FUNCTION_TRACE;

    SocketShutdown(Socket);

    IoSetNextIrpStackLocation(Irp);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);

    return STATUS_PENDING;
}


static WSK_PROVIDER_CONNECTION_DISPATCH TcpDispatch = {
    .WskControlSocket = WskControlSocket,
    .WskCloseSocket = WskCloseSocket,
    .WskBind = WskBind,
    .WskConnect = WskConnect,
    .WskGetLocalAddress = WskGetLocalAddress,
    .WskGetRemoteAddress = WskGetRemoteAddress,
    .WskSend = WskSend,
    .WskReceive = WskReceive,
    .WskDisconnect = WskDisconnect,
    .WskRelease = WskReleaseTcp,
};

static NTSTATUS WSKAPI
WskSocket(
    _In_ PWSK_CLIENT Client,
    _In_ ADDRESS_FAMILY AddressFamily,
    _In_ USHORT SocketType,
    _In_ ULONG Protocol,
    _In_ ULONG Flags,
    _In_opt_ PVOID SocketContext,
    _In_opt_ const VOID * Dispatch,
    _In_opt_ PEPROCESS OwningProcess,
    _In_opt_ PETHREAD OwningThread,
    _In_opt_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _Inout_ PIRP Irp)
{
    PWSK_SOCKET_INTERNAL Socket;
    NTSTATUS status;

    FUNCTION_TRACE;

    IoSetNextIrpStackLocation(Irp);

    if (AddressFamily != AF_INET)
    {
        DPRINT1("Address family %d not supported\n", AddressFamily);
        status = STATUS_NOT_SUPPORTED;
        goto err_out;
    }
    switch (SocketType)
    {
        case SOCK_DGRAM:
            if (Protocol != IPPROTO_UDP)
            {
                DPRINT1("SOCK_DGRAM only supports IPPROTO_UDP\n");
                status = STATUS_INVALID_PARAMETER;
                goto err_out;
            }
            if (Flags != WSK_FLAG_DATAGRAM_SOCKET)
            {
                DPRINT1("SOCK_DGRAM flags must be WSK_FLAG_DATAGRAM_SOCKET\n");
                status = STATUS_INVALID_PARAMETER;
                goto err_out;
            }
            break;

        case SOCK_STREAM:
            if (Protocol != IPPROTO_TCP)
            {
                DPRINT1("SOCK_STREAM only supports IPPROTO_TCP\n");
                status = STATUS_INVALID_PARAMETER;
                goto err_out;
            }
            if ((Flags != WSK_FLAG_CONNECTION_SOCKET) && (Flags != WSK_FLAG_LISTEN_SOCKET))
            {
                DPRINT1("SOCK_STREAM flags must be either WSK_FLAG_CONNECTION_SOCKET or WSK_FLAG_LISTEN_SOCKET\n");
                status = STATUS_INVALID_PARAMETER;
                goto err_out;
            }
            break;

        case SOCK_RAW:
            DPRINT1("SOCK_RAW not supported\n");
            status = STATUS_NOT_SUPPORTED;
            goto err_out;

        default:
            status = STATUS_INVALID_PARAMETER;
            goto err_out;
    }

    Socket = ExAllocatePoolZero(NonPagedPool, sizeof(*Socket), TAG_NETIO);
    if (Socket == NULL)
    {
        DPRINT1("WskSocket: Out of memory\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto err_out;
    }
    Socket->family = AddressFamily;
    Socket->type = SocketType;
    Socket->proto = Protocol;
    Socket->WskFlags = Flags;
    Socket->user_context = SocketContext;
    Socket->ListenDispatch = Dispatch;
    Socket->RefCount = 1;            /* DereferenceSocket() is in WskCloseSocket */

    switch (SocketType)
    {
        case SOCK_DGRAM:
            Socket->Socket.Dispatch = &UdpDispatch;
            RtlInitUnicodeString(&Socket->TdiName, L"\\Device\\Udp");
            Socket->DatagramDispatch = Dispatch;
            KeInitializeSpinLock(&Socket->ReceiveLock);
            KeInitializeEvent(&Socket->ReceivesIdle, NotificationEvent, TRUE);
            /* WSK_SET_STATIC_EVENT_CALLBACKS turns receive events on for every new datagram socket */
            Socket->ReceiveEvents = Client != NULL &&
                                    (((PNETIO_WSK_CLIENT)Client)->EventMask & WSK_EVENT_RECEIVE_FROM) != 0;
            break;
        case SOCK_STREAM:
            Socket->Socket.Dispatch = &TcpDispatch;
            RtlInitUnicodeString(&Socket->TdiName, L"\\Device\\Tcp");

            if (Flags != WSK_FLAG_LISTEN_SOCKET)
            {
                status = TdiOpenConnectionEndpointFile(&Socket->TdiName, &Socket->ConnectionHandle, &Socket->ConnectionFile);
                if (!NT_SUCCESS(status))
                {
                    DPRINT1("Could not open TDI handle, status is %x\n", status);
                    ExFreePoolWithTag(Socket, TAG_NETIO);
                    goto err_out;
                }
            }
            else
            {
                KeInitializeEvent(&Socket->StartListenEvent, SynchronizationEvent, FALSE);
                Socket->ListenThreadShouldRun = TRUE;

                status = PsCreateSystemThread(&Socket->ListenThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, RequeueListenThread, Socket);
                if (!NT_SUCCESS(status))
                {
                    DPRINT1("Could not start listen thread, status is %x\n", status);
                    ExFreePoolWithTag(Socket, TAG_NETIO);
                    goto err_out;
                }
                status = ObReferenceObjectByHandle(Socket->ListenThreadHandle, THREAD_ALL_ACCESS, NULL, KernelMode, (void **)&Socket->ListenThread, NULL);
                if (!NT_SUCCESS(status))
                {
                    DPRINT1("Could not get a PKTHREAD object, status is %x\n", status);
                    ExFreePoolWithTag(Socket, TAG_NETIO);
                    goto err_out;
                }
                ZwClose(Socket->ListenThreadHandle);
            }

            if (Flags == WSK_FLAG_LISTEN_SOCKET && Socket->ListenDispatch == NULL)
            {
                DPRINT1("Warning: no callbacks given for listen socket\n");
            }
            break;

        default:
            DPRINT1("Socket type not yet supported\n");
            status = STATUS_NOT_SUPPORTED;
            goto err_out;
    }

    Irp->IoStatus.Information = (ULONG_PTR)Socket;
    status = STATUS_SUCCESS;

err_out:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);

    return STATUS_PENDING;
}

static WSK_PROVIDER_DISPATCH provider_dispatch = {
    .Version = 0,
    .Reserved = 0,
    .WskSocket = WskSocket,
    .WskSocketConnect = WskSocketConnect,
    .WskControlClient = WskControlClient
};

NTSTATUS WSKAPI
WskRegister(_In_ PWSK_CLIENT_NPI client_npi, _Out_ PWSK_REGISTRATION reg)
{
    FUNCTION_TRACE;

    reg->ReservedRegistrationState = 0;
    reg->ReservedRegistrationContext = NULL;
    KeInitializeSpinLock(&reg->ReservedRegistrationLock);

    return STATUS_SUCCESS;
}

NTSTATUS WSKAPI
WskCaptureProviderNPI(_In_ PWSK_REGISTRATION reg, _In_ ULONG wait, _Out_ PWSK_PROVIDER_NPI npi)
{
    FUNCTION_TRACE;

    PNETIO_WSK_CLIENT ClientContext;
    NTSTATUS Status;

    ClientContext = ExAllocatePoolZero(NonPagedPool, sizeof(*ClientContext), TAG_NETIO);
    if (ClientContext == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    Status = StartSocketDereferenceThread();
    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(ClientContext, TAG_NETIO);
        return Status;
    }
    reg->ReservedRegistrationContext = ClientContext;
    npi->Client = (PWSK_CLIENT)ClientContext;
    npi->Dispatch = &provider_dispatch;
    return STATUS_SUCCESS;
}

VOID WSKAPI
WskReleaseProviderNPI(_In_ PWSK_REGISTRATION reg)
{
    FUNCTION_TRACE;

    StopSocketDereferenceThread();
    if (reg->ReservedRegistrationContext)
    {
        ExFreePoolWithTag(reg->ReservedRegistrationContext, TAG_NETIO);
        reg->ReservedRegistrationContext = NULL;
    }
}

VOID WSKAPI
WskDeregister(_In_ PWSK_REGISTRATION reg)
{
    FUNCTION_TRACE;

    reg->ReservedRegistrationState = 0;
    reg->ReservedRegistrationContext = NULL;
}

NTSTATUS
NTAPI
NetioSetTriageBlock(VOID)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
NsiEnumerateObjectsAllParametersEx(VOID)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
NsiRegisterChangeNotificationEx(VOID)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
NsiSetAllParametersEx(VOID)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
NsiSetObjectSecurity(VOID)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
NsiSetParameterEx(VOID)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}
