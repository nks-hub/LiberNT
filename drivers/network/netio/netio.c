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
#define NETIO_RECEIVE_LIMIT (4 * 1024 * 1024)

struct _WSK_SOCKET_INTERNAL;

typedef struct _NETIO_RECEIVE
{
    struct _WSK_SOCKET_INTERNAL *Socket;
    PIRP Irp;
    PMDL Mdl;
    LIST_ENTRY ParkedEntry;
    volatile BOOLEAN InFlight;
    ULONG_PTR ConnInfo[(sizeof(TDI_CONNECTION_INFORMATION) + sizeof(TA_IP_ADDRESS) + sizeof(ULONG_PTR) - 1) / sizeof(ULONG_PTR)];
    DECLSPEC_ALIGN(8) UCHAR Control[64];
    UCHAR Data[NETIO_RECEIVE_SIZE];
} NETIO_RECEIVE, *PNETIO_RECEIVE;

typedef struct _NETIO_DATAGRAM
{
    WSK_DATAGRAM_INDICATION Indication;
    LIST_ENTRY Entry;
    struct _WSK_SOCKET_INTERNAL *Socket;
    PMDL Mdl;
    SIZE_T Size;
    SOCKADDR_IN Remote;
    DECLSPEC_ALIGN(8) UCHAR Control[64];
    UCHAR Data[ANYSIZE_ARRAY];
} NETIO_DATAGRAM, *PNETIO_DATAGRAM;

typedef struct _NETIO_WSK_CLIENT
{
    ULONG EventMask;
    KSPIN_LOCK Lock;
    BOOLEAN Deregistering;
    LONG Users;
    KEVENT Idle;
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
     * it will put the socket on this list and queue the work item
     * that dereferences the sockets on it.
     */
    struct _WSK_SOCKET_INTERNAL *NextSocketToDereference;
    ULONG NumSocketDereferences;

    PNETIO_WSK_CLIENT Client;

    const WSK_CLIENT_DATAGRAM_DISPATCH *DatagramDispatch;
    BOOLEAN ReceiveEvents;
    BOOLEAN ReceiveEventsStatic;
    LONG ReceiveCallbacks;
    PIRP DisableIrp;
    BOOLEAN PktInfo;
    BOOLEAN ReceiveStarted;
    volatile BOOLEAN ReceiveClosing;
    EX_RUNDOWN_REF ReceiveStartRundown;
    LONG ReceivesBusy;
    KEVENT ReceivesIdle;
    KSPIN_LOCK ReceiveLock;
    PNETIO_RECEIVE Receives[NETIO_RECEIVE_COUNT];
    LIST_ENTRY ReceiveQueue;
    ULONG ReceiveQueued;
    SIZE_T ReceiveBytes;           /* queued and retained datagrams, at most NETIO_RECEIVE_LIMIT */
    LIST_ENTRY ReceivesParked;     /* requests kept from tcpip until there is room for a datagram again */
    WORK_QUEUE_ITEM ResumeItem;
    BOOLEAN ResumeQueued;
    LONG DeferredSends;            /* queued sends; the close takes one off, so below zero means none are left */
    KEVENT SendsIdle;
} WSK_SOCKET_INTERNAL, *PWSK_SOCKET_INTERNAL;

typedef struct _NETIO_SEND_CONTROL
{
    DECLSPEC_ALIGN(8) UCHAR Data[32];
} NETIO_SEND_CONTROL, *PNETIO_SEND_CONTROL;

typedef struct _NETIO_CONTEXT
{
    PIRP UserIrp;
    PWSK_SOCKET_INTERNAL socket;
    PTDI_CONNECTION_INFORMATION TargetConnectionInfo;
    PTDI_CONNECTION_INFORMATION PeerAddrRet;
    NETIO_SEND_CONTROL SendControl;
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
static VOID
NetioCloseSocket(_In_ PWSK_SOCKET_INTERNAL Socket, _Inout_ PIRP Irp);
static VOID
NetioReceivesReleased(_In_ PWSK_SOCKET_INTERNAL Socket);
static VOID
NetioIndicateQueued(_In_ PWSK_SOCKET_INTERNAL Socket);
static NTSTATUS
NetioEnableReceiveEvent(_In_ PWSK_SOCKET_INTERNAL Socket);
static NTSTATUS
NetioDisableReceiveEvent(_In_ PWSK_SOCKET_INTERNAL Socket, _In_opt_ PIRP Irp);
static NTSTATUS WSKAPI
WskGetLocalAddress(_In_ PWSK_SOCKET SocketParam, _Out_ PSOCKADDR LocalAddress, _Inout_ PIRP Irp);
static NTSTATUS WSKAPI
WskControlSocket(_In_ PWSK_SOCKET SocketParam, _In_ WSK_CONTROL_SOCKET_TYPE RequestType, _In_ ULONG ControlCode,
                 _In_ ULONG Level, _In_ SIZE_T InputSize, _In_reads_bytes_opt_(InputSize) PVOID InputBuffer,
                 _In_ SIZE_T OutputSize, _Out_writes_bytes_opt_(OutputSize) PVOID OutputBuffer,
                 _Out_opt_ SIZE_T *OutputSizeReturned, _Inout_opt_ PIRP Irp);

typedef enum _NETIO_PASSIVE_KIND
{
    NetioPassiveLocalAddress,
    NetioPassivePktInfo,
    NetioPassiveResumeReceives,
    NetioPassiveClose,
} NETIO_PASSIVE_KIND;

typedef struct _NETIO_PASSIVE_REQUEST
{
    WORK_QUEUE_ITEM WorkItem;
    NETIO_PASSIVE_KIND Kind;
    struct _WSK_SOCKET_INTERNAL *Socket;
    PIRP Irp;
    PSOCKADDR LocalAddress;
    ULONG PktInfo;
} NETIO_PASSIVE_REQUEST, *PNETIO_PASSIVE_REQUEST;
static NTSTATUS
NetioSetAddressOption(_In_ PFILE_OBJECT AddressFile, _In_ ULONG Option, _In_ ULONG Value);

static BOOLEAN
NetioAddClientUser(_In_ PNETIO_WSK_CLIENT Client)
{
    BOOLEAN Added;
    KIRQL OldIrql;

    KeAcquireSpinLock(&Client->Lock, &OldIrql);
    Added = !Client->Deregistering;
    if (Added && Client->Users++ == 0)
        KeClearEvent(&Client->Idle);
    KeReleaseSpinLock(&Client->Lock, OldIrql);
    return Added;
}

static VOID
NetioRemoveClientUser(_In_ PNETIO_WSK_CLIENT Client)
{
    KIRQL OldIrql;

    KeAcquireSpinLock(&Client->Lock, &OldIrql);
    ASSERT(Client->Users > 0);
    if (--Client->Users == 0)
        KeSetEvent(&Client->Idle, IO_NO_INCREMENT, FALSE);
    KeReleaseSpinLock(&Client->Lock, OldIrql);
}

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
    PNETIO_WSK_CLIENT Client = Socket->Client;

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
    if (Client)
        NetioRemoveClientUser(Client);
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
static WORK_QUEUE_ITEM DereferenceSocketsWorkItem;
static BOOLEAN DereferenceSocketsWorkerQueued;

static VOID NTAPI
DereferenceSocketsWorker(_In_opt_ PVOID Context)
{
    PWSK_SOCKET_INTERNAL SocketToDereference;
    KIRQL OldIrql;
    ULONG NumSocketDereferences;

    UNREFERENCED_PARAMETER(Context);

    ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    KeAcquireSpinLock(&SocketsToDereferenceListLock, &OldIrql);
    ASSERT(DereferenceSocketsWorkerQueued);
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
    DereferenceSocketsWorkerQueued = FALSE;
    KeReleaseSpinLock(&SocketsToDereferenceListLock, OldIrql);
}

static void
DereferenceSocket(_In_ PWSK_SOCKET_INTERNAL Socket)
{
    KIRQL OldIrql;
    BOOLEAN Queue;

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
        Queue = !DereferenceSocketsWorkerQueued;
        DereferenceSocketsWorkerQueued = TRUE;
        KeReleaseSpinLock(&SocketsToDereferenceListLock, OldIrql);

        if (Queue)
        {
            ExInitializeWorkItem(&DereferenceSocketsWorkItem, DereferenceSocketsWorker, NULL);
            ExQueueWorkItem(&DereferenceSocketsWorkItem, DelayedWorkQueue);
        }

        return;
    }
    DereferenceSocketSynchronous(Socket);
}

static VOID NTAPI
NetioPassiveWorker(
    _In_ PVOID Context)
{
    PNETIO_PASSIVE_REQUEST Request = Context;
    PWSK_SOCKET_INTERNAL Socket = Request->Socket;

    ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    ASSERT(Socket->RefCount > 0);

    switch (Request->Kind)
    {
        case NetioPassiveLocalAddress:
            WskGetLocalAddress(&Socket->Socket, Request->LocalAddress, Request->Irp);
            break;

        case NetioPassivePktInfo:
            WskControlSocket(&Socket->Socket, WskSetOption, IP_PKTINFO, IPPROTO_IP, sizeof(Request->PktInfo),
                             &Request->PktInfo, 0, NULL, NULL, Request->Irp);
            break;

        case NetioPassiveResumeReceives:
            NetioIndicateQueued(Socket);
            NetioReceivesReleased(Socket);
            break;

        case NetioPassiveClose:
            /* The reference of the request must be gone before the IRP completes: the last one closes the address */
            ASSERT(Socket->RefCount > 1);
            DereferenceSocket(Socket);
            NetioCloseSocket(Socket, Request->Irp);
            ExFreePoolWithTag(Request, TAG_NETIO);
            return;
    }

    DereferenceSocket(Socket);
    ExFreePoolWithTag(Request, TAG_NETIO);
}

static NTSTATUS
NetioQueuePassive(
    _In_ PWSK_SOCKET_INTERNAL Socket,
    _In_ NETIO_PASSIVE_KIND Kind,
    _In_opt_ PIRP Irp,
    _In_opt_ PSOCKADDR LocalAddress,
    _In_ ULONG PktInfo)
{
    PNETIO_PASSIVE_REQUEST Request = ExAllocatePoolZero(NonPagedPool, sizeof(*Request), TAG_NETIO);

    if (Request == NULL)
    {
        if (Irp == NULL)
            return STATUS_INSUFFICIENT_RESOURCES;
        IoSetNextIrpStackLocation(Irp);
        Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);
        return STATUS_PENDING;
    }

    ASSERT(Kind == NetioPassiveResumeReceives || Irp != NULL);
    ASSERT(Socket->RefCount > 0);

    Request->Kind = Kind;
    Request->Socket = Socket;
    Request->Irp = Irp;
    Request->LocalAddress = LocalAddress;
    Request->PktInfo = PktInfo;
    ReferenceSocket(Socket);
    ExInitializeWorkItem(&Request->WorkItem, NetioPassiveWorker, Request);
    ExQueueWorkItem(&Request->WorkItem, CriticalWorkQueue);
    return STATUS_PENDING;
}

NTSTATUS
WfpCreateDevice(
    _In_ PDRIVER_OBJECT DriverObject);

NTSTATUS NTAPI
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    FUNCTION_TRACE;

    return WfpCreateDevice(DriverObject);
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
    KIRQL OldIrql;

    FUNCTION_TRACE;

    if (Socket != NULL && RequestType == WskSetOption && Level == IPPROTO_IP && ControlCode == IP_PKTINFO &&
        Socket->type == SOCK_DGRAM && Socket->LocalAddressFile != NULL && Irp != NULL &&
        InputBuffer != NULL && InputSize >= sizeof(ULONG) && KeGetCurrentIrql() > PASSIVE_LEVEL)
    {
        return NetioQueuePassive(Socket, NetioPassivePktInfo, Irp, NULL, *(PULONG)InputBuffer);
    }

    if (Irp != NULL)
        IoSetNextIrpStackLocation(Irp);

    if (Socket == NULL)
    {
        status = STATUS_INVALID_PARAMETER;
        goto err_out;
    }

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
                            if (Socket->type == SOCK_DGRAM && (Control->EventMask & WSK_EVENT_RECEIVE_FROM))
                            {
                                if (Socket->ReceiveEventsStatic)
                                    status = STATUS_INVALID_PARAMETER;
                                else if (Control->EventMask & WSK_EVENT_DISABLE)
                                {
                                    status = NetioDisableReceiveEvent(Socket, Irp);
                                    if (status == STATUS_PENDING)
                                        return STATUS_PENDING;
                                }
                                else
                                {
                                    status = NetioEnableReceiveEvent(Socket);
                                }
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
                    if (InputBuffer == NULL || InputSize < sizeof(ULONG) ||
                        (Socket->LocalAddressFile && KeGetCurrentIrql() > PASSIVE_LEVEL))
                    {
                        status = STATUS_INVALID_PARAMETER;
                        break;
                    }
                    status = Socket->LocalAddressFile ?
                             NetioSetAddressOption(Socket->LocalAddressFile, AO_OPTION_IP_PKTINFO, *(PULONG)InputBuffer != 0) :
                             STATUS_SUCCESS;
                    if (NT_SUCCESS(status))
                    {
                        KeAcquireSpinLock(&Socket->ReceiveLock, &OldIrql);
                        Socket->PktInfo = *(PULONG)InputBuffer != 0;
                        KeReleaseSpinLock(&Socket->ReceiveLock, OldIrql);
                    }
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
    if (Irp == NULL)
        return status;
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);

    return STATUS_PENDING;
}

static VOID
NetioCloseSocket(_In_ PWSK_SOCKET_INTERNAL Socket, _Inout_ PIRP Irp)
{
    NTSTATUS status = STATUS_SUCCESS;

    ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    IoSetNextIrpStackLocation(Irp);

    /* A send deferred from DISPATCH_LEVEL must go out before the close completes */
    if (InterlockedDecrement(&Socket->DeferredSends) >= 0)
        KeWaitForSingleObject(&Socket->SendsIdle, Executive, KernelMode, FALSE, NULL);

    /* There might be a reference from (for example) a pending
     * receive. Shutdown the socket here explicitly. We expect
     * all pending I/O operations to be cancelled, then.
     */

    SocketShutdown(Socket);
    DereferenceSocket(Socket);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);
}

static NTSTATUS WSKAPI
WskCloseSocket(_In_ PWSK_SOCKET SocketParam, _Inout_ PIRP Irp)
{
    PWSK_SOCKET_INTERNAL Socket = CONTAINING_RECORD(SocketParam, WSK_SOCKET_INTERNAL, Socket);

    /* The close completes once the client has released the datagrams it retains */
    if (KeGetCurrentIrql() > PASSIVE_LEVEL || Socket->ReceiveStarted)
        return NetioQueuePassive(Socket, NetioPassiveClose, Irp, NULL, 0);

    NetioCloseSocket(Socket, Irp);
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
    PFILE_OBJECT AddressFile;
    HANDLE AddressHandle;
    BOOLEAN PktInfo;
    KIRQL OldIrql;

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

    /* A failed open sets the handle to INVALID_HANDLE_VALUE, which must not reach the socket */
    status = TdiOpenAddressFile(&Socket->TdiName, ta, AFD_SHARE_REUSE, &AddressHandle, &AddressFile);

    ExFreePoolWithTag(ta, TAG_NETIO);

    if (!NT_SUCCESS(status))
        goto err_out;

    Socket->LocalAddressFile = AddressFile;
    Socket->LocalAddressHandle = AddressHandle;

    if (Socket->type == SOCK_DGRAM)
    {
        KeAcquireSpinLock(&Socket->ReceiveLock, &OldIrql);
        PktInfo = Socket->PktInfo;
        KeReleaseSpinLock(&Socket->ReceiveLock, OldIrql);
        if (PktInfo)
            status = NetioSetAddressOption(AddressFile, AO_OPTION_IP_PKTINFO, TRUE);
        if (NT_SUCCESS(status) && Socket->ReceiveEvents)
            status = NetioStartReceives(Socket);

        if (!NT_SUCCESS(status))
        {
            /* Receives can have been started by a client that enabled the event meanwhile */
            NetioStopReceives(Socket);
            ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
            ExWaitForRundownProtectionRelease(&Socket->ReceiveStartRundown);
            KeAcquireSpinLock(&Socket->ReceiveLock, &OldIrql);
            ASSERT(!Socket->ReceiveStarted);
            Socket->LocalAddressFile = NULL;
            Socket->ReceiveClosing = FALSE;
            KeReleaseSpinLock(&Socket->ReceiveLock, OldIrql);
            ExReInitializeRundownProtection(&Socket->ReceiveStartRundown);

            Socket->LocalAddressHandle = NULL;
            ObDereferenceObject(AddressFile);
            ZwClose(AddressHandle);
        }
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
NetioBuildSendControl(
    _In_ ULONG ControlInfoLength,
    _In_reads_bytes_opt_(ControlInfoLength) PCMSGHDR ControlInfo,
    _Inout_ PTDI_CONNECTION_INFORMATION Target,
    _Inout_ PNETIO_SEND_CONTROL Storage)
{
    ULONG Offset = 0;

    if (ControlInfoLength != 0 && ControlInfo == NULL)
        return STATUS_INVALID_PARAMETER;

    while (Offset < ControlInfoLength)
    {
        PCMSGHDR Header = (PCMSGHDR)((PUCHAR)ControlInfo + Offset);

        if (ControlInfoLength - Offset < sizeof(WSACMSGHDR) ||
            Header->cmsg_len < WSA_CMSG_LEN(0) || Header->cmsg_len > ControlInfoLength - Offset)
        {
            return STATUS_INVALID_PARAMETER;
        }

        if (Header->cmsg_level == IPPROTO_IP && Header->cmsg_type == IP_PKTINFO)
        {
            if (Header->cmsg_len < WSA_CMSG_LEN(sizeof(IN_PKTINFO)))
                return STATUS_INVALID_PARAMETER;

            ASSERT(TDI_CMSG_SPACE(sizeof(IN_PKTINFO)) <= sizeof(*Storage));
            RtlZeroMemory(Storage, sizeof(*Storage));
            TDI_INIT_CMSGHDR(Storage->Data, IPPROTO_IP, IP_PKTINFO, sizeof(IN_PKTINFO));
            RtlCopyMemory(TDI_CMSG_DATA(Storage->Data), WSA_CMSG_DATA(Header), sizeof(IN_PKTINFO));
            Target->Options = Storage->Data;
            Target->OptionsLength = (LONG)TDI_CMSG_SPACE(sizeof(IN_PKTINFO));
        }

        if (WSA_CMSGHDR_ALIGN(Header->cmsg_len) >= ControlInfoLength - Offset)
            break;
        Offset += (ULONG)WSA_CMSGHDR_ALIGN(Header->cmsg_len);
    }

    return STATUS_SUCCESS;
}

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

    status = NetioBuildSendControl(ControlInfoLength, ControlInfo, TargetConnectionInfo, &NetioContext->SendControl);
    if (!NT_SUCCESS(status))
    {
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

    ASSERT(Socket->ReceivesBusy > 0);
    if (InterlockedDecrement(&Socket->ReceivesBusy) == 0)
        KeSetEvent(&Socket->ReceivesIdle, IO_NO_INCREMENT, FALSE);
}

static IO_COMPLETION_ROUTINE NetioReceiveComplete;

static BOOLEAN
NetioReceiveHasRoom(
    _In_ PWSK_SOCKET_INTERNAL Socket)
{
    return Socket->ReceiveBytes + FIELD_OFFSET(NETIO_DATAGRAM, Data) + NETIO_RECEIVE_SIZE <= NETIO_RECEIVE_LIMIT;
}

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
    if (!NetioReceiveHasRoom(Socket))
    {
        /* Without a request tcpip discards what arrives, as UDP does when the receive buffer is full */
        InsertTailList(&Socket->ReceivesParked, &Receive->ParkedEntry);
        KeReleaseSpinLock(&Socket->ReceiveLock, OldIrql);
        return;
    }
    ASSERT(!Receive->InFlight);
    Receive->InFlight = TRUE;
    KeReleaseSpinLock(&Socket->ReceiveLock, OldIrql);

    IoReuseIrp(Receive->Irp, STATUS_SUCCESS);
    TdiBuildNullConnectionInfoInPlace(ConnInfo, TDI_ADDRESS_TYPE_IP);
    ConnInfo->Options = Receive->Control;
    ConnInfo->OptionsLength = sizeof(Receive->Control);
    TdiBuildReceiveDatagram(Receive->Irp, DeviceObject, Socket->LocalAddressFile, NetioReceiveComplete,
                            Receive, Receive->Mdl, NETIO_RECEIVE_SIZE, ConnInfo, ConnInfo, 0);
    IoCallDriver(DeviceObject, Receive->Irp);
}

static VOID
NetioCompleteDisable(
    _In_opt_ PIRP Irp)
{
    if (Irp == NULL)
        return;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);
}

static VOID NTAPI
NetioResumeWorker(
    _In_ PVOID Context)
{
    PWSK_SOCKET_INTERNAL Socket = Context;
    LIST_ENTRY Parked;
    KIRQL OldIrql;

    ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    ASSERT(Socket->ReceivesBusy > 0);

    InitializeListHead(&Parked);
    KeAcquireSpinLock(&Socket->ReceiveLock, &OldIrql);
    ASSERT(Socket->ResumeQueued);
    Socket->ResumeQueued = FALSE;
    while (!IsListEmpty(&Socket->ReceivesParked))
        InsertTailList(&Parked, RemoveHeadList(&Socket->ReceivesParked));
    KeReleaseSpinLock(&Socket->ReceiveLock, OldIrql);

    while (!IsListEmpty(&Parked))
        NetioPostReceive(CONTAINING_RECORD(RemoveHeadList(&Parked), NETIO_RECEIVE, ParkedEntry));
    NetioReceivesReleased(Socket);
}

static VOID
NetioFreeDatagram(
    _In_ PNETIO_DATAGRAM Datagram)
{
    PWSK_SOCKET_INTERNAL Socket = Datagram->Socket;
    KIRQL OldIrql;

    KeAcquireSpinLock(&Socket->ReceiveLock, &OldIrql);
    ASSERT(Socket->ReceiveBytes >= Datagram->Size);
    Socket->ReceiveBytes -= Datagram->Size;
    if (!IsListEmpty(&Socket->ReceivesParked) && !Socket->ResumeQueued && NetioReceiveHasRoom(Socket))
    {
        /* The client can release at DISPATCH_LEVEL, where tcpip cannot take a receive request */
        Socket->ResumeQueued = TRUE;
        ASSERT(Socket->ReceivesBusy > 0);
        InterlockedIncrement(&Socket->ReceivesBusy);
        ExInitializeWorkItem(&Socket->ResumeItem, NetioResumeWorker, Socket);
        ExQueueWorkItem(&Socket->ResumeItem, CriticalWorkQueue);
    }
    KeReleaseSpinLock(&Socket->ReceiveLock, OldIrql);

    IoFreeMdl(Datagram->Mdl);
    ExFreePoolWithTag(Datagram, TAG_NETIO);
    NetioReceivesReleased(Socket);
}

static VOID
NetioQueueDatagram(
    _In_ PNETIO_RECEIVE Receive,
    _In_ SIZE_T Length)
{
    PWSK_SOCKET_INTERNAL Socket = Receive->Socket;
    PTDI_CONNECTION_INFORMATION ConnInfo = (PTDI_CONNECTION_INFORMATION)Receive->ConnInfo;
    PTA_IP_ADDRESS Source = (PTA_IP_ADDRESS)ConnInfo->RemoteAddress;
    SIZE_T Size = Length != 0 ? Length : 1;
    PNETIO_DATAGRAM Datagram;
    BOOLEAN Queued;
    KIRQL OldIrql;

    ASSERT(Length <= NETIO_RECEIVE_SIZE);

    Datagram = ExAllocatePoolZero(NonPagedPool, FIELD_OFFSET(NETIO_DATAGRAM, Data) + Size, TAG_NETIO);
    if (Datagram == NULL)
        return;
    Datagram->Mdl = IoAllocateMdl(Datagram->Data, (ULONG)Size, FALSE, FALSE, NULL);
    if (Datagram->Mdl == NULL)
    {
        ExFreePoolWithTag(Datagram, TAG_NETIO);
        return;
    }
    MmBuildMdlForNonPagedPool(Datagram->Mdl);
    RtlCopyMemory(Datagram->Data, Receive->Data, Length);
    Datagram->Socket = Socket;
    Datagram->Size = FIELD_OFFSET(NETIO_DATAGRAM, Data) + Size;

    Datagram->Remote.sin_family = AF_INET;
    Datagram->Remote.sin_port = Source->Address[0].Address[0].sin_port;
    Datagram->Remote.sin_addr.s_addr = Source->Address[0].Address[0].in_addr;

    Datagram->Indication.Buffer.Mdl = Datagram->Mdl;
    Datagram->Indication.Buffer.Length = Length;
    Datagram->Indication.ControlInfoLength = min((ULONG)ConnInfo->OptionsLength, (ULONG)sizeof(Datagram->Control));
    if (Datagram->Indication.ControlInfoLength != 0)
    {
        RtlCopyMemory(Datagram->Control, Receive->Control, Datagram->Indication.ControlInfoLength);
        Datagram->Indication.ControlInfo = (PCMSGHDR)Datagram->Control;
    }
    Datagram->Indication.RemoteAddress = (PSOCKADDR)&Datagram->Remote;

    KeAcquireSpinLock(&Socket->ReceiveLock, &OldIrql);
    if (!Socket->PktInfo)
    {
        Datagram->Indication.ControlInfoLength = 0;
        Datagram->Indication.ControlInfo = NULL;
    }
    Queued = !Socket->ReceiveClosing && Socket->ReceiveBytes + Datagram->Size <= NETIO_RECEIVE_LIMIT &&
             (Socket->ReceiveEvents || Socket->ReceiveQueued < NETIO_RECEIVE_COUNT);
    if (Queued)
    {
        InsertTailList(&Socket->ReceiveQueue, &Datagram->Entry);
        Socket->ReceiveQueued++;
        Socket->ReceiveBytes += Datagram->Size;
        ASSERT(Socket->ReceivesBusy > 0);
        InterlockedIncrement(&Socket->ReceivesBusy);
    }
    KeReleaseSpinLock(&Socket->ReceiveLock, OldIrql);

    if (!Queued)
    {
        IoFreeMdl(Datagram->Mdl);
        ExFreePoolWithTag(Datagram, TAG_NETIO);
    }
}

static VOID
NetioIndicateQueued(
    _In_ PWSK_SOCKET_INTERNAL Socket)
{
    PNETIO_DATAGRAM Datagram;
    PIRP DisableIrp;
    NTSTATUS Status;
    BOOLEAN Keep;
    KIRQL OldIrql;

    /* The caller holds a busy count: freeing the last datagram here would otherwise let the close free the socket */
    ASSERT(Socket->ReceivesBusy > 0);

    for (;;)
    {
        KeAcquireSpinLock(&Socket->ReceiveLock, &OldIrql);
        if (Socket->ReceiveCallbacks != 0 || !Socket->ReceiveEvents || Socket->ReceiveClosing ||
            IsListEmpty(&Socket->ReceiveQueue))
        {
            KeReleaseSpinLock(&Socket->ReceiveLock, OldIrql);
            return;
        }
        Datagram = CONTAINING_RECORD(RemoveHeadList(&Socket->ReceiveQueue), NETIO_DATAGRAM, Entry);
        ASSERT(Socket->ReceiveQueued > 0);
        Socket->ReceiveQueued--;
        Socket->ReceiveCallbacks++;
        KeReleaseSpinLock(&Socket->ReceiveLock, OldIrql);

        Status = Socket->DatagramDispatch->WskReceiveFromEvent(
            Socket->user_context,
            KeGetCurrentIrql() == DISPATCH_LEVEL ? WSK_FLAG_AT_DISPATCH_LEVEL : 0,
            &Datagram->Indication);

        /* The client keeps the data until it calls WskRelease */
        Keep = Status == STATUS_PENDING;

        KeAcquireSpinLock(&Socket->ReceiveLock, &OldIrql);
        if (Status == STATUS_DATA_NOT_ACCEPTED && !Socket->ReceiveEventsStatic && !Socket->ReceiveClosing)
        {
            Socket->ReceiveEvents = FALSE;
            InsertHeadList(&Socket->ReceiveQueue, &Datagram->Entry);
            Socket->ReceiveQueued++;
            Keep = TRUE;
        }
        ASSERT(Socket->ReceiveCallbacks == 1);
        Socket->ReceiveCallbacks--;
        DisableIrp = Socket->DisableIrp;
        Socket->DisableIrp = NULL;
        KeReleaseSpinLock(&Socket->ReceiveLock, OldIrql);
        NetioCompleteDisable(DisableIrp);

        if (!Keep)
            NetioFreeDatagram(Datagram);
    }
}

static NTSTATUS NTAPI
NetioReceiveComplete(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_opt_ PVOID Context)
{
    PNETIO_RECEIVE Receive = Context;
    PWSK_SOCKET_INTERNAL Socket = Receive->Socket;
    NTSTATUS Status = Irp->IoStatus.Status;
    KIRQL OldIrql;

    UNREFERENCED_PARAMETER(DeviceObject);

    KeAcquireSpinLock(&Socket->ReceiveLock, &OldIrql);
    ASSERT(Receive->InFlight);
    Receive->InFlight = FALSE;
    KeReleaseSpinLock(&Socket->ReceiveLock, OldIrql);

    if (NT_SUCCESS(Status) && !Socket->ReceiveClosing)
    {
        NetioQueueDatagram(Receive, (SIZE_T)Irp->IoStatus.Information);
        NetioIndicateQueued(Socket);
        NetioPostReceive(Receive);
    }
    else if (Status == STATUS_BUFFER_OVERFLOW && !Socket->ReceiveClosing)
    {
        NetioPostReceive(Receive);
    }
    else
    {
        if (!Socket->ReceiveClosing)
            DPRINT1("Datagram receive failed with status 0x%08lx, receiving stops\n", Status);
        NetioReceiveDone(Receive);
    }
    return STATUS_MORE_PROCESSING_REQUIRED;
}

static VOID
NetioReceivesReleased(
    _In_ PWSK_SOCKET_INTERNAL Socket)
{
    ASSERT(Socket->ReceivesBusy > 0);
    if (InterlockedDecrement(&Socket->ReceivesBusy) == 0)
        KeSetEvent(&Socket->ReceivesIdle, IO_NO_INCREMENT, FALSE);
}

static NTSTATUS
NetioEnableReceiveEvent(
    _In_ PWSK_SOCKET_INTERNAL Socket)
{
    NTSTATUS Status;
    KIRQL OldIrql;
    BOOLEAN Resume = FALSE;

    KeAcquireSpinLock(&Socket->ReceiveLock, &OldIrql);
    Socket->ReceiveEvents = TRUE;
    if (Socket->ReceiveStarted && !Socket->ReceiveClosing)
    {
        Resume = !IsListEmpty(&Socket->ReceiveQueue);
        if (Resume)
        {
            ASSERT(Socket->ReceivesBusy > 0);
            InterlockedIncrement(&Socket->ReceivesBusy);
        }
    }
    KeReleaseSpinLock(&Socket->ReceiveLock, OldIrql);

    if (!Resume)
        return NetioStartReceives(Socket);

    Status = NetioQueuePassive(Socket, NetioPassiveResumeReceives, NULL, NULL, 0);
    if (Status != STATUS_PENDING)
    {
        NetioReceivesReleased(Socket);
        return Status;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS
NetioDisableReceiveEvent(
    _In_ PWSK_SOCKET_INTERNAL Socket,
    _In_opt_ PIRP Irp)
{
    NTSTATUS Status = STATUS_SUCCESS;
    KIRQL OldIrql;

    KeAcquireSpinLock(&Socket->ReceiveLock, &OldIrql);
    Socket->ReceiveEvents = FALSE;
    if (Socket->ReceiveCallbacks != 0)
    {
        if (Irp != NULL && Socket->DisableIrp == NULL)
        {
            Socket->DisableIrp = Irp;
            Status = STATUS_PENDING;
        }
        else
        {
            Status = STATUS_EVENT_PENDING;
        }
    }
    KeReleaseSpinLock(&Socket->ReceiveLock, OldIrql);
    return Status;
}

static VOID
NetioFreeReceives(
    _Inout_updates_(NETIO_RECEIVE_COUNT) PNETIO_RECEIVE *Receives)
{
    ULONG i;

    for (i = 0; i < NETIO_RECEIVE_COUNT; i++)
    {
        PNETIO_RECEIVE Receive = Receives[i];

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
        Receives[i] = NULL;
    }
}

static NTSTATUS
NetioStartReceives(
    _In_ PWSK_SOCKET_INTERNAL Socket)
{
    PNETIO_RECEIVE Receives[NETIO_RECEIVE_COUNT] = { NULL };
    PDEVICE_OBJECT DeviceObject;
    PFILE_OBJECT AddressFile;
    NTSTATUS Status = STATUS_SUCCESS;
    BOOLEAN Start;
    KIRQL OldIrql;
    ULONG i;

    if (Socket->DatagramDispatch == NULL || Socket->DatagramDispatch->WskReceiveFromEvent == NULL)
        return STATUS_SUCCESS;

    /* A bind that failed waits for this protection before it releases the address file */
    if (!ExAcquireRundownProtection(&Socket->ReceiveStartRundown))
        return STATUS_SUCCESS;

    KeAcquireSpinLock(&Socket->ReceiveLock, &OldIrql);
    AddressFile = (Socket->ReceiveStarted || Socket->ReceiveClosing) ? NULL : Socket->LocalAddressFile;
    KeReleaseSpinLock(&Socket->ReceiveLock, OldIrql);
    if (AddressFile == NULL)
        goto Done;

    DeviceObject = IoGetRelatedDeviceObject(AddressFile);
    for (i = 0; i < NETIO_RECEIVE_COUNT; i++)
    {
        PNETIO_RECEIVE Receive = ExAllocatePoolZero(NonPagedPool, sizeof(*Receive), TAG_NETIO);

        if (Receive == NULL)
            goto Fail;
        Receives[i] = Receive;
        Receive->Socket = Socket;
        Receive->Irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);
        Receive->Mdl = IoAllocateMdl(Receive->Data, NETIO_RECEIVE_SIZE, FALSE, FALSE, NULL);
        if (Receive->Irp == NULL || Receive->Mdl == NULL)
            goto Fail;
        MmBuildMdlForNonPagedPool(Receive->Mdl);
    }

    /* Another caller can have started the receives, or the close can have begun, since the check above */
    KeAcquireSpinLock(&Socket->ReceiveLock, &OldIrql);
    Start = !Socket->ReceiveStarted && !Socket->ReceiveClosing;
    if (Start)
    {
        ASSERT(Socket->LocalAddressFile == AddressFile);
        RtlCopyMemory(Socket->Receives, Receives, sizeof(Receives));
        KeClearEvent(&Socket->ReceivesIdle);
        Socket->ReceivesBusy = NETIO_RECEIVE_COUNT;
        Socket->ReceiveStarted = TRUE;
    }
    KeReleaseSpinLock(&Socket->ReceiveLock, OldIrql);

    if (!Start)
    {
        NetioFreeReceives(Receives);
        goto Done;
    }

    for (i = 0; i < NETIO_RECEIVE_COUNT; i++)
        NetioPostReceive(Receives[i]);
    goto Done;

Fail:
    NetioFreeReceives(Receives);
    Status = STATUS_INSUFFICIENT_RESOURCES;
Done:
    ExReleaseRundownProtection(&Socket->ReceiveStartRundown);
    return Status;
}

static VOID
NetioStopReceives(
    _In_ PWSK_SOCKET_INTERNAL Socket)
{
    LARGE_INTEGER Timeout;
    LIST_ENTRY Queue;
    BOOLEAN Started;
    KIRQL OldIrql;
    ULONG i;

    if (Socket->type != SOCK_DGRAM)
        return;

    InitializeListHead(&Queue);
    KeAcquireSpinLock(&Socket->ReceiveLock, &OldIrql);
    Socket->ReceiveClosing = TRUE;
    Started = Socket->ReceiveStarted;
    while (!IsListEmpty(&Socket->ReceiveQueue))
        InsertTailList(&Queue, RemoveHeadList(&Socket->ReceiveQueue));
    Socket->ReceiveQueued = 0;
    while (!IsListEmpty(&Socket->ReceivesParked))
        NetioReceiveDone(CONTAINING_RECORD(RemoveHeadList(&Socket->ReceivesParked), NETIO_RECEIVE, ParkedEntry));
    KeReleaseSpinLock(&Socket->ReceiveLock, OldIrql);

    while (!IsListEmpty(&Queue))
        NetioFreeDatagram(CONTAINING_RECORD(RemoveHeadList(&Queue), NETIO_DATAGRAM, Entry));

    if (!Started)
        return;

    ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    Timeout.QuadPart = -1000000LL;
    do
    {
        /* A receive can be posted again just after a cancel; cancel until all are back */
        for (i = 0; i < NETIO_RECEIVE_COUNT; i++)
        {
            if (Socket->Receives[i]->InFlight)
                IoCancelIrp(Socket->Receives[i]->Irp);
        }
    } while (KeWaitForSingleObject(&Socket->ReceivesIdle, Executive, KernelMode, FALSE, &Timeout) == STATUS_TIMEOUT);

    ASSERT(Socket->ReceivesBusy == 0);

    NetioFreeReceives(Socket->Receives);

    KeAcquireSpinLock(&Socket->ReceiveLock, &OldIrql);
    Socket->ReceiveStarted = FALSE;
    KeReleaseSpinLock(&Socket->ReceiveLock, OldIrql);
}

static NTSTATUS WSKAPI
WskReleaseUdp(_In_ PWSK_SOCKET SocketParam, _In_ PWSK_DATAGRAM_INDICATION DatagramIndication)
{
    PWSK_DATAGRAM_INDICATION Next;

    UNREFERENCED_PARAMETER(SocketParam);

    for (; DatagramIndication != NULL; DatagramIndication = Next)
    {
        Next = DatagramIndication->Next;
        NetioFreeDatagram(CONTAINING_RECORD(DatagramIndication, NETIO_DATAGRAM, Indication));
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

    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
        return NetioQueuePassive(Socket, NetioPassiveLocalAddress, Irp, LocalAddress, 0);

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
    NETIO_SEND_CONTROL SendControl;
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
    Status = NetioBuildSendControl(ControlInfoLength, ControlInfo, Batch->Target, &Batch->SendControl);
    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(Batch->Target, TAG_AFD_TDI_CONNECTION_INFORMATION);
        ExFreePoolWithTag(Batch, TAG_NETIO);
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
    SOCKADDR Address;
    ULONG ControlInfoLength;
    PCMSGHDR ControlInfo;
    PIRP Irp;
    WSK_BUF_LIST List[ANYSIZE_ARRAY];
} NETIO_DEFERRED_SEND, *PNETIO_DEFERRED_SEND;

static VOID NTAPI
NetioDeferredSendWorker(
    _In_ PVOID Context)
{
    PNETIO_DEFERRED_SEND Send = Context;
    PWSK_SOCKET_INTERNAL Socket = CONTAINING_RECORD(Send->Socket, WSK_SOCKET_INTERNAL, Socket);

    ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    if (Send->BufferList)
        WskSendMessages(Send->Socket, Send->BufferList, Send->Flags, Send->RemoteAddress,
                        Send->ControlInfoLength, Send->ControlInfo, Send->Irp);
    else
        WskSendTo(Send->Socket, &Send->Buffer, Send->Flags, Send->RemoteAddress,
                  Send->ControlInfoLength, Send->ControlInfo, Send->Irp);

    if (InterlockedDecrement(&Socket->DeferredSends) < 0)
        KeSetEvent(&Socket->SendsIdle, IO_NO_INCREMENT, FALSE);
    DereferenceSocket(Socket);
    ExFreePoolWithTag(Send, TAG_NETIO);
}

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
    PNETIO_DEFERRED_SEND Send = NULL;
    SIZE_T Count = 0, Size, ControlSize = ControlInfo ? ControlInfoLength : 0;
    PWSK_BUF_LIST Entry;

    ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);

    for (Entry = BufferList; Entry != NULL; Entry = Entry->Next)
        Count++;
    Size = FIELD_OFFSET(NETIO_DEFERRED_SEND, List) + Count * sizeof(WSK_BUF_LIST);
    if (ControlSize <= MAXULONG_PTR - Size)
        Send = ExAllocatePoolZero(NonPagedPool, Size + ControlSize, TAG_NETIO);

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
    for (Count = 0, Entry = BufferList; Entry != NULL; Entry = Entry->Next, Count++)
    {
        Send->List[Count].Buffer = Entry->Buffer;
        Send->List[Count].Next = Entry->Next ? &Send->List[Count + 1] : NULL;
    }
    if (BufferList)
        Send->BufferList = Send->List;
    Send->Flags = Flags;
    if (RemoteAddress)
    {
        Send->Address = *RemoteAddress;
        Send->RemoteAddress = &Send->Address;
    }
    Send->ControlInfoLength = ControlInfoLength;
    if (ControlInfo)
    {
        Send->ControlInfo = (PCMSGHDR)&Send->List[Count];
        RtlCopyMemory(Send->ControlInfo, ControlInfo, ControlInfoLength);
    }
    Send->Irp = Irp;
    ReferenceSocket(CONTAINING_RECORD(SocketParam, WSK_SOCKET_INTERNAL, Socket));
    InterlockedIncrement(&CONTAINING_RECORD(SocketParam, WSK_SOCKET_INTERNAL, Socket)->DeferredSends);
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
            ExInitializeRundownProtection(&Socket->ReceiveStartRundown);
            InitializeListHead(&Socket->ReceiveQueue);
            InitializeListHead(&Socket->ReceivesParked);
            KeInitializeEvent(&Socket->ReceivesIdle, NotificationEvent, TRUE);
            KeInitializeEvent(&Socket->SendsIdle, NotificationEvent, FALSE);
            Socket->ReceiveEvents = Client != NULL &&
                                    (((PNETIO_WSK_CLIENT)Client)->EventMask & WSK_EVENT_RECEIVE_FROM) != 0;
            Socket->ReceiveEventsStatic = Socket->ReceiveEvents;
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

    if (Client != NULL)
    {
        if (!NetioAddClientUser((PNETIO_WSK_CLIENT)Client))
        {
            DereferenceSocket(Socket);
            status = STATUS_DEVICE_NOT_READY;
            goto err_out;
        }
        Socket->Client = (PNETIO_WSK_CLIENT)Client;
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
    PNETIO_WSK_CLIENT Client;

    FUNCTION_TRACE;

    reg->ReservedRegistrationState = 0;
    reg->ReservedRegistrationContext = NULL;
    KeInitializeSpinLock(&reg->ReservedRegistrationLock);

    Client = ExAllocatePoolZero(NonPagedPool, sizeof(*Client), TAG_NETIO);
    if (Client == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    KeInitializeSpinLock(&Client->Lock);
    KeInitializeEvent(&Client->Idle, NotificationEvent, TRUE);

    reg->ReservedRegistrationContext = Client;
    return STATUS_SUCCESS;
}

NTSTATUS WSKAPI
WskCaptureProviderNPI(_In_ PWSK_REGISTRATION reg, _In_ ULONG wait, _Out_ PWSK_PROVIDER_NPI npi)
{
    PNETIO_WSK_CLIENT Client;
    KIRQL OldIrql;

    FUNCTION_TRACE;

    UNREFERENCED_PARAMETER(wait);

    /* WskDeregister detaches the client under this lock before it frees it */
    KeAcquireSpinLock(&reg->ReservedRegistrationLock, &OldIrql);
    Client = reg->ReservedRegistrationContext;
    if (Client != NULL && !NetioAddClientUser(Client))
        Client = NULL;
    KeReleaseSpinLock(&reg->ReservedRegistrationLock, OldIrql);

    if (Client == NULL)
        return STATUS_DEVICE_NOT_READY;
    npi->Client = (PWSK_CLIENT)Client;
    npi->Dispatch = &provider_dispatch;
    return STATUS_SUCCESS;
}

VOID WSKAPI
WskReleaseProviderNPI(_In_ PWSK_REGISTRATION reg)
{
    FUNCTION_TRACE;

    NetioRemoveClientUser(reg->ReservedRegistrationContext);
}

VOID WSKAPI
WskDeregister(_In_ PWSK_REGISTRATION reg)
{
    PNETIO_WSK_CLIENT Client;
    BOOLEAN Idle = TRUE;
    KIRQL OldIrql;

    FUNCTION_TRACE;

    KeAcquireSpinLock(&reg->ReservedRegistrationLock, &OldIrql);
    Client = reg->ReservedRegistrationContext;
    if (Client != NULL)
    {
        KeAcquireSpinLockAtDpcLevel(&Client->Lock);
        Client->Deregistering = TRUE;
        Idle = Client->Users == 0;
        KeReleaseSpinLockFromDpcLevel(&Client->Lock);
    }
    KeReleaseSpinLock(&reg->ReservedRegistrationLock, OldIrql);

    if (Client == NULL)
        return;

    if (!Idle)
    {
        ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
        KeWaitForSingleObject(&Client->Idle, Executive, KernelMode, FALSE, NULL);
    }

    /* WskReleaseProviderNPI still reads the client from the registration, so detach it only now */
    KeAcquireSpinLock(&reg->ReservedRegistrationLock, &OldIrql);
    reg->ReservedRegistrationState = 0;
    reg->ReservedRegistrationContext = NULL;
    KeReleaseSpinLock(&reg->ReservedRegistrationLock, OldIrql);

    KeAcquireSpinLock(&Client->Lock, &OldIrql);
    KeReleaseSpinLock(&Client->Lock, OldIrql);

    ExFreePoolWithTag(Client, TAG_NETIO);
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
