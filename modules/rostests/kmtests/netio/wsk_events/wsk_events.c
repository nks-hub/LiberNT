/*
 * PROJECT:     LiberNT kernel-mode tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     WSK datagram receive events: turning them off and on, refused datagrams,
 *              requests made at DISPATCH_LEVEL
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include <kmt_test.h>
#include <wsk.h>

#define NDEBUG
#include <debug.h>

#include "wsk_events.h"

#define MAX_SEEN 8

static KMT_MESSAGE_HANDLER TestMessageHandler;

static volatile LONG ReceiveCount;
static volatile BOOLEAN Refuse;
static CHAR Seen[MAX_SEEN][9];
static ULONG LastControlLength;

static
NTSTATUS
WSKAPI
ReceiveFromEvent(
    _In_opt_ PVOID SocketContext,
    _In_ ULONG Flags,
    _In_opt_ PWSK_DATAGRAM_INDICATION DataIndication)
{
    PCHAR Data;
    LONG Index;

    UNREFERENCED_PARAMETER(SocketContext);
    UNREFERENCED_PARAMETER(Flags);

    if (DataIndication == NULL)
        return STATUS_SUCCESS;

    Index = InterlockedIncrement(&ReceiveCount) - 1;
    Data = MmGetSystemAddressForMdlSafe(DataIndication->Buffer.Mdl, NormalPagePriority);
    if (Index < MAX_SEEN && Data != NULL && DataIndication->Buffer.Length >= 8)
        RtlCopyMemory(Seen[Index], Data + DataIndication->Buffer.Offset, 8);
    LastControlLength = DataIndication->ControlInfoLength;
    return Refuse ? STATUS_DATA_NOT_ACCEPTED : STATUS_SUCCESS;
}

static const WSK_CLIENT_DATAGRAM_DISPATCH DatagramDispatch = { ReceiveFromEvent };
static const WSK_CLIENT_DISPATCH ClientDispatch = { MAKE_WSK_VERSION(1, 0), 0, NULL };

static
NTSTATUS
NTAPI
IrpComplete(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    KeSetEvent(Context, IO_NO_INCREMENT, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

static
PIRP
NewIrp(
    _Out_ PKEVENT Event)
{
    PIRP Irp = IoAllocateIrp(1, FALSE);

    KeInitializeEvent(Event, NotificationEvent, FALSE);
    if (Irp != NULL)
        IoSetCompletionRoutine(Irp, IrpComplete, Event, TRUE, TRUE, TRUE);
    return Irp;
}

static
NTSTATUS
WaitIrp(
    _In_ PIRP Irp,
    _In_ PKEVENT Event,
    _In_ NTSTATUS Status)
{
    if (Status == STATUS_PENDING)
        KeWaitForSingleObject(Event, Executive, KernelMode, FALSE, NULL);
    return Irp->IoStatus.Status;
}

static
PWSK_SOCKET
OpenSocket(
    _In_ PWSK_PROVIDER_NPI Provider,
    _In_ USHORT Port)
{
    PWSK_SOCKET Socket = NULL;
    SOCKADDR_IN Address;
    KEVENT Event;
    NTSTATUS Status;
    PIRP Irp;

    Irp = NewIrp(&Event);
    if (Irp == NULL)
        return NULL;
    Status = Provider->Dispatch->WskSocket(Provider->Client, AF_INET, SOCK_DGRAM, IPPROTO_UDP,
                                           WSK_FLAG_DATAGRAM_SOCKET, NULL, &DatagramDispatch,
                                           NULL, NULL, NULL, Irp);
    Status = WaitIrp(Irp, &Event, Status);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
        Socket = (PWSK_SOCKET)Irp->IoStatus.Information;
    IoFreeIrp(Irp);
    if (Socket == NULL)
        return NULL;

    RtlZeroMemory(&Address, sizeof(Address));
    Address.sin_family = AF_INET;
    Address.sin_port = RtlUshortByteSwap(Port);
    Address.sin_addr.s_addr = RtlUlongByteSwap(0x7f000001);
    Irp = NewIrp(&Event);
    if (Irp != NULL)
    {
        Status = ((PWSK_PROVIDER_DATAGRAM_DISPATCH)Socket->Dispatch)->WskBind(Socket, (PSOCKADDR)&Address, 0, Irp);
        Status = WaitIrp(Irp, &Event, Status);
        ok_eq_hex(Status, STATUS_SUCCESS);
        IoFreeIrp(Irp);
    }
    return Socket;
}

static
VOID
CloseSocket(
    _In_ PWSK_SOCKET Socket)
{
    KEVENT Event;
    NTSTATUS Status;
    PIRP Irp;

    Irp = NewIrp(&Event);
    if (Irp == NULL)
        return;
    Status = ((PWSK_PROVIDER_DATAGRAM_DISPATCH)Socket->Dispatch)->WskCloseSocket(Socket, Irp);
    Status = WaitIrp(Irp, &Event, Status);
    ok_eq_hex(Status, STATUS_SUCCESS);
    IoFreeIrp(Irp);
}

static
NTSTATUS
SetReceiveEvent(
    _In_ PWSK_SOCKET Socket,
    _In_ BOOLEAN Enable)
{
    WSK_EVENT_CALLBACK_CONTROL Control;
    KEVENT Event;
    NTSTATUS Status;
    PIRP Irp;

    Control.NpiId = (PNPIID)&NPI_WSK_INTERFACE_ID;
    Control.EventMask = WSK_EVENT_RECEIVE_FROM | (Enable ? 0 : WSK_EVENT_DISABLE);

    if (Enable)
    {
        return ((PWSK_PROVIDER_DATAGRAM_DISPATCH)Socket->Dispatch)->WskControlSocket(
            Socket, WskSetOption, SO_WSK_EVENT_CALLBACK, SOL_SOCKET, sizeof(Control), &Control, 0, NULL, NULL, NULL);
    }

    Irp = NewIrp(&Event);
    if (Irp == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    Status = ((PWSK_PROVIDER_DATAGRAM_DISPATCH)Socket->Dispatch)->WskControlSocket(
        Socket, WskSetOption, SO_WSK_EVENT_CALLBACK, SOL_SOCKET, sizeof(Control), &Control, 0, NULL, NULL, Irp);
    Status = WaitIrp(Irp, &Event, Status);
    IoFreeIrp(Irp);
    return Status;
}

static
NTSTATUS
SendTo(
    _In_ PWSK_SOCKET Socket,
    _In_ PCSTR Payload,
    _In_ USHORT Port)
{
    SOCKADDR_IN Address;
    WSK_BUF Buffer;
    KEVENT Event;
    NTSTATUS Status;
    PCHAR Data;
    PIRP Irp;

    Data = ExAllocatePoolWithTag(NonPagedPool, 8, 'tEsW');
    if (Data == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(Data, Payload, 8);
    Buffer.Mdl = IoAllocateMdl(Data, 8, FALSE, FALSE, NULL);
    if (Buffer.Mdl == NULL)
    {
        ExFreePoolWithTag(Data, 'tEsW');
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    MmBuildMdlForNonPagedPool(Buffer.Mdl);
    Buffer.Offset = 0;
    Buffer.Length = 8;

    RtlZeroMemory(&Address, sizeof(Address));
    Address.sin_family = AF_INET;
    Address.sin_port = RtlUshortByteSwap(Port);
    Address.sin_addr.s_addr = RtlUlongByteSwap(0x7f000001);

    Status = STATUS_INSUFFICIENT_RESOURCES;
    Irp = NewIrp(&Event);
    if (Irp != NULL)
    {
        Status = ((PWSK_PROVIDER_DATAGRAM_DISPATCH)Socket->Dispatch)->WskSendTo(
            Socket, &Buffer, 0, (PSOCKADDR)&Address, 0, NULL, Irp);
        Status = WaitIrp(Irp, &Event, Status);
        IoFreeIrp(Irp);
    }
    IoFreeMdl(Buffer.Mdl);
    ExFreePoolWithTag(Data, 'tEsW');
    return Status;
}

static
LONG
WaitReceives(
    _In_ LONG Count,
    _In_ ULONG Milliseconds)
{
    LARGE_INTEGER Delay;
    ULONG Waited;

    Delay.QuadPart = -10 * 1000 * 50;
    for (Waited = 0; ReceiveCount < Count && Waited < Milliseconds; Waited += 50)
        KeDelayExecutionThread(KernelMode, FALSE, &Delay);
    return ReceiveCount;
}

static
BOOLEAN
WasSeen(
    _In_ PCSTR Payload)
{
    LONG Index;

    for (Index = 0; Index < min(ReceiveCount, MAX_SEEN); Index++)
    {
        if (RtlEqualMemory(Seen[Index], Payload, 8))
            return TRUE;
    }
    return FALSE;
}

static
VOID
TestDispatchLevel(
    _In_ PWSK_SOCKET Socket,
    _In_ USHORT Port)
{
    SOCKADDR_IN Address;
    ULONG PktInfo = 1;
    KEVENT Event;
    NTSTATUS Status;
    KIRQL OldIrql;
    PIRP Irp;

    RtlZeroMemory(&Address, sizeof(Address));
    Irp = NewIrp(&Event);
    if (Irp != NULL)
    {
        KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);
        Status = ((PWSK_PROVIDER_DATAGRAM_DISPATCH)Socket->Dispatch)->WskGetLocalAddress(
            Socket, (PSOCKADDR)&Address, Irp);
        KeLowerIrql(OldIrql);
        Status = WaitIrp(Irp, &Event, Status);
        ok_eq_hex(Status, STATUS_SUCCESS);
        ok_eq_uint(Address.sin_family, AF_INET);
        ok_eq_uint(RtlUshortByteSwap(Address.sin_port), Port);
        IoFreeIrp(Irp);
    }

    Irp = NewIrp(&Event);
    if (Irp != NULL)
    {
        KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);
        Status = ((PWSK_PROVIDER_DATAGRAM_DISPATCH)Socket->Dispatch)->WskControlSocket(
            Socket, WskSetOption, IP_PKTINFO, IPPROTO_IP, sizeof(PktInfo), &PktInfo, 0, NULL, NULL, Irp);
        KeLowerIrql(OldIrql);
        Status = WaitIrp(Irp, &Event, Status);
        ok_eq_hex(Status, STATUS_SUCCESS);
        IoFreeIrp(Irp);
    }
}

static
VOID
TestStaticCallbacks(VOID)
{
    WSK_EVENT_CALLBACK_CONTROL Control;
    WSK_CLIENT_NPI ClientNpi;
    WSK_PROVIDER_NPI ProviderNpi;
    WSK_REGISTRATION Registration;
    PWSK_SOCKET Receiver = NULL, Sender = NULL;
    NTSTATUS Status;
    LONG Count;

    ReceiveCount = 0;
    Refuse = FALSE;
    RtlZeroMemory(Seen, sizeof(Seen));

    ClientNpi.ClientContext = NULL;
    ClientNpi.Dispatch = &ClientDispatch;
    Status = WskRegister(&ClientNpi, &Registration);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;
    Status = WskCaptureProviderNPI(&Registration, WSK_INFINITE_WAIT, &ProviderNpi);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        goto deregister;

    Control.NpiId = (PNPIID)&NPI_WSK_INTERFACE_ID;
    Control.EventMask = WSK_EVENT_RECEIVE_FROM;
    Status = ProviderNpi.Dispatch->WskControlClient(ProviderNpi.Client, WSK_SET_STATIC_EVENT_CALLBACKS,
                                                   sizeof(Control), &Control, 0, NULL, NULL, NULL);
    ok_eq_hex(Status, STATUS_SUCCESS);

    Receiver = OpenSocket(&ProviderNpi, WSKEVENTS_PORT + 1);
    Sender = OpenSocket(&ProviderNpi, 0);
    if (Receiver == NULL || Sender == NULL)
        goto close;

    Status = SendTo(Sender, "STAT0001", WSKEVENTS_PORT + 1);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Count = WaitReceives(1, 2000);
    ok_eq_long(Count, 1L);

    Status = SetReceiveEvent(Receiver, FALSE);
    ok(!NT_SUCCESS(Status), "Disabling a static receive callback returned 0x%lx\n", Status);
    Status = SendTo(Sender, "STAT0002", WSKEVENTS_PORT + 1);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Count = WaitReceives(2, 2000);
    ok_eq_long(Count, 2L);
    ok(WasSeen("STAT0002"), "STAT0002 was not indicated after the refused disable\n");

close:
    if (Receiver != NULL)
        CloseSocket(Receiver);
    if (Sender != NULL)
        CloseSocket(Sender);
    WskReleaseProviderNPI(&Registration);
deregister:
    WskDeregister(&Registration);
}

static
VOID
TestRun(VOID)
{
    WSK_CLIENT_NPI ClientNpi;
    WSK_PROVIDER_NPI ProviderNpi;
    WSK_REGISTRATION Registration;
    PWSK_SOCKET Receiver, Sender;
    NTSTATUS Status;
    LONG Count;

    ReceiveCount = 0;
    Refuse = FALSE;
    RtlZeroMemory(Seen, sizeof(Seen));

    ClientNpi.ClientContext = NULL;
    ClientNpi.Dispatch = &ClientDispatch;
    Status = WskRegister(&ClientNpi, &Registration);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;
    Status = WskCaptureProviderNPI(&Registration, WSK_INFINITE_WAIT, &ProviderNpi);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        goto deregister;

    Receiver = OpenSocket(&ProviderNpi, WSKEVENTS_PORT);
    Sender = OpenSocket(&ProviderNpi, 0);
    if (Receiver == NULL || Sender == NULL)
        goto close;

    /* ok_eq_* evaluate their argument twice, so each call goes to a variable first */
    Status = SetReceiveEvent(Receiver, TRUE);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Status = SendTo(Sender, "DATA0001", WSKEVENTS_PORT);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Count = WaitReceives(1, 2000);
    ok_eq_long(Count, 1L);
    ok(WasSeen("DATA0001"), "DATA0001 was not indicated\n");

    Status = SetReceiveEvent(Receiver, FALSE);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Status = SendTo(Sender, "DATA0002", WSKEVENTS_PORT);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Count = WaitReceives(2, 500);
    ok_eq_long(Count, 1L);
    Status = SetReceiveEvent(Receiver, TRUE);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Count = WaitReceives(2, 2000);
    ok_eq_long(Count, 2L);
    ok(WasSeen("DATA0002"), "DATA0002 was not indicated after enabling the event again\n");

    Refuse = TRUE;
    Status = SendTo(Sender, "DATA0003", WSKEVENTS_PORT);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Count = WaitReceives(3, 2000);
    ok_eq_long(Count, 3L);
    Status = SendTo(Sender, "DATA0004", WSKEVENTS_PORT);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Count = WaitReceives(4, 500);
    ok_eq_long(Count, 3L);
    Refuse = FALSE;
    Status = SetReceiveEvent(Receiver, TRUE);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Count = WaitReceives(5, 2000);
    ok_eq_long(Count, 5L);
    ok(RtlEqualMemory(Seen[3], "DATA0003", 8) || RtlEqualMemory(Seen[4], "DATA0003", 8),
       "The refused DATA0003 was not indicated again: %s %s\n", Seen[3], Seen[4]);
    ok(RtlEqualMemory(Seen[3], "DATA0004", 8) || RtlEqualMemory(Seen[4], "DATA0004", 8),
       "DATA0004 was not indicated after enabling the event again: %s %s\n", Seen[3], Seen[4]);

    TestDispatchLevel(Receiver, WSKEVENTS_PORT);
    Status = SendTo(Sender, "DATA0006", WSKEVENTS_PORT);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Count = WaitReceives(6, 2000);
    ok_eq_long(Count, 6L);
    ok(LastControlLength != 0, "No IP_PKTINFO control data after enabling it at DISPATCH_LEVEL\n");

close:
    if (Receiver != NULL)
        CloseSocket(Receiver);
    if (Sender != NULL)
        CloseSocket(Sender);
    WskReleaseProviderNPI(&Registration);
deregister:
    WskDeregister(&Registration);
}

NTSTATUS
TestEntry(
    IN PDRIVER_OBJECT DriverObject,
    IN PCUNICODE_STRING RegistryPath,
    OUT PCWSTR *DeviceName,
    IN OUT INT *Flags)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    UNREFERENCED_PARAMETER(Flags);

    *DeviceName = L"WskEvents";
    KmtRegisterMessageHandler(0, NULL, TestMessageHandler);
    return STATUS_SUCCESS;
}

VOID
TestUnload(
    IN PDRIVER_OBJECT DriverObject)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(DriverObject);
}

static
NTSTATUS
TestMessageHandler(
    IN PDEVICE_OBJECT DeviceObject,
    IN ULONG ControlCode,
    IN PVOID Buffer OPTIONAL,
    IN SIZE_T InLength,
    IN OUT PSIZE_T OutLength)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(InLength);
    UNREFERENCED_PARAMETER(OutLength);

    if (ControlCode != IOCTL_WSKEVENTS_RUN)
        return STATUS_NOT_SUPPORTED;

    TestRun();
    TestStaticCallbacks();
    return STATUS_SUCCESS;
}
