/* SPDX-License-Identifier: BSD-2-Clause */
#include "smss.h"

#define NDEBUG
#include <debug.h>

static NTSTATUS NTAPI
SmpExecuteUpdate(PWSTR ValueName, ULONG ValueType, PVOID ValueData,
                 ULONG ValueLength, PVOID Context, PVOID EntryContext)
{
    UNICODE_STRING Command, FileName, Directory, Arguments;
    ULONG Flags = 0;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(ValueName);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(EntryContext);
    if (ValueType != REG_SZ || ValueLength < sizeof(WCHAR) ||
        ValueLength > MAXUSHORT || ValueLength % sizeof(WCHAR) ||
        ((PWSTR)ValueData)[ValueLength / sizeof(WCHAR) - 1])
        return STATUS_INVALID_PARAMETER;

    RtlInitUnicodeString(&Command, ValueData);
    Status = SmpParseCommandLine(&Command, &Flags, &FileName, &Directory, &Arguments);
    if (NT_SUCCESS(Status))
    {
        if (Flags & (SMP_ASYNC_FLAG | SMP_DEBUG_FLAG | SMP_AUTOCHK_FLAG |
                     SMP_SUBSYSTEM_FLAG | SMP_INVALID_PATH))
            Status = STATUS_INVALID_PARAMETER;
        else
            Status = SmpExecuteImage(&FileName, &Directory, &Command, 0, Flags, NULL);
        if (FileName.Buffer) RtlFreeHeap(RtlGetProcessHeap(), 0, FileName.Buffer);
        if (Directory.Buffer) RtlFreeHeap(RtlGetProcessHeap(), 0, Directory.Buffer);
        if (Arguments.Buffer) RtlFreeHeap(RtlGetProcessHeap(), 0, Arguments.Buffer);
    }
    if (!NT_SUCCESS(Status))
        DPRINT1("SMSS: UpdateExecute failed for %wZ: %lx\n", &Command, Status);
    /* The updater journal owns recovery; a missing updater must not stop boot. */
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
SmpInitializeUpdateRegistry(VOID)
{
    NTSTATUS Status;
    UNICODE_STRING Path, Name;
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Key;
    ULONG Version = 1;
    RTL_QUERY_REGISTRY_TABLE Query[2] = {{0}};

    Status = NtInitializeRegistry(CM_BOOT_FLAG_SMSS);
    if (!NT_SUCCESS(Status)) return Status;

    /* HARDWARE is a volatile hive, including keys created by an earlier boot component. */
    RtlInitUnicodeString(&Path, L"\\Registry\\Machine\\HARDWARE\\LiberNTUpdate");
    InitializeObjectAttributes(&Attributes, &Path, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtCreateKey(&Key, KEY_SET_VALUE, &Attributes, 0, NULL, REG_OPTION_VOLATILE, NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("SMSS: UpdateExecute capability unavailable: %lx\n", Status);
        return STATUS_SUCCESS;
    }
    RtlInitUnicodeString(&Name, L"Version");
    Status = NtSetValueKey(Key, &Name, 0, REG_DWORD, &Version, sizeof(Version));
    NtClose(Key);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("SMSS: UpdateExecute capability write failed: %lx\n", Status);
        return STATUS_SUCCESS;
    }

    Query[0].QueryRoutine = SmpExecuteUpdate;
    Query[0].Name = L"UpdateExecute";
    Status = RtlQueryRegistryValues(RTL_REGISTRY_CONTROL,
                                    L"Session Manager", Query, NULL, NULL);
    if (!NT_SUCCESS(Status)) DPRINT1("SMSS: UpdateExecute query failed: %lx\n", Status);
    return STATUS_SUCCESS;
}
