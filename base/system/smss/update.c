/*
 * PROJECT:     LiberNT Session Manager
 * LICENSE:     BSD-2-Clause (https://spdx.org/licenses/BSD-2-Clause)
 * PURPOSE:     UpdateExecute commands that run after the registry is initialized
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include "smss.h"

#define NDEBUG
#include <debug.h>

static VOID
SmpTerminateUpdate(HANDLE ProcessHandle, NTSTATUS ExitStatus)
{
    NTSTATUS Status;

    Status = NtTerminateProcess(ProcessHandle, ExitStatus);
    if (NT_SUCCESS(Status))
        Status = NtWaitForSingleObject(ProcessHandle, FALSE, NULL);
    if (!NT_SUCCESS(Status))
        DPRINT1("SMSS: UpdateExecute cannot terminate its process: %lx\n", Status);
}

static NTSTATUS NTAPI
SmpExecuteUpdate(PWSTR ValueName, ULONG ValueType, PVOID ValueData,
                 ULONG ValueLength, PVOID Context, PVOID EntryContext)
{
    UNICODE_STRING Command, FileName, Directory, Arguments;
    RTL_USER_PROCESS_INFORMATION ProcessInfo;
    PROCESS_BASIC_INFORMATION BasicInfo;
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
        {
            /* Started suspended so the wait covers the whole process, not only its first thread */
            Status = SmpExecuteImage(&FileName, &Directory, &Command, 0,
                                     Flags | SMP_DEFERRED_FLAG, &ProcessInfo);
            if (NT_SUCCESS(Status))
            {
                if (ProcessInfo.ImageInformation.SubSystemType == IMAGE_SUBSYSTEM_NATIVE)
                {
                    Status = NtResumeThread(ProcessInfo.ThreadHandle, NULL);
                    if (NT_SUCCESS(Status))
                        Status = NtWaitForSingleObject(ProcessInfo.ProcessHandle, FALSE, NULL);
                    if (Status == STATUS_WAIT_0)
                    {
                        /* The command reports its own failure through its exit status */
                        Status = NtQueryInformationProcess(ProcessInfo.ProcessHandle, ProcessBasicInformation,
                                                           &BasicInfo, sizeof(BasicInfo), NULL);
                        if (NT_SUCCESS(Status))
                            Status = BasicInfo.ExitStatus;
                    }
                    else
                    {
                        SmpTerminateUpdate(ProcessInfo.ProcessHandle, Status);
                        if (NT_SUCCESS(Status))
                            Status = STATUS_UNSUCCESSFUL;
                    }
                }
                else
                {
                    Status = STATUS_INVALID_IMAGE_FORMAT;
                    SmpTerminateUpdate(ProcessInfo.ProcessHandle, Status);
                }
                NtClose(ProcessInfo.ThreadHandle);
                NtClose(ProcessInfo.ProcessHandle);
            }
        }
    }
    if (FileName.Buffer)
        RtlFreeHeap(RtlGetProcessHeap(), 0, FileName.Buffer);
    if (Directory.Buffer)
        RtlFreeHeap(RtlGetProcessHeap(), 0, Directory.Buffer);
    if (Arguments.Buffer)
        RtlFreeHeap(RtlGetProcessHeap(), 0, Arguments.Buffer);
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

    /* As before UpdateExecute existed, a failure here does not stop the boot */
    Status = NtInitializeRegistry(CM_BOOT_FLAG_SMSS);
    if (!NT_SUCCESS(Status))
        DPRINT1("SMSS: NtInitializeRegistry failed: %lx\n", Status);

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
    if (!NT_SUCCESS(Status))
        DPRINT1("SMSS: UpdateExecute query failed: %lx\n", Status);
    return STATUS_SUCCESS;
}
