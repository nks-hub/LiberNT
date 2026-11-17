/*
 * PROJECT:     LiberNT kernel-mode tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Kernel-Mode Test Suite boot driver whose service key differs from its image name
 * COPYRIGHT:   Copyright 2026 LiberNT contributors
 */

#include <kmt_test.h>

#define NDEBUG
#include <debug.h>

START_TEST(IoBootDriverKey)
{
    UNICODE_STRING KeyDriverName = RTL_CONSTANT_STRING(L"\\Driver\\KmtBootKey");
    UNICODE_STRING ImageDriverName = RTL_CONSTANT_STRING(L"\\Driver\\kmtbootimg");
    UNICODE_STRING KeyName = RTL_CONSTANT_STRING(L"KmtBootKey");
    UNICODE_STRING ExpectedImagePath = RTL_CONSTANT_STRING(L"system32\\drivers\\kmtbootimg.sys");
    RTL_QUERY_REGISTRY_TABLE Query[2];
    UNICODE_STRING ImagePath;
    WCHAR Buffer[64];
    PDRIVER_OBJECT Driver;
    NTSTATUS Status;

    RtlInitEmptyUnicodeString(&ImagePath, Buffer, sizeof(Buffer));
    RtlZeroMemory(Query, sizeof(Query));
    Query[0].Flags = RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_REQUIRED | RTL_QUERY_REGISTRY_NOEXPAND;
    Query[0].Name = L"ImagePath";
    Query[0].EntryContext = &ImagePath;

    Status = RtlQueryRegistryValues(RTL_REGISTRY_SERVICES, L"KmtBootKey", Query, NULL, NULL);
    if (skip(NT_SUCCESS(Status), "Boot-start service KmtBootKey is not in this system's hive: status=%lx\n", Status))
        return;
    ok(RtlEqualUnicodeString(&ImagePath, &ExpectedImagePath, TRUE), "ImagePath = %wZ\n", &ImagePath);

    Status = ObReferenceObjectByName(&KeyDriverName, OBJ_CASE_INSENSITIVE, NULL, 0, IoDriverObjectType, KernelMode, NULL,
                                     (PVOID *)&Driver);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ok(RtlEqualUnicodeString(&Driver->DriverExtension->ServiceKeyName, &KeyName, FALSE),
           "ServiceKeyName = %wZ\n", &Driver->DriverExtension->ServiceKeyName);
        ok(RtlEqualUnicodeString(&Driver->DriverName, &KeyDriverName, FALSE), "DriverName = %wZ\n", &Driver->DriverName);
        ObDereferenceObject(Driver);
    }

    Status = ObReferenceObjectByName(&ImageDriverName, OBJ_CASE_INSENSITIVE, NULL, 0, IoDriverObjectType, KernelMode, NULL,
                                     (PVOID *)&Driver);
    ok_eq_hex(Status, STATUS_OBJECT_NAME_NOT_FOUND);
    if (NT_SUCCESS(Status))
        ObDereferenceObject(Driver);
}
