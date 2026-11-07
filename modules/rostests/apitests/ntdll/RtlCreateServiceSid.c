/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Test for RtlCreateServiceSid
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#include "precomp.h"

static NTSTATUS (NTAPI *pRtlCreateServiceSid)(PUNICODE_STRING, PSID, PULONG);

static VOID
CheckServiceSid(PCWSTR Name, PCWSTR Expected)
{
    UNICODE_STRING ServiceName, Text;
    UCHAR Buffer[SECURITY_MAX_SID_SIZE];
    ULONG Length = sizeof(Buffer);
    NTSTATUS Status;

    RtlInitUnicodeString(&ServiceName, Name);
    Status = pRtlCreateServiceSid(&ServiceName, (PSID)Buffer, &Length);
    ok(Status == STATUS_SUCCESS, "%S: status 0x%lx\n", Name, Status);
    if (!NT_SUCCESS(Status))
        return;
    ok(Length == RtlLengthRequiredSid(6), "%S: length %lu\n", Name, Length);
    Status = RtlConvertSidToUnicodeString(&Text, (PSID)Buffer, TRUE);
    ok(Status == STATUS_SUCCESS, "RtlConvertSidToUnicodeString: 0x%lx\n", Status);
    if (!NT_SUCCESS(Status))
        return;
    ok(!_wcsicmp(Text.Buffer, Expected), "%S: got %wZ, expected %S\n", Name, &Text, Expected);
    RtlFreeUnicodeString(&Text);
}

START_TEST(RtlCreateServiceSid)
{
    UNICODE_STRING ServiceName = RTL_CONSTANT_STRING(L"TrustedInstaller");
    UCHAR Buffer[SECURITY_MAX_SID_SIZE];
    ULONG Length;
    NTSTATUS Status;

    pRtlCreateServiceSid = (PVOID)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateServiceSid");
    if (!pRtlCreateServiceSid)
    {
        skip("RtlCreateServiceSid is not available\n");
        return;
    }

    /* The well-known SID of the TrustedInstaller service; the name is not case sensitive */
    CheckServiceSid(L"TrustedInstaller", L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
    CheckServiceSid(L"trustedinstaller", L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    Length = 0;
    Status = pRtlCreateServiceSid(&ServiceName, NULL, &Length);
    ok(Status == STATUS_BUFFER_TOO_SMALL, "size query: 0x%lx\n", Status);
    ok(Length == RtlLengthRequiredSid(6), "needed %lu\n", Length);

    Length = RtlLengthRequiredSid(6) - 1;
    Status = pRtlCreateServiceSid(&ServiceName, (PSID)Buffer, &Length);
    ok(Status == STATUS_BUFFER_TOO_SMALL, "small buffer: 0x%lx\n", Status);
    ok(Length == RtlLengthRequiredSid(6), "needed %lu\n", Length);
}
