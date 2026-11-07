/*
 * PROJECT:         ReactOS API tests
 * LICENSE:         GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:         Tests for the NtDuplicateToken API
 * COPYRIGHT:       Copyright 2021 George Bișoc <george.bisoc@reactos.org>
 */

#include "precomp.h"

static
HANDLE
OpenTokenFromProcess(VOID)
{
    BOOL Success;
    HANDLE Token;

    Success = OpenProcessToken(GetCurrentProcess(),
                               TOKEN_READ | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_DUPLICATE | TOKEN_QUERY,
                               &Token);
    if (!Success)
    {
        skip("OpenProcessToken() has failed to get the process' token (error code: %lu)!\n", GetLastError());
        return NULL;
    }

    return Token;
}

static
VOID
DisablePrivilege(
    _In_ HANDLE Token,
    _In_ LPCWSTR PrivilegeName)
{
    TOKEN_PRIVILEGES TokenPriv;
    LUID PrivLuid;
    BOOL Success;

    Success = LookupPrivilegeValueW(NULL, PrivilegeName, &PrivLuid);
    if (!Success)
    {
        skip("LookupPrivilegeValueW() has failed to locate the privilege value (error code: %lu)!\n", GetLastError());
        return;
    }

    TokenPriv.PrivilegeCount = 1;
    TokenPriv.Privileges[0].Luid = PrivLuid;
    TokenPriv.Privileges[0].Attributes = 0;

    Success = AdjustTokenPrivileges(Token,
                                    FALSE,
                                    &TokenPriv,
                                    0,
                                    NULL,
                                    NULL);
    if (!Success)
    {
        skip("AdjustTokenPrivileges() has failed to adjust privileges of token (error code: %lu)!\n", GetLastError());
        return;
    }
}

static
VOID
DuplicateTokenAsEffective(VOID)
{
    NTSTATUS Status;
    ULONG Size;
    HANDLE TokenHandle;
    HANDLE DuplicatedTokenHandle;
    OBJECT_ATTRIBUTES ObjectAttributes;
    PTOKEN_STATISTICS TokenStats;

    /* Initialize the object attributes for token duplication */
    InitializeObjectAttributes(&ObjectAttributes,
                               NULL,
                               0,
                               NULL,
                               NULL);

    /* Get the token from process and begin the tests */
    TokenHandle = OpenTokenFromProcess();

    /* We give a bogus invalid handle */
    Status = NtDuplicateToken(NULL,
                              0,
                              NULL,
                              TRUE,
                              TokenPrimary,
                              NULL);
    ok_hex(Status, STATUS_ACCESS_VIOLATION);

    /*
     * Disable a privilege, the impersonation privilege for example.
     * Why we're doing this is because such privilege is enabled
     * by default and we'd want to know what the kernel does
     * at the moment of removing disabled privileges during making
     * the token effective, with this potential privilege being
     * disabled by ourselves.
     */
    DisablePrivilege(TokenHandle, L"SeImpersonatePrivilege");

    /* Query the total size of the token statistics structure */
    Status = NtQueryInformationToken(TokenHandle, TokenStatistics, NULL, 0, &Size);
    if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_TOO_SMALL)
    {
        skip("Failed to query the total size for token statistics structure! (Status -> 0x%lx)\n", Status);
        return;
    }

    /* Total size queried, time to allocate our buffer based on that size */
    TokenStats = RtlAllocateHeap(RtlGetProcessHeap(), 0, Size);
    if (TokenStats == NULL)
    {
        skip("Failed to allocate our token statistics buffer!\n");
        return;
    }

    /* Time to query our token statistics, prior duplicating the token as effective */
    Status = NtQueryInformationToken(TokenHandle, TokenStatistics, TokenStats, Size, &Size);
    if (!NT_SUCCESS(Status))
    {
        skip("Failed to query the token statistics! (Status -> 0x%lx)\n", Status);
        return;
    }

    trace("Number of privileges of regular token -- %lu\n", TokenStats->PrivilegeCount);
    trace("Number of groups of regular token -- %lu\n", TokenStats->GroupCount);

    /* Duplicate the token as effective only */
    Status = NtDuplicateToken(TokenHandle,
                              0,
                              &ObjectAttributes,
                              TRUE,
                              TokenPrimary,
                              &DuplicatedTokenHandle);
    ok_hex(Status, STATUS_SUCCESS);

    /*
     * Query the token statistics again, but now this time of
     * the duplicated effective token. On this moment this token
     * should have the disabled privileges (including the one we
     * disabled ourselves) removed as well as the disabled groups
     * that the duplicated token includes, whatever that is.
     */
    Status = NtQueryInformationToken(DuplicatedTokenHandle, TokenStatistics, TokenStats, Size, &Size);
    if (!NT_SUCCESS(Status))
    {
        skip("Failed to query the token statistics! (Status -> 0x%lx)\n", Status);
        return;
    }

    trace("Number of privileges of effective only token -- %lu\n", TokenStats->PrivilegeCount);
    trace("Number of groups of effective only token -- %lu\n", TokenStats->GroupCount);

    /*
     * We finished our tests, free the memory
     * block and close the handles now.
     */
    RtlFreeHeap(RtlGetProcessHeap(), 0, TokenStats);
    CloseHandle(TokenHandle),
    CloseHandle(DuplicatedTokenHandle);
}

static
PVOID
QueryToken(
    _In_ HANDLE Token,
    _In_ TOKEN_INFORMATION_CLASS Class)
{
    NTSTATUS Status;
    ULONG Size = 0;
    PVOID Buffer;

    Status = NtQueryInformationToken(Token, Class, NULL, 0, &Size);
    if (Status != STATUS_BUFFER_TOO_SMALL)
    {
        trace("Querying the size of class %d failed (Status 0x%lx)\n", Class, Status);
        return NULL;
    }
    Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, Size);
    if (!Buffer)
        return NULL;
    Status = NtQueryInformationToken(Token, Class, Buffer, Size, &Size);
    if (!NT_SUCCESS(Status))
    {
        trace("Querying class %d failed (Status 0x%lx)\n", Class, Status);
        RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
        Buffer = NULL;
    }
    return Buffer;
}

/*
 * The integrity label is not an enabled group, yet an effective only copy
 * keeps it, also when a disabled group before it is removed.
 */
static
VOID
DuplicateTokenAsEffectiveKeepsLabel(VOID)
{
    NTSTATUS Status;
    HANDLE ProcessToken, Token = NULL, EffectiveToken;
    OBJECT_ATTRIBUTES ObjectAttributes;
    PTOKEN_GROUPS Groups, EffectiveGroups;
    PTOKEN_MANDATORY_LABEL Label, EffectiveLabel;
    SID_AND_ATTRIBUTES Disable;
    PSID Disabled = NULL;
    ULONG Index, LabelIndex = MAXULONG;
    BOOLEAN LabelFound = FALSE, DisabledFound = FALSE;

    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    ProcessToken = OpenTokenFromProcess();
    if (!ProcessToken)
        return;

    Groups = QueryToken(ProcessToken, TokenGroups);
    Label = QueryToken(ProcessToken, TokenIntegrityLevel);
    if (!Groups || !Label)
    {
        skip("The token has no groups or no integrity label\n");
        goto Cleanup;
    }
    for (Index = 0; Index < Groups->GroupCount; Index++)
    {
        if (Groups->Groups[Index].Attributes & SE_GROUP_INTEGRITY)
        {
            LabelIndex = Index;
            break;
        }
    }
    for (Index = 0; Index < LabelIndex && Index < Groups->GroupCount; Index++)
    {
        if (Groups->Groups[Index].Attributes & SE_GROUP_ENABLED)
        {
            Disabled = Groups->Groups[Index].Sid;
            break;
        }
    }
    if (!Disabled)
    {
        skip("No enabled group precedes the integrity label\n");
        goto Cleanup;
    }

    /* A group made deny only is no longer enabled */
    Disable.Sid = Disabled;
    Disable.Attributes = 0;
    if (!CreateRestrictedToken(ProcessToken, 0, 1, &Disable, 0, NULL, 0, NULL, &Token))
    {
        skip("CreateRestrictedToken failed (%lu)\n", GetLastError());
        Token = NULL;
        goto Cleanup;
    }

    Status = NtDuplicateToken(Token, TOKEN_QUERY, &ObjectAttributes, TRUE, TokenPrimary, &EffectiveToken);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        goto Cleanup;

    EffectiveGroups = QueryToken(EffectiveToken, TokenGroups);
    EffectiveLabel = QueryToken(EffectiveToken, TokenIntegrityLevel);
    ok(EffectiveGroups != NULL && EffectiveLabel != NULL, "Querying the effective token failed\n");
    if (EffectiveGroups && EffectiveLabel)
    {
        for (Index = 0; Index < EffectiveGroups->GroupCount; Index++)
        {
            if (EqualSid(EffectiveGroups->Groups[Index].Sid, Disabled))
                DisabledFound = TRUE;
            if ((EffectiveGroups->Groups[Index].Attributes & SE_GROUP_INTEGRITY) &&
                EqualSid(EffectiveGroups->Groups[Index].Sid, Label->Label.Sid))
                LabelFound = TRUE;
        }
        ok(!DisabledFound, "The disabled group was kept\n");
        ok(LabelFound, "The integrity label was removed\n");
        ok(EqualSid(EffectiveLabel->Label.Sid, Label->Label.Sid), "The integrity level differs\n");
    }
    if (EffectiveGroups) RtlFreeHeap(RtlGetProcessHeap(), 0, EffectiveGroups);
    if (EffectiveLabel) RtlFreeHeap(RtlGetProcessHeap(), 0, EffectiveLabel);
    CloseHandle(EffectiveToken);

Cleanup:
    if (Groups) RtlFreeHeap(RtlGetProcessHeap(), 0, Groups);
    if (Label) RtlFreeHeap(RtlGetProcessHeap(), 0, Label);
    if (Token) CloseHandle(Token);
    CloseHandle(ProcessToken);
}

START_TEST(NtDuplicateToken)
{
    DuplicateTokenAsEffective();
    DuplicateTokenAsEffectiveKeepsLabel();
}
