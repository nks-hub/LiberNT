/*
 * PROJECT:         ReactOS API tests
 * LICENSE:         GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:         Tests for the NtAdjustGroupsToken API
 * COPYRIGHT:       Copyright 2021 George Bișoc <george.bisoc@reactos.org>
 */

#include "precomp.h"

static
HANDLE
GetProcessToken(
    _In_ DWORD Access)
{
    BOOL Success;
    HANDLE Token;

    Success = OpenProcessToken(GetCurrentProcess(), Access, &Token);
    if (!Success)
    {
        skip("Failed to open the process' token (error code: %lu)!\n", GetLastError());
        return NULL;
    }

    return Token;
}

static
PTOKEN_GROUPS
QueryGroups(
    _In_ HANDLE Token)
{
    NTSTATUS Status;
    ULONG Size = 0;
    PTOKEN_GROUPS Groups;

    Status = NtQueryInformationToken(Token, TokenGroups, NULL, 0, &Size);
    if (Status != STATUS_BUFFER_TOO_SMALL)
        return NULL;
    Groups = RtlAllocateHeap(RtlGetProcessHeap(), 0, Size);
    if (Groups && !NT_SUCCESS(NtQueryInformationToken(Token, TokenGroups, Groups, Size, &Size)))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, Groups);
        Groups = NULL;
    }
    return Groups;
}

/* Disabling one group leaves the others alone, and a reset enables it again */
static
VOID
AdjustOneGroup(VOID)
{
    NTSTATUS Status;
    HANDLE ProcessToken, Token;
    OBJECT_ATTRIBUTES ObjectAttributes;
    PTOKEN_GROUPS Before = NULL, After = NULL, Reset = NULL;
    TOKEN_GROUPS Disable;
    ULONG Index, Target = MAXULONG;

    ProcessToken = GetProcessToken(TOKEN_DUPLICATE);
    if (!ProcessToken)
        return;
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    Status = NtDuplicateToken(ProcessToken, TOKEN_ADJUST_GROUPS | TOKEN_QUERY, &ObjectAttributes,
                              FALSE, TokenPrimary, &Token);
    CloseHandle(ProcessToken);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

    Before = QueryGroups(Token);
    for (Index = 0; Before && Index < Before->GroupCount; Index++)
    {
        if ((Before->Groups[Index].Attributes & (SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY)) ==
            (SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT))
        {
            Target = Index;
            break;
        }
    }
    if (Target == MAXULONG)
    {
        skip("The token has no optional group that is enabled by default\n");
        goto Cleanup;
    }

    Disable.GroupCount = 1;
    Disable.Groups[0].Sid = Before->Groups[Target].Sid;
    Disable.Groups[0].Attributes = 0;
    Status = NtAdjustGroupsToken(Token, FALSE, &Disable, 0, NULL, NULL);
    ok_hex(Status, STATUS_SUCCESS);

    After = QueryGroups(Token);
    ok(After != NULL && After->GroupCount == Before->GroupCount, "The group count changed\n");
    for (Index = 0; After && Index < After->GroupCount && Index < Before->GroupCount; Index++)
    {
        if (Index == Target)
            ok(After->Groups[Index].Attributes == (Before->Groups[Index].Attributes & ~SE_GROUP_ENABLED),
               "Group %lu has attributes 0x%lx, expected 0x%lx\n", Index, After->Groups[Index].Attributes,
               Before->Groups[Index].Attributes & ~SE_GROUP_ENABLED);
        else
            ok(After->Groups[Index].Attributes == Before->Groups[Index].Attributes,
               "Group %lu has attributes 0x%lx, expected 0x%lx\n", Index, After->Groups[Index].Attributes,
               Before->Groups[Index].Attributes);
    }

    Status = NtAdjustGroupsToken(Token, TRUE, NULL, 0, NULL, NULL);
    ok_hex(Status, STATUS_SUCCESS);
    Reset = QueryGroups(Token);
    ok(Reset != NULL && Reset->GroupCount == Before->GroupCount, "The group count changed\n");
    for (Index = 0; Reset && Index < Reset->GroupCount && Index < Before->GroupCount; Index++)
    {
        ok(Reset->Groups[Index].Attributes == Before->Groups[Index].Attributes,
           "Group %lu has attributes 0x%lx after the reset, expected 0x%lx\n", Index,
           Reset->Groups[Index].Attributes, Before->Groups[Index].Attributes);
    }

Cleanup:
    if (Before) RtlFreeHeap(RtlGetProcessHeap(), 0, Before);
    if (After) RtlFreeHeap(RtlGetProcessHeap(), 0, After);
    if (Reset) RtlFreeHeap(RtlGetProcessHeap(), 0, Reset);
    CloseHandle(Token);
}

START_TEST(NtAdjustGroupsToken)
{
    HANDLE TokenHandle;
    NTSTATUS Status;

    /* Get the token from current process but with incorrect rights */
    TokenHandle = GetProcessToken(TOKEN_DUPLICATE);

    /* We give an invalid handle */
    Status = NtAdjustGroupsToken(NULL,
                                 TRUE,
                                 NULL,
                                 0,
                                 NULL,
                                 NULL);
    ok_hex(Status, STATUS_INVALID_HANDLE);

    /* We're trying to adjust the token's groups with wrong rights */
    Status = NtAdjustGroupsToken(TokenHandle,
                                 TRUE,
                                 NULL,
                                 0,
                                 NULL,
                                 NULL);
    ok_hex(Status, STATUS_ACCESS_DENIED);

    /* Close our handle and open a new one with right access right */
    CloseHandle(TokenHandle);
    TokenHandle = GetProcessToken(TOKEN_ADJUST_GROUPS);

    /* We don't give a list of groups to be adjusted in token */
    Status = NtAdjustGroupsToken(TokenHandle,
                                 FALSE,
                                 NULL,
                                 0,
                                 NULL,
                                 NULL);
    ok_hex(Status, STATUS_INVALID_PARAMETER);

    /* Reset the groups of an access token to default */
    Status = NtAdjustGroupsToken(TokenHandle,
                                 TRUE,
                                 NULL,
                                 0,
                                 NULL,
                                 NULL);
    ok_hex(Status, STATUS_SUCCESS);

    CloseHandle(TokenHandle);

    AdjustOneGroup();
}
