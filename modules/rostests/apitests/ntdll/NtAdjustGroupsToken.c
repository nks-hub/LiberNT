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

/* As measured on Windows 11, a 32-bit caller on a 64-bit system must give room for the 64-bit layout */
static
ULONG
PreviousStateLength(
    _In_ ULONG Count,
    _In_ ULONG SidLength)
{
    ULONG_PTR Wow64 = 0;

    if (NT_SUCCESS(NtQueryInformationProcess(NtCurrentProcess(), ProcessWow64Information, &Wow64, sizeof(Wow64), NULL)) && Wow64)
        return 8 + Count * 16 + SidLength;
    return FIELD_OFFSET(TOKEN_GROUPS, Groups[Count]) + SidLength;
}

static
HANDLE
DuplicateProcessToken(VOID)
{
    NTSTATUS Status;
    HANDLE ProcessToken, Token = NULL;
    OBJECT_ATTRIBUTES ObjectAttributes;

    ProcessToken = GetProcessToken(TOKEN_DUPLICATE);
    if (!ProcessToken)
        return NULL;
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    Status = NtDuplicateToken(ProcessToken, TOKEN_ADJUST_GROUPS | TOKEN_QUERY, &ObjectAttributes,
                              FALSE, TokenPrimary, &Token);
    CloseHandle(ProcessToken);
    ok_hex(Status, STATUS_SUCCESS);
    return NT_SUCCESS(Status) ? Token : NULL;
}

static
VOID
CheckGroupsUnchanged(
    _In_ HANDLE Token,
    _In_ PTOKEN_GROUPS Before)
{
    PTOKEN_GROUPS After = QueryGroups(Token);
    ULONG Index;

    ok(After != NULL && After->GroupCount == Before->GroupCount, "The group count changed\n");
    for (Index = 0; After && Index < After->GroupCount && Index < Before->GroupCount; Index++)
    {
        ok(After->Groups[Index].Attributes == Before->Groups[Index].Attributes,
           "Group %lu has attributes 0x%lx, expected 0x%lx\n", Index,
           After->Groups[Index].Attributes, Before->Groups[Index].Attributes);
    }
    if (After) RtlFreeHeap(RtlGetProcessHeap(), 0, After);
}

static
ULONG
FindDefaultOptionalGroup(
    _In_opt_ PTOKEN_GROUPS Groups)
{
    ULONG Index;

    for (Index = 0; Groups && Index < Groups->GroupCount; Index++)
    {
        if ((Groups->Groups[Index].Attributes & (SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY)) ==
            (SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT))
        {
            return Index;
        }
    }
    skip("The token has no optional group that is enabled by default\n");
    return MAXULONG;
}

static
VOID
AdjustOneGroup(VOID)
{
    NTSTATUS Status;
    HANDLE Token;
    PTOKEN_GROUPS Before = NULL, After = NULL, Reset = NULL;
    TOKEN_GROUPS Disable;
    ULONG Index, Target = MAXULONG;

    Token = DuplicateProcessToken();
    if (!Token)
        return;

    Before = QueryGroups(Token);
    Target = FindDefaultOptionalGroup(Before);
    if (Target == MAXULONG)
        goto Cleanup;

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

static
VOID
AdjustMandatoryGroup(VOID)
{
    NTSTATUS Status;
    HANDLE Token;
    PTOKEN_GROUPS Before;
    struct
    {
        ULONG GroupCount;
        SID_AND_ATTRIBUTES Groups[2];
    } Disable;
    ULONG Index, Optional = MAXULONG, Mandatory = MAXULONG;

    Token = DuplicateProcessToken();
    if (!Token)
        return;
    Before = QueryGroups(Token);
    for (Index = 0; Before && Index < Before->GroupCount; Index++)
    {
        ULONG Attributes = Before->Groups[Index].Attributes;

        if (Optional == MAXULONG &&
            (Attributes & (SE_GROUP_ENABLED | SE_GROUP_MANDATORY)) == SE_GROUP_ENABLED)
        {
            Optional = Index;
        }
        else if (Optional != MAXULONG && (Attributes & SE_GROUP_MANDATORY))
        {
            Mandatory = Index;
            break;
        }
    }
    if (Mandatory == MAXULONG)
    {
        skip("The token has no mandatory group after an optional enabled one\n");
        goto Cleanup;
    }

    /* The optional group comes first in the token, so it would change first */
    Disable.GroupCount = 2;
    Disable.Groups[0].Sid = Before->Groups[Optional].Sid;
    Disable.Groups[0].Attributes = 0;
    Disable.Groups[1].Sid = Before->Groups[Mandatory].Sid;
    Disable.Groups[1].Attributes = 0;
    Status = NtAdjustGroupsToken(Token, FALSE, (PTOKEN_GROUPS)&Disable, 0, NULL, NULL);
    ok_hex(Status, STATUS_CANT_DISABLE_MANDATORY);
    CheckGroupsUnchanged(Token, Before);

Cleanup:
    if (Before) RtlFreeHeap(RtlGetProcessHeap(), 0, Before);
    CloseHandle(Token);
}

static
VOID
AdjustWithPreviousState(VOID)
{
    NTSTATUS Status;
    HANDLE Token;
    PTOKEN_GROUPS Before, Previous = NULL;
    TOKEN_GROUPS Disable, Small;
    ULONG Target, Length, Expected, Needed;

    Token = DuplicateProcessToken();
    if (!Token)
        return;
    Before = QueryGroups(Token);
    Target = FindDefaultOptionalGroup(Before);
    if (Target == MAXULONG)
        goto Cleanup;

    Disable.GroupCount = 1;
    Disable.Groups[0].Sid = Before->Groups[Target].Sid;
    Disable.Groups[0].Attributes = 0;
    Expected = FIELD_OFFSET(TOKEN_GROUPS, Groups[1]) + RtlLengthSid(Before->Groups[Target].Sid);
    Needed = PreviousStateLength(1, RtlLengthSid(Before->Groups[Target].Sid));

    Length = 0;
    Status = NtAdjustGroupsToken(Token, FALSE, &Disable, 0, &Small, &Length);
    ok_hex(Status, STATUS_BUFFER_TOO_SMALL);
    ok(Length == Needed, "ReturnLength is %lu, expected %lu\n", Length, Needed);
    CheckGroupsUnchanged(Token, Before);

    Status = NtAdjustGroupsToken(Token, FALSE, &Disable, 0, &Small, NULL);
    ok_hex(Status, STATUS_ACCESS_VIOLATION);
    CheckGroupsUnchanged(Token, Before);

    Previous = RtlAllocateHeap(RtlGetProcessHeap(), 0, Needed);
    if (!Previous)
    {
        skip("Out of memory\n");
        goto Cleanup;
    }

    Length = 0;
    Status = NtAdjustGroupsToken(Token, FALSE, &Disable, Needed - 1, Previous, &Length);
    ok_hex(Status, STATUS_BUFFER_TOO_SMALL);
    ok(Length == Needed, "ReturnLength is %lu, expected %lu\n", Length, Needed);
    CheckGroupsUnchanged(Token, Before);
    if (Length != Needed)
        goto Cleanup;

    Status = NtAdjustGroupsToken(Token, FALSE, &Disable, Length, Previous, &Length);
    ok_hex(Status, STATUS_SUCCESS);
    ok(Length == Expected, "ReturnLength is %lu, expected %lu\n", Length, Expected);
    ok(Previous->GroupCount == 1, "GroupCount is %lu\n", Previous->GroupCount);
    if (Previous->GroupCount != 1)
        goto Cleanup;
    ok((PUCHAR)Previous->Groups[0].Sid == (PUCHAR)&Previous->Groups[1],
       "The SID is at %p, expected after the array at %p\n", Previous->Groups[0].Sid, &Previous->Groups[1]);
    ok(RtlEqualSid(Previous->Groups[0].Sid, Before->Groups[Target].Sid), "The previous SID differs\n");
    ok(Previous->Groups[0].Attributes == Before->Groups[Target].Attributes,
       "The previous attributes are 0x%lx, expected 0x%lx\n",
       Previous->Groups[0].Attributes, Before->Groups[Target].Attributes);

    /* The group is disabled now, so the same request changes nothing */
    Needed = PreviousStateLength(0, 0);
    Length = 0;
    Status = NtAdjustGroupsToken(Token, FALSE, &Disable, Needed - 1, &Small, &Length);
    ok_hex(Status, STATUS_BUFFER_TOO_SMALL);
    ok(Length == Needed, "ReturnLength is %lu, expected %lu\n", Length, Needed);
    Small.GroupCount = MAXULONG;
    Length = 0;
    Status = NtAdjustGroupsToken(Token, FALSE, &Disable, Needed, &Small, &Length);
    ok_hex(Status, STATUS_SUCCESS);
    ok(Length == FIELD_OFFSET(TOKEN_GROUPS, Groups[0]), "ReturnLength is %lu without a change\n", Length);
    ok(Small.GroupCount == 0, "GroupCount is %lu without a change\n", Small.GroupCount);

    Status = NtAdjustGroupsToken(Token, FALSE, Previous, 0, NULL, NULL);
    ok_hex(Status, STATUS_SUCCESS);
    CheckGroupsUnchanged(Token, Before);

Cleanup:
    if (Previous) RtlFreeHeap(RtlGetProcessHeap(), 0, Previous);
    if (Before) RtlFreeHeap(RtlGetProcessHeap(), 0, Before);
    CloseHandle(Token);
}

static
VOID
AdjustAndResetWithPreviousState(VOID)
{
    static SID Absent = { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { SECURITY_ANONYMOUS_LOGON_RID } };
    NTSTATUS Status;
    HANDLE Token;
    PTOKEN_GROUPS Before, Previous = NULL;
    struct
    {
        ULONG GroupCount;
        SID_AND_ATTRIBUTES Groups[2];
    } Disable;
    ULONG Index, Target, Length, Expected, Needed;

    Token = DuplicateProcessToken();
    if (!Token)
        return;
    Before = QueryGroups(Token);
    Target = FindDefaultOptionalGroup(Before);
    if (Target == MAXULONG)
        goto Cleanup;
    for (Index = 0; Index < Before->GroupCount; Index++)
    {
        if (RtlEqualSid(Before->Groups[Index].Sid, &Absent))
        {
            skip("The anonymous logon SID is group %lu of the token\n", Index);
            goto Cleanup;
        }
    }

    Expected = FIELD_OFFSET(TOKEN_GROUPS, Groups[1]) + RtlLengthSid(Before->Groups[Target].Sid);
    Needed = PreviousStateLength(1, RtlLengthSid(Before->Groups[Target].Sid));
    Previous = RtlAllocateHeap(RtlGetProcessHeap(), 0, Needed);
    if (!Previous)
    {
        skip("Out of memory\n");
        goto Cleanup;
    }

    Disable.GroupCount = 2;
    Disable.Groups[0].Sid = Before->Groups[Target].Sid;
    Disable.Groups[0].Attributes = 0;
    Disable.Groups[1].Sid = &Absent;
    Disable.Groups[1].Attributes = 0;
    Length = 0;
    Status = NtAdjustGroupsToken(Token, FALSE, (PTOKEN_GROUPS)&Disable, Needed, Previous, &Length);
    ok_hex(Status, STATUS_NOT_ALL_ASSIGNED);
    if (Status != STATUS_NOT_ALL_ASSIGNED)
        goto Cleanup;
    ok(Length == Expected, "ReturnLength is %lu, expected %lu\n", Length, Expected);
    ok(Previous->GroupCount == 1, "GroupCount is %lu\n", Previous->GroupCount);
    if (Previous->GroupCount == 1)
    {
        ok(RtlEqualSid(Previous->Groups[0].Sid, Before->Groups[Target].Sid), "The previous SID differs\n");
        ok(Previous->Groups[0].Attributes == Before->Groups[Target].Attributes,
           "The previous attributes are 0x%lx, expected 0x%lx\n",
           Previous->Groups[0].Attributes, Before->Groups[Target].Attributes);
    }

    Length = 0;
    Status = NtAdjustGroupsToken(Token, TRUE, NULL, Needed, Previous, &Length);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        goto Cleanup;
    ok(Length == Expected, "ReturnLength is %lu after the reset, expected %lu\n", Length, Expected);
    ok(Previous->GroupCount == 1, "GroupCount is %lu after the reset\n", Previous->GroupCount);
    if (Previous->GroupCount == 1)
    {
        ok(RtlEqualSid(Previous->Groups[0].Sid, Before->Groups[Target].Sid), "The SID before the reset differs\n");
        ok(Previous->Groups[0].Attributes == (Before->Groups[Target].Attributes & ~SE_GROUP_ENABLED),
           "The attributes before the reset are 0x%lx, expected 0x%lx\n",
           Previous->Groups[0].Attributes, Before->Groups[Target].Attributes & ~SE_GROUP_ENABLED);
    }
    CheckGroupsUnchanged(Token, Before);

Cleanup:
    if (Previous) RtlFreeHeap(RtlGetProcessHeap(), 0, Previous);
    if (Before) RtlFreeHeap(RtlGetProcessHeap(), 0, Before);
    CloseHandle(Token);
}

static
VOID
AdjustUserSid(VOID)
{
    NTSTATUS Status;
    HANDLE Token;
    PTOKEN_GROUPS Before;
    TOKEN_GROUPS Adjust;
    union
    {
        TOKEN_USER User;
        UCHAR Buffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    } UserBefore, UserAfter;
    ULONG Index, Length;

    Token = DuplicateProcessToken();
    if (!Token)
        return;
    Before = QueryGroups(Token);
    Status = NtQueryInformationToken(Token, TokenUser, &UserBefore, sizeof(UserBefore), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    if (!Before || !NT_SUCCESS(Status))
    {
        skip("Failed to query the token\n");
        goto Cleanup;
    }
    for (Index = 0; Index < Before->GroupCount; Index++)
    {
        if (RtlEqualSid(Before->Groups[Index].Sid, UserBefore.User.User.Sid))
        {
            skip("The user SID is also group %lu of the token\n", Index);
            goto Cleanup;
        }
    }

    Adjust.GroupCount = 1;
    Adjust.Groups[0].Sid = UserBefore.User.User.Sid;
    Adjust.Groups[0].Attributes = UserBefore.User.User.Attributes ^ SE_GROUP_ENABLED;
    Status = NtAdjustGroupsToken(Token, FALSE, &Adjust, 0, NULL, NULL);
    ok_hex(Status, STATUS_NOT_ALL_ASSIGNED);

    Status = NtQueryInformationToken(Token, TokenUser, &UserAfter, sizeof(UserAfter), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ok(UserAfter.User.User.Attributes == UserBefore.User.User.Attributes,
           "The user has attributes 0x%lx, expected 0x%lx\n",
           UserAfter.User.User.Attributes, UserBefore.User.User.Attributes);
    }
    CheckGroupsUnchanged(Token, Before);

    Status = NtAdjustGroupsToken(Token, TRUE, NULL, 0, NULL, NULL);
    ok_hex(Status, STATUS_SUCCESS);
    Status = NtQueryInformationToken(Token, TokenUser, &UserAfter, sizeof(UserAfter), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ok(UserAfter.User.User.Attributes == UserBefore.User.User.Attributes,
           "The user has attributes 0x%lx after the reset, expected 0x%lx\n",
           UserAfter.User.User.Attributes, UserBefore.User.User.Attributes);
    }

Cleanup:
    if (Before) RtlFreeHeap(RtlGetProcessHeap(), 0, Before);
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
    AdjustMandatoryGroup();
    AdjustWithPreviousState();
    AdjustAndResetWithPreviousState();
    AdjustUserSid();
}
