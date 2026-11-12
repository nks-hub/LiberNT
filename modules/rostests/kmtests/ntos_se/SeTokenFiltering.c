/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Kernel mode tests for token filtering implementation
 * COPYRIGHT:   Copyright 2021 George Bișoc <george.bisoc@reactos.org>
 */

#include <kmt_test.h>
#include <ntifs.h>

static
VOID
FilterToken(VOID)
{
    NTSTATUS Status;
    PSECURITY_SUBJECT_CONTEXT SubjectContext;
    PACCESS_TOKEN Token, FilteredToken = NULL;
    TOKEN_GROUPS SidsToDisable, RestrictedGroups;
    TOKEN_PRIVILEGES Privilege;

    /* Capture the subject context and token for tests */
    SubjectContext = ExAllocatePool(PagedPool, sizeof(SECURITY_SUBJECT_CONTEXT));
    if (SubjectContext == NULL)
    {
        trace("Failed to allocate memory pool for the subject context!\n");
        return;
    }

    SeCaptureSubjectContext(SubjectContext);
    SeLockSubjectContext(SubjectContext);
    Token = SeQuerySubjectContextToken(SubjectContext);
    ok(Token != NULL, "Token mustn't be NULL...\n");

    /* Delete a privilege */
    Privilege.PrivilegeCount = 1;
    Privilege.Privileges[0].Attributes = 0;
    Privilege.Privileges[0].Luid = SeExports->SeSystemEnvironmentPrivilege;

    Status = SeFilterToken(Token,
                           0,
                           NULL,
                           &Privilege,
                           NULL,
                           &FilteredToken);
    ok_irql(PASSIVE_LEVEL);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
        ObDereferenceObject(FilteredToken);

    /* Disable all the privileges */
    FilteredToken = NULL;
    Status = SeFilterToken(Token,
                           DISABLE_MAX_PRIVILEGE,
                           NULL,
                           NULL,
                           NULL,
                           &FilteredToken);
    ok_irql(PASSIVE_LEVEL);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
        ObDereferenceObject(FilteredToken);

    /* Disable a SID */
    SidsToDisable.GroupCount = 1;
    SidsToDisable.Groups[0].Attributes = 0;
    SidsToDisable.Groups[0].Sid = SeExports->SeWorldSid;

    FilteredToken = NULL;
    Status = SeFilterToken(Token,
                           0,
                           &SidsToDisable,
                           NULL,
                           NULL,
                           &FilteredToken);
    ok_irql(PASSIVE_LEVEL);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
        ObDereferenceObject(FilteredToken);

    /*
     * Add a restricted SID but we're going to fail...
     * Because no attributes must be within restricted
     * SIDs.
     */
    RestrictedGroups.GroupCount = 1;
    RestrictedGroups.Groups[0].Attributes = SE_GROUP_ENABLED;
    RestrictedGroups.Groups[0].Sid = SeExports->SeDialupSid;

    FilteredToken = NULL;
    Status = SeFilterToken(Token,
                           0,
                           NULL,
                           NULL,
                           &RestrictedGroups,
                           &FilteredToken);
    ok_irql(PASSIVE_LEVEL);
    ok_eq_hex(Status, STATUS_INVALID_PARAMETER);

    if (skip(GetNTVersion() >= _WIN32_WINNT_VISTA,
             "Restricted SID SeFilterToken probe poisons subsequent process creation on NT 5.x\n"))
        goto done;

    /* Add a restricted SID now */
    RestrictedGroups.GroupCount = 1;
    RestrictedGroups.Groups[0].Attributes = 0;
    RestrictedGroups.Groups[0].Sid = SeExports->SeDialupSid;

    FilteredToken = NULL;
    Status = SeFilterToken(Token,
                           0,
                           NULL,
                           NULL,
                           &RestrictedGroups,
                           &FilteredToken);
    ok_irql(PASSIVE_LEVEL);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
        ObDereferenceObject(FilteredToken);

done:
    /* We're done */
    SeUnlockSubjectContext(SubjectContext);
    SeReleaseSubjectContext(SubjectContext);
    if (SubjectContext)
        ExFreePool(SubjectContext);
}

static
BOOLEAN
CheckAccess(
    _In_ PSECURITY_DESCRIPTOR Sd,
    _In_ PSECURITY_SUBJECT_CONTEXT ProcessContext,
    _In_ PACCESS_TOKEN ClientToken,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PACCESS_MASK GrantedAccess)
{
    GENERIC_MAPPING Mapping = { FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS };
    SECURITY_SUBJECT_CONTEXT Context = *ProcessContext;
    NTSTATUS AccessStatus = STATUS_PENDING;
    BOOLEAN Granted;

    Context.ClientToken = ClientToken;
    Context.ImpersonationLevel = SecurityImpersonation;
    *GrantedAccess = 0;
    Granted = SeAccessCheck(Sd, &Context, FALSE, DesiredAccess, 0, NULL, &Mapping, UserMode, GrantedAccess, &AccessStatus);
    ok_eq_hex(AccessStatus, Granted ? STATUS_SUCCESS : STATUS_ACCESS_DENIED);
    return Granted;
}

static
VOID
WriteRestrictedToken(VOID)
{
    ULONG DaclBuffer[(sizeof(ACL) + 2 * (sizeof(ACCESS_ALLOWED_ACE) + SECURITY_MAX_SID_SIZE)) / sizeof(ULONG) + 1];
    PACL Dacl = (PACL)DaclBuffer;
    SECURITY_SUBJECT_CONTEXT SubjectContext;
    PACCESS_TOKEN Token, Restricted = NULL, WriteRestricted = NULL;
    TOKEN_GROUPS RestrictedGroups;
    SECURITY_DESCRIPTOR Sd;
    ACCESS_MASK GrantedAccess;
    NTSTATUS Status;

    SeCaptureSubjectContext(&SubjectContext);
    Token = SubjectContext.PrimaryToken;

    RestrictedGroups.GroupCount = 1;
    RestrictedGroups.Groups[0].Attributes = 0;
    RestrictedGroups.Groups[0].Sid = SeExports->SeDialupSid;

    Status = SeFilterToken(Token, 0, NULL, NULL, &RestrictedGroups, &Restricted);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        Restricted = NULL;
    Status = SeFilterToken(Token, WRITE_RESTRICTED, NULL, NULL, &RestrictedGroups, &WriteRestricted);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        WriteRestricted = NULL;
    if (Restricted == NULL || WriteRestricted == NULL)
        goto done;

    ok_bool_true(SeTokenIsRestricted(Restricted), "restricted token is restricted");
    ok_bool_false(SeTokenIsWriteRestricted(Restricted), "restricted token is write restricted");
    ok_bool_true(SeTokenIsRestricted(WriteRestricted), "write-restricted token is restricted");
    ok_bool_true(SeTokenIsWriteRestricted(WriteRestricted), "write-restricted token is write restricted");

    Status = RtlCreateSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Status = RtlCreateAcl(Dacl, sizeof(DaclBuffer), ACL_REVISION);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, FILE_ALL_ACCESS, SeExports->SeWorldSid);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Status = RtlSetDaclSecurityDescriptor(&Sd, TRUE, Dacl, FALSE);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Status = RtlSetOwnerSecurityDescriptor(&Sd, SeExports->SeNullSid, FALSE);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Status = RtlSetGroupSecurityDescriptor(&Sd, SeExports->SeNullSid, FALSE);
    ok_eq_hex(Status, STATUS_SUCCESS);

    ok_bool_false(CheckAccess(&Sd, &SubjectContext, Restricted, FILE_GENERIC_READ, &GrantedAccess), "restricted token reads");
    ok_bool_false(CheckAccess(&Sd, &SubjectContext, Restricted, FILE_WRITE_DATA, &GrantedAccess), "restricted token writes");

    ok_bool_true(CheckAccess(&Sd, &SubjectContext, WriteRestricted, FILE_GENERIC_READ, &GrantedAccess), "write-restricted token reads");
    ok_eq_hex(GrantedAccess, FILE_GENERIC_READ);
    ok_bool_true(CheckAccess(&Sd, &SubjectContext, WriteRestricted, FILE_GENERIC_EXECUTE, &GrantedAccess), "write-restricted token executes");
    ok_bool_false(CheckAccess(&Sd, &SubjectContext, WriteRestricted, FILE_WRITE_DATA, &GrantedAccess), "write-restricted token writes");
    ok_bool_false(CheckAccess(&Sd, &SubjectContext, WriteRestricted, FILE_READ_DATA | FILE_APPEND_DATA, &GrantedAccess),
                  "write-restricted token reads and appends");
    ok_bool_true(CheckAccess(&Sd, &SubjectContext, WriteRestricted, MAXIMUM_ALLOWED, &GrantedAccess), "write-restricted token gets its maximum");
    ok_eq_hex(GrantedAccess & (FILE_READ_DATA | FILE_EXECUTE | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES),
              FILE_READ_DATA | FILE_EXECUTE);
    ok_eq_hex(GrantedAccess & (DELETE | WRITE_DAC | WRITE_OWNER), 0);
    ok_bool_false(CheckAccess(&Sd, &SubjectContext, WriteRestricted, DELETE, &GrantedAccess), "write-restricted token deletes");
    ok_bool_false(CheckAccess(&Sd, &SubjectContext, WriteRestricted, WRITE_DAC, &GrantedAccess), "write-restricted token writes the DACL");
    ok_bool_false(CheckAccess(&Sd, &SubjectContext, WriteRestricted, WRITE_OWNER, &GrantedAccess), "write-restricted token writes the owner");
    ok_bool_false(CheckAccess(&Sd, &SubjectContext, WriteRestricted, FILE_READ_DATA | DELETE, &GrantedAccess),
                  "write-restricted token reads and deletes");

    Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, FILE_WRITE_DATA, SeExports->SeDialupSid);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok_bool_true(CheckAccess(&Sd, &SubjectContext, WriteRestricted, FILE_READ_DATA | FILE_WRITE_DATA, &GrantedAccess),
                 "write-restricted token writes with its restricted SID");
    ok_bool_false(CheckAccess(&Sd, &SubjectContext, WriteRestricted, FILE_APPEND_DATA, &GrantedAccess),
                  "write-restricted token appends with its restricted SID");
    ok_bool_true(CheckAccess(&Sd, &SubjectContext, WriteRestricted, MAXIMUM_ALLOWED, &GrantedAccess), "write-restricted token gets its maximum");
    ok_eq_hex(GrantedAccess & (FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA), FILE_READ_DATA | FILE_WRITE_DATA);

done:
    if (WriteRestricted != NULL)
        ObDereferenceObject(WriteRestricted);
    if (Restricted != NULL)
        ObDereferenceObject(Restricted);
    SeReleaseSubjectContext(&SubjectContext);
}

static
VOID
OwnerRights(VOID)
{
    static const PCSTR TokenNames[] = { "unrestricted", "restricted", "write-restricted", "restricted with the owner",
                                        "write-restricted with the owner" };
    static const ACCESS_MASK Desired[] = { READ_CONTROL, WRITE_DAC, MAXIMUM_ALLOWED };
    static const struct
    {
        PCSTR Name;
        ACCESS_MASK Access;
        ACCESS_MASK Granted[RTL_NUMBER_OF(TokenNames)][RTL_NUMBER_OF(Desired)];
    } Tests[] =
    {
        { "user: all", FILE_ALL_ACCESS, { { 0x20000, 0x40000, 0x1f01ff }, { 0, 0, 0 }, { 0x20000, 0, 0x1200e9 },
                                          { 0x20000, 0x40000, 0x1f01ff }, { 0x20000, 0x40000, 0x1f01ff } } },
        { "empty", 0, { { 0x20000, 0x40000, 0x60000 }, { 0, 0, 0 }, { 0, 0, 0 }, { 0x20000, 0x40000, 0x60000 }, { 0x20000, 0x40000, 0x60000 } } },
        { "owner rights: RC WD", READ_CONTROL | WRITE_DAC, { { 0x20000, 0x40000, 0x60000 }, { 0, 0, 0 }, { 0, 0, 0 },
                                                             { 0x20000, 0x40000, 0x60000 }, { 0x20000, 0x40000, 0x60000 } } },
        { "restricting SID: all", FILE_ALL_ACCESS, { { 0x20000, 0x40000, 0x60000 }, { 0, 0, 0 }, { 0, 0, 0 },
                                                     { 0x20000, 0x40000, 0x60000 }, { 0x20000, 0x40000, 0x60000 } } },
        { "user: read", FILE_GENERIC_READ, { { 0x20000, 0x40000, 0x160089 }, { 0, 0, 0 }, { 0x20000, 0, 0x120089 },
                                             { 0x20000, 0x40000, 0x160089 }, { 0x20000, 0x40000, 0x160089 } } },
    };
    ULONG DaclBuffer[(sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + SECURITY_MAX_SID_SIZE) / sizeof(ULONG) + 1];
    PACL Dacl = (PACL)DaclBuffer;
    SECURITY_SUBJECT_CONTEXT SubjectContext;
    PACCESS_TOKEN Tokens[RTL_NUMBER_OF(TokenNames)] = { NULL };
    PSID AceSids[RTL_NUMBER_OF(Tests)];
    ULONG_PTR GroupsBuffer[(FIELD_OFFSET(TOKEN_GROUPS, Groups) + 2 * sizeof(SID_AND_ATTRIBUTES)) / sizeof(ULONG_PTR) + 1];
    PTOKEN_GROUPS RestrictedGroups = (PTOKEN_GROUPS)GroupsBuffer;
    PSID_AND_ATTRIBUTES RestrictedSids;
    PTOKEN_USER User = NULL;
    SECURITY_DESCRIPTOR Sd;
    ACCESS_MASK GrantedAccess;
    BOOLEAN Granted;
    NTSTATUS Status;
    ULONG i, j, k;

    SeCaptureSubjectContext(&SubjectContext);
    Tokens[0] = SubjectContext.PrimaryToken;

    Status = SeQueryInformationToken(Tokens[0], TokenUser, (PVOID*)&User);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
    {
        User = NULL;
        goto done;
    }

    RestrictedSids = RestrictedGroups->Groups;
    RestrictedSids[0].Attributes = 0;
    RestrictedSids[0].Sid = SeExports->SeDialupSid;
    RestrictedSids[1].Attributes = 0;
    RestrictedSids[1].Sid = User->User.Sid;

    for (j = 1; j < RTL_NUMBER_OF(Tokens); j++)
    {
        RestrictedGroups->GroupCount = j < 3 ? 1 : 2;
        Status = SeFilterToken(Tokens[0], (j & 1) ? 0 : WRITE_RESTRICTED, NULL, NULL, RestrictedGroups, &Tokens[j]);
        ok_eq_hex(Status, STATUS_SUCCESS);
        if (!NT_SUCCESS(Status))
        {
            Tokens[j] = NULL;
            goto done;
        }
    }

    AceSids[0] = User->User.Sid;
    AceSids[1] = NULL;
    AceSids[2] = SeExports->SeOwnerRightsSid;
    AceSids[3] = SeExports->SeDialupSid;
    AceSids[4] = User->User.Sid;

    for (i = 0; i < RTL_NUMBER_OF(Tests); i++)
    {
        Status = RtlCreateSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION);
        ok_eq_hex(Status, STATUS_SUCCESS);
        Status = RtlCreateAcl(Dacl, sizeof(DaclBuffer), ACL_REVISION);
        ok_eq_hex(Status, STATUS_SUCCESS);
        if (AceSids[i] != NULL)
        {
            Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, Tests[i].Access, AceSids[i]);
            ok_eq_hex(Status, STATUS_SUCCESS);
        }
        Status = RtlSetDaclSecurityDescriptor(&Sd, TRUE, Dacl, FALSE);
        ok_eq_hex(Status, STATUS_SUCCESS);
        Status = RtlSetOwnerSecurityDescriptor(&Sd, User->User.Sid, FALSE);
        ok_eq_hex(Status, STATUS_SUCCESS);
        Status = RtlSetGroupSecurityDescriptor(&Sd, User->User.Sid, FALSE);
        ok_eq_hex(Status, STATUS_SUCCESS);

        for (j = 0; j < RTL_NUMBER_OF(Tokens); j++)
        {
            for (k = 0; k < RTL_NUMBER_OF(Desired); k++)
            {
                Granted = CheckAccess(&Sd, &SubjectContext, Tokens[j], Desired[k], &GrantedAccess);
                ok(Granted == (Tests[i].Granted[j][k] != 0), "DACL %s, %s token, access 0x%lx: granted %d\n",
                   Tests[i].Name, TokenNames[j], Desired[k], Granted);
                if (Granted)
                {
                    ok(GrantedAccess == Tests[i].Granted[j][k], "DACL %s, %s token, access 0x%lx: granted 0x%lx, expected 0x%lx\n",
                       Tests[i].Name, TokenNames[j], Desired[k], GrantedAccess, Tests[i].Granted[j][k]);
                }
            }
        }
    }

done:
    for (j = 1; j < RTL_NUMBER_OF(Tokens); j++)
    {
        if (Tokens[j] != NULL)
            ObDereferenceObject(Tokens[j]);
    }
    if (User != NULL)
        ExFreePool(User);
    SeReleaseSubjectContext(&SubjectContext);
}

START_TEST(SeTokenFiltering)
{
    FilterToken();
    WriteRestrictedToken();
    OwnerRights();
}
