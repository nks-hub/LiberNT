/*
 * PROJECT:     LiberNT kernel-mode tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     State a process notify routine runs in, shared declarations
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#pragma once

#define IOCTL_PSNOTIFYAPC_WATCH 1
#define IOCTL_PSNOTIFYAPC_QUERY 2

typedef struct _PSNOTIFYAPC_RESULT
{
    ULONG CreateCalls;
    ULONG CreateIrql;
    ULONG CreateApcsDisabled;
    ULONG ExitCalls;
    ULONG ExitIrql;
    ULONG ExitApcsDisabled;
} PSNOTIFYAPC_RESULT, *PPSNOTIFYAPC_RESULT;
