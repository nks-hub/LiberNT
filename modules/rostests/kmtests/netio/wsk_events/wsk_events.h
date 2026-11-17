/*
 * PROJECT:     LiberNT kernel-mode tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     WSK datagram receive events, declarations
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#pragma once

#define IOCTL_WSKEVENTS_RUN 1
#define IOCTL_WSKEVENTS_INTERFACES 2

#define WSKEVENTS_PORT 47377

typedef struct _WSKEVENTS_INTERFACES
{
    ULONG LoopbackIndex;
    ULONG OtherIndex;
    ULONG OtherAddress;
    ULONG WeakHostSend;
} WSKEVENTS_INTERFACES, *PWSKEVENTS_INTERFACES;
