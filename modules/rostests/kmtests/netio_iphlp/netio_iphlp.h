/*
 * PROJECT:     LiberNT kernel-mode tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Kernel-mode IP Helper routines of netio.sys, declarations
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#pragma once

#define IOCTL_NETIOIPHLP_GET_IF_ENTRY2 1
#define IOCTL_NETIOIPHLP_GET_BEST_ROUTE2 2
#define IOCTL_NETIOIPHLP_NOTIFY 3

#define NETIOIPHLP_LOOPBACK_ADDRESS 0x0100007F

typedef struct _NETIOIPHLP_BEST_ROUTE
{
    ULONG Destination;
    MIB_IPFORWARD_ROW2 Route;
} NETIOIPHLP_BEST_ROUTE, *PNETIOIPHLP_BEST_ROUTE;
