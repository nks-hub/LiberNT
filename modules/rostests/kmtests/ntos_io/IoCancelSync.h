/*
 * PROJECT:     LiberNT kernel-mode tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Cancelling a synchronous request that has no cancel routine, shared declarations
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#pragma once

#define IOCTL_IOCANCELSYNC_WAIT_ALERTABLE 1
#define IOCTL_IOCANCELSYNC_WAIT_PLAIN     2
#define IOCTL_IOCANCELSYNC_WAIT_CANCELLABLE 3

#define IOCANCELSYNC_ALERTABLE_TIMEOUT_MS 10000
#define IOCANCELSYNC_PLAIN_DELAY_MS       1500
