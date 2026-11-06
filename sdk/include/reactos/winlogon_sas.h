/*
 * PROJECT:     LiberNT Winlogon
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Software secure attention sequence shared between Winlogon and sas.dll
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#pragma once

/*
 * Winlogon of session %lu waits on this auto-reset event and handles a signal
 * like Ctrl+Alt+Del from the keyboard. Only SYSTEM may set it.
 */
#define WINLOGON_SOFTWARE_SAS_EVENT L"Global\\WinlogonSoftwareSas%lu"
