/*
 * PROJECT:     LiberNT Winlogon
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Software secure attention sequence shared between Winlogon and sas.dll
 * COPYRIGHT:   Copyright 2026 LuRy <lury@lury.cz>
 */

#pragma once

#define WINLOGON_SOFTWARE_SAS_EVENT L"Global\\WinlogonSoftwareSas%lu"

/* LocalSystem: full access, the SERVICE logon group: EVENT_MODIFY_STATE */
#define WINLOGON_SOFTWARE_SAS_EVENT_SDDL L"D:(A;;GA;;;SY)(A;;0x2;;;SU)"

#define WINLOGON_SOFTWARE_SAS_SERVICES 0x1
