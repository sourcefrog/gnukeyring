/* -*- c-indentation-style: "bsd"; c-basic-offset: 4; indent-tabs-mode: t; -*-
 *
 * $Id$
 * 
 * GNU Keyring for PalmOS -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000 Martin Pool <mbp@humbug.org.au>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <PalmOS.h>

#include "auto.h"
#include "keyring.h"
#include "resource.h"
#include "memdebug.h"

/*
 * Toggle memory debugging flags, and update the menuitem in the
 * current form to reflect their setting.
 */
void App_SetMemDebug(Int16 cmdId)
{
    Err			err;
    UInt16		flags;
    UInt16		bit;
    Char		hexbuf[10];

    flags = MemDebugMode();

    switch (cmdId) {
    case MemAllHeapsCmd:
	bit = memDebugModeAllHeaps;
	break;
    case MemCheckOnChangeCmd:
	bit = memDebugModeCheckOnChange;
	break;
    case MemCheckOnAllCmd:
	bit = memDebugModeCheckOnAll;
	break;
    case MemScrambleOnChangeCmd:
	bit = memDebugModeScrambleOnChange;
	break;
    case MemScrambleOnAllCmd:
	bit = memDebugModeScrambleOnAll;
	break;
    case MemFillFreeCmd:
	bit = memDebugModeFillFree;
	break;
    case MemRecordMinDynHeapFreeCmd:	
	bit = memDebugModeRecordMinDynHeapFree;
	break;
    default:
	return;			/* shrug */
    }

    flags ^= bit;

    err = MemSetDebugMode(flags);
    if (err) {
	App_ReportSysError(MemDebugFailedAlert, err);
	return;
    }

    flags = MemDebugMode();
    StrIToH(hexbuf, flags);
    FrmCustomAlert(MemDebugSetAlert, hexbuf, "", "");
}
