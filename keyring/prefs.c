/* -*- c-file-style: "k&r"; -*-
 *
 * $Id$
 * 
 * Keyring -- store passwords securely on a handheld
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

/*
 * This file looks after the "Preferences" dialog.  For the time being
 * the only setting here is how long the keyring stays unlocked.
 *
 * TODO: Require that we're unlocked to set the preferences.
 */

#include <PalmOS.h>

#include "resource.h"
#include "keyring.h"
#include "memutil.h"
#include "keydb.h"
#include "uiutil.h"
#include "prefs.h"
#include "auto.h"

// ======================================================================
// Preferences

void PrefsForm_Run(void) {
    FormPtr 	prevFrm = FrmGetActiveForm();
    FormPtr	frm = FrmInitForm(ID_PrefsForm);
    UInt16	btn;
    Int16		chosen;
    
    static const UInt16 map[] = {
	0,   Expiry0Push,
	15,  Expiry15Push,
	60,  Expiry60Push,
	300, Expiry300Push,
	-1
    };

    UI_ScanAndSet(frm, map, gPrefs.timeoutSecs);

    btn = FrmDoDialog(frm);

    if (btn == CancelBtn)
	goto leave;

    chosen = UI_ScanForFirst(frm, map);
    if (chosen != -1) {
	gPrefs.timeoutSecs = chosen;
    }
    
 leave:
    FrmDeleteForm(frm);
    FrmSetActiveForm(prevFrm);
}


