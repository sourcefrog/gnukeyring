/* -*- c-file-style: "java" -*-
 *
 * $Header$
 * 
 * Keyring -- store passwords securely on a handheld
 *
 * Copyright (C) 1999, 2000 by Martin Pool <mbp@users.sourceforge.net>
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

#include "resource.h"
#include "keyring.h"
#include "beta.h"

/* True if this is a stable rather than a beta release of the app */
#define kAppStableVers 0

/* ======================================================================
 *
 * Checking for beta versions.
 *
 * To save grief, I think it would be sensible to warn people as the
 * start the app that it is only a beta and that they should keep
 * backup copies of all their data.
 *
 * We don't want to do this every time it starts, so we keep a
 * Preference giving the last seen application version.
 */


static void Gkr_BetaWarning(void)
{
    FrmAlert(BetaAlert);
}



void Gkr_CheckBeta(void)
{
    Int16 lastVers = 0;
    Int16 size = sizeof lastVers;
    Int16 ret;
    Boolean useSavedPref = true;

    ret = PrefGetAppPreferences(kKeyringCreatorID,
                                kLastVersionPref,
                                &lastVers, &size,
                                useSavedPref);

    if (((ret == noPreferenceFound)
	 || (size != sizeof lastVers)
	 || (lastVers != kAppVersion))
	&& !kAppStableVers)
        Gkr_BetaWarning();

    lastVers = kAppVersion;
    size = sizeof lastVers;
    PrefSetAppPreferences(kKeyringCreatorID,
                          kLastVersionPref,
                          kAppVersion,
                          &lastVers,
                          size,
                          useSavedPref);
}
