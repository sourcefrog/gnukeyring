/* -*- c-file-style: "java"; -*-
 *
 * $Id$
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 2002-2005 by Jochen Hoenicke <hoenicke@users.sourceforge.net>
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
#include <palmOne_68K.h>
#include <TxtGlue.h>
#include <WinGlue.h>
#include "sections.h"
#include "sha1.h"
#include <md5.h>

#include <des.h>
#include "AESLib-noinline.h"

#include "resource.h"
#include "keyring.h"
#include "error.h"
#include "crypto.h"
#include "pwhash.h"
#include "record.h"
#include "snib.h"
#include "pronounce.h"
#include "prototype.h"
#include "pbkdf-arm.h"
