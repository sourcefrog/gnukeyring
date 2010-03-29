/* -*- c-file-style: "java"; -*-
 *
 * $Id: keyring.h 783 2007-06-03 15:17:46Z hoenicke $
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000 by Martin Pool <mbp@users.sourceforge.net>
 * Copyright (C) 2001-2005 Jochen Hoenicke <hoenicke@users.sourceforge.net>
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

#ifdef __GNUC__
#  define UNUSED(x) x __attribute__((unused))
#endif	/* !__GNUC__ */

#define RESOURCE_NUM_PBKDF_PNO 1
#define RESOURCE_TYPE_PNO      'armc'

typedef struct {
    void*  result;
    Int32  resultLen;
    const Char *passwd;
    const Char *salt;
    Int32  iter;
} PbkdfPnoDataType;
