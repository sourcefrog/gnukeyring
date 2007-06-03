/* -*- c-file-style: "java"; -*-
 *
 * $Id$
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000, 2001 Martin Pool <mbp@users.sourceforge.net>
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

#include "includes.h"
#include "AESLib-inline.h"

// ======================================================================
// Crypto functions

Err CheckGlib(UInt32 creator, char* libname) {
    DmOpenRef libdb;

    if ((libdb = DmOpenDatabaseByTypeCreator('GLib', creator, 
					     dmModeReadOnly))) {
	DmCloseDatabase(libdb);
	return 0;
    }

    FrmCustomAlert(NotEnoughFeaturesAlert, libname, NULL, NULL);
    return sysErrLibNotFound;
}

/**
 * Returns the number of bytes of the key.  Note that the key
 * is also used to protect opening the database, so it shouldn't
 * be zero, even for no cipher.
 */
UInt16 CryptoKeySize(UInt16 cipher)
{
    static const UInt16 keysize[] = {
	/*NO_CIPHER*/            8,
	/*DES3_EDE_CBC_CIPHER*/ 24,
	/*AES_128_CBC_CIPHER*/  16,
	/*AES_256_CBC_CIPHER*/  32
    };
    return keysize[cipher];
}

void CryptoPrepareSnib(UInt16 cipher, SnibType *rawKey)
{
    int i;
    if (cipher == DES3_EDE_CBC_CIPHER) {
	for (i = 0; i < 3; i++)
	    des_set_odd_parity(&rawKey->key.des[i]);
    }
}

Boolean CryptoPrepareKey(UInt16 cipher, SnibType *rawKey, CryptoKey *cryptKey)
{
    int i;
    cryptKey->cipher = cipher;
    switch (cipher) {
    case NO_CIPHER:
	cryptKey->blockSize = 1;
	break;
    case DES3_EDE_CBC_CIPHER:
	/* Check if the necessary openssl libraries are installed */
	if (CheckGlib('CrDS', "DESLib.prc"))
	    return 0;

	cryptKey->blockSize = sizeof(des_cblock);
	for (i = 0; i < 3; i++) {
	    des_set_key(&rawKey->key.des[i], cryptKey->key.des[i]);
	}
	break;
    case AES_128_CBC_CIPHER:
    case AES_256_CBC_CIPHER:
	cryptKey->blockSize = 16;
	if (AESLib_OpenLibrary(&cryptKey->key.aes.refNum)) {
	    FrmCustomAlert(NotEnoughFeaturesAlert, "AESLib.prc", NULL, NULL);
	    return 0;
	}
	AESLibEncKey(cryptKey->key.aes.refNum, rawKey->key.aes,
		     cipher == AES_256_CBC_CIPHER ? 32 : 16,
		     &cryptKey->key.aes.enc);
	AESLibDecKey(cryptKey->key.aes.refNum, rawKey->key.aes,
		     cipher == AES_256_CBC_CIPHER ? 32 : 16,
		     &cryptKey->key.aes.dec);
	break;
    default:
	{
	    Char buffer[maxStrIToALen];
	    StrIToA(buffer, cipher);
	    FrmCustomAlert(CipherNotSupportedAlert, buffer, NULL, NULL);
	}
	return 0;
    }
    return 1;
}

void CryptoDeleteKey(CryptoKey *cryptKey) {
    switch (cryptKey->cipher) {
    case AES_128_CBC_CIPHER:
    case AES_256_CBC_CIPHER:
	AESLib_CloseLibrary(cryptKey->key.aes.refNum);
    }
    MemWipe(cryptKey, sizeof(CryptoKey));
}

Err CryptoRead(void * from, void * to, UInt32 len, 
	       CryptoKey *cryptKey, UInt8 *ivec)
{
    switch (cryptKey->cipher) {
    case NO_CIPHER:
	MemMove(to, from, len);
	break;
    case DES3_EDE_CBC_CIPHER:
	des_ede3_cbc_encrypt(from, to, len, 
			     cryptKey->key.des[0], 
			     cryptKey->key.des[1], 
			     cryptKey->key.des[2],
			     (des_cblock*) ivec, false);
	break;
    case AES_128_CBC_CIPHER:
    case AES_256_CBC_CIPHER:
	AESLibDecBigBlk(cryptKey->key.aes.refNum, from, to, 
			&len, true, ivec, &cryptKey->key.aes.dec);
	break;
    }
    return 0;
}


Err CryptoWrite(void *from, void * to, UInt32 len,
		CryptoKey *cryptKey, UInt8 *ivec)
{
    switch (cryptKey->cipher) {
    case NO_CIPHER:
	MemMove(to, from, len);
	break;
    case DES3_EDE_CBC_CIPHER:
	des_ede3_cbc_encrypt(from, to, len, 
			     cryptKey->key.des[0], 
			     cryptKey->key.des[1], 
			     cryptKey->key.des[2],
			     (des_cblock*) ivec, true);
	break;
    case AES_128_CBC_CIPHER:
    case AES_256_CBC_CIPHER:
	AESLibEncBigBlk(cryptKey->key.aes.refNum, from, to, 
			&len, true, ivec, &cryptKey->key.aes.enc);
	break;
    }
    return 0;
}
