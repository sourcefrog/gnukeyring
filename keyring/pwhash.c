/* -*- c-file-style: "java"; -*-
 *
 * $Header$
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000, 2001 Martin Pool <mbp@users.sourceforge.net>
 * Copyright (C) 2001-2003 Jochen Hoenicke <hoenicke@users.sourceforge.net>
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
 * The AppInfo record in the database contains a salted hash of the
 * password, which we use to check whether the password is correct or
 * not.  The database key is calculated by the PBKDF2 algorithm of
 * PKCS#5v2 (RFC 2898):
 *
 * key = PBKDF2(PASSWORD, SALT, ITER)
 *
 * The hash are the first eight bytes of the SHA1 sum of the key.  The
 * reason to use only eight bytes is to make it impossible to just
 * brute-force reverse the SHA1 sum.  It is enough to protect against
 * mistyped passwords.
 */

#include "includes.h"

/*
 * Generate the hash of a password, using specified salt.
 * We use an algorithm following PBKDF2 of PKCS #5
 * the iteration count ITER.
 */
static void PwHash_CalcSnib(SnibType *snib, UInt16 snibSize,
			    const Char *passwd, Char *salt, UInt16 iter)
{
    MemSet(snib, sizeof(SnibType), 0);
    PwHash_PBKDF2(snib, snibSize, passwd, salt, iter);
}


/*
 * Generate the hash of a password, using specified salt.
 * This calculates the first kHashSize bytes of the standard SHA1 sum 
 * of hash concatenated with snib.
 *
 * This code relies on the fact that SHA1 and m68k are both big endian and
 * that kSaltSize + snibSize < 55 bytes.  Fix this if you support passwords
 * with more than 376 bits.
 */
static void PwHash_CalcHash(HashType hash, SnibType *snib, UInt16 snibSize,
			    UInt8 *salt)
{
    UInt32 buffer[kSHA1BlockSize / sizeof(UInt32)];

    MemSet(buffer, sizeof(buffer), 0);
    MemMove(((char*)buffer), snib, snibSize);
    MemMove(((char*)buffer) + snibSize, salt, kSaltSize);
    ((char*)buffer)[snibSize + kSaltSize] = 0x80;
    buffer[15] = (snibSize + kSaltSize) * 8;
    SHA1_Block(initsha1, buffer, buffer);
    MemMove(hash, buffer, kHashSize);
    MemSet(buffer, sizeof(buffer), 0);
}


/*
 * Generate new salt, and calculate a checking-hash.
 */
Err PwHash_Create(const Char *newPasswd, UInt16 cipher, UInt16 iter, 
		  SaltHashType *salthash, CryptoKey *newKey) {
    SnibType snib;
    UInt16   snibSize = CryptoKeySize(cipher);
    int      i;

    /* Now create the salt, which must not contain NUL characters */
    for (i = 0; i < kSaltSize; i++) {
	do {
	    salthash->salt[i] = Secrand_GetByte();
	} while (salthash->salt[i] == 0);
    }
    salthash->iter = iter;
    salthash->cipher = cipher;

    PwHash_CalcSnib(&snib, snibSize, newPasswd, salthash->salt, iter);
    CryptoPrepareSnib(cipher, &snib);
    PwHash_CalcHash(salthash->hash, &snib, snibSize, salthash->salt);
    if (newKey) {
	if (!CryptoPrepareKey(cipher, &snib, newKey)) {
	    MemSet(&snib, sizeof(snib), 0);
	    return sysErrLibNotFound;
	}
    }
    MemSet(&snib, sizeof(snib), 0);
    return 0;
}


/*
 * Store new salt and hash  in kMasterHashRec.
 */
Err PwHash_Store(const Char *newPasswd, SaltHashType *salthash)
{
    SnibType            snib;
    KrAppInfoPtr        appInfoPtr;

    PwHash_CalcSnib(&snib, CryptoKeySize(salthash->cipher), 
		    newPasswd, salthash->salt, salthash->iter);
    CryptoPrepareSnib(salthash->cipher, &snib);
    Snib_StoreRecordKey(&snib);
    appInfoPtr = KeyDB_LockAppInfo();
    DmWrite(appInfoPtr, (UInt16) &((KrAppInfoType*)NULL)->keyHash, 
	    salthash, sizeof(SaltHashType));
    MemPtrUnlock(appInfoPtr);
    MemSet(salthash, sizeof(salthash), 0);

    return 0;
}

/*
 * Check whether snib is up to date.
 */
Boolean PwHash_CheckSnib(SnibType *snib, CryptoKey *cryptoKey)
{
    Boolean		result;
    KrAppInfoPtr        appInfoPtr;
    HashType            hash;

    appInfoPtr = KeyDB_LockAppInfo();

    PwHash_CalcHash(hash, snib, CryptoKeySize(appInfoPtr->keyHash.cipher), 
		    appInfoPtr->keyHash.salt);
    result = !MemCmp(hash, appInfoPtr->keyHash.hash, kHashSize);
    if (result && cryptoKey) {
	result = CryptoPrepareKey(appInfoPtr->keyHash.cipher, 
				  snib, cryptoKey);
	if (!result)
	    FrmCustomAlert(NotEnoughFeaturesAlert, "crypto library", 
			   NULL, NULL);
    }
    MemPtrUnlock(appInfoPtr);

    return result;
}

/*
 * Check whether GUESS is the correct password for the database.
 */
Boolean PwHash_Check(CryptoKey *cryptoKey, Char *guess)
{
    SnibType            snib;
    Boolean		result;
    KrAppInfoPtr        appInfoPtr;
    HashType            hash;
    UInt16              snibSize;

    appInfoPtr = KeyDB_LockAppInfo();

    snibSize = CryptoKeySize(appInfoPtr->keyHash.cipher);
    PwHash_CalcSnib(&snib, snibSize, 
		    guess, appInfoPtr->keyHash.salt, 
		    appInfoPtr->keyHash.iter);
    CryptoPrepareSnib(appInfoPtr->keyHash.cipher, &snib);
    PwHash_CalcHash(hash, &snib, snibSize,
		    appInfoPtr->keyHash.salt);
    result = !MemCmp(hash, appInfoPtr->keyHash.hash, kHashSize);
    if (result) {
	Snib_StoreRecordKey(&snib);
	if (cryptoKey) {
	    result = CryptoPrepareKey(appInfoPtr->keyHash.cipher, 
				      &snib, cryptoKey);
	    if (!result)
		FrmCustomAlert(NotEnoughFeaturesAlert, "crypto library", 
			       NULL, NULL);
	}
    }
    MemSet(&snib, sizeof(snib), 0);
    MemPtrUnlock(appInfoPtr);

    return result;
}
