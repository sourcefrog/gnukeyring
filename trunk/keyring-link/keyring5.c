/* -*- c-basic-offset: 4; -*-
 *
 * $Id$
 * 
 * GNU Keyring -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000, 2001 Martin Pool <mbp@sourcefrog.net>
 * Copyright (C) 2003 Jochen Hoenicke <hoenicke@users.sourceforge.net>
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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>

#include <netinet/in.h>

#include <pi-file.h>
#include <pi-dlp.h>

#include <openssl/des.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "trace.h"
#include "hextype.h"
#include "keyring5.h"
#include "keyring.h"


typedef struct {
    UInt16 cipher;
    UInt16 blockSize;
    union {
	DES_key_schedule des[3];
	struct {
	    AES_KEY dec;
	} aes;
    } key;
} CryptoKey;

#define false 0
#define true  1

/* #include <popt.h> */


/*
 * TODO: Construct records given a text form.  They're a bit hard to
 * parse, though.
 *
 * TODO: Choose a record to edit in $EDITOR.
 *
 * TODO: Use getpass() or an environment variable, not an insecure
 * command-line argument.
 *
 * TODO: Optionally turn off trace.
 */


static int verbose = 0;


static int keyring5_verify(KrAppInfoType *appdata, size_t data_len,
			  const char *pass, unsigned char **key)
{
    const int keylens[4] = { 8, 24, 16, 32 };
    int                keylen, i;
    int                cipher, iter;
    char               digest[SHA_DIGEST_LENGTH];
    SHA_CTX            shactx;

    cipher = ntohs(appdata->keyHash.cipher);
    iter = ntohs(appdata->keyHash.iter);
    keylen = keylens[cipher];
    *key = malloc(keylen);


    if (verbose) {
	fprintf(stderr, "AppInfo:\n");
	hextype(stderr, appdata, sizeof(KrAppInfoType));
	fprintf(stderr, "cipher %u, iter %u:\n",
		cipher, iter);
    }
    
    PKCS5_PBKDF2_HMAC_SHA1(pass, strlen(pass), 
			   appdata->keyHash.salt, kSaltSize, 
			   iter,
			   keylen, *key);
    if (verbose) {
	fprintf(stderr, "calculated key is:\n");
	hextype(stderr, *key, keylen);
    }

    if (cipher == DES3_EDE_CBC_CIPHER) {
	for (i = 0; i < 3; i++)
	    DES_set_odd_parity(((DES_cblock*) *key) + i);
    }


    SHA1_Init(&shactx);
    SHA1_Update(&shactx, *key, keylen);
    SHA1_Update(&shactx, appdata->keyHash.salt, kSaltSize);
    SHA1_Final(digest, &shactx);

    if (verbose) {
	fprintf(stderr, "calculated digest is:\n");
	hextype(stderr, digest, sizeof digest);
    }

    return !memcmp(digest, appdata->keyHash.hash, kHashSize);
}



static void crypto_read(char const *from, char *to, size_t len, 
			unsigned char *ivec,
			CryptoKey *cryptKey)
{
    if (len & (cryptKey->blockSize-1)) 
	rs_fatal("crypted data is not an even number of DES blocks!");

    switch (cryptKey->cipher) {
    case NO_CIPHER:
	memcpy(to, from, len);
	break;
    case DES3_EDE_CBC_CIPHER:
	DES_ede3_cbc_encrypt(from, to, len, 
			     &cryptKey->key.des[0], 
			     &cryptKey->key.des[1], 
			     &cryptKey->key.des[2],
			     (DES_cblock*) ivec, false);
	break;
    case AES_128_CBC_CIPHER:
    case AES_256_CBC_CIPHER:
	AES_cbc_encrypt(from, to, len, &cryptKey->key.aes.dec,
			ivec, false);
	break;
    }
}


static void crypto_setup(UInt16 cipher, unsigned char const *dbkey, 
			 CryptoKey *cryptKey)
{
    int i;
    cryptKey->cipher = cipher;
    switch (cipher) {
    case NO_CIPHER:
	cryptKey->blockSize = 1;
	break;
    case DES3_EDE_CBC_CIPHER:
	cryptKey->blockSize = sizeof(DES_cblock);
	for (i = 0; i < 3; i++)
	    DES_set_key(((DES_cblock *)dbkey) + i, &cryptKey->key.des[i]);
	break;
    case AES_128_CBC_CIPHER:
    case AES_256_CBC_CIPHER:
	cryptKey->blockSize = 16;
	AES_set_decrypt_key(dbkey,
			    cipher == AES_256_CBC_CIPHER ? 256 : 128,
			    &cryptKey->key.aes.dec);
	break;
    }
}


void keyring5_print_record(FILE *f, const keyring_record_t *rec)
{
    fprintf(f, "#%d%s\n", rec->idx,
	   (rec->attr & dlpRecAttrDeleted ? " DELETED" : ""));
    fprintf(f, "Name: %s\n", rec->name);
    fprintf(f, "Account: %s\n", rec->acct);
    fprintf(f, "Password: %s\n", rec->passwd);
    fprintf(f, "Notes: %s\n", rec->notes);
}


void keyring5_free_record(keyring_record_t *rec)
{
    if (rec->name)
	free(rec->name);
    if (rec->acct)
	free(rec->acct);
    if (rec->passwd)
	free(rec->passwd);
    if (rec->notes)
	free(rec->notes);
    free(rec);
}

#define EVEN(x) (((x)+1)&~1)

void keyring5_unpack_field(unsigned char **recpp, size_t *rec_lenp,
			  keyring_record_t *rec)
{
    size_t len, reallen;
    unsigned char *recp = *recpp;
    char **fieldp;

    len = (recp[0] << 8) + recp[1];
    reallen = EVEN(len) + 4;

    if (reallen + 2 > *rec_lenp)
	rs_fatal("record underflow");

    switch (recp[2]) {
    case 0:
	fieldp = &rec->name;
	break;
    case 1:
	fieldp = &rec->acct;
	break;
    case 2:
	fieldp = &rec->passwd;
	break;
    case 255:
	fieldp = &rec->notes;
	break;
    default:
	fieldp = NULL;
    }
	
    if (fieldp) {
	*fieldp = malloc(len + 1);
	memcpy(*fieldp, recp + 4, len);
	(*fieldp)[len] = 0;
    }
    *recpp += reallen;
    *rec_lenp -= reallen;
}
			 

void keyring5_unpack(struct pi_file *pif, int idx, CryptoKey *cryptoKey,
		    keyring_record_t **prec)
{
    unsigned char      *plain;
    unsigned char      *recp;
    size_t             rec_len;
    keyring_record_t   *rec;
    char               *ivec;

    rec = malloc(sizeof(*rec));
    *prec = rec;

    rec->idx = idx;
	
    if (pi_file_read_record(pif, idx, &recp, &rec_len,
			    &rec->attr, &rec->category, NULL) == -1) {
	rs_fatal("error reading record");
    }

    keyring5_unpack_field(&recp, &rec_len, rec);
    
    if (cryptoKey->blockSize + 2 > rec_len)
	rs_fatal("record underflow");

    ivec = recp;
    recp += cryptoKey->blockSize;
    rec_len -= cryptoKey->blockSize;

    if (!(plain = malloc(rec_len))) 
	rs_fatal("allocation failed");
    
    crypto_read(recp, plain, rec_len, ivec, cryptoKey);

    recp = plain;
    while (recp[0] != 0xff || recp[1] != 0xff) {
	keyring5_unpack_field(&recp, &rec_len, rec);
    }
    free(plain);
}


static void keyring5_dumprecords(struct pi_file *pif, 
				int cipher, unsigned char *dbkey)
{
    int                nrecords;
    int                idx;
    CryptoKey          cryptkey;

    if (pi_file_get_entries(pif, &nrecords) == -1) {
	rs_fatal("error getting number of records");
    }

    crypto_setup(cipher, dbkey, &cryptkey);

    for (idx = 0; idx < nrecords; idx++) {
	keyring_record_t       *keyp;
	
	keyring5_unpack(pif, idx, &cryptkey, &keyp);
	keyring5_print_record(stdout, keyp);
	keyring5_free_record(keyp);
    }
}


void keyring5_dumpfile(struct pi_file *pif, const char *pass)
{
    KrAppInfoType *pdata;
    size_t             data_len;
    unsigned char      *dbkey;
    
    pi_file_get_app_info(pif, &pdata, &data_len);

    if (!keyring5_verify(pdata, data_len, pass, &dbkey)) {
	rs_log(RS_LOG_ERR, "password is incorrect");
	exit(2);
    }

    keyring5_dumprecords(pif, ntohs(pdata->keyHash.cipher), dbkey);
}
