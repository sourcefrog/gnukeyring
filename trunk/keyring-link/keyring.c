/* -*- c-basic-offset: 4; -*-
 *
 * $Id$
 * 
 * GNU Keyring -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000, 2001 Martin Pool <mbp@sourcefrog.net>
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

#include <libpisock/pi-file.h>
#include <libpisock/pi-dlp.h>

#include <openssl/ssl.h>
#include <openssl/des.h>
#include <openssl/md5.h>

#include "trace.h"

/* #include <popt.h> */


static void keyring_dumpfile(struct pi_file *pif, const char *);

#define kKeyDBType		0x476b7972  /* 'Gkyr' as network-endian int */
#define kKeyringCreatorID	0x47746b72  /* 'Gtkr' as network-endian int */

#define kDatabaseVersion	4

#define kSaltSize               4

#define kNumReservedRecords     1

#define kDESBlockSize           8

des_key_schedule key1, key2;


int main(int argc, char **argv) 
{
    struct pi_file *pif;

    if (!argv[1] || !argv[2]) {
	rs_fatal("usage: keyring DATAFILE PASSWORD");
    }

    if (!(pif = pi_file_open(argv[1]))) {
	rs_fatal("couldn't open \"%s\": %s", argv[1], strerror(errno));
    }

    keyring_dumpfile(pif, argv[2]);

    pi_file_close(pif);

    return 0;
}


static void hextype(FILE *f, unsigned char const *d, size_t len)
{
    int               i, j;

    for (i = 0; i < len; i++) {
	j = i;
	fprintf(f, "%6x: ", i);
	for (; i < len && (i%16) != 15; i++) {
	    fprintf(f, "%02x ", d[i]);
	}
	for (; (i%16) != 15; i++) {
	    fprintf(f, "   ");
	}
	printf("    ");
	i = j;
	for (; i < len && (i%16) != 15; i++) {
	    fprintf(f, "%c", isprint(d[i]) ? d[i] : '.');
	} 
	
	if (i != (len-1))
	    fprintf(f, "\n");
    }
    fprintf(f, "\n");
}


static int keyring_verify(const unsigned char *rec0, size_t rec_len,
			  const char *pass)
{
    char               digest[MD5_DIGEST_LENGTH];
    char               msg[MD5_CBLOCK];

    memset(msg, 0, sizeof msg);
    memcpy(msg, rec0, kSaltSize);
    strncpy(msg + kSaltSize, pass, MD5_CBLOCK - 1 - kSaltSize);

    MD5(msg, sizeof msg, digest);
    
    fprintf(stdout, "calculated digest is:\n");
    hextype(stdout, digest, sizeof digest);

    return !memcmp(digest, rec0+kSaltSize, MD5_DIGEST_LENGTH);
}


static void keyring_dumpheader(struct pi_file *pif)
{
    struct DBInfo      db_info;

    if (pi_file_get_info(pif, &db_info) == -1) {
	rs_fatal("error getting DBInfo");
    }

    if (db_info.type != kKeyDBType) {
	rs_fatal("database type is %#lx, but should be %#lx -- perhaps "
		 "this is not a Keyring database?",
		 db_info.type, (long) kKeyDBType);
    }

    if (db_info.version != kDatabaseVersion) {
	rs_fatal("database version is %d, but this program can only handle "
		 "version %d",
		 db_info.version, kDatabaseVersion);
    }

    printf("Database: %.34s\n", db_info.name);

    /* Note ctime result has a trailing newline */
    printf("Create: %s", ctime(&db_info.createDate));
    printf("Modify: %s", ctime(&db_info.modifyDate));
    printf("Backup: %s",
	   (db_info.backupDate > 0) ? ctime(&db_info.backupDate) : "none\n");
}


static void des_read(char const *from, char *to, size_t len, char const *snib)
{
    while (len >= kDESBlockSize) {
	des_ecb2_encrypt((const_des_cblock *) from,
			 (des_cblock *) to, key1, key2, DES_DECRYPT);
	from += kDESBlockSize;
	to   += kDESBlockSize;
	len  -= kDESBlockSize;
    }

    if (len) 
	rs_fatal("crypted data is not an even number of DES blocks!");
}


static void des_setup(unsigned char const *snib)
{
    des_set_key((const_des_cblock *) snib,                key1);
    des_set_key((const_des_cblock *) (snib + DES_KEY_SZ), key2);
}


static void keyring_dumprecords(struct pi_file *pif, char const *pass)
{
    int                nrecords;
    int                i;
    unsigned char      snib[MD5_DIGEST_LENGTH];
    unsigned char      *plain;
    void               *recp;
    size_t             rec_len;
    int                attr, category;
    char const         *record_name, *acct;

    if (pi_file_get_entries(pif, &nrecords) == -1) {
	rs_fatal("error getting number of records");
    }

    MD5((unsigned char *) pass, strlen(pass), snib);
    printf("Snib:\n");
    hextype(stdout, snib, sizeof snib);
    des_setup(snib);

    for (i = kNumReservedRecords; i < nrecords; i++) {
	printf("Record %d:\n", i);
	if (pi_file_read_record(pif, i, &recp, &rec_len,
				&attr, &category, NULL) == -1) {
	    rs_fatal("error reading record");
	}

	record_name = (char const *) recp;
	printf("Record: %s\n", record_name);

	rec_len -= strlen(record_name) + 1;

 	if (!(plain = malloc(rec_len))) 
 	    rs_fatal("allocation failed");

 	des_read(recp, plain, rec_len, snib);
	acct = plain;
	printf("Account: \n");

	hextype(stdout, acct, strlen(acct));
	printf("\n");
    }
}


static void keyring_dumpfile(struct pi_file *pif,
			     const char *pass)
{
    int                attr, category;
    pi_uid_t           uid;
    void               *pdata;
    size_t             data_len;
    
    keyring_dumpheader(pif);

    if (pi_file_read_record(pif, 0, &pdata, &data_len, &attr, &category, &uid)
	== -1) {
	rs_fatal("failed to read first record!");
    }

    if (!keyring_verify(pdata, data_len, pass)) {
	rs_log(RS_LOG_ERR, "password is incorrect");
	exit(2);
    }

    keyring_dumprecords(pif, pass);
}
