//
//  Keyring.h
//  View Keyring
//
// Copyright (c) 2003, Chris Ridd <chrisridd@mac.com>
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the distribution.
//
// * Neither the name of the Keyring for PalmOS project nor the names of
//   its contributors may be used to endorse or promote products derived
//   from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// $Id$

#import <Foundation/Foundation.h>
#import "PDB.h"

/*!
 * @class Keyring
 * @abstract Class modelling a Keyring for PalmOS 'keyring' file
 * @discussion This class is a model of a Keyring for PalmOS PDB file.
 *
 * The -isKeyring method should be used to ensure that the data is a valid
 * Keyring for PalmOS backup file.
 *
 * The keyring is either "locked" or "unlocked", which means that a password
 * has successfully been hashed and compared with the contents of record 0.
 *
 * Once unlocked, a record can be decrypted and the fields extracted.
 */

@interface Keyring : NSObject {
    PDB             *pdb;
    BOOL             unlocked;
    NSData          *key;
    int              category;
    NSMutableArray  *records;
    NSMutableArray  *decryptedRecord;
    int              decryptedRecordIndex;
}

/*!
 * @method initWithData:
 * @abstract Initialize with a PDB file contents (designated initializer)
 * @result A locked keyring.
 */
- (id)initWithData: (NSData *)d;

/*!
 * @method isKeyring
 * @abstract Checks if this is a valid-looking Keyring PDB file.
 * @result YES if the format looks valid, NO if not.
 * @discussion Minimal checks are made; essentially the type and creator
 *             codes have to match.
 */
- (BOOL)isKeyring;

/*!
 * @method title
 * @abstract Returns the PalmOS file title.
 * @result Title string.
 */
- (NSString *)title;

/*!
 * @method isUnlocked
 * @abstract Checks if a valid password was previously given to unlock the
 *           records in the database.
 * @result YES if the records can be decrypted.
 */
- (BOOL)isUnlocked;

/*!
 * @method unlock:
 * @abstract Try to unlock the database with a given password.
 * @param p The password to use.
 * @result YES if the password was correct.
 * @discussion No character translations are performed on the input Unicode
 *             string; this method is unlikely to work if the password contains
 *             non-7-bit ASCII data.
 */
- (BOOL)unlock: (NSString *)p;

/*!
 * @method lock
 * @abstract Lock the database (destroy the copy of the decryption key)
 * @result NO in all cases
 */
- (BOOL)lock;

/*!
 * @method categories
 * @abstract Return the category names used in this keyring.
 * @result An autoreleased array of names. Ignore empty strings.
 */
- (NSArray *)categories;

/*
 * @method names
 * @abstract Return all the key names for the current category.
 * @result An autoreleased array
 */
- (NSArray *)names;

/*!
 * @method setCategory:
 * @abstract Switch to a given category.
 * @param i Category index to switch to.
 */
- (void)setCategory: (int)i;

/*!
 * @method nameForIndex:
 * @abstract Returns the record's name, even for locked databases.
 * @param i Raw record index (0..)
 * @result Autoreleased string.
 */
- (NSString *)nameForIndex: (unsigned int)i;

/*!
    * @method decryptIndex:
 * @abstract Decrypt a record.
 * @param i Raw record index to decrypt
 * @discussion This is used internally by the -decrypted...ForIndex methods.
 *             There is no need to use this method directly.
 */
- (void)decryptIndex: (unsigned int)i;

/*!
 * @method decryptedAccountNameForIndex:
 * @abstract Return the decrypted account name for a record.
 * @param i Raw record index
 * @result Autoreleased string
 */
- (NSString *)decryptedAccountNameForIndex: (unsigned int)i;

/*!
 * @method decryptedPasswordForIndex:
 * @abstract Return the decrypted password for a record.
 * @param i Raw record index
 * @result Autoreleased string
 */
- (NSString *)decryptedPasswordForIndex: (unsigned int)i;

/*!
 * @method decryptedDateForIndex:
 * @abstract Return the decrypted date for a record.
 * @param i Raw record index
 * @result Autoreleased date
 */
- (NSCalendarDate *)decryptedDateForIndex: (unsigned int)i;

/*!
 * @method decryptedNotesForIndex:
 * @abstract Return the decrypted notes for a record.
 * @param i Raw record index
 * @result Autoreleased string
 */
- (NSString *)decryptedNotesForIndex: (unsigned int)i;

@end
