//
//  Keyring.m
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

#import "Keyring.h"
#import "PDB.h"
#import "DataAdditions.h"

@implementation Keyring

- (id)initWithData: (NSData *)d
{
    if (self = [super init]) {
        pdb = [[PDB alloc] initWithData: d];
        [pdb useCategoriesWithAllFromFirst: 1 toLast: [pdb numRecords] - 1];
        decryptedRecord = [[NSMutableArray alloc] init];
        decryptedRecordIndex = -1;
        unlocked = NO;
    }
    return self;
}

- (void)dealloc
{
    [pdb release];
    [key release];
    [records release];
    [decryptedRecord release];
    [super dealloc];
}

- (BOOL)isKeyring
{
    return ([[pdb type] isEqualToString: @"Gkyr"] &&
            [[pdb creator] isEqualToString: @"Gtkr"]);
}

- (NSString *)title
{
    return [pdb title];
}

- (BOOL)isUnlocked
{
    return unlocked;
}

- (BOOL)unlock: (NSString *)p
{
    if (!unlocked) {
        NSMutableData *saltedPassword;
        NSData *recordZero;
        NSData *pass;
        NSData *digest;

        // Input to digest must be 64 bytes long (NUL-extended if necessary)
        // First four bytes are salt from record 0.
        // Remaining bytes are guessed password
        recordZero = [pdb recordData: 0];
        if ([recordZero length] < 20) {
            NSLog(@"PDB record zero is too short! (%d < 20)", [recordZero length]);
        }
        // BUG - should convert to one of the PalmOS encodings, not Latin 1.
        pass = [p dataUsingEncoding: NSISOLatin1StringEncoding
               allowLossyConversion: NO];
        if (pass == nil) {
            NSLog(@"Guessed password must contain legal Palm characters only");
            return NO;
        }
        saltedPassword = [NSMutableData dataWithData:
            [recordZero subdataWithRange: NSMakeRange(0, 4)]];
        [saltedPassword appendData: pass];
        [saltedPassword setLength: 64];
        
        digest = [saltedPassword MD5];
        // Compare with next 16 bytes of record 0.
        if ([digest isEqualToData:
            [recordZero subdataWithRange: NSMakeRange(4, 16)]]) {
            unlocked = YES;
            [key release];
            key = [pass MD5];
            [key retain];
        }
    }
    return unlocked;
}

- (BOOL)lock
{
    if (unlocked) {
        [key release];
        key = nil;
        [decryptedRecord removeAllObjects];
        decryptedRecordIndex = -1;
        unlocked = NO;
    }
    return unlocked;
}

- (NSString *)nameForIndex: (unsigned)i
{
    // Each record starts with a NUL-terminated string containing the unencrypted name
    return [[pdb recordData: i] palmCString: 0];
}

- (void)_decryptIndex: (unsigned int)i
{
    if (i != decryptedRecordIndex) {
        NSData *k1, *k2;
        NSData *encrypted, *decrypted;
        NSData *record;
        NSString *account;
        NSString *password;
        NSString *notes;
        NSCalendarDate *date;
        unsigned short packeddate;
        int year, month, day;
        const char *p;
        size_t len, len2, len3;
        
        record = [pdb recordData: i];
        p = [record bytes];
        len = strlen(p) + 1;
        encrypted = [record subdataWithRange: NSMakeRange(len, [record length] - len)];
        if ([encrypted length] % 8 != 0) {
            NSLog(@"Encrypted data is not a block multiple (%d)", [encrypted length]);
            return;
        }
        k1 = [key subdataWithRange: NSMakeRange(0, 8)];
        k2 = [key subdataWithRange: NSMakeRange(8, 8)];
        decrypted = [encrypted decryptDES_EDE_CBCwithKey1: k1
                                                     key2: k2
                                                     key3: k1];
        len = strlen([decrypted bytes]);
        account = [decrypted palmString: NSMakeRange(0, len)];
        len2 = strlen([decrypted bytes] + len + 1); // +1 skips the account's NUL terminator
        password = [decrypted palmString: NSMakeRange(len + 1, len2)];
        len3 = strlen([decrypted bytes] + len + len2 + 2); // +2 skips the two NUL terminators
        notes = [decrypted palmString: NSMakeRange(len + len2 + 2, len3)];
        // Now there could be 2 bytes of date
        if (len + len2 + len3 + 5 <= [decrypted length]) { // +3 skips the three NUL terminators, + 2 more for the date
            packeddate = [decrypted networkShort: len + len2 + len3 + 3];
        } else {
            // there isn't space, so fake it
            packeddate = 0;
        }
        year = (packeddate >> 9) & 0x7f; // since 1904
        month = (packeddate >> 5) & 0x1f; // 1-12
        day = (packeddate >> 0) & 0x0f;   // 1-31
// map month=0 and date=0 to Jan 1.
        date = [NSCalendarDate dateWithYear: year + 1904
                                      month: month ? month : 1
                                        day: day ? day : 1
                                       hour: 0
                                     minute: 0
                                     second: 0
                                   timeZone: [NSTimeZone localTimeZone]];
        [decryptedRecord removeAllObjects];
        [decryptedRecord addObject: account];
        [decryptedRecord addObject: password];
        [decryptedRecord addObject: date];
        [decryptedRecord addObject: notes];
    }
    decryptedRecordIndex = i;
}

- (NSString *)decryptedAccountNameForIndex: (unsigned int)i
{
    [self _decryptIndex: i];
    return [decryptedRecord objectAtIndex: 0];
}

- (NSString *)decryptedPasswordForIndex: (unsigned int)i
{
    [self _decryptIndex: i];
    return [decryptedRecord objectAtIndex: 1];
}

- (NSCalendarDate *)decryptedDateForIndex: (unsigned int)i
{
    [self _decryptIndex: i];
    return [decryptedRecord objectAtIndex: 2];
}

- (NSString *)decryptedNotesForIndex: (unsigned int)i
{
    [self _decryptIndex: i];
    return [decryptedRecord objectAtIndex: 3];
}

- (NSArray *)categories
{
    return [pdb categories];
}

- (void)setCategory: (int)c
{
    category = c;
}

- (NSArray *)names
{
    return [pdb recordNumbersForCategory: category];
}

@end
