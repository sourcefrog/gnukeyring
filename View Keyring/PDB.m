//
//  PDB.m
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

#import "PDB.h"
#import "DataAdditions.h"

#define dmRecAttrCategoryMask	0x0f
#define dmRecAttrDelete		0x80
#define dmRecAttrDirty		0x40
#define dmRecAttrBusy		0x20
#define dmRecAttrSecret		0x10

@implementation PDB

- (id)initWithData: (NSData *)pdb
{
    if (self = [super init]) {
        data = pdb;
        [data retain];
        if ([self parseData] == NO) {
            [self release];
            self = nil;
        }
    }
    return self;
}

- (void)useCategories
{
    [self useCategoriesWithAllFromFirst: 0
                                 toLast: [self numRecords] - 1];
}

- (void)useCategoriesWithAllFromFirst: (unsigned)f
                               toLast: (unsigned)l
{
    unsigned short mask;
    int i;

    mask = [data networkShort: appInfo];
    category = [[NSMutableArray alloc] initWithCapacity: 16];

    for (i = 0; i < 16; i++) {
        NSString *s = @"";
        if ((1 << i) & mask) {
            s = [data palmString: NSMakeRange(appInfo + 2 + (i * 16), 16)];
        }
        [category addObject: s];
        if (![s isEqualToString: @""]) {
            recordsByCategory[i] = [[NSMutableArray alloc] initWithCapacity: 10];
        }
    }
    recordsByCategory[16] = [[NSMutableArray alloc] initWithCapacity: [self numRecords]];
    
    // Now build arrays of all the records in each category
    for (i = f; i < l; i++) {
        unsigned attr;
        NSNumber *n;

        attr = [self recordAttr: i];
        if (attr & dmRecAttrDelete ||
            attr & dmRecAttrSecret) {
            // skip deleted, secret, etc records
            continue;
        }
        attr &= dmRecAttrCategoryMask;
//        NSLog(@"Record %d has attr %u", i, attr);
        n = [NSNumber numberWithInt: i];
        [recordsByCategory[attr] addObject: n];
        [recordsByCategory[16] addObject: n];
    }
}

- (void)dealloc
{
    int i;
    
    [data release];
    [category release];
    for (i = 0; i <= 16; i++) {
        [recordsByCategory[i] release];
    }
    [super dealloc];
}

- (NSString *)title
{
    return [data palmString: NSMakeRange(0x0000, 32)];
}

- (NSString *)type
{
    return [data palmString: NSMakeRange(0x003c, 4)];
}

- (NSString *)creator
{
    return [data palmString: NSMakeRange(0x0040, 4)];
}

- (unsigned short)numRecords
{
    return numRecords;
}

- (NSArray *)categories
{
    return category;
}

- (BOOL)parseData
{
    unsigned tmpRecordList;
    
    tmpRecordList = [data networkLong: 0x0048];
    if (tmpRecordList != 0) {
        return NO;
    }
    numRecords = [data networkShort: 0x004c];
    recordList = 0x004e + ([self numRecords] == 0 ? 2 : 0);
    appInfo = [data networkLong: 0x0034];
    sortInfo = [data networkLong: 0x0038];
    return YES;
}

- (NSData *)recordData: (unsigned int)i
{
    unsigned offset;
    unsigned length;

    offset = [data networkLong: recordList + (i * 8)];
    // Calculate length using start of next record, or EOF if last record
    if (i == ([self numRecords] - 1)) {
        length = [data length] - offset;
    } else {
        length = [data networkLong: recordList + ((i + 1) * 8)] - offset;
    }
    return [data subdataWithRange: NSMakeRange(offset, length)];
}

- (unsigned)recordAttr: (unsigned)i
{
    return (unsigned)[data networkByte: recordList + (i * 8) + 4] & 0xff;
}

- (NSArray *)recordNumbersForCategory: (int)c
{
    return recordsByCategory[c];
}

@end
