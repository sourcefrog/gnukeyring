//
//  PDB.h
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

/*!
 * @class PDB
 * @abstract Class modelling a PalmOS backup file (PDB format)
 * @discussion This class is a model of a PalmOS 'PDB' database file.
 *
 * PDB files contain an internal filename, which is the name that is seen in
 * PalmOS and NOT the name of the backup file. PDB files also contain internal
 * type and creator codes, similar to the Mac (pre-OS X) type and creator codes.
 * These may be retrieved using the -title, -type and -creator methods. You
 * should check the type and creator are the expected values before trying to
 * process the database.
 *
 * PDB files consist of a header and a number of records. Each record is
 * unstructured; knowledge of the application that created the database is
 * required to parse the record. The -recordData: message returns the message
 * for a given raw record index.
 *
 * The first record in the database has index 0. There are -numRecords
 * raw records in the database.
 *
 * Each record has a separate attribute field obtained from the -recordAttr:
 * message.
 *
 * The record attribute indicates if the record is secret, deleted, dirty, or
 * busy. It also indicates the record's category.
 *
 * Not all PDB files use categories. If the PDB does, then the -useCategories:
 * message (or the -useCategoriesFromFirst:toLast: message) must be used to
 * locate the records in each category.
 *
 * The -categories method returns an array of category names; the indexes to the
 * array items that are not empty NSStrings are used as the input to the
 * -recordNumbersForCategory: method.
 *
 */
@interface PDB : NSObject {
    NSData              *data;
    unsigned             appInfo;
    unsigned             sortInfo;
    unsigned             recordList;
    unsigned short       numRecords;
    NSMutableArray      *category;
    NSMutableArray      *recordsByCategory[17];
}

/*!
 * @method initWithData:
 * @abstract Initialize with NSData from a PDB file (designated initializer)
 * @param pdb PDB-format data
 * @result nil if the data wasn't from a PDB
 */
- (id)initWithData: (NSData *)pdb;

/*!
 * @method useCategories
 * @abstract Categorize all the records.
 * @discussion Not all Palm databases use categories; if one does send this message.
 */
- (void)useCategories;

/*!
 * @method useCategoriesWithAllFromFirst:toLast:
 * @abstract Categorize a range of records.
 */
- (void)useCategoriesWithAllFromFirst: (unsigned)f toLast: (unsigned)l;

// Header accessors

/*!
 * @method type
 * @abstract Returns the PalmOS 'type' code of the PDB.
 * @result 4-character long string.
 */
- (NSString *)type;

/*!
 * @method creator
 * @abstract Returns the PalmOS 'creator' code of the PDB.
 * @result 4-character long string.
 */
- (NSString *)creator;

/*!
 * @method title
 * @abstract Returns the PalmOS filename inside the PDB.
 * @result 32-character long string.
 */
- (NSString *)title;

/*!
 * @method numRecords
 * @abstract Returns the number of records in the PDB
 * @discussion This is the raw number of records from the header.
 */
- (unsigned short)numRecords;

/*!
 * @method categories
 * @abstract Returns the category names used in the PDB.
 * @result Array of 16 strings. Empty strings may be present. The position
 *         in the array is the category index used with recordNumbersForCategory:.
 *         Index 16 represents all the records (ie "All" category)
 * @discussion Send useCategories: first!
 */
- (NSArray *)categories;

// Data accessors

/*!
 * @method recordData:
 * @abstract Return the data for a given record
 * @param i record to return (raw record number)
 * @result Record data
 */
- (NSData *)recordData: (unsigned int)i;

/*!
 * @method recordAttr:
 * @abstract Return the attribute for a given record
 * @param i record to return the attribute from (raw record number)
 * @discussion Attribute is a bitmask of dmRecAttrCategoryMask,
 *             dmRecAttrDelete, dmRecAttrDirty, dmRecAttrBusy and
 *             dmRecAttrSecret (and maybe others)
 */
- (unsigned int)recordAttr: (unsigned int)i;

/*!
 * @method recordNumbersForCategory:
 * @abstract Return an array of raw record numbers of records in a given
 *           category.
 * @param i Category index.
 * @result Array of raw record numbers.
 */
- (NSArray *)recordNumbersForCategory: (int)i;

// Private stuff

/*!
 * @method parseData
 * @abstract Parse the PDB header.
 * @result YES if the header looked valid, NO if not.
 */
- (BOOL)parseData;

@end
