//
//  DataAdditions.h
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
 * @category NSData(DataAdditions)
 * @abstract NSData enhancements useful for dealing with PalmOS-derived data.
 *           Also enhancements to perform simple cryptographic tasks.
 */
@interface NSData (DataAdditions)

/*!
 * @method palmString:
 * @abstract Extracts a given range of bytes from the data and convert them
 *           into an NSString.
 * @param r NSRange describing bytes to extract and convert. No trailing NUL is
 *          required in the data.
 * @result An NSString (not auto-released)
 */
- (NSString *)palmString: (NSRange)r;

/*!
 * @method palmCString:
 * @abstract Extracts a NUL-terminated range of bytes from the data and convert
 *           them into an NSString.
 * @param offset Offset to first byte to extract and convert. A trailing NUL is
 *          required in the data.
 * @result An NSString (not auto-released)
 */
- (NSString *)palmCString: (unsigned)offset;

/*!
 * @method networkLong:
 * @abstract Returns 4 bytes from the data in network byte order
 * @param offset Offset to first byte in network long.
 * @result 32-bit integer.
 */
- (unsigned)networkLong: (unsigned)offset;

/*!
 * @method networkShort:
 * @abstract Returns 2 bytes from the data in network byte order
 * @param offset Offset to first byte in network short.
 * @result 16-bit integer.
 */
- (unsigned short)networkShort: (unsigned)offset;

/*!
 * @method networkByte:
 * @abstract Returns a single byte from the data
 * @param offset Offset to byte.
 * @result Byte as integer
 */
- (int)networkByte: (unsigned)offset;

/*!
 * @method MD5:
 * @abstract Compute MD5 hash of entire data
 * @result Hashed data.
 */
- (NSData *)MD5;

/*!
 * @method decryptDES_EDE_CBCwithKey1:key2:key3:
 * @abstract Decrypt using 3-key Triple-DES in ECB mode.
 * @result Decrypted data
 */
- (NSData *)decryptDES_EDE_CBCwithKey1: (NSData *)k1
                                  key2: (NSData *)k2
                                  key3: (NSData *)k3;

@end
