//
//  CryptoEngine.h
//  View Keyring
//
// Copyright (c) 2005, Chris Ridd <chrisridd@mac.com>
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

#import <Cocoa/Cocoa.h>

/*!
 * @class CryptoEngine
 *
 * @abstract Interface to provide the crypto required by Keyring for PalmOS.
 * @discussion This class provides the cryptographic functions required for
 * Keyring for PalmOS.
 *
 * It is implemented using Apple's CDSA implementation in Security.framework.
 *
 * Call the factory method +defaultEngine to get a singleton object which
 * will perform the cryptography.
 */

@interface CryptoEngine : NSObject {
}

/*!
 * @method defaultEngine
 * @abstract Returns an object which can perform cryptography.
 * @result nil if there was a problem, otherwise a CryptoEngine object.
 * @discussion This returns a singleton.
 */
+ (CryptoEngine *)defaultEngine;

/*!
 * @method digestUsingMD5:
 * @abstract Calculate an MD5 digest of some data.
 * @result nil if there was a problem, otherwise a 16-byte digest.
 */
- (NSData *)digestUsingMD5: (NSData *)d;

/*!
 * @method decryptUsing3DESEDE:WithKey1:WithKey2:WithKey3
 * @abstract Decrypt some data using Triple DES (3DES-EDE-CBC).
 * @result nil if there was a problem, otherwise the decrypted data.
 */
- (NSData *)decryptUsing3DESEDE: (NSData *)d
                       WithKey1: (NSData *)k1
                       WithKey2: (NSData *)k2
                       WithKey3: (NSData *)k3;

@end
