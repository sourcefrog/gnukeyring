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
#import <Security/Security.h>
#import "CryptoEngine.h"

@implementation CryptoEngine

static CryptoEngine *DefaultEngine = nil;

static CSSM_VERSION vers = { 2, 0 };
static const CSSM_GUID dummyGuid = { 0xfade, 0, 0, { 1, 2, 3, 4, 6, 7, 0 } };
static CSSM_CSP_HANDLE cspHandle;
static CSSM_CC_HANDLE md5Handle;

void * cuAppMalloc (uint32 size, void *allocRef)
{
    return( malloc(size) );
}

void cuAppFree (void *mem_ptr, void *allocRef)
{
    free(mem_ptr);
    return;
}

void * cuAppRealloc (void *ptr, uint32 size, void *allocRef)
{
    return( realloc( ptr, size ) );
}

void * cuAppCalloc (uint32 num, uint32 size, void *allocRef)
{
    return( calloc( num, size ) );
}

static CSSM_API_MEMORY_FUNCS memFuncs = {
    cuAppMalloc,
    cuAppFree,
    cuAppRealloc,
    cuAppCalloc,
    NULL
};

+ (CryptoEngine *)defaultEngine
{
    if (!DefaultEngine) {
        CSSM_PVC_MODE pvcPolicy = CSSM_PVC_NONE;
        CSSM_RETURN ret;

        ret = CSSM_Init(&vers,
                        CSSM_PRIVILEGE_SCOPE_NONE,
                        &dummyGuid,
                        CSSM_KEY_HIERARCHY_NONE,
                        &pvcPolicy,
                        NULL);
        if (ret != CSSM_OK) {
            NSLog(@"CSSM_Init failed %d\n", ret);
            return nil;
        }
        
        ret = CSSM_ModuleLoad(&gGuidAppleCSP,
                              CSSM_KEY_HIERARCHY_NONE,
                              NULL, NULL);
        if (ret != CSSM_OK) {
            NSLog(@"CSSM error loading csp %d", ret);
            return nil;
        }
        
        ret = CSSM_ModuleAttach(&gGuidAppleCSP,
                                &vers, &memFuncs, 0,
                                CSSM_SERVICE_CSP, 0,
                                CSSM_KEY_HIERARCHY_NONE,
                                NULL, 0, NULL, &cspHandle);
        if (ret != CSSM_OK) {
            NSLog(@"CSSM error attaching csp %d", ret);
            return nil;
        }
        
        ret = CSSM_CSP_CreateDigestContext(cspHandle,
                                           CSSM_ALGID_MD5,
                                           &md5Handle);
        if (ret != CSSM_OK) {
            NSLog(@"CSSM error creating md5 context %d", ret);
            return nil;
        }
        DefaultEngine = [[self allocWithZone: NULL] init];
    }
    return DefaultEngine;
}

- (NSData *)digestUsingMD5: (NSData *)d
{
    CSSM_RETURN ret;
    CSSM_DATA in;
    CSSM_DATA out;
    unsigned char md[16];
    
    in.Data = (void *)[d bytes];
    in.Length = [d length];
    out.Data = md;
    out.Length = sizeof(md);
    
    ret = CSSM_DigestData(md5Handle,
                          &in, 1,
                          &out);

    if (ret != CSSM_OK) {
        NSLog(@"CSSM error digesting data %d", ret);
        return nil;
    }

    return [NSData dataWithBytes: out.Data length: out.Length];    
}

- (NSData *)decryptUsing3DESEDE: (NSData *)d
                       WithKey1: (NSData *)k1
                       WithKey2: (NSData *)k2
                       WithKey3: (NSData *)k3
{
    unsigned char keys[24];
    CSSM_KEY edeKeys;
    CSSM_ACCESS_CREDENTIALS creds;
    CSSM_RETURN ret;
    CSSM_DATA work;
    unsigned char *output;
    uint32 count;
    CSSM_CC_HANDLE desHandle;
    
    if ([k1 length] != 8 &&
        [k2 length] != 8 &&
        [k3 length] != 8)
        return nil;
    
    output = malloc([d length]);
    if (output == NULL)
        return nil;

    memcpy(keys +  0, [k1 bytes], 8);
    memcpy(keys +  8, [k2 bytes], 8);
    memcpy(keys + 16, [k3 bytes], 8);
    
    edeKeys.KeyData.Data = keys;
    edeKeys.KeyData.Length = sizeof(keys);
    edeKeys.KeyHeader.HeaderVersion = CSSM_KEYHEADER_VERSION;
    edeKeys.KeyHeader.CspId = dummyGuid;
    edeKeys.KeyHeader.BlobType = CSSM_KEYBLOB_RAW;
    edeKeys.KeyHeader.Format = CSSM_KEYBLOB_RAW_FORMAT_OCTET_STRING;
    edeKeys.KeyHeader.AlgorithmId = CSSM_ALGID_3DES_3KEY_EDE;
    edeKeys.KeyHeader.KeyClass = CSSM_KEYCLASS_SESSION_KEY;
    edeKeys.KeyHeader.LogicalKeySizeInBits = 8 * sizeof(keys);
    edeKeys.KeyHeader.KeyAttr = CSSM_KEYATTR_PERMANENT;
    edeKeys.KeyHeader.KeyUsage = CSSM_KEYUSE_ANY;
    memset(&edeKeys.KeyHeader.StartDate, 0, sizeof(CSSM_DATE));
    memset(&edeKeys.KeyHeader.EndDate, 0, sizeof(CSSM_DATE));
    edeKeys.KeyHeader.WrapAlgorithmId = CSSM_ALGID_NONE;
    edeKeys.KeyHeader.WrapMode = CSSM_ALGMODE_NONE;
    
    memset(&creds, 0, sizeof(CSSM_ACCESS_CREDENTIALS));
    
    ret = CSSM_CSP_CreateSymmetricContext(cspHandle,
                                          CSSM_ALGID_3DES_3KEY_EDE,
                                          CSSM_ALGMODE_ECB,
                                          &creds,
                                          &edeKeys,
                                          NULL, NULL, NULL,
                                          &desHandle);
    if (ret != CSSM_OK) {
        NSLog(@"CSSM error creating DES3 context %d", ret);
        free(output);
        return nil;
    }
    
    work.Data = output;
    work.Length = [d length];
    
    memcpy(output, [d bytes], [d length]);
    
    ret = CSSM_DecryptData(desHandle,
                           &work, 1,
                           &work, 1,
                           &count,
                           &work);
    CSSM_DeleteContext(desHandle);

    if (ret != CSSM_OK) {
        NSLog(@"CSSM error decrypting 3DESEDE %d", ret);
        free(output);
        return nil;
    }
    return [NSData dataWithBytes: work.Data length: count];    
}
@end
