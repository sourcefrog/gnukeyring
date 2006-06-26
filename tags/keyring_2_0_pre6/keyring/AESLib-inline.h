/*
 -------------------------------------------------------------------------
 Copyright (c) 2003, Copera, Inc., Mountain View, CA, USA.
 All rights reserved.

 LICENSE TERMS

 The free distribution and use of this software in both source and binary 
 form is allowed (with or without changes) provided that:

   1. distributions of this source code include the above copyright 
      notice, this list of conditions and the following disclaimer;

   2. distributions in binary form include the above copyright
      notice, this list of conditions and the following disclaimer
      in the documentation and/or other associated materials;

   3. the copyright holder's name is not used to endorse products 
      built using this software without specific written permission. 

 DISCLAIMER

 This software is provided 'as is' with no explcit or implied warranties
 in respect of any properties, including, but not limited to, correctness 
 and fitness for purpose.
 -------------------------------------------------------------------------
 Issue Date: March 27, 2003
 -------------------------------------------------------------------------
 Changed for keyring 2003-10-05 by Jochen Hoenicke:
   split the include file into two files, one for the inlined
   function and one without. Otherwise some unneeded string constants
   are unneccessarily included in every object file.
*/
#ifndef AESLIB_INLINE_H
#define AESLIB_INLINE_H

#define AES_INLINE static __inline__

/**************************************************************************
 *
 * Inline function to conveniently open the library.  
 *
 **************************************************************************/

AES_INLINE Err AESLib_OpenLibrary(UInt16 *refNumP)
{
  Err error;
  Boolean loaded = false;
  
  /* first try to find the library */
  error = SysLibFind(AESLibName, refNumP);
  
  /* If not found, load the library instead */
  if (error == sysErrLibNotFound)
  {
    error = SysLibLoad(AESLibTypeID, AESLibCreatorID, refNumP);
    loaded = true;
  }
  
  if (error == errNone)
  {
    error = AESLibOpen(*refNumP);
    if (error != errNone)
    {
      if (loaded)
      {
        SysLibRemove(*refNumP);
      }
      
      *refNumP = sysInvalidRefNum;
    }
  }
  
  return error;
}

AES_INLINE Err AESLib_OpenLibrary_Force68K(UInt16 *refNumP)
{
  Err error;
  
  FtrSet (AESLibCreatorID, AESLibFtrNumForce68K, 1);

  error = AESLib_OpenLibrary(refNumP);

  return error;

}

/**************************************************************************
 *
 * Inline function to conveniently load and open the library when it
 * has not been installed separately.  If you have included the AESLib's
 * code resource into your PRC you can use this function to easily install
 * it as a system shared library.  The arguments to this function should
 * be your application or shared library's database type, creator ID, and 
 * the resource type and resource id you used to store the AESLib code 
 * resource.  This function is useful for developer's who wish to include
 * AESLib in their application or shared library and do not want to 
 * distribute a separate PRC.  See the sample projects for an example.
 *
 * This code was adopted from SysLibLoad as presented in the OS 4.0 sources.
 *
 **************************************************************************/

AES_INLINE Err AESLib_LoadLibrary(UInt16 *refNumP, 
                                  UInt32 DbType, UInt32 DbCreatorID,
                                  DmResType type, DmResID id)
{
  Err                         error;
  MemHandle            codeRscH = 0;
  SysLibEntryProcPtr   codeRscP = 0;
  UInt16                 cardNo = 0;
  LocalID                  dbID = 0;
  DmSearchStateType     searchState;
  DmOpenRef                 dbR = 0;
  SysLibTblEntryPtr      entryP = 0;
  Boolean          libInROM = false;
  Boolean            loaded = false;
  
  ErrFatalDisplayIf(!refNumP, "null arg");

  *refNumP = sysInvalidRefNum;

  DmGetNextDatabaseByTypeCreator(true, &searchState, DbType, 
                                 DbCreatorID, true, &cardNo, &dbID);

  if (!dbID)
    return sysErrLibNotFound;

  libInROM = (MemLocalIDKind(dbID) != memIDHandle);

  if (0 == (dbR = DmOpenDatabase(cardNo, dbID, dmModeReadOnly)))
    return sysErrNoFreeRAM;

  if (0 == (codeRscH = DmGet1Resource(type, id)))
  {
    ErrNonFatalDisplay("Can't get library rsrc");
    error = sysErrLibNotFound;
  }
  else
  {
    codeRscP = (SysLibEntryProcPtr)MemHandleLock(codeRscH);
    error = SysLibInstall(codeRscP, refNumP);
    
    if (!error && !libInROM)
      DmDatabaseProtect(cardNo, dbID, true);
  }

  DmCloseDatabase(dbR);
  dbR = 0;

  if (error)
  {
    *refNumP = sysInvalidRefNum;
    
    if (codeRscP && !libInROM)
    {
      MemPtrUnlock(codeRscP);
      DmReleaseResource(codeRscH);
    }
  }
  else
  {
    entryP = SysLibTblEntry(*refNumP);
    entryP->dbID = dbID;
    if (libInROM)
    {
      entryP->codeRscH = 0;
    }
    else
    {
      entryP->codeRscH = codeRscH;
    }
  }
  
  if (error == errNone)
  {
    error = AESLibOpen(*refNumP);
    if (error != errNone)
    {
      if (loaded)
      {
        SysLibRemove(*refNumP);
      }
      
      *refNumP = sysInvalidRefNum;
    }
  }
  
  return error;
}

AES_INLINE Err AESLib_LoadLibrary_Force68K(UInt16 *refNumP, 
                                           UInt32 DbType, UInt32 DbCreatorID,
                                           DmResType type, DmResID id)
{
  Err                         error;

  FtrSet (AESLibCreatorID, AESLibFtrNumForce68K, 1);

  error = AESLib_LoadLibrary(refNumP, DbType, DbCreatorID, type, id);

  return error;
}


/**************************************************************************
 *
 * Inline function to conveniently close the library.  
 *
 **************************************************************************/


AES_INLINE Err AESLib_CloseLibrary(UInt16 refNum)
{
  Err error;
  
  if (refNum == sysInvalidRefNum)
  {
    return sysErrParamErr;
  }
  
  error = AESLibClose(refNum);
  
  if (error == errNone)
  {
    /* no users left, so unload library */
    SysLibRemove(refNum);
  } 
  else if (error != sysErrParamErr)
  {
    /* don't unload library, but mask "still open" from caller  */
    error = errNone;
  }
  
  return error;
}

AES_INLINE Err AESLib_CloseLibrary_Force68K(UInt16 refNum)
{
  Err error;

  FtrUnregister (AESLibCreatorID, AESLibFtrNumForce68K);

  error = AESLib_CloseLibrary(refNum);

  return error;
}

#endif
