/*
 * $Id$
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 2004 Jochen Hoenicke <hoenicke@users.sourceforge.net>
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
package net.sf.gnukeyring.decoder;

import net.sf.gnukeyring.*;
import java.util.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;


public class PDBKeyringEntry5 implements KeyringEntry {
    PDBKeyringLibrary library;
    String keyname;
    String category;
    byte[] crypted;
    HashMap fields;
    
    public PDBKeyringEntry5(PDBKeyringLibrary lib, String name, 
			    String cat, byte[] crypted) {
	this.library = lib;
	this.keyname = name;
	this.category = cat;
	this.crypted = crypted;
    }

    public String getName() {
	return keyname;
    }
    
    public String getCategory() {
	return category;
    }

    private static String dump(byte[] b) {
	StringBuffer sb = new StringBuffer();
	for (int i = 0; i < b.length; i++) {
	    sb.append(Integer.toString(b[i]&0xff, 16)).append(" ");
	}
	return sb.toString();
    }

    public String dumpEntry() {
	int blocksize = library.getBlockSize();
	byte[] iv = new byte[blocksize];
	System.arraycopy(crypted, 0, iv, 0, blocksize);
// 	System.err.println("IV: "+dump(iv));
	Cipher c = library.getCipher(Cipher.DECRYPT_MODE, iv);
	byte[] decrypted;
	try {
	    decrypted = c.doFinal(crypted, 
				  blocksize, crypted.length - blocksize);
// 	    System.err.println("decrypted: "+dump(decrypted));
	} catch (GeneralSecurityException ex) {
	    throw new InternalError(ex.toString());
	}
	return "Name: "+keyname+"\nIV: "+dump(iv)+"\ndecrypted: "+dump(decrypted)+"\n";
    }

    private void createFields() throws UnsupportedEncodingException {
	int blocksize = library.getBlockSize();
	byte[] iv = new byte[blocksize];
	System.arraycopy(crypted, 0, iv, 0, blocksize);
// 	System.err.println("IV: "+dump(iv));
	Cipher c = library.getCipher(Cipher.DECRYPT_MODE, iv);
	byte[] decrypted;
	try {
	    decrypted = c.doFinal(crypted, 
				  blocksize, crypted.length - blocksize);
// 	    System.err.println("decrypted: "+dump(decrypted));
	} catch (GeneralSecurityException ex) {
	    throw new InternalError(ex.toString());
	}

	fields = new HashMap();
	int index = 0;

	int len;
	while ((len = (decrypted[index] & 0xff) << 8
		| (decrypted[index+1] & 0xff)) != 0xffff) {
	    int rawlen = (len + 1) & ~1;
	    int fnr = decrypted[index+2] & 0xff;
	    int font = decrypted[index+3] & 0xff;
	    index += 4;
	    switch (fnr) {
		case 3: {
		    int datetype = (decrypted[index] & 0xff) << 8
			| (decrypted[index+1] & 0xff);
		    fields.put("Changed", new Date((datetype>>9) + 4,
						   (datetype>>5) & 0x0f,
						   datetype & 0x1f));
		    break;
		}
		case 1: {
		    fields.put("Account", 
			       new String(decrypted, index, len, 
					  library.charSetName));
		}
		case 2: {
		    fields.put("Password", 
			       new String(decrypted, index, len, 
					  library.charSetName));
		}
		case 255: {
		    fields.put("Notes", 
			       new String(decrypted, index, len, 
					  library.charSetName));
		}
	    }
	    index += rawlen;
	}
    }

    public Object getField(String fld) {
	if (library.isLocked()) {
	    fields = null;
	    return null;
	}
	try {
	    if (fields == null)
		createFields();
	} catch (UnsupportedEncodingException ex) {
	    InternalError err = new InternalError("Encoding not supported");
	    err.initCause(ex);
	    throw err;
	}
	return fields.get(fld);
    }

    public List getFieldNames() {
	if (library.isLocked())
	    return null;
	try {
	    if (fields == null)
		createFields();
	} catch (UnsupportedEncodingException ex) {
	    InternalError err = new InternalError("Encoding not supported");
	    err.initCause(ex);
	    throw err;
	}
	return new ArrayList(fields.keySet());
    }

    public boolean isLocked() {
	return library.isLocked();
    }
    public boolean unlockLibrary(String pw) {
	return library.unlock(pw);
    }
    public void lockLibrary() {
	library.lock();
	fields = null;
    }


    public String toString() {
	return keyname;
    }
}

