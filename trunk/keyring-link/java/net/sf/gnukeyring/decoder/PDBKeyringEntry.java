/*
 * $Header$
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


public class PDBKeyringEntry implements KeyringEntry {
    PDBKeyringLibrary library;
    String keyname;
    String category;
    byte[] crypted;
    HashMap fields;
    
    static List fieldnames = new AbstractList() {
	    public int size() {
		return 4;
	    }
	    public Object get(int index) {
		switch (index) {
		case 0:
		    return "Account";
		case 1:
		    return "Password";
		case 2:
		    return "Changed";
		case 3:
		    return "Notes";
		}
		return null;
	    }
	};

    public PDBKeyringEntry(PDBKeyringLibrary lib, String name, 
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

    private void createFields() {
	Cipher c = library.getCipher(Cipher.DECRYPT_MODE, null);
	int blockSize = c.getBlockSize();
	if ((crypted.length & (blockSize - 1)) != 0) {
	    System.err.println("WARNING: Key " + keyname + ": length of crypted block not a multiple of blocksize.");
	    byte[] blocked = new byte[crypted.length & ~(blockSize - 1)];
	    System.arraycopy(crypted, 0, blocked,0, blocked.length);
	    crypted = blocked;
	}

	byte[] encrypted;
	try {
	    encrypted = c.doFinal(crypted);
	} catch (GeneralSecurityException ex) {
	    throw new InternalError(ex.toString());
	}

	fields = new HashMap();
	int index = 0;
	for (int i = 0; i < 3; i++) {
	    int lastindex = index;
	    while (index < encrypted.length && encrypted[index] != 0)
		index++;
	    try {
		fields.put(fieldnames.get(i == 2 ? 3 : i), 
			   new String(encrypted, lastindex, index - lastindex, 
				      library.charSetName));
	    } catch (UnsupportedEncodingException ex) {
		throw new InternalError(ex.toString());
	    }
	    if (index >= encrypted.length)
		break;
	    index++;
	}
	int datetype = 0;
	if (index+2 <= encrypted.length)
	    datetype =  (((encrypted[index] & 0xff) << 8) 
			 | (encrypted[index+1] & 0xff));
	Date changed = new Date((datetype>>9) + 4,
				(datetype>>5) & 0x0f,
				datetype & 0x1f);
	fields.put("Changed", changed);
    }

    public Object getField(String fld) {
	if (library.isLocked()) {
	    fields = null;
	    return null;
	}
	if (fields == null)
	    createFields();
	return fields.get(fld);
    }

    public List getFieldNames() {
	if (library.isLocked())
	    return null;
	if (fields == null)
	    createFields();
	return fieldnames;
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

