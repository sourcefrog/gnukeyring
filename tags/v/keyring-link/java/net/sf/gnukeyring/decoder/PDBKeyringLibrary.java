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
import net.sf.astroinfo.pdb.*;
import java.util.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

public class PDBKeyringLibrary implements KeyringLibrary {
    Database db;
    TreeMap categories;
    Cipher cipher;
    byte[] salt;
    byte[] mdigest;
    List entries;

    static {
	/* We want SunJCE provider for DES encryption */
	Security.addProvider(new com.sun.crypto.provider.SunJCE());
    }


    public static class KeyAppInfo extends AppInfoBlock {
	public void read(PalmDataInputStream in) throws IOException {
	    readCategories(in);
	}

	public void write(PalmDataOutputStream out) throws IOException {
	    writeCategories(out);
	}
    }

    public static class KeyRecord extends PDBRecord {
	String keyname;
	byte[] crypted;
	byte[] salt;
	byte[] mdigest;

	public void write(PalmDataOutputStream out) throws IOException {
	    throw new IOException("Write is not implemented");
	}

	public void read(PalmDataInputStream in) throws IOException {
	    if ((getAttributes() & DMRECATTRDELETE) != 0) {
		return;
	    } else if ((getAttributes() & DMRECATTRSECRET) == 0) {
		byte[] data = new byte[1024];
		keyname = in.readPackedString();
		int len = 0;
		while (len < 1024) {
		    int read = in.read(data, len, 1024 - len);
		    if (read <= 0)
			break;
		    len += read;
		}
		crypted = new byte[len];
		System.arraycopy(data, 0, crypted, 0, len);
	    } else {
		salt = new byte[4];
		mdigest = new byte[16];
		in.readFully(salt, 0, 4);
		in.readFully(mdigest, 0, 16);
	    }
	}	
    }

    public void setFilename (File file) {
	db = new Database();
	try {
	    db.read(new FileInputStream(file), 
		    KeyAppInfo.class, null, KeyRecord.class);
	} catch (Exception ex) {
	    ex.printStackTrace();
	    return;
	}

	categories = new TreeMap();
	for (int i = 0; i < 16; i++) {
	    String cat = db.getAppInfo().getCategories(i);
	    if (cat.length() > 0)
		categories.put(cat, new Integer(i));
	}
	    
	Record[] rawEntries = db.getEntries();
	salt = ((KeyRecord) rawEntries[0]).salt;
	mdigest = ((KeyRecord) rawEntries[0]).mdigest;

	entries = new ArrayList(rawEntries.length - 1);
	for (int i = 1; i < rawEntries.length; i++) {
	    KeyRecord entry = (KeyRecord) rawEntries[i];
	    if ((entry.getAttributes() & entry.DMRECATTRDELETE) != 0)
		continue;
	    int cat = (entry.getAttributes() & entry.DMRECATTRCATEGORYMASK);
	    entries.add(new PDBKeyringEntry(this, entry.keyname, 
					    db.getAppInfo().getCategories(cat),
					    entry.crypted));
	}
    }

    public Set getCategories() {
	return categories.keySet();
    }

    public List getEntries() {
	return entries;
    }
    
    public List getEntryNames() {
	return new AbstractList() {
		public int size() {
		    return entries.size();
		}
		
		public Object get(int index) {
		    return ((PDBKeyringEntry) entries.get(index)).getName();
		}
	    };
    }

    public List getEntries(String category) {
	ArrayList l = new ArrayList();
	Iterator i = entries.iterator();
	while (i.hasNext()) {
	    PDBKeyringEntry entry = (PDBKeyringEntry) i.next();
	    if (entry.getCategory().equals(category))
		l.add(entry);
	}
	return l;
    }

    public KeyringEntry getEntry(String key) {
	Iterator i = entries.iterator();
	while (i.hasNext()) {
	    PDBKeyringEntry entry = (PDBKeyringEntry) i.next();
	    if (entry.getName().equals(key))
		return entry;
	}
	return null;
    }

    public boolean unlock(String password)
    {
	byte[] buff = (new String(salt) + password).getBytes();
	byte[] pw = new byte[64];
	System.arraycopy(buff, 0, pw, 0, Math.min(64,buff.length));
	pw = md5(pw);
	for (int i = 0; i < 16; i++) {
	    if (pw[i] != mdigest[i])
		return false;
	}

	try {
	    cipher = Cipher.getInstance("DESede/ECB/NoPadding");
	} catch (GeneralSecurityException ex) {
	    throw new InternalError("Can't get DESede encryption: "
				    +ex.toString());
	}

	SecretKey key = getKey(password);
	try {
	    cipher.init(cipher.DECRYPT_MODE, key);
	} catch (InvalidKeyException ex) {
	    throw new InternalError("Invalid key: "+ex);
	}
	return true;
    }

    public void lock() {
	cipher = null;
    }

    Cipher getCipher() {
	return cipher;
    }

    public boolean isLocked() {
	return cipher == null;
    }

    private short odd_parity[] = {
	1,  1,  2,  2,  4,  4,  7,  7,  8,  8, 11, 11, 13, 13, 14, 14,
	16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
	32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
	49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
	64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
	81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
	97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
	112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
	128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
	145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
	161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
	176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
	193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
	208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
	224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
	241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254
    };

    public SecretKey getKey(String password) {
	byte[] digest = md5(password.getBytes());
	byte[] key = new byte[24];
	for (int i = 0; i < 16; i++) {
	    key[i] = (byte) odd_parity[digest[i] & 0xff];
	}
	for (int i = 0; i < 8; i++) {
	    key[i+16] = key[i];
	}
	try {
	    DESedeKeySpec keySpec = new DESedeKeySpec(key);
	    return SecretKeyFactory.getInstance("DESede").generateSecret(keySpec);
	} catch (GeneralSecurityException ex) {
	    throw new InternalError("Can't generate DES key: "+ex);
	}
    }

    public byte[] md5(byte[] bytes) {
	MessageDigest md;
	try {
	    md = MessageDigest.getInstance("MD5");
	} catch (NoSuchAlgorithmException ex) {
	    throw new InternalError("Can't get MD5 MessageDigest");
	}

	md.update(bytes);
	return md.digest();
    }
}
