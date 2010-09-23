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
    SecretKey key;
    int    iter;
    int    ciphnr;
    byte[] salt;
    byte[] mdigest;
    List entries;

    String charSetName = "ISO-8859-1";

    static {
	/* We want SunJCE provider for DES encryption */
	Security.addProvider(new com.sun.crypto.provider.SunJCE());
    }

    private static int keylens[] = { 8, 24, 16, 32 };
    private static String keyalgos[] = { "", 
					 "DESede/CBC/NoPadding",
					 "AES/CBC/NoPadding",
					 "AES/CBC/NoPadding" };
    private static String keyalgosShort[] = { "", 
					      "DES",
					      "AES",
					      "AES" };


    public static class KeyAppInfo extends AppInfoBlock {
	byte[] salt;
	byte[] mdigest;
	byte[] ivec;
	int    iter;
	int    cipher;
	
	public void read(PalmDataInputStream in) throws IOException {
	    if (getDatabase().getVersion() == 0) {
		salt = new byte[4];
		mdigest = new byte[16];
		in.readFully(salt, 0, 4);
		in.readFully(mdigest, 0, 16);
	    }
	    if (getDatabase().getVersion() >= 1) {
		readCategories(in);
	    }
	    if (getDatabase().getVersion() >= 5) {
		salt = new byte[8];
		mdigest = new byte[8];
		in.readFully(salt, 0, 8);
		iter = in.readUnsignedShort();
		cipher = in.readUnsignedShort();
		in.readFully(mdigest, 0, 8);
	    }
	}

	public void write(PalmDataOutputStream out) throws IOException {
	    writeCategories(out);
	    if (getDatabase().getVersion() >= 5) {
		salt = new byte[8];
		mdigest = new byte[8];
		out.write(salt);
		out.writeShort(iter);
		out.writeShort(cipher);
		out.write(mdigest);
	    }
	}
    }

    public static class KeyRecord extends PDBRecord {
	byte[] keyname;
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
		if (getDatabase().getVersion() <= 4) {
		    byte[] data = new byte[1024];
		    int len = 0;
		    while (true) {
			if (len == data.length) {
			    byte[] ndata = new byte[data.length*2];
			    System.arraycopy(data, 0, ndata, 0, data.length);
			    data = ndata;
			}
			int read = in.read(data, len, data.length - len);
			if (read <= 0)
			    break;
			len += read;
		    }
		    int idx;
		    for (idx = 0; idx < len; idx++) {
			if (data[idx] == 0)
			    break;
		    }
		    keyname = new byte[idx];
		    System.arraycopy(data, 0, keyname, 0, idx);
		    if (idx < len)
			idx++; // skip 0 terminator
		    crypted = new byte[len - idx];
		    System.arraycopy(data, idx, crypted, 0, len-idx);
		} else {
		    int namelen = in.readUnsignedShort();
		    in.read();  // field id
		    in.read();  // font
		    keyname = new byte[namelen];
		    in.readFully(keyname, 0, namelen);

		    if ((namelen & 1) == 1)
			in.read(); // padding;
		    byte[] data = new byte[1024];
		    int len = 0;
		    while (true) {
			if (len == data.length) {
			    byte[] ndata = new byte[data.length*2];
			    System.arraycopy(data, 0, ndata, 0, data.length);
			    data = ndata;
			}
			int read = in.read(data, len, data.length - len);
			if (read <= 0)
			    break;
			len += read;
		    }
		    crypted = new byte[len];
		    System.arraycopy(data, 0, crypted, 0, len);
		}
	    } else {
		salt = new byte[4];
		mdigest = new byte[16];
		in.readFully(salt, 0, 4);
		in.readFully(mdigest, 0, 16);
	    }
	}	
    }

    public void setCharset (String charset) {
	charSetName = charset;
    }

    public void setFilename (File file) {
	db = new Database();
	try {
	    db.read(new FileInputStream(file), 
		    KeyAppInfo.class, null, KeyRecord.class);
	    if (db.getVersion() > 5) {
		System.err.println("Unsupported database version!");
		return;
	    }
	} catch (Exception ex) {
	    ex.printStackTrace();
	    return;
	}

	categories = new TreeMap();
	if (db.getVersion() >= 1) {
	    for (int i = 0; i < 16; i++) {
		String cat = db.getAppInfo().getCategories(i);
		if (cat.length() > 0)
		    categories.put(cat, new Integer(i));
	    }
	}

	Record[] rawEntries = db.getEntries();
	int start = 0;
	if (db.getVersion() == 0) {
	    salt = ((KeyAppInfo) db.getAppInfo()).salt;
	    mdigest = ((KeyAppInfo) db.getAppInfo()).mdigest;
	} else if (db.getVersion() <= 4) {
	    salt = ((KeyRecord) rawEntries[0]).salt;
	    mdigest = ((KeyRecord) rawEntries[0]).mdigest;
	    start++;
	} else {
	    salt = ((KeyAppInfo) db.getAppInfo()).salt;
	    ciphnr = ((KeyAppInfo) db.getAppInfo()).cipher;
	    iter = ((KeyAppInfo) db.getAppInfo()).iter;
	    mdigest = ((KeyAppInfo) db.getAppInfo()).mdigest;
	}
	
	entries = new ArrayList(rawEntries.length);
	for (int i = start; i < rawEntries.length; i++) {
	    KeyRecord entry = (KeyRecord) rawEntries[i];
	    if ((entry.getAttributes() & entry.DMRECATTRDELETE) != 0)
		continue;
	    if (entry.keyname == null)
		continue;
	    int cat = (entry.getAttributes() & entry.DMRECATTRCATEGORYMASK);
	    String name;
	    try {
		name = new String(entry.keyname, charSetName);
	    } catch (UnsupportedEncodingException ex) {
		ex.printStackTrace();
		return;
	    }
	    
	    if (db.getVersion() == 0) {
		entries.add(new PDBKeyringEntry(this, name, null,
						entry.crypted));
	    } else if (db.getVersion() <= 4) {
		entries.add(new PDBKeyringEntry(this, name, 
						db.getAppInfo().getCategories(cat),
						entry.crypted));
	    } else {
		entries.add(new PDBKeyringEntry5(this, name, 
						 db.getAppInfo().getCategories(cat),
						 entry.crypted));
	    }
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
	return getKey(password);
    }

    public void lock() {
	cipher = null;
	key = null;
    }

    int getBlockSize() {
	return cipher.getBlockSize();
    }

    Cipher getCipher(int mode, byte[] iv) {
	AlgorithmParameters params = null;
	try {
	    if (db.getVersion() > 4) {
		switch (ciphnr) {
		    case 1:
			params = AlgorithmParameters.getInstance("DES");
			params.init(new IvParameterSpec(iv));
			break;
		    case 2:
		    case 3:
			params = AlgorithmParameters.getInstance("AES");
			params.init(new IvParameterSpec(iv));
			break;
		}
	    }
	    cipher.init(mode, key, params);
	} catch (GeneralSecurityException ex) {
	    throw new InternalError("Cannot create IV: "+ex);
	}
	return cipher;
    }

    public boolean isLocked() {
	return cipher == null;
    }

    private static byte odd_parity[] = new byte[256];

    static {
	for (int i = 0; i < 256; i++) {
	    int p = (i ^ (i >> 4));
	    p ^= p >> 2;
	    p ^= p >> 1;
	    odd_parity[i] = (byte) (i ^ (p&1) ^ 1);
	}
    }

    private boolean getKey(String password) {
	byte[] pwbytes;
	try {
	    pwbytes = password.getBytes(charSetName);
	} catch (UnsupportedEncodingException ex) {
	    throw new InternalError("Encoding not supported");
	}
	if (db.getVersion() <= 4)
	    return getKey4(pwbytes);
	else
	    return getKey5(pwbytes);
    }

    private boolean getKey4(byte[] password) {
	if (salt != null && mdigest != null) {
	    byte[] pw = new byte[64];
	    System.arraycopy(salt, 0, pw, 0, 4);
	    System.arraycopy(password, 0, pw, 4, Math.min(60,password.length));
	    if (!Arrays.equals(md5(pw), mdigest))
		return false;
	}

	byte[] digest = md5(password);
	byte[] rawkey = new byte[24];
	for (int i = 0; i < 16; i++) {
	    rawkey[i] = odd_parity[digest[i] & 0xff];
	}
	for (int i = 0; i < 8; i++) {
	    rawkey[i+16] = rawkey[i];
	}


	try {
	    cipher = Cipher.getInstance("DESede/ECB/NoPadding");
	    key = SecretKeyFactory.getInstance("DESede")
		.generateSecret(new DESedeKeySpec(rawkey));
	} catch (GeneralSecurityException ex) {
	    throw new InternalError("Can't get DESede encryption: "
				    +ex.toString());
	}
	return true;
    }
    
    /**
     * This method is an implementation of PKCS#5 PBKDF2.
     *
     * @param pass Database password
     * @param salt Salt
     * @param iter Iterations
     * @param keylen Keylength of choosen cipher type
     *
     * @return Record encryption key
     */
    public byte[] pbkdf2(byte[] pass, byte[] salt, int iter, int keylen) 
	throws GeneralSecurityException
    {
	// PKCS#5 PBKDF2
	// Key Derivation function
	int SHA_DIGEST_LENGTH = 20;
	int blocklen;
	int i = 1;
	byte itmp[] = new byte[4];
	int pos = 0;
	byte digtmp[] = new byte[SHA_DIGEST_LENGTH];
	byte p[] = new byte[keylen];
	int j, k;
	
	Mac mac = Mac.getInstance("HmacSHA1");
        SecretKeySpec key = new SecretKeySpec(pass, "HmacSHA1");
        mac.init(key);
	
	while(keylen > 0) {
	    
	    if(keylen > SHA_DIGEST_LENGTH)
		blocklen = SHA_DIGEST_LENGTH;
	    else
		blocklen = keylen;
	    
	    itmp[0] = (byte)(0xff & (i >> 24));
	    itmp[1] = (byte)(0xff & (i >> 16));
	    itmp[2] = (byte)(0xff & (i >> 8));
	    itmp[3] = (byte)(0xff & i);

	    mac.reset();
	    mac.update(salt);
	    digtmp = mac.doFinal(itmp);
	    System.arraycopy(digtmp, 0, p, pos, blocklen);
	    
	    for(j = 1; j < iter; j++) {
		mac.reset();
		digtmp = mac.doFinal(digtmp);

		for(k = 0; k < blocklen; k++)
		    p[pos + k] ^= digtmp[k];
	    }
	    
	    keylen = keylen - blocklen;
	    pos = pos + blocklen;
	    i++;
	}
	
	return p;
    }
    
//     private static String dump(byte[] b) {
// 	StringBuffer sb = new StringBuffer();
// 	for (int i = 0; i < b.length; i++) {
// 	    sb.append(Integer.toString(b[i]&0xff, 16)).append(" ");
// 	}
// 	return sb.toString();
//     }

    public boolean getKey5(byte[] password) {
	try {
// 	    System.err.println("password: "+dump(password));
// 	    System.err.println("salt: "+dump(salt)+ "iter: "+iter+" ciph: "+ciphnr);
	    byte[] rawkey = pbkdf2(password, salt, iter, keylens[ciphnr]);
// 	    System.err.println("rawkey: "+dump(rawkey));
	    if(ciphnr == 1) { // TripleDES
		// set odd parity
		for(int i=0; i<24; i++) {
		    rawkey[i] = odd_parity[rawkey[i] & 0xff];
		}
	    }
	    MessageDigest md = MessageDigest.getInstance("SHA1");
	    md.update(rawkey);
	    md.update(salt);
	    byte[] shadig = md.digest();
// 	    System.err.println("shadig: "+dump(shadig));
// 	    System.err.println("mdigest: "+dump(mdigest));
	    for (int i = 0; i < mdigest.length; i++) {
		if (shadig[i] != mdigest[i])
		    return false;
	    }
	
	    if (ciphnr == 0) {
		cipher = new NullCipher();
		key = new SecretKeySpec(rawkey, "NULL");
	    } else {
		cipher = Cipher.getInstance(keyalgos[ciphnr]);
		key = new SecretKeySpec(rawkey, keyalgosShort[ciphnr]);
	    }
	} catch (GeneralSecurityException ex) {
	    throw new InternalError("Can't generate key: "+ex);
	}
	return true;
    }

    private byte[] md5(byte[] bytes) {
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
