/*
 * Astro Info - a an astronomical calculator/almanac for PalmOS devices.
 * 
 * $Id$
 * Copyright (C) 2002, Astro Info SourceForge Project
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

package net.sf.astroinfo.pdb;
import java.lang.reflect.Array;
import java.util.Date;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;

/**
 * Represents a Palm database, either a PDB or a PRC file.
 */
public class Database {
    private String name;
    private short attributes;
    private short version;
    private Date creationDate     = new Date();
    private Date modificationDate = creationDate;
    private Date lastBackupDate   = creationDate;
    private int modificationNumber;
    private AppInfoBlock appInfo;
    private SortInfoBlock sortInfo;
    private int type;
    private int creator;
    private int uniqueIDSeed;
    private Record[] entries;

    /**
     * Resource database (PRC).
     */
    public final static int DMHDRATTRRESDB = 0x0001;

    /**
     * Read Only database.
     */
    public final static int DMHDRATTRREADONLY = 0x0002;

    /**
     * Set if Application Info block is dirty.  Optionally supported
     * by an App's conduit.
     */
    public final static int DMHDRATTRAPPINFODIRTY = 0x0004;

    /**
     * Set if database should be backed up to PC if no app-specific
     * synchronization conduit has been supplied.
     */
    public final static int DMHDRATTRBACKUP = 0x0008;

    /**
     * This tells the backup conduit that it's OK; for it to install a
     * newer version of this database with a different name if the
     * current database is open. This mechanism is used to update the
     * Graffiti Shortcuts database, for example.  
     */
    public final static int DMHDRATTROKTOINSTALLNEWER = 0x0010;

    /**
     * Device requires a reset after this database is installed.
     */
    public final static int DMHDRATTRRESETAFTERINSTALL = 0x0020;
    /**
     * This database should not be copied to.
     */
    /**
     */
    public final static int DMHDRATTRCOPYPREVENTION = 0x0040;
    /**
     * This database is used for file stream implementation.
     */
    public final static int DMHDRATTRSTREAM  = 0x0080;
    /**
     * This database should generally be hidden from view.  Used to
     * hide some apps from the main view of the launcher for example.
     *
     * For data (non-resource) databases, this hides the record
     * count within the launcher info screen.
     */
    public final static int DMHDRATTRHIDDEN = 0x0100;
    /**
     * This data database (not applicable for executables) can be
     * "launched" by passing it's name to it's owner app ('appl'
     * database with same creator) using the
     * sysAppLaunchCmdOpenNamedDB action code.
     */
    public final static int DMHDRATTRLAUNCHABLEDATA = 0x0200;
    /**
     * This database (resource or record) is recyclable: it will be
     * deleted Real Soon Now, generally the next time the database is
     * closed.
     */
    public final static int DMHDRATTRRECYCLABLE = 0x0400;
    /**
     * This database (resource or record) is associated with the
     * application with the same creator. It will be beamed and copied
     * along with the application.
     */
    public final static int DMHDRATTRBUNDLE = 0x0800;

    /**
     * Database not closed properly.
     */
    public final static int DMHDRATTROPEN = 0x8000;

    public Database() {
    }

    public void read(InputStream is, 
		     Class appInfoClass, Class sortInfoClass,
		     Class recordClass) 
	throws IOException, InstantiationException, IllegalAccessException
    {
	PalmDataInputStream in = new PalmDataInputStream(is);
	name = in.readString(32);
	attributes   = in.readShort();
	version      = in.readShort();
	creationDate = in.readDate();
	modificationDate = in.readDate();
	lastBackupDate = in.readDate();
	modificationNumber = in.readInt();
	int appInfoOffset = in.readInt();
	int sortInfoOffset = in.readInt();
	type    = in.readInt();
	creator = in.readInt();
	uniqueIDSeed = in.readInt();
	if (in.readInt() != 0)
	    throw new IOException("Can't handle chunked record lists");
	entries = (Record[]) Array.newInstance(recordClass, 
					       in.readUnsignedShort());
	int[] offsets = new int[entries.length];
	for (int i = 0; i < entries.length; i++) {
	    if (isResourceDB()) {
		PRCRecord e = (PRCRecord) recordClass.newInstance();
		e.setDatabase(this);
		e.setIndex(i);
		e.setType(in.readInt());
		e.setID(in.readUnsignedShort());
		offsets[i] = in.readInt();
		entries[i] = e;
	    } else {
		PDBRecord e = (PDBRecord) recordClass.newInstance();
		offsets[i] = in.readInt();
		int value = in.readInt();
		e.setDatabase(this);
		e.setIndex(i);
		e.setAttributes((value >> 24) & 0xff);
		e.setUniqueID(value & 0xffffff);
		entries[i] = e;
	    }
	}
	if (appInfoOffset > 0) {
	    if (appInfoOffset < in.size())
		throw new IOException("appinfo "+appInfoOffset
				      +" before end of header");
	    if (appInfoOffset > in.size())
		in.skip(appInfoOffset - in.size());

	    if (sortInfoOffset > 0)
		in.restrict(sortInfoOffset);
	    else if (offsets.length > 0)
		in.restrict(offsets[0]);
	    else
		in.restrict(Integer.MAX_VALUE);
	    appInfo = (AppInfoBlock) appInfoClass.newInstance();
	    appInfo.read(in);
	}
	if (sortInfoOffset > 0) {
	    if (sortInfoOffset < in.size())
		throw new IOException("sortinfo "+sortInfoOffset
				      +" before end of header");
	    if (sortInfoOffset > in.size())
		in.skip(sortInfoOffset - in.size());

	    if (offsets.length > 0)
		in.restrict(offsets[0]);
	    else
		in.restrict(Integer.MAX_VALUE);
	    sortInfo = (SortInfoBlock) sortInfoClass.newInstance();
	    sortInfo.read(in);
	}
	for (int i = 0; i < entries.length; i++) {
	    if (offsets[i] < in.size())
		throw new IOException("entry "+i+" too early at "+offsets[i]);
	    if (offsets[i] > in.size())
		in.skip(offsets[i] - in.size());
	    if (offsets.length > i+1)
		in.restrict(offsets[i+1]);
	    else
		in.restrict(Integer.MAX_VALUE);
	    entries[i].read(in);
	}
    }

    private boolean isResourceDB() {
	return (attributes & DMHDRATTRRESDB) != 0;
    }

    public void write(OutputStream os) throws IOException {
	ByteArrayOutputStream baos = new ByteArrayOutputStream(); 
	PalmDataOutputStream out = new PalmDataOutputStream(baos);
	int offsets[] = new int[entries.length];
	int sortInfoOffset;
	if (appInfo != null)
	    appInfo.write(out);
	sortInfoOffset = out.size();
	if (sortInfo != null)
	    sortInfo.write(out);
	for (int i = 0; i <entries.length; i++) {
	    offsets[i] = out.size();
	    entries[i].setDatabase(this);
	    entries[i].setIndex(i);
	    entries[i].write(out);
	}
	out.flush();

	int headersize = 0x48 + 6 + entries.length * (isResourceDB() ? 10 : 8);

	out = new PalmDataOutputStream(os);
	out.writeString(name, 32);
	out.writeShort(attributes);
	out.writeShort(version);
	out.writeDate(creationDate);
	out.writeDate(modificationDate);
	out.writeDate(lastBackupDate);
	out.writeInt(modificationNumber);
	out.writeInt(appInfo != null  ? headersize : 0);
	out.writeInt(sortInfo != null ? headersize + sortInfoOffset : 0);
	out.writeInt(type);
	out.writeInt(creator);
	out.writeInt(uniqueIDSeed);
	out.writeInt(0);
	out.writeShort(entries.length);
	for (int i = 0; i < entries.length; i++) {
	    if (isResourceDB()) {
		PRCRecord e = (PRCRecord) entries[i];
		out.writeInt(e.getType());
		out.writeShort(e.getID());
		out.writeInt(headersize + offsets[i]);
	    } else {
		PDBRecord e = (PDBRecord) entries[i];
		out.writeInt(headersize + offsets[i]);
		int value = (e.getAttributes() << 24) | e.getUniqueID();
		out.writeInt(value);
	    }
	}
	out.write(baos.toByteArray());
	out.flush();
    }

    public String getName() {
	return name;
    }
    public void setName(String n) {
	name = n;
    }

    public int getAttributes() {
	return attributes & 0xffff;
    }
    public void setAttributes(int n) {
	attributes = (short) n;
    }

    public int getVersion() {
	return version & 0xffff;
    }
    public void setVersion(int n) {
	version = (short) n;
    }

    public Date getCreationDate() {
	return creationDate;
    }
    public void setCreationDate(Date d) {
	creationDate = d;
    }

    public Date getModificationDate() {
	return modificationDate;
    }
    public void setModificationDate(Date d) {
	modificationDate = d;
    }

    public Date getLastBackupDate() {
	return lastBackupDate;
    }
    public void setLastBackupDate(Date d) {
	lastBackupDate = d;
    }

    public int getModificationNumber() {
	return modificationNumber;
    }
    public void setModificationNumber(int mod) {
	modificationNumber = mod;
    }

    public AppInfoBlock getAppInfo() {
	return appInfo;
    }
    public void setAppInfo(AppInfoBlock ai) {
	appInfo = ai;
    }

    public SortInfoBlock getSortInfo() {
	return sortInfo;
    }
    public void setSortInfo(SortInfoBlock ai) {
	sortInfo = ai;
    }

    public int getType() {
	return type;
    }
    public void setType(int t) {
	type = t;
    }

    public int getCreator() {
	return creator;
    }
    public void setCreator(int c) {
	creator = c;
    }

    public int getUniqueIDSeed() {
	return uniqueIDSeed;
    }
    public void setUniqueIDSeed(int uid) {
	uniqueIDSeed = uid;
    }

    public Record[] getEntries() {
	return entries;
    }
    public void setEntries(Record[] e) {
	entries = e;
    }

    public static int StringToID (String id) {
	byte[] bytes = id.getBytes();
	if (bytes.length != 4)
	    throw new IllegalArgumentException("id "+id);
	return (bytes[0] & 0xff) << 24
	    | (bytes[1] & 0xff) << 16
	    | (bytes[2] & 0xff) <<  8
	    | (bytes[3] & 0xff);
    }

    public static String IDToString (int id) {
	byte[] bytes = new byte[] {
	    (byte) (id >> 24), (byte) (id >> 16), (byte) (id >> 8), (byte) id
	};
	return new String(bytes);
    }

    public String toString() {
	return "DB[\""+name+"\","+Integer.toHexString(attributes)+","
	    +version+","+creationDate+","+modificationNumber+","
	    +IDToString(creator)+","+IDToString(type)+","
	    +appInfo+","+sortInfo+","+entries.length+"]";
    }
}

