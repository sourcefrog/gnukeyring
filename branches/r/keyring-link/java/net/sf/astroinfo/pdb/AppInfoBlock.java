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
import java.util.Date;
import java.io.*;

public abstract class AppInfoBlock extends Record {
    private int      renamed    = 0;
    private String[] categories = new String[16];
    private int[]    uniqIds    = new int[16];
    private int      lastUniqId = 0;

    public AppInfoBlock() {
    }

    public String getCategories(int i) {
	return categories[i];
    }
    public void setCategories(int i, String cat) {
	categories[i] = cat;
    }
    public int getUniqID(int i) {
	return uniqIds[i];
    }
    public void setUniqID(int i, int uid) {
	if (uid < 0 || uid > 255)
	    throw new IllegalArgumentException("uid "+uid);
	uniqIds[i] = uid;
    }
    public boolean hasRenamed(int i) {
	if (i < 0 || i > 15)
	    throw new ArrayIndexOutOfBoundsException(i);
	return (renamed & (1 << i)) != 0;
    }
    public void setRenamed(int i, boolean r) {
	if (i < 0 || i > 15)
	    throw new ArrayIndexOutOfBoundsException(i);
	if (r)
	    renamed |=   1 << i;
	else
	    renamed &= ~(1 << i);
    }
    public int getLastUniqID() {
	return lastUniqId;
    }
    public void setLastUniqID(int uid) {
	if (uid < 0 || uid > 255)
	    throw new IllegalArgumentException("uid "+uid);
	lastUniqId = uid;
    }

    public void writeCategories(PalmDataOutputStream out) throws IOException {
	out.writeShort(renamed);
	for (int i = 0; i < 16; i++) 
	    out.writeString(categories[i], 16);
	for (int i = 0; i < 16; i++) 
	    out.writeByte(uniqIds[i]);
	out.writeByte(lastUniqId);
	out.writeByte(0);
    }

    public void readCategories(PalmDataInputStream in) throws IOException {
	renamed = in.readUnsignedShort();
	for (int i = 0; i < 16; i++) 
	    categories[i] = in.readString(16);
	for (int i = 0; i < 16; i++) 
	    uniqIds[i] = in.readUnsignedByte();
	lastUniqId = in.readUnsignedByte();
	in.readUnsignedByte();
    }
}


