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

/**
 * Output data in Palm's format.
 */
public class PalmDataOutputStream extends DataOutputStream {
    /**
     * The difference between 1904 and 1970 (the two different epochs)
     * in seconds.  This are 66 years including 17 leap years.
     */
    private static int dateOffset = (66*365 + 17) * 24 * 60 * 60;

    public PalmDataOutputStream(OutputStream os) {
	super(os);
    }

    public void writeDate(Date date) throws IOException {
	writeInt((int)(date.getTime() / 1000L) + dateOffset);
    }

    public void writeString(String str, int len) throws IOException {
	byte[] bytes = str.getBytes();
	if (bytes.length < len) {
	    write(bytes);
	    write(new byte[len - bytes.length]);
	} else {
	    bytes[len-1] = 0;
	    write (bytes, 0, len);
	}
    }

    public void writePackedString(String str) throws IOException {
	byte[] bytes = str.getBytes();
	write(bytes);
	if ((bytes.length & 2) == 1)
	    writeByte(0);
	else
	    writeShort(0);
    }
}
