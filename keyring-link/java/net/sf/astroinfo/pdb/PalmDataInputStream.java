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
 * Input data in Palm's format.
 */
public class PalmDataInputStream extends DataInputStream {
    /**
     * The difference between 1904 and 1970 (the two different epochs)
     * in seconds.  This are 66 years including 17 leap years.
     */
    private static final int dateOffset = (66*365 + 17) * 24 * 60 * 60;

    private static class CountingInputStream extends FilterInputStream {
	public CountingInputStream(InputStream is) {
	    super(is);
	}
	
	int offset = 0;
	int limit = Integer.MAX_VALUE;

	public int read() throws IOException {
	    if (offset >= limit)
		return -1;
	    int result = super.read();
	    if (result >= 0)
		offset++;
	    return result;
	}
	public int read(byte[] b, int o, int l) throws IOException {
	    if (offset >= limit)
		return -1;
	    if (l > limit - offset)
		l = limit - offset;
	    int result = super.read(b, o, l);
	    if (result >= 0)
		offset += result;
	    return result;
	}
	public long skip(long n) throws IOException {
	    if (offset >= limit)
		return 0;
	    if (n > limit - offset)
		n = limit - offset;
	    long result = super.skip(n);
	    if (result >= 0)
		offset += (int)result;
	    return result;
	}	    
    }

    public PalmDataInputStream(InputStream is) {
	super(new CountingInputStream(is));
    }

    public Date readDate() throws IOException {
	int seconds = readInt();
	return new Date((seconds - dateOffset) * 1000L);
    }

    public String readString(int len) throws IOException {
	byte[] bytes = new byte[len];
	readFully(bytes);
	while (--len >= 0)
	    if (bytes[len] != 0)
		break;
	return new String(bytes, 0, len+1);
    }

    public String readPackedString() throws IOException {
	byte[] bytes = new byte[100];
	int ptr = 0;
	int i;
	while ((i = read()) != 0) {
	    if (i < 0)
		throw new EOFException();
	    bytes[ptr++] = (byte) i;
	    if (ptr == bytes.length) {
		byte[] nbytes = new byte[bytes.length*2];
		System.arraycopy(bytes, 0, nbytes, 0, bytes.length);
		bytes = nbytes;
	    }
	}
	String result = new String(bytes, 0, ptr);
	return result;
    }

    /**
     * Returns the current offset from the start of the stream.
     */
    public int size() {
	return ((CountingInputStream) in).offset;
    }

    /**
     * Forbid to read beyond offset.  We return EOF.
     */
    public void restrict(int offset) {
	((CountingInputStream) in).limit = offset;
    }
}
