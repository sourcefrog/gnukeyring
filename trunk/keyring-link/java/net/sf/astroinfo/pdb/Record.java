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
 * The base class of records.  Don't extend this. Extend PRCRecord or
 * PDBRecord.
 */
public abstract class Record {
    public Record() {
    }
    private Database db;
    private int idx;
    
    public abstract void read(PalmDataInputStream in) throws IOException;
    public abstract void write(PalmDataOutputStream in) throws IOException;

    public Database getDatabase() {
	return db;
    }
    public void setDatabase(Database db) {
	this.db = db;
    }
    public int getIndex() {
	return idx;
    }
    public void setIndex(int i) {
	idx = i;
    }
}
