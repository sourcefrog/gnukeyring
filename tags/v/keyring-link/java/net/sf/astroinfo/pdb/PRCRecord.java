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

public abstract class PRCRecord extends Record {
    int type;
    int id;

    public PRCRecord() {
    }
    public int getType() {
	return type;
    }
    public void setType(int type) {
	this.type = type;
    }
    public int getID() {
	return id;
    }
    public void setID(int id) {
	this.id = id;
    }
}
