/*
 * $Id$
 * 
 * Keyring CSV Exporter
 * Copyright (C) 2009 Gervase Markham <gerv@gerv.net>
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

package net.sf.gnukeyring.export;

import net.sf.gnukeyring.KeyringEntry;
import net.sf.gnukeyring.KeyringLibrary;
import java.io.*;
import java.util.Iterator;
import java.util.List;
import com.Ostermiller.util.*;

/**
 * The CSV export for a keyring database.
 *
 * @author Gervase Markham <gerv@gerv.net>
 * @version $Revision$
 */

public class CSVExport extends Export {
    public CSVExport(String[] param) throws IOException {
        super(param);
    }
    
    public void export() throws IOException {
	writer.write("Category,Description,Website,Username,Password,Notes\n");
	exportEntries();
	writer.close();
    }

    public void exportEntries() throws IOException {
	List entries = keylib.getEntries();
        ExcelCSVPrinter csvp = new ExcelCSVPrinter(writer);
	
	for (Iterator i = entries.iterator(); i.hasNext(); ) {
	    KeyringEntry entry = (KeyringEntry) i.next();

	    String name = (String) entry.getName();
	    String category = (String) entry.getCategory();
	    String account = (String) entry.getField("Account");
	    String password = (String) entry.getField("Password");
	    String notes = (String) entry.getField("Notes");
            
            // Website category is always empty, but this makes the export
            // format directly compatible with OI Safe for Android.
            // http://www.openintents.org/en/node/205
            csvp.writeln(new String[]{
                category, name, "", account, password, notes    
            });
	}
    }
}
