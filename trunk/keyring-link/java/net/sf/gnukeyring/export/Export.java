package net.sf.gnukeyring.export;

import net.sf.gnukeyring.KeyringLibrary;
import java.io.*;

public class Export {
    KeyringLibrary keylib;
    Writer writer;

    public static void main(String[] param) throws IOException {
	if (param.length < 2 || param.length > 3) {
	    System.err.println("USAGE: java net.sf.gnukeyring.export.Export <pdb-file> <password> [<outputfilename>.csv|xml]");
	    return;
	}
        
        if (param[2].indexOf(".xml") != -1) {
            new XMLExport(param).export();
        }
        else if (param[2].indexOf(".csv") != -1) {
            new CSVExport(param).export();
        }
        else {
            System.err.println("Export format for '" + param[2] + "' unknown.");
        }
    }
    
    public Export(String[] param) throws IOException {
	keylib = new net.sf.gnukeyring.decoder.PDBKeyringLibrary();
	keylib.setFilename(new File(param[0]));
	keylib.unlock(param[1]);
	OutputStream os;
	if (param.length == 2) {
	    os = System.out;
	} else {
	    os = new FileOutputStream(new File(param[2]));
	}
	writer = new OutputStreamWriter(os, "UTF-8");
    }
}

