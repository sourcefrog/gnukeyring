package net.sf.gnukeyring.export;

import net.sf.gnukeyring.KeyringLibrary;
import java.io.*;

public abstract class Export {
    KeyringLibrary keylib;
    Writer writer;

    public static void main(String[] param) throws IOException {
	if (param.length < 2 || param.length > 3) {
	    System.err.println("USAGE: java net.sf.gnukeyring.export.Export <pdb-file> <password> [<outputfilename>.csv|xml]");
	    return;
	}
        Export exporter; 
        if (param.length == 2 || param[2].indexOf(".xml") != -1) {
            exporter = new XMLExport();
        }
        else if (param[2].indexOf(".csv") != -1) {
            exporter = new CSVExport();
        }
        else {
            System.err.println("Export format for '" + param[2] + "' unknown.");
	    return;
        }

	exporter.setInputStream(param[0]);
	if (!exporter.unlock(param[1])) {
	    System.err.println("Wrong password!");
	    return;
	}
	exporter.setOutputStream(param.length == 2 ? null : param[2]);
	exporter.export();
    }
    
    public Export() {
	keylib = new net.sf.gnukeyring.decoder.PDBKeyringLibrary();
    }

    public boolean unlock(String pw) {
	return keylib.unlock(pw);
    }

    public void setInputStream(String inputfile) throws IOException {
	keylib.setFilename(new File(inputfile));
    }
    public void setOutputStream(String outputfile) throws IOException {
	OutputStream os;
	if (outputfile == null) {
	    os = System.out;
	} else {
	    os = new FileOutputStream(new File(outputfile));
	}
	writer = new OutputStreamWriter(os, "UTF-8");
    }

    public abstract void export() throws IOException;
}

