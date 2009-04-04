package net.sf.gnukeyring.export;
import net.sf.gnukeyring.KeyringEntry;
import net.sf.gnukeyring.KeyringLibrary;
import java.io.*;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.text.DateFormat;
import java.text.SimpleDateFormat;

/**
 * The XML export for a keyring database.
 *
 * @author Jochen Hoenicke
 * @version $Revision: 697 $
 */

public class XMLExport {
    KeyringLibrary keylib;
    Writer writer;

    public static void main(String[] param) throws IOException {
	if (param.length < 2 || param.length > 3) {
	    System.err.println("USAGE: java net.sf.gnukeyring.export.XMLExport <pdb-file> <password> [<outputfile>]");
	    return;
	}
	new XMLExport(param).export();;
    }

    public XMLExport(String[] param) throws IOException {
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

    public void export() throws IOException {
	writer.write("\uFEFF");
	writer.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
	writer.write("<pwlist>\n");
	exportEntries();
	writer.write("</pwlist>\n");
	writer.close();
    }

    public String xmlencode(String str) {
	StringBuffer sb = new StringBuffer();
	for (int i = 0; i < str.length(); i++) {
	    char c = str.charAt(i);
	    switch (c) {
		case '&':
		    sb.append("&amp;");
		    break;
		case '<':
		    sb.append("&lt;");
		    break;
		case '>':
		    sb.append("&gt;");
		    break;
		default:
		    sb.append(c);
	    }
	}
	return sb.toString();
    }

    public String dateencode(Date date) {
	DateFormat df = new SimpleDateFormat("yyyy-MM-dd");
	return df.format(date);
    }

    public void exportEntries() throws IOException {
	List entries = keylib.getEntries();
	
	for (Iterator i = entries.iterator(); i.hasNext(); ) {
	    KeyringEntry entry = (KeyringEntry) i.next();

	    writer.write("<pwentry>\n");
	    writer.write("  <title>"+xmlencode(entry.getName())+"</title>\n");
	    String category = (String) entry.getCategory();
	    String account = (String) entry.getField("Account");
	    String password = (String) entry.getField("Password");
	    Date   changed = (Date) entry.getField("Changed");
	    String notes = (String) entry.getField("Notes");
	    if (category != null)
		writer.write("  <category>"+xmlencode(category)+"</category>\n");
	    if (account != null)
		writer.write("  <username>"+xmlencode(account)+"</username>\n");
	    if (password != null)
		writer.write("  <password>"+xmlencode(password)+"</password>\n");
	    if (notes != null)
		writer.write("  <notes>"+xmlencode(notes)+"</notes>\n");
	    if (changed != null)
		writer.write("  <lastmodtime>"+dateencode(changed)+"</lastmodtime>\n");
	    writer.write("</pwentry>\n");
	}
    }
}
