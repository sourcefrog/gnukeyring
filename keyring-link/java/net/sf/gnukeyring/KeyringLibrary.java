package net.sf.gnukeyring;

import java.io.File;
import java.util.List;
import java.util.Set;

/**
 * <p>A collection (or library) of keyring entries.
 * <p>Title: JKeyring</p>
 * <p>Description: Viewer for Gnu Keyring data.</p>
 * <p>Copyright: Copyright (c) 2003</p>
 * @author Jay Dickon Glanville
 * @version $Revision$
 */
public interface KeyringLibrary {

    /** Sets the name of the file that this library represents. */
    public void setFilename( File filename );

    /** Gets a set containing all the categories within the library. */
    public Set getCategories();

    /**
     * Gets a list containing all the entries within this library.  The format
     * of the return is a {@link java.util.List List} containing
     * {@link net.sf.gnukeyring.jkeyring.KeyringEntry KeyringEntry}s.
     * @return A list of all keyring entries.
     */
    public List getEntries();

    /** Gets a list of the names of all entries within this library. */
    public List getEntryNames();

    /**
     * Gets all the
     * {@link net.sf.gnukeyring.jkeyring.KeyringEntry KeyringEntry}s in the
     * category <code>categoryName</code>.
     * @param categoryName The category to find all entries for.
     * @return A List of KeyringEntrys all in the named category.  The return
     * is an empty list if there are no entries in that category, or that
     * category doesn't exist.
     */
    public List getEntries( String categoryName );

    /**
     * Gets the {@link net.sf.gnukeyring.jkeyring.KeyringEntry KeyringEntry}
     * who's name/key is <code>key</code>.
     * @param key The name/key of the desired entry.
     * @return The KeyringEntry who's name is key, or null if that key doesn't
     * exist.
     */
    public KeyringEntry getEntry( String key );

    /**
     * Unlocks this library using the provided password.
     * @param password The password for this library.
     * @return <code>true</code> if the unlock was successful,
     * <code>false</code> otherwise.
     */
    public boolean unlock( String password );

    /** Locks the library back up. */
    public void lock();

    /** Is this entry, and it's associated parent library, locked? */
    public boolean isLocked();
}
