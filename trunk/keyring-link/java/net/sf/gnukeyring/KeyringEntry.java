package net.sf.gnukeyring;

import java.util.Date;
import java.util.List;

/**
 * <p>A single entry in the keyring collection.</p>
 *
 * <p>Title: JKeyring</p>
 * <p>Description: Viewer for Gnu Keyring data.</p>
 * <p>Copyright: Copyright (c) 2003</p>
 * @author Jay Dickon Glanville
 * @version $Revision$
 */

public interface KeyringEntry {

    /** Gets the name (or key) for this entry. */
    public String getName();

    /** Gets the category that this entry is stored in. */
    public String getCategory();

    /**
     * Given a field name, gets the value for that field.  This is currently
     * intended for future versions of GNU Keyring, but can be used now.
     * @param fieldName the name (label) of the field to
     * @return The value of the named field, or null if the field doesn't exist.
     */
    public Object getField( String fieldName );

    /**
     * Gets a collection of field names that this entry has.  The format of the
     * return is a {@link java.util.List List} of String entries, listing all
     * field names in the order they're stored.
     * @return The list of field names this entry has.
     */
    public List getFieldNames();

    /** Is this entry, and it's associated parent library, locked? */
    public boolean isLocked();

    /**
     * Unlocks this entry, and it's associated library, using the provided
     * password.
     * @param password The password for this entry and library.
     * @return <code>true</code> if the unlock was successful,
     * <code>false</code> otherwise.
     */
    public boolean unlockLibrary( String password );

    /** Locks this entry, and it's library, back up. */
    public void lockLibrary();

}
