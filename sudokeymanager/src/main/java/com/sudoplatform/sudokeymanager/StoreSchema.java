package com.sudoplatform.sudokeymanager;

/**
 * Key store schema common to all key store implementations.
 */
public final class StoreSchema {

    private StoreSchema() {};

    public static class Keys {

        // Table name.
        public static final String TABLE_NAME = "KEYS";

        // Columns.
        public static final String COLUMN_NAME_NAME = "NAME";
        public static final String COLUMN_NAME_TYPE = "TYPE";
        public static final String COLUMN_NAME_EXPORTABLE = "EXPORTABLE";
        public static final String COLUMN_NAME_DATA = "DATA";

        // Create table.
        public static final String CREATE_TABLE = "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " ("
                + COLUMN_NAME_NAME + " TEXT NOT NULL,"
                + COLUMN_NAME_TYPE + " INT NOT NULL,"
                + COLUMN_NAME_EXPORTABLE + " INT NOT NULL,"
                + COLUMN_NAME_DATA + " BLOB NOT NULL,"
                + "PRIMARY KEY (NAME, TYPE)"
                + ");";

    }

}
