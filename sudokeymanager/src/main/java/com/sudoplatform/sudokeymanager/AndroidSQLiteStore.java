package com.sudoplatform.sudokeymanager;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteException;
import android.database.sqlite.SQLiteOpenHelper;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * KeyManager store implementation using AndroidSQLiteStore.
 */
public final class AndroidSQLiteStore extends SQLiteOpenHelper implements StoreInterface {

    // Database name,
    private static final String DATABASE_NAME = "keys.db";

    // Database version.
    private static final int DATABASE_VERSION = 1;

    // SQL statements for various operations we need to execute.
    private static final String SQL_DROP_TABLE = "DROP TABLE IF EXISTS " + StoreSchema.Keys.TABLE_NAME;
    private static final String SQL_DELETE_ALL = "DELETE FROM " + StoreSchema.Keys.TABLE_NAME;

    private static final String NAME_CANT_BE_NULL = "name can't be null.";
    private static final String TYPE_CANT_BE_NULL = "type can't be null.";

    // Delegate for encrypting and decrypting keys.
    private SecureKeyDelegateInterface secureKeyDelegate;

    /**
     * Instantiates AndroidSQLiteStore.
     *
     * @param context Android app context.
     */
    public AndroidSQLiteStore(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
    }

    /**
     * Instantiates AndroidSQLiteStore.
     *
     * @param context Android app context.
     */
    public AndroidSQLiteStore(Context context, SecureKeyDelegateInterface secureKeyDelegate) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
        this.secureKeyDelegate = secureKeyDelegate;
    }

    public void onCreate(SQLiteDatabase db) {
        db.execSQL(StoreSchema.Keys.CREATE_TABLE);
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        db.execSQL(SQL_DROP_TABLE);
        onCreate(db);
    }

    public void onDowngrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        onUpgrade(db, oldVersion, newVersion);
    }

    @Override
    public void insertKey(byte[] keyBytes, String name, KeyType type, boolean isExportable) throws KeyManagerException {
        Objects.requireNonNull(keyBytes, "keyBytes can't be null.");
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);
        Objects.requireNonNull(type, TYPE_CANT_BE_NULL);

        if (this.secureKeyDelegate != null) {
            keyBytes = this.secureKeyDelegate.encryptKey(keyBytes);
        }

        ContentValues values = new ContentValues();
        values.put(StoreSchema.Keys.COLUMN_NAME_NAME, name);
        values.put(StoreSchema.Keys.COLUMN_NAME_TYPE, type.getValue());
        values.put(StoreSchema.Keys.COLUMN_NAME_EXPORTABLE, isExportable ? 1 : 0);
        values.put(StoreSchema.Keys.COLUMN_NAME_DATA, keyBytes);

        SQLiteDatabase db = this.getWritableDatabase();

       try {
            db.insertOrThrow(StoreSchema.Keys.TABLE_NAME, null, values);
        } catch (SQLiteException e) {
            throw new StoreException("Failed to insert a key.", e);
        }
    }

    @Override
    public void updateKey(byte[] keyBytes, String name, KeyType type) {
        Objects.requireNonNull(keyBytes, "keyBytes can't be null.");
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);
        Objects.requireNonNull(type, TYPE_CANT_BE_NULL);

    }

    @Override
    public byte[] getKey(String name, KeyType type) throws KeyManagerException {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);
        Objects.requireNonNull(type, TYPE_CANT_BE_NULL);

        byte[] keyBytes = null;

        SQLiteDatabase db = this.getReadableDatabase();

        String[] columns = { StoreSchema.Keys.COLUMN_NAME_DATA };
        String selection = StoreSchema.Keys.COLUMN_NAME_NAME + " = ? AND " + StoreSchema.Keys.COLUMN_NAME_TYPE + " = ?";
        String[] selectionArgs = { name, String.valueOf(type.getValue())};

        try (Cursor cursor = db.query(
                StoreSchema.Keys.TABLE_NAME,
                columns,
                selection,
                selectionArgs,
                null,
                null,
                null)
        ) {
            if (cursor.moveToNext()) {
                keyBytes = cursor.getBlob(cursor.getColumnIndexOrThrow(StoreSchema.Keys.COLUMN_NAME_DATA));
            }
        } catch (Exception e) {
            throw new StoreException("Failed to retrieve the key.", e);
        }

        if (this.secureKeyDelegate != null && keyBytes != null) {
            keyBytes = this.secureKeyDelegate.decryptKey(keyBytes);
        }

        return keyBytes;
    }

    @Override
    public void deleteKey(String name, KeyType type) throws KeyManagerException {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);
        Objects.requireNonNull(type, TYPE_CANT_BE_NULL);

        SQLiteDatabase db = this.getWritableDatabase();

        String selection = StoreSchema.Keys.COLUMN_NAME_NAME + " = ? AND " + StoreSchema.Keys.COLUMN_NAME_TYPE + " = ?";
        String[] selectionArgs = { name, String.valueOf(type.getValue())};
        db.delete(StoreSchema.Keys.TABLE_NAME, selection, selectionArgs);
    }

    @Override
    public void reset() throws KeyManagerException {
        SQLiteDatabase db = this.getWritableDatabase();

        try {
            db.execSQL(SQL_DELETE_ALL);
        } catch (SQLException e) {
            throw new StoreException("Failed to reset the store.", e);
        }
    }

    @Override
    public boolean isExportable() {
        return true;
    }

    @Override
    public void setSecureKeyDelegate(SecureKeyDelegateInterface secureKeyDelegate) {
        this.secureKeyDelegate = secureKeyDelegate;
    }

    /**
     * Returns the names of the keys in this key store.
     *
     * @return set containing the key names.
     * @throws KeyManagerException if a failure occurred while fetching the key names.
     */
    @Override
    public Set<String> getKeyNames() throws KeyManagerException {
        SQLiteDatabase db = this.getReadableDatabase();

        String[] columns = { StoreSchema.Keys.COLUMN_NAME_NAME };
        Set<String> aliases = new HashSet<>();

        try (Cursor cursor = db.query(
            StoreSchema.Keys.TABLE_NAME,
            columns,
            null,
            null,
            null,
            null,
            null)
        ) {
            while (cursor.moveToNext()) {
                aliases.add(cursor.getString(0));
            }
        } catch (Exception e) {
            throw new StoreException("Failed to retrieve key aliases.", e);
        }
        return aliases;
    }
}
