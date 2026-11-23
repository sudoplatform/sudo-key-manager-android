/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sudoplatform.sudokeymanager

import android.content.ContentValues
import android.content.Context
import android.database.SQLException
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteException
import android.database.sqlite.SQLiteOpenHelper
import java.util.Objects

/**
 * KeyManager store implementation using AndroidSQLiteStore.
 */
class AndroidSQLiteStore :
    SQLiteOpenHelper,
    StoreInterface {
    // Delegate for encrypting and decrypting keys.
    private var secureKeyDelegate: SecureKeyDelegateInterface? = null

    // Prefixed to every stored name as `<namespace>.`. Null only for the internal store with no
    // namespace that LegacyKeyManager reads from.
    private val namespace: String?

    override val keyNamespace: String
        get() = namespace ?: KeyNamespaces.NONE

    /**
     * Instantiates AndroidSQLiteStore.
     *
     * @param context Android app context.
     * @param keyNamespace key namespace to use to prevent name clashes when multiple consumers are
     * using the same underlying key store. Must not be empty.
     * @throws IllegalArgumentException if [keyNamespace] is empty.
     */
    constructor(context: Context?, keyNamespace: String) : this(context, keyNamespace, DEFAULT_DATABASE_NAME)

    /**
     * Instantiates AndroidSQLiteStore.
     *
     * @param context Android app context.
     * @param keyNamespace key namespace to use to prevent name clashes when multiple consumers are
     * using the same underlying key store. Must not be empty.
     * @param databaseName database name to use for the SQLite database based key store.
     * @throws IllegalArgumentException if [keyNamespace] is empty.
     */
    constructor(context: Context?, keyNamespace: String, databaseName: String?) : super(
        context,
        databaseName,
        null,
        DATABASE_VERSION,
    ) {
        namespace = KeyNamespaces.requireValid(keyNamespace)
    }

    /**
     * Instantiates AndroidSQLiteStore with no namespace over the default database, where key
     * manager 9.x and earlier kept keys created with no namespace. Its [reset] and [getKeyNames]
     * throw [UnsupportedOperationException].
     */
    internal constructor(
        context: Context?,
        @Suppress("UNUSED_PARAMETER") noNamespace: NoNamespace,
    ) : super(
        context,
        DEFAULT_DATABASE_NAME,
        null,
        DATABASE_VERSION,
    ) {
        namespace = null
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(StoreSchema.Keys.CREATE_TABLE)
    }

    override fun onUpgrade(
        db: SQLiteDatabase,
        oldVersion: Int,
        newVersion: Int,
    ) {
        db.execSQL(SQL_DROP_TABLE)
        onCreate(db)
    }

    override fun onDowngrade(
        db: SQLiteDatabase,
        oldVersion: Int,
        newVersion: Int,
    ) {
        onUpgrade(db, oldVersion, newVersion)
    }

    @Throws(KeyManagerException::class)
    override fun insertKey(
        keyBytes: ByteArray,
        name: String,
        type: KeyType,
        isExportable: Boolean,
    ) {
        var keyBytes = keyBytes
        Objects.requireNonNull(keyBytes, "keyBytes can't be null.")
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        Objects.requireNonNull(type, TYPE_CANT_BE_NULL)
        if (secureKeyDelegate != null) {
            keyBytes = secureKeyDelegate!!.encryptKey(keyBytes)
        }
        val values = ContentValues()
        values.put(StoreSchema.Keys.COLUMN_NAME_NAME, toNamespacedName(name))
        values.put(StoreSchema.Keys.COLUMN_NAME_TYPE, type.value)
        values.put(StoreSchema.Keys.COLUMN_NAME_EXPORTABLE, if (isExportable) 1 else 0)
        values.put(StoreSchema.Keys.COLUMN_NAME_DATA, keyBytes)
        val db = this.writableDatabase
        try {
            db.insertOrThrow(StoreSchema.Keys.TABLE_NAME, null, values)
        } catch (e: SQLiteException) {
            throw StoreException("Failed to insert a key.", e)
        }
    }

    override fun updateKey(
        keyBytes: ByteArray,
        name: String,
        type: KeyType,
    ) {
        Objects.requireNonNull(keyBytes, "keyBytes can't be null.")
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        Objects.requireNonNull(type, TYPE_CANT_BE_NULL)
    }

    @Throws(KeyManagerException::class)
    override fun getKey(
        name: String,
        type: KeyType,
    ): ByteArray? {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        Objects.requireNonNull(type, TYPE_CANT_BE_NULL)
        var keyBytes: ByteArray? = null
        val db = this.readableDatabase
        val columns = arrayOf(StoreSchema.Keys.COLUMN_NAME_DATA)
        val selection =
            StoreSchema.Keys.COLUMN_NAME_NAME + " = ? AND " + StoreSchema.Keys.COLUMN_NAME_TYPE + " = ?"
        val selectionArgs = arrayOf(toNamespacedName(name), type.value.toString())
        try {
            db
                .query(
                    StoreSchema.Keys.TABLE_NAME,
                    columns,
                    selection,
                    selectionArgs,
                    null,
                    null,
                    null,
                ).use { cursor ->
                    if (cursor.moveToNext()) {
                        keyBytes =
                            cursor.getBlob(cursor.getColumnIndexOrThrow(StoreSchema.Keys.COLUMN_NAME_DATA))
                    }
                }
        } catch (e: Exception) {
            throw StoreException("Failed to retrieve the key.", e)
        }
        if (secureKeyDelegate != null && keyBytes != null) {
            keyBytes = secureKeyDelegate!!.decryptKey(keyBytes!!)
        }
        return keyBytes
    }

    @Throws(KeyManagerException::class)
    override fun deleteKey(
        name: String,
        type: KeyType,
    ) {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        Objects.requireNonNull(type, TYPE_CANT_BE_NULL)
        val db = this.writableDatabase
        val selection =
            StoreSchema.Keys.COLUMN_NAME_NAME + " = ? AND " + StoreSchema.Keys.COLUMN_NAME_TYPE + " = ?"
        val selectionArgs = arrayOf(toNamespacedName(name), type.value.toString())
        db.delete(StoreSchema.Keys.TABLE_NAME, selection, selectionArgs)
    }

    @Throws(KeyManagerException::class)
    override fun reset() {
        val namespace = namespace ?: throw KeyNamespaces.unsupportedWithoutNamespace("reset")
        val db = this.writableDatabase
        try {
            db.delete(StoreSchema.Keys.TABLE_NAME, NAMESPACE_SELECTION, namespaceSelectionArgs(namespace))
        } catch (e: SQLException) {
            throw StoreException("Failed to reset the store.", e)
        }
    }

    override fun isExportable(): Boolean = true

    override fun setSecureKeyDelegate(secureKeyDelegate: SecureKeyDelegateInterface) {
        this.secureKeyDelegate = secureKeyDelegate
    }

    /**
     * Returns the names of the keys in this store's namespace, without the namespace prefix.
     *
     * @return set containing the key names.
     * @throws KeyManagerException if a failure occurred while fetching the key names.
     */
    @Throws(KeyManagerException::class)
    override fun getKeyNames(): Set<String> {
        val namespace = namespace ?: throw KeyNamespaces.unsupportedWithoutNamespace("getKeyNames")
        val db = this.readableDatabase
        val columns = arrayOf(StoreSchema.Keys.COLUMN_NAME_NAME)
        val names: MutableSet<String> = HashSet()
        try {
            db
                .query(
                    StoreSchema.Keys.TABLE_NAME,
                    columns,
                    NAMESPACE_SELECTION,
                    namespaceSelectionArgs(namespace),
                    null,
                    null,
                    null,
                ).use { cursor ->
                    while (cursor.moveToNext()) {
                        names.add(cursor.getString(0).substring(namespace.length + 1))
                    }
                }
        } catch (e: Exception) {
            throw StoreException("Failed to retrieve key aliases.", e)
        }
        return names
    }

    private fun toNamespacedName(name: String): String = if (namespace != null) "$namespace.$name" else name

    companion object {
        // Database name,
        const val DEFAULT_DATABASE_NAME = "keys.db"

        // Database version.
        private const val DATABASE_VERSION = 1

        // SQL statements for various operations we need to execute.
        private const val SQL_DROP_TABLE = "DROP TABLE IF EXISTS " + StoreSchema.Keys.TABLE_NAME

        /**
         * Selects the names that start with `<namespace>.`, exactly and case-sensitively: under the
         * column's BINARY collation, those are the names from `<namespace>.` up to, but not
         * including, `<namespace>/` (`/` is the character after `.`).
         */
        private val NAMESPACE_SELECTION =
            "${StoreSchema.Keys.COLUMN_NAME_NAME} >= ? AND ${StoreSchema.Keys.COLUMN_NAME_NAME} < ?"

        private fun namespaceSelectionArgs(namespace: String) = arrayOf("$namespace.", "$namespace/")

        private const val NAME_CANT_BE_NULL = "name can't be null."
        private const val TYPE_CANT_BE_NULL = "type can't be null."
    }
}
