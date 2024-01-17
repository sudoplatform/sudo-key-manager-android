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
class AndroidSQLiteStore : SQLiteOpenHelper, StoreInterface {
    // Delegate for encrypting and decrypting keys.
    private var secureKeyDelegate: SecureKeyDelegateInterface? = null

    // Key namespace used to prevent name clashes between keys used by multiple consumers of the
    // underlying key store such as Android Keystore.
    private var keyNamespace: String? = null

    /**
     * Instantiates AndroidSQLiteStore.
     *
     * @param context Android app context.
     */
    constructor(context: Context?) : super(context, DEFAULT_DATABASE_NAME, null, DATABASE_VERSION)

    /**
     * Instantiates AndroidSQLiteStore.
     *
     * @param context Android app context.
     * @param keyNamespace key namespace to use to prevent name clashes when multiple consumers are
     * using the same underlying key store.
     */
    constructor(context: Context?, keyNamespace: String?) : super(
        context,
        DEFAULT_DATABASE_NAME,
        null,
        DATABASE_VERSION
    ) {
        this.keyNamespace = keyNamespace
    }

    /**
     * Instantiates AndroidSQLiteStore.
     *
     * @param context Android app context.
     * @param keyNamespace key namespace to use to prevent name clashes when multiple consumers are
     * using the same underlying key store.
     * @param databaseName database name to use for the SQLite database based key store.
     */
    constructor(context: Context?, keyNamespace: String?, databaseName: String?) : super(
        context,
        databaseName,
        null,
        DATABASE_VERSION
    ) {
        this.keyNamespace = keyNamespace
    }

    /**
     * Instantiates AndroidSQLiteStore.
     *
     * @param context Android app context.
     */
    constructor(context: Context?, secureKeyDelegate: SecureKeyDelegateInterface?) : super(
        context,
        DEFAULT_DATABASE_NAME,
        null,
        DATABASE_VERSION
    ) {
        this.secureKeyDelegate = secureKeyDelegate
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(StoreSchema.Keys.CREATE_TABLE)
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        db.execSQL(SQL_DROP_TABLE)
        onCreate(db)
    }

    override fun onDowngrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        onUpgrade(db, oldVersion, newVersion)
    }

    @Throws(KeyManagerException::class)
    override fun insertKey(
        keyBytes: ByteArray,
        name: String,
        type: KeyType,
        isExportable: Boolean
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

    override fun updateKey(keyBytes: ByteArray, name: String, type: KeyType) {
        Objects.requireNonNull(keyBytes, "keyBytes can't be null.")
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        Objects.requireNonNull(type, TYPE_CANT_BE_NULL)
    }

    @Throws(KeyManagerException::class)
    override fun getKey(name: String, type: KeyType): ByteArray? {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        Objects.requireNonNull(type, TYPE_CANT_BE_NULL)
        var keyBytes: ByteArray? = null
        val db = this.readableDatabase
        val columns = arrayOf(StoreSchema.Keys.COLUMN_NAME_DATA)
        val selection =
            StoreSchema.Keys.COLUMN_NAME_NAME + " = ? AND " + StoreSchema.Keys.COLUMN_NAME_TYPE + " = ?"
        val selectionArgs = arrayOf(toNamespacedName(name), type.value.toString())
        try {
            db.query(
                StoreSchema.Keys.TABLE_NAME,
                columns,
                selection,
                selectionArgs,
                null,
                null,
                null
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
    override fun deleteKey(name: String, type: KeyType) {
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
        val db = this.writableDatabase
        try {
            if (keyNamespace != null) {
                db.delete(
                    StoreSchema.Keys.TABLE_NAME,
                    StoreSchema.Keys.COLUMN_NAME_NAME + " LIKE ?",
                    arrayOf(
                        keyNamespace + ".%"
                    )
                )
            } else {
                db.execSQL(SQL_DELETE_ALL)
            }
        } catch (e: SQLException) {
            throw StoreException("Failed to reset the store.", e)
        }
    }

    override fun isExportable(): Boolean {
        return true
    }

    override fun setSecureKeyDelegate(secureKeyDelegate: SecureKeyDelegateInterface) {
        this.secureKeyDelegate = secureKeyDelegate
    }

    /**
     * Returns the names of the keys in this key store.
     *
     * @return set containing the key names.
     * @throws KeyManagerException if a failure occurred while fetching the key names.
     */
    @Throws(KeyManagerException::class)
    override fun getKeyNames(): Set<String> {
        val db = this.readableDatabase
        val columns = arrayOf(StoreSchema.Keys.COLUMN_NAME_NAME)
        val aliases: MutableSet<String> = HashSet()
        if (keyNamespace != null) {
            try {
                db.query(
                    StoreSchema.Keys.TABLE_NAME,
                    columns,
                    StoreSchema.Keys.COLUMN_NAME_NAME + " LIKE ?", arrayOf(keyNamespace + ".%"),
                    null,
                    null,
                    null
                ).use { cursor ->
                    while (cursor.moveToNext()) {
                        aliases.add(cursor.getString(0).substring((keyNamespace + ".").length))
                    }
                }
            } catch (e: Exception) {
                throw StoreException("Failed to retrieve key aliases.", e)
            }
        } else {
            try {
                db.query(
                    StoreSchema.Keys.TABLE_NAME,
                    columns,
                    null,
                    null,
                    null,
                    null,
                    null
                ).use { cursor ->
                    while (cursor.moveToNext()) {
                        aliases.add(cursor.getString(0))
                    }
                }
            } catch (e: Exception) {
                throw StoreException("Failed to retrieve key aliases.", e)
            }
        }
        return aliases
    }

    private fun toNamespacedName(name: String): String {
        return if (keyNamespace != null) "$keyNamespace.$name" else name
    }

    companion object {
        // Database name,
        const val DEFAULT_DATABASE_NAME = "keys.db"

        // Database version.
        private const val DATABASE_VERSION = 1

        // SQL statements for various operations we need to execute.
        private const val SQL_DROP_TABLE = "DROP TABLE IF EXISTS " + StoreSchema.Keys.TABLE_NAME
        private const val SQL_DELETE_ALL = "DELETE FROM " + StoreSchema.Keys.TABLE_NAME
        private const val NAME_CANT_BE_NULL = "name can't be null."
        private const val TYPE_CANT_BE_NULL = "type can't be null."
    }
}
