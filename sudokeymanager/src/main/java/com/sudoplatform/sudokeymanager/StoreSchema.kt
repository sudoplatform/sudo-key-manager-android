/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sudoplatform.sudokeymanager

/**
 * Key store schema common to all key store implementations.
 */
class StoreSchema private constructor() {
    object Keys {
        // Table name.
        const val TABLE_NAME = "KEYS"

        // Columns.
        const val COLUMN_NAME_NAME = "NAME"
        const val COLUMN_NAME_TYPE = "TYPE"
        const val COLUMN_NAME_EXPORTABLE = "EXPORTABLE"
        const val COLUMN_NAME_DATA = "DATA"

        // Create table.
        const val CREATE_TABLE = (
            "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " (" +
                COLUMN_NAME_NAME + " TEXT NOT NULL," +
                COLUMN_NAME_TYPE + " INT NOT NULL," +
                COLUMN_NAME_EXPORTABLE + " INT NOT NULL," +
                COLUMN_NAME_DATA + " BLOB NOT NULL," +
                "PRIMARY KEY (NAME, TYPE)" +
                ");"
        )
    }
}
