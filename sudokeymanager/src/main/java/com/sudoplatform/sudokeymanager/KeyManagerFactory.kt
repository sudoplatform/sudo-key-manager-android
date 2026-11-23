/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sudoplatform.sudokeymanager

import android.content.Context

class KeyManagerFactory(
    private val context: Context,
) {
    /**
     * Creates a `KeyManager` instance that's backed by Android Keystore and using the specified
     * the namespace.
     *
     * @param keyNamespace key namespace to use to prevent name clashes when multiple consumers are
     *                     using the same underlying key store. Must not be empty.
     * @throws IllegalArgumentException if [keyNamespace] is empty.
     */
    @Throws(KeyManagerException::class)
    fun createAndroidKeyManager(keyNamespace: String): KeyManagerInterface {
        val storeInterface =
            ExportableAndroidStore(
                context,
                KeyManager.SYMMETRIC_KEY_ALGORITHM_AES,
                KeyNamespaces.requireValid(keyNamespace),
            )
        val androidKeyStore = storeInterface.androidKeyStore
        return AndroidKeyManager(storeInterface, androidKeyStore, keyNamespace)
    }

    /**
     * Creates a `KeyManager` instance that's backed by Android Keystore and using the specified
     * the namespace and database name for exportable key store.
     *
     * @param keyNamespace key namespace to use to prevent name clashes when multiple consumers are
     *                     using the same underlying key store. Must not be empty.
     * @param databaseName database name to use for the SQLite database based key store.
     * @throws IllegalArgumentException if [keyNamespace] is empty.
     */
    @Throws(KeyManagerException::class)
    fun createAndroidKeyManager(
        keyNamespace: String,
        databaseName: String,
    ): KeyManagerInterface {
        val storeInterface =
            ExportableAndroidStore(
                context,
                KeyManager.SYMMETRIC_KEY_ALGORITHM_AES,
                KeyNamespaces.requireValid(keyNamespace),
                databaseName,
            )
        val androidKeyStore = storeInterface.androidKeyStore
        return AndroidKeyManager(storeInterface, androidKeyStore, keyNamespace)
    }

    /**
     * Creates a [LegacyKeyManager] for the keys key manager 9.x and earlier stored with no
     * namespace (by `createAndroidKeyManager()` with no arguments). Use it to move those keys into a
     * namespaced key manager: read each key by name, add it there, then delete it here.
     */
    @Throws(KeyManagerException::class)
    fun createLegacyKeyManager(): LegacyKeyManager {
        val store = ExportableAndroidStore(context, KeyManager.SYMMETRIC_KEY_ALGORITHM_AES, NoNamespace)
        return DefaultLegacyKeyManager(store, AndroidKeyManager(store, store.androidKeyStore, NoNamespace))
    }
}
