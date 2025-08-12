/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sudoplatform.sudokeymanager

/**
 * Defines a set of interface for persistent storage and lifecycle management of crytographic keys and
 * secure data.
 */
interface StoreInterface : AutoCloseable {
    /**
     * Inserts a new key.
     *
     * @param keyBytes raw key bytes.
     * @param name key name.
     * @param type key type. See [com.sudoplatform.sudokeymanager.KeyType].
     * @param isExportable true if the key should be exportable.
     * @throws KeyManagerException
     */
    @Throws(KeyManagerException::class)
    fun insertKey(
        keyBytes: ByteArray,
        name: String,
        type: KeyType,
        isExportable: Boolean,
    )

    /**
     * Updates an existing key.
     *
     * @param keyBytes raw key bytes.
     * @param name key name.
     * @param type key type. See [com.sudoplatform.sudokeymanager.KeyType].
     */
    fun updateKey(
        keyBytes: ByteArray,
        name: String,
        type: KeyType,
    )

    /**
     * Retrieves the specified key.
     *
     * @param name key name.
     * @param type key type. See [com.sudoplatform.sudokeymanager.KeyType].
     * @return raw key bytes of the specified key. null if the key is not found.
     * @throws KeyManagerException
     */
    @Throws(KeyManagerException::class)
    fun getKey(
        name: String,
        type: KeyType,
    ): ByteArray?

    /**
     * Deletes the specified key.
     *
     * @param name key name.
     * @param type key type. See [com.sudoplatform.sudokeymanager.KeyType].
     * @throws KeyManagerException
     */
    @Throws(KeyManagerException::class)
    fun deleteKey(
        name: String,
        type: KeyType,
    )

    /**
     * Resets the store by removing all keys.
     *
     * @throws KeyManagerException
     */
    @Throws(KeyManagerException::class)
    fun reset()

    /**
     * Closes the store and frees up any system resource associated with the store.
     *
     * @throws Exception if closing failed
     */
    @Throws(Exception::class)
    override fun close()

    /**
     * Determines whether or not the store supports exporting keys.
     *
     * @return true if the store supports exporting keys.
     */
    fun isExportable(): Boolean

    /**
     * Sets a delegate for encrypting/decrypting the keys stored.
     *
     * @param secureKeyDelegate delegate for securing the keys.
     */
    fun setSecureKeyDelegate(secureKeyDelegate: SecureKeyDelegateInterface)

    /**
     * Returns the names of the keys in this key store.
     *
     * @return set containing the key names.
     * @throws KeyManagerException if a failure occurred while fetching the key names.
     */
    @Throws(KeyManagerException::class)
    fun getKeyNames(): Set<String>
}
