/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sudoplatform.sudokeymanager

/**
 * A set of methods required for creating and processing an encrypted archive
 * containing a set of cryptographic keys and passwords.
 */
interface SecureKeyArchiveInterface {
    /**
     * The namespaces of the keys loaded or unarchived into this archive, including namespaces whose
     * keys aren't imported. Keys with no `NameSpace` aren't counted.
     */
    val namespaces: Set<String>

    /**
     * Loads the key manager's keys into the archive, replacing any keys loaded or unarchived before.
     * Each key is written with the key manager's namespace as its `NameSpace`.
     *
     * @throws KeyManagerException if the keys could not be exported.
     * @throws StoreNotExportable if the key store does not permit keys to be exported.
     */
    @Throws(KeyManagerException::class)
    fun loadKeys()

    /**
     * Replaces the key manager's keys with the keys in this archive that are in its namespace. The
     * key manager's keys are removed only once the archive is known to hold keys for it.
     *
     * @throws SecureKeyArchiveException with one of the following reasons:
     * [SecureKeyArchiveException.ARCHIVE_EMPTY],
     * [SecureKeyArchiveException.FATAL_ERROR]
     */
    @Throws(SecureKeyArchiveException::class)
    fun saveKeys()

    /**
     * Archives and encrypts the keys loaded into this archive.
     *
     * @param password the password to use to encrypt the archive.
     * @return encrypted archive data.
     * @throws SecureKeyArchiveException with one of the following reasons:
     * [SecureKeyArchiveException.INVALID_PASSWORD],
     * [SecureKeyArchiveException.ARCHIVE_EMPTY],
     * [SecureKeyArchiveException.MALFORMED_ARCHIVEDATA]
     */
    @Throws(SecureKeyArchiveException::class)
    fun archive(password: String): ByteArray

    /**
     * Archives, in plaintext, the keys loaded into this archive.
     *
     * @return archive data.
     * @throws SecureKeyArchiveException with one of the following reasons:
     * [SecureKeyArchiveException.ARCHIVE_EMPTY],
     * [SecureKeyArchiveException.MALFORMED_ARCHIVEDATA]
     */
    @Throws(SecureKeyArchiveException::class)
    fun archive(): ByteArray

    /**
     * Decrypts and unarchives the keys in this archive. Only keys whose `NameSpace` is the key
     * manager's namespace are kept; keys with another `NameSpace`, an empty one or none are skipped.
     *
     * @param password the password to use to decrypt the archive.
     * @throws SecureKeyArchiveException with one of the following reasons:
     * [SecureKeyArchiveException.INVALID_PASSWORD],
     * [SecureKeyArchiveException.INVALID_ARCHIVE_DATA],
     * [SecureKeyArchiveException.MALFORMED_KEYSET_DATA],
     * [SecureKeyArchiveException.MALFORMED_ARCHIVEDATA],
     * [SecureKeyArchiveException.NO_KEYS_FOR_NAMESPACE],
     * [SecureKeyArchiveException.DUPLICATE_KEY]
     */
    @Throws(SecureKeyArchiveException::class)
    fun unarchive(password: String)

    /**
     * Unarchives plaintext keys in this archive. Only keys whose `NameSpace` is the key manager's
     * namespace are kept; keys with another `NameSpace`, an empty one or none are skipped.
     *
     * @throws SecureKeyArchiveException with one of the following reasons:
     * [SecureKeyArchiveException.INVALID_ARCHIVE_DATA],
     * [SecureKeyArchiveException.MALFORMED_KEYSET_DATA],
     * [SecureKeyArchiveException.NO_KEYS_FOR_NAMESPACE],
     * [SecureKeyArchiveException.DUPLICATE_KEY]
     */
    @Throws(SecureKeyArchiveException::class)
    fun unarchive()

    /**
     * Resets the archive by clearing loaded keys and archive data.
     */
    fun reset()

    /**
     * Determines whether or not the archive contains the key with the
     * specified name and type in the key manager's namespace. The archive
     * must be unarchived before the key can be searched.
     *
     * @param name the key name.
     * @param type the key type.
     * @return true if the specified key exists in the archive.
     */
    fun containsKey(
        name: String,
        type: KeyType,
    ): Boolean

    /**
     * Retrieves the specified key data from the archive. The archive must
     * be unarchived before the key data can be retrieved.
     *
     * @param name the key name.
     * @param type the key type.
     * @return a byte array containing the specified key data or null if it was not found.
     */
    fun getKeyData(
        name: String,
        type: KeyType,
    ): ByteArray?

    /**
     * Sets the Key manager used for managing keys and performing cryptographic operations.
     *
     * @param keyManager the Key manager used for managing keys and performing cryptographic operations.
     *
     * @return the Key manager used for managing keys and performing cryptographic operations.
     *
     */
    var keyManager: KeyManagerInterface

    /**
     * Sets the key names to exclude from the archive.
     *
     * @param excludedKeys the key names to exclude from the archive.
     *
     * @return the key names to exclude from the archive in an unmodifiable set.
     *
     */
    var excludedKeys: MutableSet<String>

    /**
     * Sets the key types to exclude from the archive.
     *
     * @param excludedKeyTypes the key names to exclude from the archive.
     */
    var excludedKeyTypes: MutableSet<KeyType>

    /**
     * @return the meta-information associated with this archive in an unmodifiable map.
     */
    fun getMetaInfo(): Map<String, String>?

    /**
     * Sets the meta-information associated with this archive.
     *
     * @param metaInfo the meta-information associated with this archive.
     */
    fun setMetaInfo(metaInfo: Map<String, String>)

    val version: Int

    val type: String?
}
