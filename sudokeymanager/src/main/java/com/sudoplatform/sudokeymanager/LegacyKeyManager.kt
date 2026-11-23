/*
 * Copyright © 2026 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sudoplatform.sudokeymanager

/**
 * Access, by name, to keys stored with no namespace by key manager 9.x and earlier
 * (`createAndroidKeyManager()` with no arguments). It exists so apps can move those keys into a
 * namespaced key manager themselves: read each key, add it to the namespaced key manager, then
 * delete it here.
 *
 * Keys stored with no namespace share the database and the Android Keystore with every
 * namespace's keys, and a name alone doesn't show which key manager a key belongs to. So keys can
 * only be read and deleted by name; nothing lists, exports or removes them in bulk.
 *
 * Create one with [KeyManagerFactory.createLegacyKeyManager].
 */
interface LegacyKeyManager : AutoCloseable {
    /** Returns the password or other secure data stored as [name], or null if there is none. */
    @Throws(KeyManagerException::class)
    fun getPassword(name: String): ByteArray?

    /** Returns the raw bytes of the symmetric key stored as [name], or null if there is none. */
    @Throws(KeyManagerException::class)
    fun getSymmetricKeyData(name: String): ByteArray?

    /** Returns the private key of the key pair stored as [name], as PKCS#1 DER, or null if there is none. */
    @Throws(KeyManagerException::class)
    fun getPrivateKeyData(name: String): ByteArray?

    /** Returns the public key stored as [name], as PKCS#1 DER, or null if there is none. */
    @Throws(KeyManagerException::class)
    fun getPublicKeyData(name: String): ByteArray?

    /** Deletes the password stored as [name], if any. Other key types with the same name are kept. */
    @Throws(KeyManagerException::class)
    fun deletePassword(name: String)

    /** Deletes the symmetric key stored as [name], if any. Other key types with the same name are kept. */
    @Throws(KeyManagerException::class)
    fun deleteSymmetricKey(name: String)

    /** Deletes the key pair stored as [name], if any. Other key types with the same name are kept. */
    @Throws(KeyManagerException::class)
    fun deleteKeyPair(name: String)

    /** Deletes the public key stored as [name], if any. Other key types with the same name are kept. */
    @Throws(KeyManagerException::class)
    fun deletePublicKey(name: String)
}

/**
 * [LegacyKeyManager] over a key manager and store with no namespace.
 *
 * Deletes are limited to the key's type: a symmetric key and a private key of the same name share
 * one Android Keystore entry, so that entry is only deleted when no key of the other type uses it.
 */
internal class DefaultLegacyKeyManager(
    private val store: ExportableAndroidStore,
    private val keyManager: AndroidKeyManager,
) : LegacyKeyManager {
    override fun getPassword(name: String): ByteArray? = keyManager.getPassword(name)

    override fun getSymmetricKeyData(name: String): ByteArray? = keyManager.getSymmetricKeyData(name)

    override fun getPrivateKeyData(name: String): ByteArray? = keyManager.getPrivateKeyData(name)

    override fun getPublicKeyData(name: String): ByteArray? = keyManager.getPublicKeyData(name)

    override fun deletePassword(name: String) = store.deleteExportableCopy(name, KeyType.PASSWORD)

    override fun deletePublicKey(name: String) = store.deleteExportableCopy(name, KeyType.PUBLIC_KEY)

    override fun deleteSymmetricKey(name: String) {
        store.deleteExportableCopy(name, KeyType.SYMMETRIC_KEY)
        if (store.getKey(name, KeyType.PRIVATE_KEY) == null) store.deleteKeyStoreEntry(name)
    }

    override fun deleteKeyPair(name: String) {
        store.deleteExportableCopy(name, KeyType.PRIVATE_KEY)
        store.deleteExportableCopy(name, KeyType.PUBLIC_KEY)
        if (store.getKey(name, KeyType.SYMMETRIC_KEY) == null) store.deleteKeyStoreEntry(name)
    }

    override fun close() = keyManager.close()
}
