/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sudoplatform.sudokeymanager

import android.content.Context
import android.security.keystore.KeyProperties
import android.security.keystore.KeyProtection
import java.io.IOException
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.cert.CertificateException
import java.util.Objects
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * Exportable Android keystore. Android Keystore does not allow the keys to be exported once they
 * are generated or imported. The purpose for this class is to provide a way to maintain copies of
 * keys that are exportable while still leveraging the security benefits of using Android Keystore.
 */
class ExportableAndroidStore : StoreInterface {
    // Exportable store to store the copies of keys that can be exported.
    private val exportableStore: StoreInterface

    // Android Keystore. This is where crypto will be done so keys are not leaked into user space.
    val androidKeyStore: KeyStore

    // Android Keystore requires the keys to be stored with metadata indicating what their purposes
    // are so we will need to let consumer of this store specify the intent and store them for
    // future use.
    private val symmetricKeyAlgorithm: String

    // Prefixed to every alias as `<namespace>.`. Null only for the internal store with no namespace
    // that LegacyKeyManager reads from.
    private val namespace: String?

    override val keyNamespace: String
        get() = namespace ?: KeyNamespaces.NONE

    /**
     * Instantiates a ExportableAndroidStore.
     *
     * @param context Android app context.
     * @param symmetricKeyAlgorithm symmetric key algorithm.
     * @param keyNamespace key namespace to use to prevent name clashes when multiple consumers are
     * using the same underlying key store. Must not be empty.
     * @throws KeyManagerException
     * @throws IllegalArgumentException if [keyNamespace] is empty.
     */
    constructor(
        context: Context,
        symmetricKeyAlgorithm: String,
        keyNamespace: String,
    ) : this(context, symmetricKeyAlgorithm, keyNamespace, AndroidSQLiteStore.DEFAULT_DATABASE_NAME)

    /**
     * Instantiates a ExportableAndroidStore.
     *
     * @param context Android app context.
     * @param symmetricKeyAlgorithm symmetric key algorithm.
     * @param keyNamespace key namespace to use to prevent name clashes when multiple consumers are
     * using the same underlying key store. Must not be empty.
     * @param databaseName database name to use for the SQLite database based key store.
     * @throws KeyManagerException
     * @throws IllegalArgumentException if [keyNamespace] is empty.
     */
    constructor(
        context: Context,
        symmetricKeyAlgorithm: String,
        keyNamespace: String,
        databaseName: String?,
    ) : this(
        symmetricKeyAlgorithm,
        KeyNamespaces.requireValid(keyNamespace),
        AndroidSQLiteStore(context, keyNamespace, databaseName),
    )

    /**
     * Instantiates a ExportableAndroidStore with no namespace over the default database, where key
     * manager 9.x and earlier kept keys created with no namespace. Its [reset] and [getKeyNames]
     * throw [UnsupportedOperationException].
     */
    internal constructor(
        context: Context,
        symmetricKeyAlgorithm: String,
        noNamespace: NoNamespace,
    ) : this(symmetricKeyAlgorithm, null, AndroidSQLiteStore(context, noNamespace))

    private constructor(
        symmetricKeyAlgorithm: String,
        namespace: String?,
        exportableStore: StoreInterface,
    ) {
        Objects.requireNonNull(symmetricKeyAlgorithm, "symmetricKeyAlgorithm can't be null.")
        this.symmetricKeyAlgorithm = symmetricKeyAlgorithm
        this.namespace = namespace
        this.exportableStore = exportableStore
        try {
            androidKeyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
            androidKeyStore.load(null)
        } catch (e: KeyStoreException) {
            throw KeyManagerException(KEY_STORE_LOAD_ERROR_MSG, e)
        } catch (e: CertificateException) {
            throw KeyManagerException(KEY_STORE_LOAD_ERROR_MSG, e)
        } catch (e: NoSuchAlgorithmException) {
            throw KeyManagerException(KEY_STORE_LOAD_ERROR_MSG, e)
        } catch (e: IOException) {
            throw KeyManagerException(KEY_STORE_LOAD_ERROR_MSG, e)
        }
    }

    @Throws(KeyManagerException::class)
    override fun insertKey(
        keyBytes: ByteArray,
        name: String,
        type: KeyType,
        isExportable: Boolean,
    ) {
        Objects.requireNonNull(keyBytes, "keyBytes can't be null.")
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        Objects.requireNonNull(type, TYPE_CANT_BE_NULL)
        exportableStore.insertKey(keyBytes, name, type, isExportable)
        when (type) {
            KeyType.PRIVATE_KEY, KeyType.KEY_PAIR -> {}
            KeyType.PUBLIC_KEY -> {}
            KeyType.SYMMETRIC_KEY -> {
                val secretKey: SecretKey =
                    SecretKeySpec(keyBytes, 0, keyBytes.size, symmetricKeyAlgorithm)
                val builder =
                    KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                builder.setRandomizedEncryptionRequired(false)
                if (symmetricKeyAlgorithm == KeyManager.SYMMETRIC_KEY_ALGORITHM_AES) {
                    builder.setBlockModes(
                        KeyProperties.BLOCK_MODE_CBC,
                        KeyProperties.BLOCK_MODE_GCM,
                    )
                    builder.setEncryptionPaddings(
                        KeyProperties.ENCRYPTION_PADDING_PKCS7,
                        KeyProperties.ENCRYPTION_PADDING_NONE,
                    )
                }
                try {
                    androidKeyStore.setEntry(
                        toNamespacedName(name),
                        KeyStore.SecretKeyEntry(secretKey),
                        builder.build(),
                    )
                } catch (e: KeyStoreException) {
                    throw KeyManagerException(SYMMETRIC_KEY_ADDITION_ERROR_MSG, e)
                }
            }

            KeyType.PASSWORD -> {}
        }
    }

    override fun updateKey(
        keyBytes: ByteArray,
        name: String,
        type: KeyType,
    ) {
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
        return exportableStore.getKey(name, type)
    }

    @Throws(KeyManagerException::class)
    override fun deleteKey(
        name: String,
        type: KeyType,
    ) {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        Objects.requireNonNull(type, TYPE_CANT_BE_NULL)
        exportableStore.deleteKey(name, type)
        deleteKeyStoreEntry(name)
    }

    /** Deletes the exportable copy of a key only, leaving any Android Keystore entry of that name. */
    @Throws(KeyManagerException::class)
    internal fun deleteExportableCopy(
        name: String,
        type: KeyType,
    ) = exportableStore.deleteKey(name, type)

    /** Deletes the Android Keystore entry of [name], which holds a symmetric key or a private key. */
    @Throws(KeyManagerException::class)
    internal fun deleteKeyStoreEntry(name: String) {
        try {
            androidKeyStore.deleteEntry(toNamespacedName(name))
        } catch (e: KeyStoreException) {
            throw KeyManagerException(KEY_DELETION_ERROR_MSG, e)
        }
    }

    @Throws(KeyManagerException::class)
    override fun reset() {
        val prefix = namespacePrefix("reset")
        exportableStore.reset()
        try {
            val aliases = androidKeyStore.aliases()
            while (aliases.hasMoreElements()) {
                val alias = aliases.nextElement()
                if (alias.startsWith(prefix)) {
                    androidKeyStore.deleteEntry(alias)
                }
            }
        } catch (e: KeyStoreException) {
            throw KeyManagerException(KEY_STORE_RESET_ERROR_MSG, e)
        }
    }

    override fun isExportable(): Boolean = true

    @Throws(Exception::class)
    override fun close() {
        exportableStore.close()
    }

    override fun setSecureKeyDelegate(secureKeyDelegate: SecureKeyDelegateInterface) {
        exportableStore.setSecureKeyDelegate(secureKeyDelegate)
    }

    /**
     * Returns the names of the keys in this store's namespace, without the namespace prefix. The
     * namespace's master key isn't included.
     *
     * @return set containing the key names.
     * @throws KeyManagerException if a failure occurred while fetching the key names.
     */
    @Throws(KeyManagerException::class)
    override fun getKeyNames(): Set<String> {
        val prefix = namespacePrefix("getKeyNames")
        val names: MutableSet<String> = HashSet(exportableStore.getKeyNames())
        try {
            val aliases = androidKeyStore.aliases()
            while (aliases.hasMoreElements()) {
                val alias = aliases.nextElement()
                if (alias.length > prefix.length && alias.startsWith(prefix)) {
                    names.add(alias.substring(prefix.length))
                }
            }
        } catch (e: KeyStoreException) {
            throw KeyManagerException(KEY_STORE_QUERY_ERROR_MSG, e)
        }
        names.remove(AndroidKeyManager.MASTER_KEY_NAME)
        return names
    }

    private fun namespacePrefix(operation: String): String = "${namespace ?: throw KeyNamespaces.unsupportedWithoutNamespace(operation)}."

    private fun toNamespacedName(name: String): String = if (namespace != null) "$namespace.$name" else name

    companion object {
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val NAME_CANT_BE_NULL = "name can't be null."
        private const val TYPE_CANT_BE_NULL = "type can't be null."

        /** Exception messages */
        private const val KEY_STORE_LOAD_ERROR_MSG = "Failed to load Android Keystore."
        private const val SYMMETRIC_KEY_ADDITION_ERROR_MSG = "Failed to add a symmetric key to the store."
        private const val KEY_DELETION_ERROR_MSG = "Failed to delete a key."
        private const val KEY_STORE_RESET_ERROR_MSG = "Failed to reset Android keystore."
        private const val KEY_STORE_QUERY_ERROR_MSG = "Failed to query Android keystore for key aliases."
    }
}
