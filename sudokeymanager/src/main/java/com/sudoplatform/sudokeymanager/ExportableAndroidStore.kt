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

    /**
     * Returns Android Keystore associated with this store.
     *
     * @return Android Keystore.
     */
    // Android Keystore. This is where crypto will be done so keys are not leaked into user space.
    val androidKeyStore: KeyStore

    // Android Keystore requires the keys to be stored with metadata indicating what their purposes
    // are so we will need to let consumer of this store specify the intent and store them for
    // future use.
    private val symmetricKeyAlgorithm: String

    // Key namespace used to prevent name clashes between keys used by multiple consumers of the
    // underlying key store such as Android Keystore.
    private var keyNamespace: String? = null

    /**
     * Instantiates a ExportableAndroidStore.
     *
     * @param context Android app context.
     * @param symmetricKeyAlgorithm symmetric key algorithm.
     * @throws KeyManagerException
     */
    constructor(
        context: Context,
        symmetricKeyAlgorithm: String
    ) {
        Objects.requireNonNull(context, "context can't be null.")
        Objects.requireNonNull(symmetricKeyAlgorithm, "symmetricKeyAlgorithm can't be null.")
        this.symmetricKeyAlgorithm = symmetricKeyAlgorithm
        exportableStore = AndroidSQLiteStore(context)
        try {
            androidKeyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
            androidKeyStore?.load(null)
        } catch (e: KeyStoreException) {
            throw KeyManagerException("Failed to load Android Keystore.", e)
        } catch (e: CertificateException) {
            throw KeyManagerException("Failed to load Android Keystore.", e)
        } catch (e: NoSuchAlgorithmException) {
            throw KeyManagerException("Failed to load Android Keystore.", e)
        } catch (e: IOException) {
            throw KeyManagerException("Failed to load Android Keystore.", e)
        }
    }

    /**
     * Instantiates a ExportableAndroidStore.
     *
     * @param context Android app context.
     * @param symmetricKeyAlgorithm symmetric key algorithm.
     * @param keyNamespace key namespace to use to prevent name clashes when multiple consumers are
     * using the same underlying key store.
     * @throws KeyManagerException
     */
    constructor(
        context: Context,
        symmetricKeyAlgorithm: String,
        keyNamespace: String?
    ) {
        Objects.requireNonNull(context, "context can't be null.")
        Objects.requireNonNull(symmetricKeyAlgorithm, "symmetricKeyAlgorithm can't be null.")
        this.symmetricKeyAlgorithm = symmetricKeyAlgorithm
        exportableStore = AndroidSQLiteStore(context, keyNamespace)
        this.keyNamespace = keyNamespace
        try {
            androidKeyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
            androidKeyStore?.load(null)
        } catch (e: KeyStoreException) {
            throw KeyManagerException("Failed to load Android Keystore.", e)
        } catch (e: CertificateException) {
            throw KeyManagerException("Failed to load Android Keystore.", e)
        } catch (e: NoSuchAlgorithmException) {
            throw KeyManagerException("Failed to load Android Keystore.", e)
        } catch (e: IOException) {
            throw KeyManagerException("Failed to load Android Keystore.", e)
        }
    }

    /**
     * Instantiates a ExportableAndroidStore.
     *
     * @param context Android app context.
     * @param symmetricKeyAlgorithm symmetric key algorithm.
     * @param keyNamespace key namespace to use to prevent name clashes when multiple consumers are
     * using the same underlying key store.
     * @param databaseName database name to use for the SQLite database based key store.
     * @throws KeyManagerException
     */
    constructor(
        context: Context,
        symmetricKeyAlgorithm: String,
        keyNamespace: String?,
        databaseName: String?
    ) {
        Objects.requireNonNull(context, "context can't be null.")
        Objects.requireNonNull(symmetricKeyAlgorithm, "symmetricKeyAlgorithm can't be null.")
        this.symmetricKeyAlgorithm = symmetricKeyAlgorithm
        exportableStore = AndroidSQLiteStore(context, keyNamespace, databaseName)
        this.keyNamespace = keyNamespace
        try {
            androidKeyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
            androidKeyStore?.load(null)
        } catch (e: KeyStoreException) {
            throw KeyManagerException("Failed to load Android Keystore.", e)
        } catch (e: CertificateException) {
            throw KeyManagerException("Failed to load Android Keystore.", e)
        } catch (e: NoSuchAlgorithmException) {
            throw KeyManagerException("Failed to load Android Keystore.", e)
        } catch (e: IOException) {
            throw KeyManagerException("Failed to load Android Keystore.", e)
        }
    }

    @Throws(KeyManagerException::class)
    override fun insertKey(
        keyBytes: ByteArray,
        name: String,
        type: KeyType,
        isExportable: Boolean
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
                        KeyProperties.BLOCK_MODE_GCM
                    )
                    builder.setEncryptionPaddings(
                        KeyProperties.ENCRYPTION_PADDING_PKCS7,
                        KeyProperties.ENCRYPTION_PADDING_NONE
                    )
                }
                try {
                    androidKeyStore.setEntry(
                        toNamespacedName(name),
                        KeyStore.SecretKeyEntry(secretKey),
                        builder.build()
                    )
                } catch (e: KeyStoreException) {
                    throw KeyManagerException("Failed to add a symmetric key to the store.", e)
                }
            }

            KeyType.PASSWORD -> {}
        }
    }

    override fun updateKey(keyBytes: ByteArray, name: String, type: KeyType) {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        Objects.requireNonNull(type, TYPE_CANT_BE_NULL)
    }

    @Throws(KeyManagerException::class)
    override fun getKey(name: String, type: KeyType): ByteArray? {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        Objects.requireNonNull(type, TYPE_CANT_BE_NULL)
        return exportableStore.getKey(name, type)
    }

    @Throws(KeyManagerException::class)
    override fun deleteKey(name: String, type: KeyType) {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        Objects.requireNonNull(type, TYPE_CANT_BE_NULL)
        exportableStore.deleteKey(name, type)
        try {
            androidKeyStore.deleteEntry(toNamespacedName(name))
        } catch (e: KeyStoreException) {
            throw KeyManagerException("Failed to delete a key.", e)
        }
    }

    @Throws(KeyManagerException::class)
    override fun reset() {
        exportableStore.reset()
        try {
            val aliases = androidKeyStore.aliases()
            while (aliases.hasMoreElements()) {
                val alias = aliases.nextElement()
                if (keyNamespace != null) {
                    if (alias.startsWith(keyNamespace + ".")) {
                        androidKeyStore.deleteEntry(alias)
                    }
                } else {
                    androidKeyStore.deleteEntry(alias)
                }
            }
        } catch (e: KeyStoreException) {
            throw KeyManagerException("Failed to reset Android keystore.", e)
        }
    }

    override fun isExportable(): Boolean {
        return true
    }

    @Throws(Exception::class)
    override fun close() {
        exportableStore.close()
    }

    override fun setSecureKeyDelegate(secureKeyDelegate: SecureKeyDelegateInterface) {
        exportableStore.setSecureKeyDelegate(secureKeyDelegate)
    }

    /**
     * Returns the names of the keys in this key store.
     *
     * @return set containing the key names.
     * @throws KeyManagerException if a failure occurred while fetching the key names.
     */
    @Throws(KeyManagerException::class)
    override fun getKeyNames(): Set<String> {
        val aliasSet: MutableSet<String> = HashSet(exportableStore.getKeyNames())
        try {
            val aliases = androidKeyStore.aliases()
            while (aliases.hasMoreElements()) {
                val alias = aliases.nextElement()
                if (keyNamespace != null) {
                    aliasSet.add(alias.substring((keyNamespace + ".").length))
                } else {
                    aliasSet.add(alias)
                }
            }
        } catch (e: KeyStoreException) {
            throw KeyManagerException("Failed to query Android keystore for key aliases.", e)
        }
        return aliasSet
    }

    private fun toNamespacedName(name: String): String {
        return if (keyNamespace != null) "$keyNamespace.$name" else name
    }

    companion object {
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val NAME_CANT_BE_NULL = "name can't be null."
        private const val TYPE_CANT_BE_NULL = "type can't be null."
    }
}
