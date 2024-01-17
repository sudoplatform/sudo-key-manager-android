/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sudoplatform.sudokeymanager

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import com.sudoplatform.sudokeymanager.KeyManagerInterface.SymmetricEncryptionAlgorithm
import org.spongycastle.cert.X509v3CertificateBuilder
import org.spongycastle.cert.jcajce.JcaX509CertificateConverter
import org.spongycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.spongycastle.operator.OperatorCreationException
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.InvalidAlgorithmParameterException
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.UnrecoverableEntryException
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.util.Date
import java.util.Objects
import java.util.concurrent.TimeUnit
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.security.auth.x500.X500Principal

/**
 * KeyManager implementation using Android Keystore. Android Keystore provides system level
 * (or hardware level if supported by the device) key management and crypto. Keys in the
 * Android Keystore is only accessible by the app that had created them and all cryptographic
 * operations are performed at system level and keys are never passed to the user space.
 */
class AndroidKeyManager : KeyManager, SecureKeyDelegateInterface {
    // Android Keystore. All crypto operations will be performed within this system level
    // store.
    private val androidKeyStore: KeyStore

    // Key namespace used to prevent name clashes between keys used by multiple consumers of the
    // underlying key store such as Android Keystore.
    private var keyNamespace: String? = null

    /**
     * Instantiate AndroidKeyManager.
     *
     * @param storeInterface Key store to use for exportable keys.
     * @param androidKeyStore Android Keystore to use for securely storing keys.
     * @throws KeyManagerException
     */
    constructor(
        storeInterface: StoreInterface,
        androidKeyStore: KeyStore
    ) : super(storeInterface) {
        keyManagerStore.setSecureKeyDelegate(this)
        this.androidKeyStore = androidKeyStore
        createMasterKey()
    }

    /**
     * Instantiate AndroidKeyManager.
     *
     * @param storeInterface Key store to use for exportable keys.
     * @param androidKeyStore Android Keystore to use for securely storing keys.
     * @param keyNamespace key namespace to use to prevent name clashes when multiple consumers are
     * using the same underlying key store.
     * @throws KeyManagerException
     */
    constructor(
        storeInterface: StoreInterface,
        androidKeyStore: KeyStore,
        keyNamespace: String?
    ) : super(storeInterface) {
        keyManagerStore.setSecureKeyDelegate(this)
        this.androidKeyStore = androidKeyStore
        this.keyNamespace = keyNamespace
        createMasterKey()
    }

    /** Create a non exportable symmetric key that will be used to secure the exportable keys.  */
    @Throws(KeyManagerException::class)
    private fun createMasterKey() {
        if (getSymmetricKey(MASTER_KEY_NAME) != null) {
            return
        }
        try {
            val builder = KeyGenParameterSpec.Builder(
                toNamespacedName(MASTER_KEY_NAME),
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
            val keySpec = builder
                .setKeySize(SYMMETRIC_KEY_SIZE)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .setRandomizedEncryptionRequired(false)
                .build()
            val keyGenerator =
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE)
            keyGenerator.init(keySpec)
            keyGenerator.generateKey()
        } catch (e: InvalidAlgorithmParameterException) {
            throw KeyManagerException("Failed to create the master key.", e)
        } catch (e: NoSuchAlgorithmException) {
            throw KeyManagerException("Failed to create the master key.", e)
        } catch (e: NoSuchProviderException) {
            throw KeyManagerException("Failed to create the master key.", e)
        }
    }

    @Throws(KeyManagerException::class)
    override fun addKeyPair(
        privateKey: ByteArray,
        publicKey: ByteArray,
        name: String,
        isExportable: Boolean
    ) {
        try {
            val publicKeyObj = bytesToPublicKey(publicKey)
            val privateKeyObj = bytesToPrivateKey(privateKey)
            // Android Keystore requires the private key to be accompanied by a certificate. We have
            // to use BouncyCastle (SpongyCastle in Android land) here since there's no security
            // provider on Android that supports generating a self-signed certificate.
            val signer = contentSignerBuilder.build(privateKeyObj)

            // 99 years should be long enough since key lifetime should be less then that.
            val now = System.currentTimeMillis()
            val oneDay = TimeUnit.DAYS.toMillis(1)
            val ninetyNineYears = TimeUnit.DAYS.toMillis(99 * 365L)
            val startDate = Date(now - oneDay)
            val endDate = Date(now + ninetyNineYears)
            val builder: X509v3CertificateBuilder = JcaX509v3CertificateBuilder(
                X500Principal(CERTIFICATE_PRINCIPAL_ANONYOME),
                BigInteger.ONE,
                startDate, endDate,
                X500Principal(CERTIFICATE_PRINCIPAL_ANONYOME),
                publicKeyObj
            )
            val certificate = certificateConverter.getCertificate(builder.build(signer))
            androidKeyStore.setKeyEntry(
                toNamespacedName(name),
                privateKeyObj,
                null,
                arrayOf<Certificate>(certificate)
            )
            // Now store the exportable copies of the keys since we can't extract keys from Android Keystore.
            keyManagerStore.insertKey(privateKey, name, KeyType.PRIVATE_KEY, isExportable)
            keyManagerStore.insertKey(publicKey, name, KeyType.PUBLIC_KEY, isExportable)
        } catch (e: CertificateException) {
            throw KeyManagerException("Failed to create a certificate.", e)
        } catch (e: OperatorCreationException) {
            throw KeyManagerException("Failed to create a certificate.", e)
        } catch (e: GeneralSecurityException) {
            throw KeyManagerException("Failed to add a key pair.", e)
        }
    }

    @Throws(KeyManagerException::class)
    override fun addKeyPairFromKeyInfo(
        privateKey: ByteArray,
        publicKey: ByteArray,
        name: String,
        isExportable: Boolean
    ) {
        try {
            val publicKeyObj = keyInfoBytesToPublicKey(publicKey)
            val privateKeyObj = keyInfoBytesToPrivateKey(privateKey)
            // Android Keystore requires the private key to be accompanied by a certificate. We have
            // to use BouncyCastle (SpongyCastle in Android land) here since there's no security
            // provider on Android that supports generating a self-signed certificate.
            val signer = contentSignerBuilder.build(privateKeyObj)

            // 99 years should be long enough since key lifetime should be less then that.
            val now = System.currentTimeMillis()
            val oneDay = TimeUnit.DAYS.toMillis(1)
            val ninetyNineYears = TimeUnit.DAYS.toMillis(99 * 365L)
            val startDate = Date(now - oneDay)
            val endDate = Date(now + ninetyNineYears)
            val builder: X509v3CertificateBuilder = JcaX509v3CertificateBuilder(
                X500Principal(CERTIFICATE_PRINCIPAL_ANONYOME),
                BigInteger.ONE,
                startDate, endDate,
                X500Principal(CERTIFICATE_PRINCIPAL_ANONYOME),
                publicKeyObj
            )
            val certificate = certificateConverter.getCertificate(builder.build(signer))
            androidKeyStore.setKeyEntry(
                toNamespacedName(name),
                privateKeyObj,
                null,
                arrayOf<Certificate>(certificate)
            )
            // Now store the exportable copies of the keys since we can't extract keys from Android Keystore.
            keyManagerStore.insertKey(
                privateKeyToBytes(privateKeyObj),
                name,
                KeyType.PRIVATE_KEY,
                isExportable
            )
            keyManagerStore.insertKey(
                publicKeyToBytes(publicKeyObj),
                name,
                KeyType.PUBLIC_KEY,
                isExportable
            )
        } catch (e: CertificateException) {
            throw KeyManagerException("Failed to create a certificate.", e)
        } catch (e: OperatorCreationException) {
            throw KeyManagerException("Failed to create a certificate.", e)
        } catch (e: GeneralSecurityException) {
            throw KeyManagerException("Failed to add a key pair.", e)
        }
    }

    private val contentSignerBuilder: JcaContentSignerBuilder
        get() {
            val signerBuilder = JcaContentSignerBuilder(CERTIFICATE_SIGNATURE_ALGORITHM)
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
                // SHA256WITHRSA from BC provider deprecated in Android P and later.
                // https://android-developers.googleblog.com/2018/03/cryptography-changes-in-android-p.html
                signerBuilder.setProvider(CERTIFICATE_GENERATOR_PROVIDER)
            }
            return signerBuilder
        }
    private val certificateConverter: JcaX509CertificateConverter
        get() {
            val converter = JcaX509CertificateConverter()
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
                // SHA256WITHRSA from BC provider deprecated in Android P and later.
                // https://android-developers.googleblog.com/2018/03/cryptography-changes-in-android-p.html
                converter.setProvider(CERTIFICATE_GENERATOR_PROVIDER)
            }
            return converter
        }

    @Throws(KeyManagerException::class)
    override fun addPrivateKey(key: ByteArray, name: String, isExportable: Boolean) {
        throw UnsupportedOperationException("Cannot add a private key on its own to an Android key store.")
    }

    @Throws(
        UnrecoverableEntryException::class,
        NoSuchAlgorithmException::class,
        KeyStoreException::class
    )
    private fun getAndroidKeyStoreEntry(
        name: String,
        param: KeyStore.ProtectionParameter?
    ): KeyStore.Entry? {
        // Workaround for "java.security.UnrecoverableKeyException: Failed to obtain information about key"
        // caused by "android.security.KeyStoreException: System error"
        // https://anonyome.atlassian.net/browse/NPFA-9542
        var attempt = 1
        while (true) {
            try {
                return androidKeyStore.getEntry(toNamespacedName(name), param)
            } catch (ex: UnrecoverableEntryException) {
                if (attempt < 5 && isSystemError(ex)) {
                    Log.w(TAG, "Error getting AndroidKeyStore entry. Attempt=$attempt", ex)
                } else {
                    Log.e(TAG, "Can't get AndroidKeyStore entry", ex)
                    throw ex
                }
            }
            attempt++
        }
    }

    @Throws(KeyManagerException::class)
    override fun getPrivateKey(name: String): PrivateKey? {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        var privateKey: PrivateKey? = null
        try {
            val entry = getAndroidKeyStoreEntry(name, null)
            if (entry is KeyStore.PrivateKeyEntry) {
                privateKey = entry.privateKey
            }
        } catch (e: NoSuchAlgorithmException) {
            throw KeyManagerException("Failed to retrieve the private key.", e)
        } catch (e: KeyStoreException) {
            throw KeyManagerException("Failed to retrieve the private key.", e)
        } catch (e: UnrecoverableEntryException) {
            throw KeyManagerException("Failed to retrieve the private key.", e)
        }
        return privateKey
    }

    @Throws(KeyManagerException::class)
    override fun addPublicKey(key: ByteArray, name: String, isExportable: Boolean) {
        // Validate the key bytes by converting them
        bytesToPublicKey(key)
        // A public key without a private key cannot be stored in the AndroidKeyStore, so store it outside.
        keyManagerStore.insertKey(key, name, KeyType.PUBLIC_KEY, isExportable)
    }

    @Throws(KeyManagerException::class)
    override fun getPublicKey(name: String): PublicKey? {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        var publicKey: PublicKey? = null
        try {
            val entry = getAndroidKeyStoreEntry(name, null)
            if (entry is KeyStore.PrivateKeyEntry) {
                publicKey = entry.certificate.publicKey
            } else if (entry == null) {
                val publicKeyBytes = keyManagerStore.getKey(name, KeyType.PUBLIC_KEY)
                if (publicKeyBytes != null) {
                    publicKey = bytesToPublicKey(publicKeyBytes)
                }
            }
        } catch (e: NoSuchAlgorithmException) {
            throw KeyManagerException("Failed to retrieve the public key.", e)
        } catch (e: KeyStoreException) {
            throw KeyManagerException("Failed to retrieve the public key.", e)
        } catch (e: UnrecoverableEntryException) {
            throw KeyManagerException("Failed to retrieve the public key.", e)
        }
        return publicKey
    }

    @Throws(KeyManagerException::class)
    override fun getSymmetricKey(name: String): SecretKey? {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        var secretKey: SecretKey? = null
        try {
            val entry = getAndroidKeyStoreEntry(name, null)
            if (entry is KeyStore.SecretKeyEntry) {
                secretKey = entry.secretKey
            }
        } catch (e: KeyStoreException) {
            throw KeyManagerException("Failed to retrieve the symmetric key.", e)
        } catch (e: NoSuchAlgorithmException) {
            throw KeyManagerException("Failed to retrieve the symmetric key.", e)
        } catch (e: UnrecoverableEntryException) {
            throw KeyManagerException("Failed to retrieve the symmetric key.", e)
        }
        return secretKey
    }

    @Throws(KeyManagerException::class)
    override fun encryptKey(key: ByteArray): ByteArray {
        return this.encryptWithSymmetricKey(
            MASTER_KEY_NAME,
            key,
            SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256
        )
    }

    @Throws(KeyManagerException::class)
    override fun decryptKey(key: ByteArray): ByteArray {
        return this.decryptWithSymmetricKey(
            MASTER_KEY_NAME,
            key,
            SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256
        )
    }

    @Throws(KeyManagerException::class)
    override fun removeAllKeys() {
        super.removeAllKeys()
        createMasterKey()
    }

    private fun toNamespacedName(name: String): String {
        return if (keyNamespace != null) "$keyNamespace.$name" else name
    }

    companion object {
        private const val TAG = "AndroidKeyManager"

        // Constants for certificate generation.
        private const val CERTIFICATE_SIGNATURE_ALGORITHM = "SHA256withRSA"
        private const val CERTIFICATE_GENERATOR_PROVIDER = "BC"
        private const val CERTIFICATE_PRINCIPAL_ANONYOME = "cn=Anonyome"
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val MASTER_KEY_NAME = "com.anonyome.android.masterkey"
        private const val NAME_CANT_BE_NULL = "name can't be null."
        private fun isSystemError(ex: UnrecoverableEntryException): Boolean {
            val cause = ex.cause
            if (cause != null) {
                val message = cause.message
                return message != null && message.contains("System error")
            }
            return false
        }
    }
}
