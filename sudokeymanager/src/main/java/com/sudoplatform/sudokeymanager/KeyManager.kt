/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sudoplatform.sudokeymanager

import com.sudoplatform.sudokeymanager.KeyManagerInterface.PublicKeyEncryptionAlgorithm
import com.sudoplatform.sudokeymanager.KeyManagerInterface.PublicKeyFormat
import com.sudoplatform.sudokeymanager.KeyManagerInterface.SymmetricEncryptionAlgorithm
import org.spongycastle.asn1.pkcs.RSAPublicKey
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo
import org.spongycastle.crypto.digests.SHA256Digest
import org.spongycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.spongycastle.crypto.params.KeyParameter
import org.spongycastle.openssl.jcajce.JcaPEMWriter
import org.spongycastle.util.io.pem.PemObject
import org.spongycastle.util.io.pem.PemReader
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.StringReader
import java.io.StringWriter
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Security
import java.security.Signature
import java.security.SignatureException
import java.security.spec.InvalidKeySpecException
import java.security.spec.KeySpec
import java.security.spec.RSAPublicKeySpec
import java.util.EnumMap
import java.util.Objects
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.IllegalBlockSizeException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Basic KeyManager implementation. It implements key management and cryptographic operations common
 * to all its subclasses without a specific knowledge about the underlying technology used to store
 * the keys.
 */
open class KeyManager(keyManagerStore: StoreInterface) : KeyManagerInterface {
    // KeyManager store responsible for providing basic lifecycle management operations for keys.
    protected val keyManagerStore: StoreInterface

    // Key generators.
    private var keyGenerator: KeyGenerator? = null
    private var keyPairGenerator: KeyPairGenerator? = null
    private var keyFactory: KeyFactory? = null
    private var passwordKeyFactory: SecretKeyFactory? = null

    // Key related services
    protected var keyService: KeyService = KeyService()

    /**
     * Instantiates a KeyManager with the specified store.
     *
     * @param keyManagerStore KeyManager store responsible persistent storage of keys.
     * @throws KeyManagerException if key generation failed. Will contain a java.security exception.
     */
    init {
        Objects.requireNonNull(keyManagerStore, "keyManagerStore can't be null.")
        this.keyManagerStore = keyManagerStore
        SecurityProviders.installSpongyCastleProvider()
        setupKeyGenerators()
    }

    /**
     * Initializes key generators. A subclass should override this method to provide their own
     * key generators.
     *
     * @throws KeyManagerException if key generation failed. Will contain a java.security exception.
     */
    @Throws(KeyManagerException::class) // Use of hashing is safe here
    protected fun setupKeyGenerators() {
        try {
            keyGenerator = KeyGenerator.getInstance(SYMMETRIC_KEY_ALGORITHM_AES)
            keyGenerator?.init(SYMMETRIC_KEY_SIZE)
            keyPairGenerator = KeyPairGenerator.getInstance(PRIVATE_PUBLIC_KEY_ALGORITHM)
            keyPairGenerator?.initialize(PRIVATE_PUBLIC_KEY_SIZE)
            keyFactory = KeyFactory.getInstance(PRIVATE_PUBLIC_KEY_ALGORITHM)
            passwordKeyFactory = SecretKeyFactory.getInstance(PASSWORD_KEY_ALGORITHM)
        } catch (e: NoSuchAlgorithmException) {
            throw KeyManagerException(FAILED_TO_GENERATE_SYMMETRIC_KEY, e)
        }
    }

    @Throws(KeyManagerException::class)
    override fun addPassword(password: ByteArray, name: String) {
        this.addPassword(password, name, true)
    }

    @Throws(KeyManagerException::class)
    override fun addPassword(password: ByteArray, name: String, isExportable: Boolean) {
        Objects.requireNonNull(password, PASSWORD_CANT_BE_NULL)
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        keyManagerStore.insertKey(password, name, KeyType.PASSWORD, isExportable)
    }

    @Throws(KeyManagerException::class)
    override fun getPassword(name: String): ByteArray? {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        return keyManagerStore.getKey(name, KeyType.PASSWORD)
    }

    @Throws(KeyManagerException::class)
    override fun deletePassword(name: String) {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        keyManagerStore.deleteKey(name, KeyType.PASSWORD)
    }

    override fun updatePassword(password: ByteArray, name: String) {
        Objects.requireNonNull(password, PASSWORD_CANT_BE_NULL)
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        keyManagerStore.updateKey(password, name, KeyType.PASSWORD)
    }

    @Throws(KeyManagerException::class)
    override fun generateSymmetricKey(name: String) {
        this.generateSymmetricKey(name, true)
    }

    @Throws(KeyManagerException::class)
    override fun generateSymmetricKey(name: String, isExportable: Boolean) {
        val secretKey = keyGenerator!!.generateKey()
        this.addSymmetricKey(secretKey.encoded, name, isExportable)
    }

    @Throws(KeyManagerException::class)
    override fun addSymmetricKey(key: ByteArray, name: String) {
        this.addSymmetricKey(key, name, true)
    }

    @Throws(KeyManagerException::class)
    override fun addSymmetricKey(key: ByteArray, name: String, isExportable: Boolean) {
        Objects.requireNonNull(key, KEY_CANT_BE_NULL)
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        keyManagerStore.insertKey(key, name, KeyType.SYMMETRIC_KEY, isExportable)
    }

    @Throws(KeyManagerException::class)
    override fun getSymmetricKeyData(name: String): ByteArray? {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        return keyManagerStore.getKey(name, KeyType.SYMMETRIC_KEY)
    }

    @Throws(KeyManagerException::class)
    override fun deleteSymmetricKey(name: String) {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        keyManagerStore.deleteKey(name, KeyType.SYMMETRIC_KEY)
    }

    @Throws(KeyManagerException::class)
    override fun encryptWithSymmetricKey(name: String, data: ByteArray): ByteArray {
        return encryptWithSymmetricKey(
            name,
            data,
            getDefaultIV(SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256),
            SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256,
        )
    }

    @Throws(KeyManagerException::class)
    override fun encryptWithSymmetricKey(
        name: String,
        data: ByteArray,
        algorithm: SymmetricEncryptionAlgorithm,
    ): ByteArray {
        return encryptWithSymmetricKey(name, data, getDefaultIV(algorithm), algorithm)
    }

    @Throws(KeyManagerException::class)
    override fun encryptWithSymmetricKey(name: String, data: ByteArray, iv: ByteArray): ByteArray {
        return encryptWithSymmetricKey(
            name,
            data,
            iv,
            SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256,
        )
    }

    @Throws(KeyManagerException::class)
    override fun encryptWithSymmetricKey(
        name: String,
        data: ByteArray,
        iv: ByteArray,
        algorithm: SymmetricEncryptionAlgorithm,
    ): ByteArray {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        return this.encryptWithSymmetricKey(getSymmetricKey(name), data, iv, algorithm)
    }

    @Throws(KeyManagerException::class)
    override fun encryptWithSymmetricKey(key: ByteArray, data: ByteArray): ByteArray {
        return encryptWithSymmetricKey(
            key,
            data,
            getDefaultIV(SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256),
            SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256,
        )
    }

    @Throws(KeyManagerException::class)
    override fun encryptWithSymmetricKey(
        key: ByteArray,
        data: ByteArray,
        algorithm: SymmetricEncryptionAlgorithm,
    ): ByteArray {
        return this.encryptWithSymmetricKey(key, data, getDefaultIV(algorithm), algorithm)
    }

    @Throws(KeyManagerException::class)
    override fun encryptWithSymmetricKey(
        key: ByteArray,
        data: ByteArray,
        iv: ByteArray,
    ): ByteArray {
        return encryptWithSymmetricKey(
            key,
            data,
            iv,
            SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256,
        )
    }

    @Throws(KeyManagerException::class)
    override fun encryptWithSymmetricKey(
        key: ByteArray,
        data: ByteArray,
        iv: ByteArray,
        algorithm: SymmetricEncryptionAlgorithm,
    ): ByteArray {
        Objects.requireNonNull(key, KEY_CANT_BE_NULL)
        val keySpec = SecretKeySpec(key, SYMMETRIC_KEY_ALGORITHM_AES)
        return this.encryptWithSymmetricKey(keySpec, data, iv, algorithm)
    }

    @Throws(KeyManagerException::class)
    override fun decryptWithSymmetricKey(name: String, data: ByteArray): ByteArray {
        return this.decryptWithSymmetricKey(
            name,
            data,
            getDefaultIV(SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256),
            SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256,
        )
    }

    @Throws(KeyManagerException::class)
    override fun decryptWithSymmetricKey(
        name: String,
        data: ByteArray,
        algorithm: SymmetricEncryptionAlgorithm,
    ): ByteArray {
        return this.decryptWithSymmetricKey(name, data, getDefaultIV(algorithm), algorithm)
    }

    @Throws(KeyManagerException::class)
    override fun decryptWithSymmetricKey(
        name: String,
        data: ByteArray,
        iv: ByteArray,
        algorithm: SymmetricEncryptionAlgorithm,
    ): ByteArray {
        Objects.requireNonNull(name, KEY_CANT_BE_NULL)
        return decryptWithSymmetricKey(getSymmetricKey(name), data, iv, algorithm)
    }

    @Throws(KeyManagerException::class)
    override fun decryptWithSymmetricKey(name: String, stream: InputStream): InputStream {
        return decryptWithSymmetricKey(
            name,
            stream,
            getDefaultIV(SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256),
            SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256,
        )
    }

    @Throws(KeyManagerException::class)
    override fun decryptWithSymmetricKey(
        name: String,
        stream: InputStream,
        algorithm: SymmetricEncryptionAlgorithm,
    ): InputStream {
        return this.decryptWithSymmetricKey(name, stream, getDefaultIV(algorithm), algorithm)
    }

    @Throws(KeyManagerException::class)
    override fun decryptWithSymmetricKey(name: String, data: ByteArray, iv: ByteArray): ByteArray {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        return this.decryptWithSymmetricKey(
            getSymmetricKey(name),
            data,
            iv,
            SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256,
        )
    }

    @Throws(KeyManagerException::class)
    override fun decryptWithSymmetricKey(
        name: String,
        stream: InputStream,
        iv: ByteArray,
    ): InputStream {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        return this.decryptWithSymmetricKey(
            getSymmetricKey(name),
            stream,
            iv,
            SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256,
        )
    }

    @Throws(KeyManagerException::class)
    override fun decryptWithSymmetricKey(
        name: String,
        stream: InputStream,
        iv: ByteArray,
        algorithm: SymmetricEncryptionAlgorithm,
    ): InputStream {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        return this.decryptWithSymmetricKey(getSymmetricKey(name), stream, iv, algorithm)
    }

    @Throws(KeyManagerException::class)
    override fun decryptWithSymmetricKey(key: ByteArray, data: ByteArray): ByteArray {
        return this.decryptWithSymmetricKey(
            key,
            data,
            getDefaultIV(SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256),
            SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256,
        )
    }

    @Throws(KeyManagerException::class)
    override fun decryptWithSymmetricKey(
        key: ByteArray,
        data: ByteArray,
        algorithm: SymmetricEncryptionAlgorithm,
    ): ByteArray {
        return this.decryptWithSymmetricKey(key, data, getDefaultIV(algorithm), algorithm)
    }

    @Throws(KeyManagerException::class)
    override fun decryptWithSymmetricKey(
        key: ByteArray,
        data: ByteArray,
        iv: ByteArray,
        algorithm: SymmetricEncryptionAlgorithm,
    ): ByteArray {
        Objects.requireNonNull(key, KEY_CANT_BE_NULL)
        val keySpec = SecretKeySpec(key, SYMMETRIC_KEY_ALGORITHM_AES)
        return this.decryptWithSymmetricKey(keySpec, data, iv, algorithm)
    }

    @Throws(KeyManagerException::class)
    override fun decryptWithSymmetricKey(key: ByteArray, source: InputStream): InputStream {
        return this.decryptWithSymmetricKey(
            key,
            source,
            getDefaultIV(SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256),
            SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256,
        )
    }

    @Throws(KeyManagerException::class)
    override fun decryptWithSymmetricKey(
        key: ByteArray,
        source: InputStream,
        algorithm: SymmetricEncryptionAlgorithm,
    ): InputStream {
        return this.decryptWithSymmetricKey(
            key,
            source,
            getDefaultIV(SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256),
            SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256,
        )
    }

    @Throws(KeyManagerException::class)
    override fun decryptWithSymmetricKey(
        key: ByteArray,
        data: ByteArray,
        iv: ByteArray,
    ): ByteArray {
        Objects.requireNonNull(key, KEY_CANT_BE_NULL)
        val keySpec = SecretKeySpec(key, SYMMETRIC_KEY_ALGORITHM_AES)
        return this.decryptWithSymmetricKey(
            keySpec,
            data,
            iv,
            SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256,
        )
    }

    @Throws(KeyManagerException::class)
    override fun decryptWithSymmetricKey(
        key: ByteArray,
        stream: InputStream,
        iv: ByteArray,
    ): InputStream {
        Objects.requireNonNull(key, KEY_CANT_BE_NULL)
        val keySpec = SecretKeySpec(key, SYMMETRIC_KEY_ALGORITHM_AES)
        return this.decryptWithSymmetricKey(
            keySpec,
            stream,
            iv,
            SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256,
        )
    }

    @Throws(KeyManagerException::class)
    override fun decryptWithSymmetricKey(
        key: ByteArray,
        stream: InputStream,
        iv: ByteArray,
        algorithm: SymmetricEncryptionAlgorithm,
    ): InputStream {
        Objects.requireNonNull(key, KEY_CANT_BE_NULL)
        val keySpec = SecretKeySpec(key, SYMMETRIC_KEY_ALGORITHM_AES)
        return this.decryptWithSymmetricKey(keySpec, stream, iv, algorithm)
    }

    @Throws(KeyManagerException::class)
    override fun createSymmetricKeyFromPassword(password: String): KeyComponents {
        val keyComponents = KeyComponents()
        keyComponents.salt = createRandomData(PASSWORD_SALT_SIZE)
        keyComponents.rounds = PASSWORD_DEFAULT_ROUNDS
        keyComponents.key =
            createSymmetricKeyFromPassword(password, keyComponents.salt, keyComponents.rounds)
        return keyComponents
    }

    @Throws(KeyManagerException::class)
    override fun createSymmetricKeyFromPassword(
        password: String,
        salt: ByteArray,
        rounds: Int,
    ): ByteArray {
        Objects.requireNonNull(password, PASSWORD_CANT_BE_NULL)
        return this.createSymmetricKeyFromPassword(password.toCharArray(), salt, rounds)
    }

    @Throws(KeyManagerException::class)
    override fun createSymmetricKeyFromPassword(
        password: CharArray,
        salt: ByteArray,
        rounds: Int,
    ): ByteArray {
        Objects.requireNonNull(password, PASSWORD_CANT_BE_NULL)
        Objects.requireNonNull(salt, "salt can't be null.")
        val secretKey: SecretKey = try {
            val keySpec: KeySpec = PBEKeySpec(password, salt, rounds, PASSWORD_KEY_SIZE)
            passwordKeyFactory!!.generateSecret(keySpec)
        } catch (e: InvalidKeySpecException) {
            throw KeyManagerException(FAILED_SYMMETRIC_KEY_CREATION, e)
        }
        return secretKey.encoded
    }

    @Throws(KeyManagerException::class)
    override fun createSymmetricKeyFromPassword(
        password: ByteArray,
        salt: ByteArray,
        rounds: Int,
    ): ByteArray {
        Objects.requireNonNull(password, PASSWORD_CANT_BE_NULL)
        Objects.requireNonNull(salt, "salt can't be null.")
        val generator = PKCS5S2ParametersGenerator(SHA256Digest())
        generator.init(password, salt, rounds)
        val secretKey = generator.generateDerivedMacParameters(PASSWORD_KEY_SIZE) as KeyParameter
        return secretKey.key
    }

    @Throws(KeyManagerException::class) // Use of hashing is safe here
    override fun generateHash(data: ByteArray): ByteArray {
        Objects.requireNonNull(data, DATA_CANT_BE_NULL)
        val hash: ByteArray = try {
            val digest = MessageDigest.getInstance(MESSAGE_DIGEST_ALGORITHM)
            digest.digest(data)
        } catch (e: NoSuchAlgorithmException) {
            throw KeyManagerException(
                String.format(
                    "Failed to generate a hash because %s was not found.",
                    MESSAGE_DIGEST_ALGORITHM,
                ),
                e,
            )
        }
        return hash
    }

    @Throws(KeyManagerException::class)
    override fun generateKeyPair(name: String) {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        this.generateKeyPair(name, true)
    }

    @Throws(KeyManagerException::class)
    override fun generateKeyPair(name: String, isExportable: Boolean) {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        val keyPair = keyPairGenerator!!.generateKeyPair()
        val privateKey = keyPair.private
        val publicKey = keyPair.public
        this.addKeyPair(
            keyService.privateKeyToBytes(privateKey),
            keyService.publicKeyToBytes(publicKey),
            name,
            isExportable,
        )
    }

    @Throws(KeyManagerException::class)
    override fun addPrivateKey(key: ByteArray, name: String) {
        this.addPrivateKey(key, name, true)
    }

    @Throws(KeyManagerException::class)
    override fun addPrivateKey(key: ByteArray, name: String, isExportable: Boolean) {
        Objects.requireNonNull(key, KEY_CANT_BE_NULL)
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        keyManagerStore.insertKey(key, name, KeyType.PRIVATE_KEY, isExportable)
    }

    @Throws(KeyManagerException::class)
    override fun getPrivateKeyData(name: String): ByteArray? {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        return keyManagerStore.getKey(name, KeyType.PRIVATE_KEY)
    }

    @Throws(KeyManagerException::class)
    override fun deletePublicKey(name: String) {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        keyManagerStore.deleteKey(name, KeyType.PUBLIC_KEY)
    }

    @Throws(KeyManagerException::class)
    override fun addPublicKey(key: ByteArray, name: String) {
        this.addPublicKey(key, name, true)
    }

    @Throws(KeyManagerException::class)
    override fun addPublicKey(key: ByteArray, name: String, isExportable: Boolean) {
        Objects.requireNonNull(key, KEY_CANT_BE_NULL)
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        keyManagerStore.insertKey(key, name, KeyType.PUBLIC_KEY, isExportable)
    }

    /**
     * Add a public key to the secure store from PEM encoded RSAPublicKey.
     *
     * @param key public key to store securely.
     * @param name name of the public key to store.
     * @param isExportable indicates whether or not the public key is exportable.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    override fun addPublicKeyFromPEM(key: String, name: String, isExportable: Boolean) {
        Objects.requireNonNull(key, KEY_CANT_BE_NULL)
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        val stringReader = StringReader(key)
        val pemReader = PemReader(stringReader)
        val content: ByteArray = try {
            val pemObject = pemReader.readPemObject()
            pemObject.content
        } catch (e: IOException) {
            throw KeyManagerException(FAILED_PUBLIC_KEY_READ, e)
        }
        keyManagerStore.insertKey(content, name, KeyType.PUBLIC_KEY, isExportable)
    }

    @Throws(KeyManagerException::class)
    override fun getPublicKeyData(name: String): ByteArray? {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        return keyManagerStore.getKey(name, KeyType.PUBLIC_KEY)
    }

    @Throws(KeyManagerException::class)
    override fun addKeyPair(privateKey: ByteArray, publicKey: ByteArray, name: String) {
        this.addKeyPair(privateKey, publicKey, name, true)
    }

    @Throws(KeyManagerException::class)
    override fun addKeyPair(
        privateKey: ByteArray,
        publicKey: ByteArray,
        name: String,
        isExportable: Boolean,
    ) {
        this.addPrivateKey(privateKey, name, isExportable)
        this.addPublicKey(publicKey, name, isExportable)
    }

    @Throws(KeyManagerException::class)
    override fun addKeyPairFromKeyInfo(
        privateKey: ByteArray,
        publicKey: ByteArray,
        name: String,
        isExportable: Boolean,
    ) {
        val publicKeyObj = keyService.keyInfoBytesToPublicKey(publicKey)
        val privateKeyObj = keyService.keyInfoBytesToPrivateKey(privateKey)
        this.addPrivateKey(keyService.privateKeyToBytes(privateKeyObj), name, isExportable)
        this.addPublicKey(keyService.publicKeyToBytes(publicKeyObj), name, isExportable)
    }

    @Throws(KeyManagerException::class)
    override fun deleteKeyPair(name: String) {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        keyManagerStore.deleteKey(name, KeyType.PRIVATE_KEY)
        keyManagerStore.deleteKey(name, KeyType.PUBLIC_KEY)
    }

    @Throws(KeyManagerException::class)
    override fun generateSignatureWithPrivateKey(name: String, data: ByteArray): ByteArray {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        Objects.requireNonNull(data, DATA_CANT_BE_NULL)
        val signatureBytes: ByteArray
        val privateKey = getPrivateKey(name)
        if (privateKey != null) {
            // Spongy/BouncyCastle are incompatible with keys from the Android key store for signing.
            // Use the special Android provider, if it's present, that works around this problem.
            val preferredProvider = Security.getProvider("AndroidKeyStoreBCWorkaround")
            try {
                val signature: Signature = if (preferredProvider != null) {
                    Signature.getInstance(PRIVATE_PUBLIC_KEY_SIGNATURE_ALGORITHM, preferredProvider)
                } else {
                    Signature.getInstance(PRIVATE_PUBLIC_KEY_SIGNATURE_ALGORITHM)
                }
                signature.initSign(privateKey)
                signature.update(data)
                signatureBytes = signature.sign()
            } catch (e: NoSuchAlgorithmException) {
                throw KeyManagerException(
                    String.format(
                        "Failed to generate a signature because %s was not found.",
                        PRIVATE_PUBLIC_KEY_SIGNATURE_ALGORITHM,
                    ),
                    e,
                )
            } catch (e: SignatureException) {
                throw KeyManagerException(FAILED_SIGNATURE_GENERATION, e)
            } catch (e: InvalidKeyException) {
                throw KeyManagerException(
                    String.format(
                        "Key \"%s\" cannot be used to generate a signature.",
                        name,
                    ),
                    e,
                )
            }
        } else {
            throw KeyNotFoundException(String.format(KEY_NOT_FOUND, name))
        }
        return signatureBytes
    }

    @Throws(KeyManagerException::class)
    override fun verifySignatureWithPublicKey(
        name: String,
        data: ByteArray,
        signature: ByteArray,
    ): Boolean {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        Objects.requireNonNull(data, DATA_CANT_BE_NULL)
        Objects.requireNonNull(signature, "signature can't be null.")
        val status: Boolean
        val publicKey = getPublicKey(name)
        status = if (publicKey != null) {
            try {
                val signatureObject = Signature.getInstance(PRIVATE_PUBLIC_KEY_SIGNATURE_ALGORITHM)
                signatureObject.initVerify(publicKey)
                signatureObject.update(data)
                signatureObject.verify(signature)
            } catch (e: NoSuchAlgorithmException) {
                throw KeyManagerException(
                    String.format(
                        "Failed to verify the signature because %s was not found.",
                        PRIVATE_PUBLIC_KEY_SIGNATURE_ALGORITHM,
                    ),
                    e,
                )
            } catch (e: SignatureException) {
                throw KeyManagerException(FAILED_SIGNATURE_VERIFICATION, e)
            } catch (e: InvalidKeyException) {
                throw KeyManagerException(
                    String.format(
                        "Key \"%s\" cannot be used to verify a signature.",
                        name,
                    ),
                    e,
                )
            }
        } else {
            throw KeyNotFoundException(String.format(KEY_NOT_FOUND, name))
        }
        return status
    }

    /**
     * Encrypts the given data with the specified public key.
     *
     * @param name name of the public key to use for encryption.
     * @param data data to encrypt with the default algorithm [PublicKeyEncryptionAlgorithm.RSA_ECB_PKCS1].
     * @return encrypted data.
     * @throws KeyManagerException on failure, which will probably contain an exception from java.security.
     */
    @Throws(KeyManagerException::class)
    override fun encryptWithPublicKey(name: String, data: ByteArray): ByteArray {
        return encryptWithPublicKey(name, data, PublicKeyEncryptionAlgorithm.RSA_ECB_PKCS1)
    }

    /**
     * Encrypts the given data with the specified public key.
     *
     * @param name      name of the public key to use for encryption.
     * @param data      data to encrypt.
     * @param algorithm the encryption algorithm to use.
     * @return encrypted data.
     * @throws KeyManagerException on failure, which will probably contain an exception from java.security.
     */
    @Throws(KeyManagerException::class)
    override fun encryptWithPublicKey(
        name: String,
        data: ByteArray,
        algorithm: PublicKeyEncryptionAlgorithm,
    ): ByteArray {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        Objects.requireNonNull(data, DATA_CANT_BE_NULL)
        Objects.requireNonNull(algorithm, ALGORITHM_CANT_BE_NULL)
        val publicKey = getPublicKey(name) ?: throw KeyNotFoundException(KEY_NOT_FOUND.format(name))
        return this.encryptWithPublicKeyData(publicKey, data, algorithm)
    }

    /**
     * Encrypts the given data with the specified public key. The public key data be in either
     * RSA Public Key (PKCS#1) or SPKI format.
     *
     * @param key [ByteArray] Raw key bytes of the public key to use for encryption.
     * @param data [ByteArray] Data to encrypt.
     * @param format [PublicKeyFormat] The format of the public key data.
     * @param algorithm [PublicKeyEncryptionAlgorithm] The encryption algorithm to use.
     * @return encrypted data.
     * @throws KeyManagerException Which might contain an exception from java.security.
     */
    @Throws(KeyManagerException::class)
    override fun encryptWithPublicKey(
        key: ByteArray,
        data: ByteArray,
        format: PublicKeyFormat,
        algorithm: PublicKeyEncryptionAlgorithm,
    ): ByteArray {
        Objects.requireNonNull(key, KEY_CANT_BE_NULL)
        Objects.requireNonNull(data, DATA_CANT_BE_NULL)
        Objects.requireNonNull(algorithm, ALGORITHM_CANT_BE_NULL)
        Objects.requireNonNull(format, KEY_FORMAT_CANT_BE_NULL)
        val publicKey: PublicKey = when (format) {
            PublicKeyFormat.RSA_PUBLIC_KEY ->
                bytesToPublicKey(key)

            PublicKeyFormat.SPKI ->
                keyInfoBytesToPublicKey(key)
        }
        return this.encryptWithPublicKeyData(publicKey, data, algorithm)
    }

    @Throws(KeyManagerException::class)
    private fun encryptWithPublicKeyData(
        publicKey: PublicKey,
        data: ByteArray,
        algorithm: PublicKeyEncryptionAlgorithm,
    ): ByteArray {
        return try {
            val cipher = synchronized(KeyManager::class.java) {
                getCipher(algorithm)!!.apply {
                    init(Cipher.ENCRYPT_MODE, publicKey)
                }
            }
            cipher.doFinal(data)
        } catch (e: BadPaddingException) {
            throw KeyManagerException(FAILED_PUBLIC_KEY_ENCRYPTION, e)
        } catch (e: IllegalBlockSizeException) {
            throw KeyManagerException(FAILED_PUBLIC_KEY_ENCRYPTION, e)
        } catch (e: InvalidKeyException) {
            throw KeyManagerException(FAILED_PUBLIC_KEY_ENCRYPTION, e)
        }
    }

    /**
     * Decrypts the given data with the specified private key.
     *
     * @param name name of the private key to use for decryption.
     * @param data data to decrypt with the default algorithm [PublicKeyEncryptionAlgorithm.RSA_ECB_PKCS1].
     * @return decrypted data.
     * @throws KeyManagerException on failure, which will probably contain an exception from java.security.
     */
    @Throws(KeyManagerException::class)
    override fun decryptWithPrivateKey(name: String, data: ByteArray): ByteArray {
        return decryptWithPrivateKey(name, data, PublicKeyEncryptionAlgorithm.RSA_ECB_PKCS1)
    }

    /**
     * Decrypts the given data with the specified private key.
     *
     * @param name      name of the private key to use for decryption.
     * @param data      data to decrypt.
     * @param algorithm the decryption algorithm to use.
     * @return decrypted data.
     * @throws KeyManagerException on failure, which will probably contain an exception from java.security.
     */
    @Throws(KeyManagerException::class)
    override fun decryptWithPrivateKey(
        name: String,
        data: ByteArray,
        algorithm: PublicKeyEncryptionAlgorithm,
    ): ByteArray {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        Objects.requireNonNull(data, DATA_CANT_BE_NULL)
        Objects.requireNonNull(algorithm, ALGORITHM_CANT_BE_NULL)
        val decrypted: ByteArray
        val privateKey = getPrivateKey(name)
        if (privateKey != null) {
            try {
                var cipher: Cipher?
                synchronized(KeyManager::class.java) {
                    cipher = getCipher(algorithm)
                    cipher!!.init(Cipher.DECRYPT_MODE, privateKey)
                }
                decrypted = cipher!!.doFinal(data)
            } catch (e: BadPaddingException) {
                throw KeyManagerException(FAILED_PRIVATE_KEY_DECRYPTION, e)
            } catch (e: IllegalBlockSizeException) {
                throw KeyManagerException(FAILED_PRIVATE_KEY_DECRYPTION, e)
            } catch (e: InvalidKeyException) {
                throw KeyManagerException("Key \"$name\" cannot be used to decrypt.", e)
            }
        } else {
            throw KeyNotFoundException("Key \"$name\" not found.")
        }
        return decrypted
    }

    override fun createRandomData(size: Int): ByteArray {
        val random = SecureRandom()
        val bytes = ByteArray(size)
        random.nextBytes(bytes)
        return bytes
    }

    @Throws(KeyManagerException::class)
    override fun removeAllKeys() {
        keyManagerStore.reset()
    }

    @Throws(Exception::class)
    override fun close() {
        keyManagerStore.close()
        SecurityProviders.removeSpongyCastleProvider()
    }

    private fun getDefaultIV(algorithm: SymmetricEncryptionAlgorithm): ByteArray {
        return if (algorithm == SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256) {
            DEFAULT_AES_CBC_IV
        } else {
            DEFAULT_AES_GCM_IV
        }
    }

    /**
     * Retrieves a platform specific private key.
     *
     * @param name name of the key to retrieve.
     * @return private key object.
     * @throws KeyManagerException on failure, which will probably contain an exception from java.security.
     */
    @Throws(KeyManagerException::class)
    override fun getPrivateKey(name: String): PrivateKey? {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        val privateKeyData = getPrivateKeyData(name) ?: return null
        return keyService.bytesToPrivateKey(privateKeyData)
    }

    /**
     * Deserializes encoded public key bytes to a PublicKey object.
     *
     * @param keyBytes encoded key bytes.
     * @return public key object.
     * @throws KeyManagerException on failure, which will probably contain an exception from java.security.
     */
    @Throws(KeyManagerException::class)
    protected fun bytesToPublicKey(keyBytes: ByteArray): PublicKey {
        Objects.requireNonNull(keyBytes, "keyBytes can't be null.")
        val publicKey: PublicKey = try {
            val pkcs1PublicKey = RSAPublicKey.getInstance(keyBytes)
            val modulus = pkcs1PublicKey.modulus
            val publicExponent = pkcs1PublicKey.publicExponent
            val keySpec = RSAPublicKeySpec(modulus, publicExponent)
            keyFactory!!.generatePublic(keySpec)
        } catch (e: InvalidKeySpecException) {
            throw KeyManagerException(FAILED_PUBLIC_KEY_CREATION, e)
        }
        return publicKey
    }

    /**
     * Deserializes encoded SubjectPublicKeyInfo bytes to a PublicKey object.
     *
     * @param keyBytes encoded key bytes.
     * @return public key object.
     * @throws KeyManagerException on failure, which will probably contain an exception from java.security.
     */
    @Throws(KeyManagerException::class)
    protected fun keyInfoBytesToPublicKey(keyBytes: ByteArray): PublicKey {
        Objects.requireNonNull(keyBytes, "keyBytes can't be null.")
        val publicKey: PublicKey = try {
            val subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(keyBytes)
            val pkcs1PublicKey = RSAPublicKey.getInstance(subjectPublicKeyInfo.parsePublicKey())
            val modulus = pkcs1PublicKey.modulus
            val publicExponent = pkcs1PublicKey.publicExponent
            val keySpec = RSAPublicKeySpec(modulus, publicExponent)
            keyFactory!!.generatePublic(keySpec)
        } catch (e: InvalidKeySpecException) {
            throw KeyManagerException(FAILED_PUBLIC_KEY_CREATION, e)
        } catch (e: IOException) {
            throw KeyManagerException(FAILED_PUBLIC_KEY_CREATION, e)
        }
        return publicKey
    }

    /**
     * Serializes a public key object into a byte array. For compatibility with iOS, we are using
     * PKCS1.
     *
     * @param publicKey public key object.
     * @return byte array representing PKCS1 DER encoded public key.
     * @throws KeyManagerException on failure, which will probably contain an exception from java.security.
     */
    @Throws(KeyManagerException::class)
    protected fun publicKeyToBytes(publicKey: PublicKey): ByteArray {
        Objects.requireNonNull(publicKey, "publicKey can't be null.")
        val publicKeyPKCS1: ByteArray = try {
            val publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.encoded)
            val publicKeyPKCS1ASN1 = publicKeyInfo.parsePublicKey()
            publicKeyPKCS1ASN1.encoded
        } catch (e: IOException) {
            throw KeyManagerException(FAILED_PUBLIC_KEY_SERIALIZATION, e)
        }
        return publicKeyPKCS1
    }

    /**
     * Retrieves a platform specific public key reference.
     *
     * @param name name of the key to retrieve.
     * @return public key object.
     * @throws KeyManagerException on failure, which will probably contain an exception from java.security.
     */
    @Throws(KeyManagerException::class)
    override fun getPublicKey(name: String): PublicKey? {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        val publicKeyBytes = getPublicKeyData(name)
        return if (publicKeyBytes != null) {
            bytesToPublicKey(publicKeyBytes)
        } else {
            null
        }
    }

    /**
     * Retrieves a public key from the secure store as PEM encoded RSAPublicKey.
     *
     * @param name name of the public key to retrieve.
     * @return requested public key or null if the key was not found.
     * @throws KeyManagerException if an error occurred while retrieving the key.
     */
    @Throws(KeyManagerException::class)
    override fun getPublicKeyAsPEM(name: String): String? {
        val keyData = getPublicKeyData(name)
        return if (keyData != null) {
            try {
                val stringWriter = StringWriter()
                val pemWriter = JcaPEMWriter(stringWriter)
                pemWriter.writeObject(PemObject("RSA PUBLIC KEY", keyData))
                pemWriter.close()
                stringWriter.toString()
            } catch (e: IOException) {
                throw KeyManagerException(FAILED_PUBLIC_KEY_CONVERSION, e)
            }
        } else {
            null
        }
    }

    /**
     * Retrieves a platform specific symmetric key reference.
     *
     * @param name name of the key to retrieve.
     * @return symmetric key object.
     * @throws KeyManagerException on failure, which will probably contain an exception from java.security.
     */
    @Throws(KeyManagerException::class)
    protected open fun getSymmetricKey(name: String): SecretKey? {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL)
        val keyBytes = getSymmetricKeyData(name) ?: return null
        return SecretKeySpec(keyBytes, 0, keyBytes.size, SYMMETRIC_KEY_ALGORITHM_AES)
    }

    /**
     * Encrypts the given data with the given symmetric key reference.
     *
     * @param key       symmetric key reference.
     * @param data      data to encrypt.
     * @param iv        Initialization vector. Must be 128 bit in size for AES-CBC and 96 for AES-GCM.
     * @param algorithm the symmetric encryption algorithm to use.
     * @return encrypted data.
     * @throws KeyManagerException on failure, which will probably contain an exception from java.security.
     */
    @Throws(KeyManagerException::class)
    protected fun encryptWithSymmetricKey(
        key: SecretKey?,
        data: ByteArray,
        iv: ByteArray,
        algorithm: SymmetricEncryptionAlgorithm,
    ): ByteArray {
        Objects.requireNonNull(data, DATA_CANT_BE_NULL)
        var encrypted: ByteArray
        try {
            synchronized(KeyManager::class.java) {
                val cipher = setupSymmetricCipher(key, iv, Cipher.ENCRYPT_MODE, algorithm)
                encrypted = performChunkCipherOperation(data, cipher)
            }
        } catch (e: Exception) {
            throw KeyManagerException(FAILED_TO_ENCRYPT, e)
        }
        return encrypted
    }

    @Throws(InvalidAlgorithmParameterException::class, InvalidKeyException::class)
    private fun setupSymmetricCipher(
        key: SecretKey?,
        iv: ByteArray,
        mode: Int,
        algorithm: SymmetricEncryptionAlgorithm,
    ): Cipher {
        Objects.requireNonNull(key, KEY_CANT_BE_NULL)
        Objects.requireNonNull(iv, "iv can't be null.")
        Objects.requireNonNull(algorithm, ALGORITHM_CANT_BE_NULL)
        require(!(algorithm != SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256 && algorithm != SymmetricEncryptionAlgorithm.AES_GCM_256)) { "Algorithm $algorithm is not supported" }
        synchronized(KeyManager::class.java) {
            val cipher: Cipher
            if (algorithm == SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256) {
                cipher = aesCbcCipher.get() ?: throw KeyManagerException(FAILED_TO_GET_CIPHER)
                cipher.init(mode, key, IvParameterSpec(iv))
            } else {
                cipher = aesGcmCipher.get() ?: throw KeyManagerException(FAILED_TO_GET_CIPHER)
                cipher.init(mode, key, GCMParameterSpec(SYMMETRIC_KEY_ALGORITHM_TAG_SIZE, iv))
            }
            return cipher
        }
    }

    /**
     * Decrypts the given data with the given symmetric key reference.
     *
     * @param key       symmetric key reference.
     * @param data      data to decrypt.
     * @param iv        Initialization vector. Must be 128 bit in size for AES-CBC and 96 for AES-GCM.
     * @param algorithm the symmetric decryption algorithm to use.
     * @return decrypted data.
     * @throws KeyManagerException on failure, which will probably contain an exception from java.security.
     */
    @Throws(KeyManagerException::class)
    protected fun decryptWithSymmetricKey(
        key: SecretKey?,
        data: ByteArray,
        iv: ByteArray,
        algorithm: SymmetricEncryptionAlgorithm,
    ): ByteArray {
        Objects.requireNonNull(data, DATA_CANT_BE_NULL)
        var decrypted: ByteArray
        try {
            synchronized(KeyManager::class.java) {
                val cipher = setupSymmetricCipher(key, iv, Cipher.DECRYPT_MODE, algorithm)
                decrypted = performChunkCipherOperation(data, cipher)
            }
        } catch (e: Exception) {
            throw KeyManagerException(FAILED_TO_DECRYPT, e)
        }
        return decrypted
    }

    /**
     * Decrypts the given data stream with the given symmetric key reference on the fly.
     *
     * @param key       symmetric key reference.
     * @param stream    data to decrypt.
     * @param iv        Initialization vector. Must be 128 bit in size for AES-CBC and 96 for AES-GCM.
     * @param algorithm the symmetric decryption algorithm to use.
     * @return decrypted data stream
     * @throws KeyManagerException on failure, which will probably contain an exception from java.security.
     */
    @Throws(KeyManagerException::class)
    protected fun decryptWithSymmetricKey(
        key: SecretKey?,
        stream: InputStream,
        iv: ByteArray,
        algorithm: SymmetricEncryptionAlgorithm,
    ): InputStream {
        Objects.requireNonNull(stream, "stream can't be null.")
        return try {
            val cipher = setupSymmetricCipher(key, iv, Cipher.DECRYPT_MODE, algorithm)
            CipherInputStream(stream, cipher)
        } catch (e: Exception) {
            throw KeyManagerException(FAILED_TO_DECRYPT, e)
        }
    }

    /**
     * Performs a chunked update / doFinal operation on a byte array of data.
     * Originally cipher operations were performed with doFinal only. This was okay
     * for small data sets however for larger ones data would be lost.
     *
     * @param data   data to process through the cipher in chunks if necessary.
     * @param cipher cipher to process data through.
     * @return processed cipher data
     */
    @Throws(KeyManagerException::class)
    private fun performChunkCipherOperation(data: ByteArray, cipher: Cipher): ByteArray {
        return try {
            val dataOutputStream = ByteArrayOutputStream()
            val dataInputStream = ByteArrayInputStream(data)
            val chunkSize = CIPHER_CHUNK_SIZE
            val buffer = ByteArray(chunkSize)

            // Process the cipher updates until the remaining available data is less than
            // the accepted chunk size.
            while (dataInputStream.available() > chunkSize) {
                val readBytes = dataInputStream.read(buffer)
                dataOutputStream.write(cipher.update(buffer, 0, readBytes))
            }

            // Read the remainder of the bytes and perform doFinal on the cipher.
            val readBytes = dataInputStream.read(buffer)
            dataOutputStream.write(cipher.doFinal(buffer, 0, readBytes))

            // Returns the data processed by the cipher.
            dataOutputStream.toByteArray()
        } catch (e: Exception) {
            throw KeyManagerException(FAILED_TO_DECRYPT, e)
        }
    }

    /**
     * Export all the keys.
     *
     * @return a [Map] with the key name as the map key and the exported key type and bytes
     * as the value. The map may be empty but it will not be null.
     * @throws StoreNotExportable  if the key store does not permit keys to be exported.
     * @throws KeyManagerException if the key cannot be exported from the store.
     */
    @Throws(KeyManagerException::class)
    override fun exportKeys(): List<KeyComponents> {
        if (!keyManagerStore.isExportable()) {
            throw StoreNotExportable("Key store is not exportable")
        }
        val keyNames = keyManagerStore.getKeyNames()
        val keyList: MutableList<KeyComponents> = ArrayList(keyNames.size)
        for (name in keyNames) {
            for (keyType in KeyType.values()) {
                val keyData = keyManagerStore.getKey(name, keyType)
                if (keyData != null) {
                    val keyComponents = KeyComponents()
                    keyComponents.name = name
                    keyComponents.keyType = keyType
                    keyComponents.key = keyData
                    keyList.add(keyComponents)
                }
            }
        }
        return keyList
    }

    companion object {
        /**
         * Checksum's for each file are generated and are used to create a checksum that is used when
         * publishing to maven central. In order to retry a failed publish without needing to change any
         * functionality, we need a way to generate a different checksum for the source code. We can
         * change the value of this property which will generate a different checksum for publishing
         * and allow us to retry. The value of `version` doesn't need to be kept up-to-date with the
         * version of the code.
         */
        private const val VERSION = "7.3.0"

        // Constants related to symmetric key crypto.
        const val SYMMETRIC_KEY_ALGORITHM_AES = "AES"
        private const val AES_BLOCK_MODE_CBC = "CBC"
        private const val AES_BLOCK_MODE_GCM = "GCM"
        private const val AES_PADDING_PKCS7 = "PKCS7Padding"
        private const val AES_PADDING_NONE = "NoPadding"
        protected const val AES_CBC_CIPHER =
            "$SYMMETRIC_KEY_ALGORITHM_AES/$AES_BLOCK_MODE_CBC/$AES_PADDING_PKCS7"
        protected const val AES_GCM_CIPHER =
            "$SYMMETRIC_KEY_ALGORITHM_AES/$AES_BLOCK_MODE_GCM/$AES_PADDING_NONE"
        const val SYMMETRIC_KEY_SIZE = 256
        protected const val SYMMETRIC_KEY_ALGORITHM_BLOCK_SIZE = 128
        protected const val SYMMETRIC_KEY_ALGORITHM_TAG_SIZE = 128
        protected const val SYMMETRIC_KEY_ALGORITHM_AES_GCM_IV_SIZE_IN_BYTES = 12
        protected const val SYMMETRIC_KEY_ALGORITHM_BLOCK_SIZE_IN_BYTES =
            SYMMETRIC_KEY_ALGORITHM_BLOCK_SIZE shr 3
        private val DEFAULT_AES_CBC_IV = ByteArray(SYMMETRIC_KEY_ALGORITHM_BLOCK_SIZE_IN_BYTES)
        private val DEFAULT_AES_GCM_IV = ByteArray(SYMMETRIC_KEY_ALGORITHM_AES_GCM_IV_SIZE_IN_BYTES)

        // Constants related to password key crypto.
        protected const val PASSWORD_KEY_SIZE = 256
        protected const val PASSWORD_KEY_ALGORITHM = "PBKDF2WithHmacSHA256" // NOSONAR
        protected const val PASSWORD_DEFAULT_ROUNDS = 10000
        protected const val PASSWORD_SALT_SIZE = 16

        // Constants related to public key crypto.
        protected const val PRIVATE_PUBLIC_KEY_ALGORITHM = "RSA"
        protected const val PRIVATE_PUBLIC_KEY_ALGORITHM_BLOCK_MODE = "ECB"
        protected const val PRIVATE_PUBLIC_KEY_ALGORITHM_ENCRYPTION_PADDING = "PKCS1Padding"
        protected const val PRIVATE_PUBLIC_KEY_CIPHER_PKCS1 =
            "$PRIVATE_PUBLIC_KEY_ALGORITHM/$PRIVATE_PUBLIC_KEY_ALGORITHM_BLOCK_MODE/$PRIVATE_PUBLIC_KEY_ALGORITHM_ENCRYPTION_PADDING"
        protected const val PRIVATE_PUBLIC_KEY_ALGORITHM_ENCRYPTION_PADDING_OAEP =
            "OAEPwithSHA-1andMGF1Padding"
        protected const val PRIVATE_PUBLIC_KEY_CIPHER_OAEP_SHA1 =
            "$PRIVATE_PUBLIC_KEY_ALGORITHM/$PRIVATE_PUBLIC_KEY_ALGORITHM_BLOCK_MODE/$PRIVATE_PUBLIC_KEY_ALGORITHM_ENCRYPTION_PADDING_OAEP"
        protected const val PRIVATE_PUBLIC_KEY_SIZE = 2048
        protected const val PRIVATE_PUBLIC_KEY_SIGNATURE_ALGORITHM = "SHA256withRSA"

        // Constants related to message digest.
        private const val MESSAGE_DIGEST_ALGORITHM = "SHA-256"
        // Constants related to cipher.
        /**
         * For all tested devices chunking into 16384 bytes was successful. If problems arise
         * we can reduce this limit (see CIPHER_CHUNK_SIZE). Note: Reducing the size of the processed
         * chunks will result in slower processing speeds.
         */
        private const val CIPHER_CHUNK_SIZE = 16 * 1024

        // Errors
        private const val PASSWORD_CANT_BE_NULL = "password can't be null." // NOSONAR
        private const val NAME_CANT_BE_NULL = "name can't be null."
        private const val KEY_CANT_BE_NULL = "key can't be null."
        private const val DATA_CANT_BE_NULL = "data can't be null."
        private const val ALGORITHM_CANT_BE_NULL = "algorithm can't be null."
        private const val KEY_FORMAT_CANT_BE_NULL = "key format can't be null."
        private const val KEY_NOT_FOUND = "Key \"%s\" not found."
        private const val FAILED_TO_DECRYPT = "Failed to decrypt using the symmetric key."
        private const val FAILED_TO_ENCRYPT = "Failed to encrypt using the symmetric key."
        private const val FAILED_TO_GET_CIPHER = "Failed to get Cipher."
        private const val FAILED_TO_GENERATE_SYMMETRIC_KEY = "Failed to generate a symmetric key."
        private const val FAILED_SYMMETRIC_KEY_CREATION = "Failed to create password based symmetric key."
        private const val FAILED_PUBLIC_KEY_READ = "Failed to read public key from PEM."
        private const val FAILED_SIGNATURE_GENERATION = "Signature generation failed."
        private const val FAILED_SIGNATURE_VERIFICATION = "Failed to verify the signature."
        private const val FAILED_PUBLIC_KEY_ENCRYPTION = "Failed to encrypt with a public key."
        private const val FAILED_PRIVATE_KEY_DECRYPTION = "Failed to decrypt with a private key."
        private const val FAILED_PUBLIC_KEY_CREATION = "Failed to create a public key from key bytes."
        private const val FAILED_PUBLIC_KEY_SERIALIZATION = "Failed to serialize the public key."
        private const val FAILED_PUBLIC_KEY_CONVERSION = "Failed to convert public key to PEM."

        // Use of encryption is safe here
        private val aesCbcCipher: ThreadLocal<Cipher> = object : ThreadLocal<Cipher>() {
            override fun initialValue(): Cipher {
                return try {
                    Cipher.getInstance(AES_CBC_CIPHER)
                } catch (e: Exception) {
                    throw RuntimeException(e)
                }
            }
        }

        // Use of encryption is safe here
        private val aesGcmCipher: ThreadLocal<Cipher> = object : ThreadLocal<Cipher>() {
            override fun initialValue(): Cipher {
                return try {
                    Cipher.getInstance(AES_GCM_CIPHER)
                } catch (e: Exception) {
                    throw RuntimeException(e)
                }
            }
        }

        // Use of encryption is safe here
        private val privatePublicKeyCipher: ThreadLocal<Map<PublicKeyEncryptionAlgorithm, Cipher>> =
            object : ThreadLocal<Map<PublicKeyEncryptionAlgorithm, Cipher>>() {
                override fun initialValue(): Map<PublicKeyEncryptionAlgorithm, Cipher> {
                    return try {
                        val ciphers = EnumMap<PublicKeyEncryptionAlgorithm, Cipher>(
                            PublicKeyEncryptionAlgorithm::class.java,
                        )
                        ciphers[PublicKeyEncryptionAlgorithm.RSA_ECB_PKCS1] = Cipher.getInstance(
                            PRIVATE_PUBLIC_KEY_CIPHER_PKCS1,
                        )
                        ciphers[PublicKeyEncryptionAlgorithm.RSA_ECB_OAEPSHA1] = Cipher.getInstance(
                            PRIVATE_PUBLIC_KEY_CIPHER_OAEP_SHA1,
                        )
                        ciphers
                    } catch (e: Exception) {
                        throw RuntimeException(e)
                    }
                }
            }

        private fun getCipher(algorithm: PublicKeyEncryptionAlgorithm): Cipher? {
            return if (algorithm == PublicKeyEncryptionAlgorithm.RSA_ECB_OAEPSHA1) {
                privatePublicKeyCipher.get()?.get(PublicKeyEncryptionAlgorithm.RSA_ECB_OAEPSHA1)
            } else {
                privatePublicKeyCipher.get()?.get(PublicKeyEncryptionAlgorithm.RSA_ECB_PKCS1)
            }
        }
    }
}
