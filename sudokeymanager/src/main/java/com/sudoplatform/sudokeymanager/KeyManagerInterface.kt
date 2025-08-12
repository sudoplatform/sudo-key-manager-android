/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sudoplatform.sudokeymanager

import java.io.InputStream
import java.security.PrivateKey
import java.security.PublicKey

/**
 * Interface encapsulating a set of methods for securely storing keys and performing cryptographic
 * operations.
 */
interface KeyManagerInterface : AutoCloseable {
    /** The public key encryption algorithms supported by KeyManagerAndroid kit  */
    enum class PublicKeyEncryptionAlgorithm {
        RSA_ECB_PKCS1,
        RSA_ECB_OAEPSHA1,
    }

    /** The public key formats supported by KeyManagerAndroid kit  */
    enum class PublicKeyFormat {
        RSA_PUBLIC_KEY,
        SPKI,
    }

    /** The symmetric encryption algorithms supported by KeyManagerAndroid kit  */
    enum class SymmetricEncryptionAlgorithm {
        AES_CBC_PKCS7_256,
        AES_GCM_256,
    }

    /**
     * Adds a password or other generic data to the secure store.
     *
     * @param password password or other data to store securely.
     * @param name name of the secure data to store.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun addPassword(
        password: ByteArray,
        name: String,
    )

    /**
     * Adds a password or other generic data to the secure store.
     *
     * @param password password or other data to store securely.
     * @param name name of the secure data to store.
     * @param isExportable indicates whether or not the password is exportable.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun addPassword(
        password: ByteArray,
        name: String,
        isExportable: Boolean,
    )

    /**
     * Retrieves a password or other generic data from the secure store.
     *
     * @param name name of the secure data to retrieve.
     * @return requested secure data or null if it is not found.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun getPassword(name: String): ByteArray?

    /**
     * Deletes a password or other generic data from the secure store.
     *
     * @param name name of the secure data to delete.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun deletePassword(name: String)

    /**
     * Updates a password or other generic data stored in the secure store.
     *
     * @param password updated password.
     * @param name name of the secure data to update.
     */
    fun updatePassword(
        password: ByteArray,
        name: String,
    )

    /**
     * Generates and securely stores a symmetric key,
     *
     * @param name name of the symmetric key to generate.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun generateSymmetricKey(name: String)

    /**
     * Generates and securely stores a symmetric key,
     *
     * @param name name of the symmetric key to generate.
     * @param isExportable indicates whether or not the symmetric key is exportable.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun generateSymmetricKey(
        name: String,
        isExportable: Boolean,
    )

    /**
     * Adds a symmetric key to the secure store.
     *
     * @param key symmetric key to store securely.
     * @param name name of the symmetric key to store.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun addSymmetricKey(
        key: ByteArray,
        name: String,
    )

    /**
     * Adds a symmetric key to the secure store.
     *
     * @param key symmetric key to store securely.
     * @param name name of the symmetric key to store.
     * @param isExportable indicates whether or not the symmetric key is exportable.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun addSymmetricKey(
        key: ByteArray,
        name: String,
        isExportable: Boolean,
    )

    /**
     * Retrieves a symmetric key from the secure store.
     *
     * @param name name of the symmetric key to retrieve.
     * @return requested symmetric key or null if the key was not found.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun getSymmetricKeyData(name: String): ByteArray?

    /**
     * Deletes a symmetric key from the secure store.
     *
     * @param name name of the symmetric key to delete.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun deleteSymmetricKey(name: String)

    /**
     * Encrypts the given data with the specified symmetric key stored in the secure store.
     *
     * @param name name of the symmetric key to use to encrypt.
     * @param data data to encrypt.
     * @return encrypted data.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun encryptWithSymmetricKey(
        name: String,
        data: ByteArray,
    ): ByteArray

    /**
     * Encrypts the given data with the specified symmetric key stored in the secure store.
     *
     * @param name name of the symmetric key to use to encrypt.
     * @param data data to encrypt.
     * @param algorithm the encryption algorithm to use.
     * @return encrypted data.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun encryptWithSymmetricKey(
        name: String,
        data: ByteArray,
        algorithm: SymmetricEncryptionAlgorithm,
    ): ByteArray

    /**
     * Encrypts the given data with the specified symmetric key stored in the secure store.
     *
     * @param name name of the symmetric key to use to encrypt.
     * @param data data to encrypt.
     * @param iv initialization vector. Must be 128 bit in size for AES-CBC and 96 for AES-GCM.
     * @return encrypted data.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun encryptWithSymmetricKey(
        name: String,
        data: ByteArray,
        iv: ByteArray,
    ): ByteArray

    /**
     * Encrypts the given data with the specified symmetric key stored in the secure store.
     *
     * @param name name of the symmetric key to use to encrypt.
     * @param data data to encrypt.
     * @param iv initialization vector. Must be 128 bit in size for AES-CBC and 96 for AES-GCM.
     * @param algorithm the encryption algorithm to use.
     * @return encrypted data.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun encryptWithSymmetricKey(
        name: String,
        data: ByteArray,
        iv: ByteArray,
        algorithm: SymmetricEncryptionAlgorithm,
    ): ByteArray

    /**
     * Encrypts the given data with the specified symmetric key stored in the secure store.
     *
     * @param key raw key bytes of the symmetric key to use to encrypt.
     * @param data data to encrypt.
     * @return encrypted data.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun encryptWithSymmetricKey(
        key: ByteArray,
        data: ByteArray,
    ): ByteArray

    /**
     * Encrypts the given data with the specified symmetric key stored in the secure store.
     *
     * @param key raw key bytes of the symmetric key to use to encrypt.
     * @param data data to encrypt.
     * @param algorithm the encryption algorithm to use.
     * @return encrypted data.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun encryptWithSymmetricKey(
        key: ByteArray,
        data: ByteArray,
        algorithm: SymmetricEncryptionAlgorithm,
    ): ByteArray

    /**
     * Encrypts the given data with the specified symmetric key stored in the secure store.
     *
     * @param key raw key bytes of the symmetric key to use to encrypt.
     * @param data data to encrypt.
     * @param iv initialization vector. Must be 128 bit in size for AES-CBC and 96 for AES-GCM.
     * @return encrypted data.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun encryptWithSymmetricKey(
        key: ByteArray,
        data: ByteArray,
        iv: ByteArray,
    ): ByteArray

    /**
     * Encrypts the given data with the specified symmetric key stored in the secure store.
     *
     * @param key raw key bytes of the symmetric key to use to encrypt.
     * @param data data to encrypt.
     * @param iv initialization vector. Must be 128 bit in size for AES-CBC and 96 for AES-GCM.
     * @param algorithm the encryption algorithm to use.
     * @return encrypted data.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun encryptWithSymmetricKey(
        key: ByteArray,
        data: ByteArray,
        iv: ByteArray,
        algorithm: SymmetricEncryptionAlgorithm,
    ): ByteArray

    /**
     * Decrypts the given data with the specified symmetric key stored in the secure store.
     *
     * @param name name of the symmetric key to use to decrypt.
     * @param data data to decrypt.
     * @return decrypted data.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun decryptWithSymmetricKey(
        name: String,
        data: ByteArray,
    ): ByteArray

    /**
     * Decrypts the given data with the specified symmetric key stored in the secure store.
     *
     * @param name name of the symmetric key to use to decrypt.
     * @param data data to decrypt.
     * @param algorithm the decryption algorithm to use.
     * @return decrypted data.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun decryptWithSymmetricKey(
        name: String,
        data: ByteArray,
        algorithm: SymmetricEncryptionAlgorithm,
    ): ByteArray

    /**
     * Decrypts the given data stream with the specified symmetric key stored in the secure store.
     *
     * @param name name of the symmetric key to use to decrypt.
     * @param stream input stream to decrypt.
     * @return decrypted data stream.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun decryptWithSymmetricKey(
        name: String,
        stream: InputStream,
    ): InputStream

    /**
     * Decrypts the given data stream with the specified symmetric key stored in the secure store.
     *
     * @param name name of the symmetric key to use to decrypt.
     * @param stream input stream to decrypt.
     * @param algorithm the decryption algorithm to use.
     * @return decrypted data stream.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun decryptWithSymmetricKey(
        name: String,
        stream: InputStream,
        algorithm: SymmetricEncryptionAlgorithm,
    ): InputStream

    /**
     * Decrypts the given data with the specified symmetric key stored in the secure store.
     *
     * @param name name of the symmetric key to use to decrypt.
     * @param data data to decrypt.
     * @param iv initialization vector. Must be 128 bit in size for AES-CBC and 96 for AES-GCM.
     * @return decrypted data.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun decryptWithSymmetricKey(
        name: String,
        data: ByteArray,
        iv: ByteArray,
    ): ByteArray

    /**
     * Decrypts the given data with the specified symmetric key stored in the secure store.
     *
     * @param name name of the symmetric key to use to decrypt.
     * @param data data to decrypt.
     * @param iv initialization vector. Must be 128 bit in size for AES-CBC and 96 for AES-GCM.
     * @param algorithm the decryption algorithm to use.
     * @return decrypted data.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun decryptWithSymmetricKey(
        name: String,
        data: ByteArray,
        iv: ByteArray,
        algorithm: SymmetricEncryptionAlgorithm,
    ): ByteArray

    /**
     * Decrypts the given data stream with the specified symmetric key stored in the secure store.
     *
     * @param name name of the symmetric key to use to decrypt.
     * @param stream input stream to decrypt.
     * @param iv initialization vector. Must be 128 bit in size for AES-CBC and 96 for AES-GCM.
     * @return decrypted data stream.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun decryptWithSymmetricKey(
        name: String,
        stream: InputStream,
        iv: ByteArray,
    ): InputStream

    /**
     * Decrypts the given data stream with the specified symmetric key stored in the secure store.
     *
     * @param name name of the symmetric key to use to decrypt.
     * @param stream input stream to decrypt.
     * @param iv initialization vector. Must be 128 bit in size for AES-CBC and 96 for AES-GCM.
     * @param algorithm the decryption algorithm to use.
     * @return decrypted data stream.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun decryptWithSymmetricKey(
        name: String,
        stream: InputStream,
        iv: ByteArray,
        algorithm: SymmetricEncryptionAlgorithm,
    ): InputStream

    /**
     * Decrypts the given data with the specified symmetric key stored in the secure store.
     *
     * @param key raw key bytes of the symmetric key to use to encrypt.
     * @param data data to decrypt.
     * @return decrypted data.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun decryptWithSymmetricKey(
        key: ByteArray,
        data: ByteArray,
    ): ByteArray

    /**
     * Decrypts the given data with the specified symmetric key stored in the secure store.
     *
     * @param key raw key bytes of the symmetric key to use to encrypt.
     * @param data data to decrypt.
     * @param algorithm the decryption algorithm to use.
     * @return decrypted data.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun decryptWithSymmetricKey(
        key: ByteArray,
        data: ByteArray,
        algorithm: SymmetricEncryptionAlgorithm,
    ): ByteArray

    /**
     * Decrypts the given data source with the given symmetric key on the fly.
     *
     * @param key raw key bytes of the symmetric key to use to encrypt.
     * @param source input stream to decrypt.
     * @return decrypted data source.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun decryptWithSymmetricKey(
        key: ByteArray,
        source: InputStream,
    ): InputStream

    /**
     * Decrypts the given data source with the given symmetric key on the fly.
     *
     * @param key raw key bytes of the symmetric key to use to encrypt.
     * @param source input stream to decrypt.
     * @param algorithm the decryption algorithm to use.
     * @return decrypted data source.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun decryptWithSymmetricKey(
        key: ByteArray,
        source: InputStream,
        algorithm: SymmetricEncryptionAlgorithm,
    ): InputStream

    /**
     * Decrypts the given data stream with the given symmetric key.
     *
     * @param key raw key bytes of the symmetric key to use to encrypt.
     * @param data data to decrypt.
     * @param iv initialization vector. Must be 128 bit in size for AES-CBC and 96 for AES-GCM.
     * @return decrypted data.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun decryptWithSymmetricKey(
        key: ByteArray,
        data: ByteArray,
        iv: ByteArray,
    ): ByteArray

    /**
     * Decrypts the given data stream with the given symmetric key.
     *
     * @param key raw key bytes of the symmetric key to use to encrypt.
     * @param data data to decrypt.
     * @param iv initialization vector. Must be 128 bit in size for AES-CBC and 96 for AES-GCM.
     * @param algorithm the decryption algorithm to use.
     * @return decrypted data.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun decryptWithSymmetricKey(
        key: ByteArray,
        data: ByteArray,
        iv: ByteArray,
        algorithm: SymmetricEncryptionAlgorithm,
    ): ByteArray

    /**
     * Decrypts the given data stream with the given symmetric key.
     *
     * @param key symmetric key reference.
     * @param stream data to decrypt.
     * @param iv Initialization vector. Must be 128 bit in size for AES-CBC and 96 for AES-GCM.
     * @return decrypted data stream
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun decryptWithSymmetricKey(
        key: ByteArray,
        stream: InputStream,
        iv: ByteArray,
    ): InputStream

    /**
     * Decrypts the given data stream with the given symmetric key.
     *
     * @param key symmetric key reference.
     * @param stream data to decrypt.
     * @param iv Initialization vector. Must be 128 bit in size for AES-CBC and 96 for AES-GCM.
     * @param algorithm the decryption algorithm to use.
     * @return decrypted data stream
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun decryptWithSymmetricKey(
        key: ByteArray,
        stream: InputStream,
        iv: ByteArray,
        algorithm: SymmetricEncryptionAlgorithm,
    ): InputStream

    /**
     * Creates a symmetric key from the specified password.
     *
     * @param password password.
     * @return key, salt and pseudo-random rounds used to generate the key.
     * @throws KeyManagerException if the key could not be created.
     */
    @Throws(KeyManagerException::class)
    fun createSymmetricKeyFromPassword(password: String): KeyComponents

    /**
     * Creates a symmetric key from the specified password.
     *
     * @param password password as String.
     * @param salt salt to use for generating the key.
     * @param rounds number of pseudo-random rounds to use for generating the key.
     * @return generated symmetric key.
     * @throws KeyManagerException if the key could not be created.
     */
    @Throws(KeyManagerException::class)
    fun createSymmetricKeyFromPassword(
        password: String,
        salt: ByteArray,
        rounds: Int,
    ): ByteArray

    /**
     * Creates a symmetric key from the specified password.
     *
     * @param password password as character array.
     * @param salt salt to use for generating the key.
     * @param rounds number of pseudo-random rounds to use for generating the key.
     * @return generated symmetric key.
     * @throws KeyManagerException if the key could not be created.
     */
    @Throws(KeyManagerException::class)
    fun createSymmetricKeyFromPassword(
        password: CharArray,
        salt: ByteArray,
        rounds: Int,
    ): ByteArray

    /**
     * Creates a symmetric key from the specified password.
     *
     * @param password password as byte array.
     * @param salt salt to use for generating the key.
     * @param rounds number of pseudo-random rounds to use for generating the key.
     * @return generated symmetric key.
     * @throws KeyManagerException if the key could not be created.
     */
    @Throws(KeyManagerException::class)
    fun createSymmetricKeyFromPassword(
        password: ByteArray,
        salt: ByteArray,
        rounds: Int,
    ): ByteArray

    /**
     * Creates a SHA256 hash of the specified data.
     *
     * @param data data to hash.
     * @return hash of the specified data.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun generateHash(data: ByteArray): ByteArray

    /**
     * Generates and securely stores a key pair for public key cryptography.
     *
     * @param name name of the key pair to generate.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun generateKeyPair(name: String)

    /**
     * Generates and securely stores a key pair for public key cryptography.
     *
     * @param name name of the key pair to generate.
     * @param isExportable indicates whether or not the key pair is exportable.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun generateKeyPair(
        name: String,
        isExportable: Boolean,
    )

    /**
     * Adds a private key to the secure store.
     *
     * @param key private key to store securely.
     * @param name name of the private key to store.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun addPrivateKey(
        key: ByteArray,
        name: String,
    )

    /**
     * Adds a private key to the secure store.
     *
     * @param key private key to store securely.
     * @param name name of the private key to store.
     * @param isExportable indicates whether or not the private key is exportable.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun addPrivateKey(
        key: ByteArray,
        name: String,
        isExportable: Boolean,
    )

    /**
     * Retrieves a private key from the secure store.
     *
     * @param name name of the private key to retrieve.
     * @return requested private key or null if the key was not found.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun getPrivateKeyData(name: String): ByteArray?

    /**
     * Retrieves a private key from the secure store.
     *
     * @param name name of the private key to retrieve.
     * @return requested private key or null if the key was not found.
     * @throws KeyManagerException if an error occurred while retrieving the key.
     */
    @Throws(KeyManagerException::class)
    fun getPrivateKey(name: String): PrivateKey?

    /**
     * Add a public key to the secure store.
     *
     * @param key public key to store securely.
     * @param name name of the public key to store.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun addPublicKey(
        key: ByteArray,
        name: String,
    )

    /**
     * Add a public key to the secure store.
     *
     * @param key public key to store securely.
     * @param name name of the public key to store.
     * @param isExportable indicates whether or not the public key is exportable.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun addPublicKey(
        key: ByteArray,
        name: String,
        isExportable: Boolean,
    )

    /**
     * Add a public key to the secure store from PEM encoded RSAPublicKey.
     *
     * @param key public key to store securely.
     * @param name name of the public key to store.
     * @param isExportable indicates whether or not the public key is exportable.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun addPublicKeyFromPEM(
        key: String,
        name: String,
        isExportable: Boolean,
    )

    /**
     * Retrieves a public key from the secure store.
     *
     * @param name name of the public key to retrieve.
     * @return requested public key or null if the key was not found.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun getPublicKeyData(name: String): ByteArray?

    /**
     * Retrieves a platform specific public key reference.
     *
     * @param name name of the public key to retrieve.
     * @return requested public key or null if the key was not found.
     * @throws KeyManagerException if an error occurred while retrieving the key.
     */
    @Throws(KeyManagerException::class)
    fun getPublicKey(name: String): PublicKey?

    /**
     * Retrieves a public key from the secure store as PEM encoded RSAPublicKey.
     *
     * @param name name of the public key to retrieve.
     * @return requested public key or null if the key was not found.
     * @throws KeyManagerException if an error occurred while retrieving the key.
     */
    @Throws(KeyManagerException::class)
    fun getPublicKeyAsPEM(name: String): String?

    /**
     * Deletes a public key from the secure store.
     * @param name of the public key to delete
     * @throws KeyManagerException if an error occurred while removing the key.
     */
    @Throws(KeyManagerException::class)
    fun deletePublicKey(name: String)

    /**
     * Adds a key pair to the secure store.
     *
     * @param privateKey private key to store securely.
     * @param publicKey public key to store securely.
     * @param name name of the key pair to store.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun addKeyPair(
        privateKey: ByteArray,
        publicKey: ByteArray,
        name: String,
    )

    /**
     * Adds a key pair to the secure store.
     *
     * @param privateKey private key to store securely.
     * @param publicKey public key to store securely.
     * @param name name of the key pair to store.
     * @param isExportable indicates whether or not the key pair is exportable.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun addKeyPair(
        privateKey: ByteArray,
        publicKey: ByteArray,
        name: String,
        isExportable: Boolean,
    )

    /**
     * Adds a key pair to the secure store from PrivateKeyInfo and SubjectPublicKeyInfo.
     *
     * @param privateKey private key to store securely.
     * @param publicKey public key to store securely.
     * @param name name of the key pair to store.
     * @param isExportable indicates whether or not the key pair is exportable.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun addKeyPairFromKeyInfo(
        privateKey: ByteArray,
        publicKey: ByteArray,
        name: String,
        isExportable: Boolean,
    )

    /**
     * Deletes a key pair from the secure store.
     *
     * @param name name of the key pair to delete.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun deleteKeyPair(name: String)

    /**
     * Generates a singature for the given data with the specified private key.
     *
     * @param name name of the private key to use for signing.
     * @param data data to sign.
     * @return generated signature.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun generateSignatureWithPrivateKey(
        name: String,
        data: ByteArray,
    ): ByteArray

    /**
     * Verifies the signature for the given data.
     *
     * @param name name of the public key to use for verifying the signature.
     * @param data data associated with the signature.
     * @param signature signature to verify.
     * @return true if the signature is valid.
     * @throws KeyManagerException on failure that may contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun verifySignatureWithPublicKey(
        name: String,
        data: ByteArray,
        signature: ByteArray,
    ): Boolean

    /**
     * Encrypts the given data with the specified public key.
     *
     * @param name name of the public key to use for encryption.
     * @param data data to encrypt.
     * @return encrypted data.
     * @throws KeyManagerException which might contain an exception from java.security.
     */
    @Throws(KeyManagerException::class)
    fun encryptWithPublicKey(
        name: String,
        data: ByteArray,
    ): ByteArray

    /**
     * Encrypts the given data with the specified public key.
     *
     * @param name name of the public key to use for encryption.
     * @param data data to encrypt.
     * @param algorithm the encryption algorithm to use.
     * @return encrypted data.
     * @throws KeyManagerException which might contain an exception from java.security.
     */
    @Throws(KeyManagerException::class)
    fun encryptWithPublicKey(
        name: String,
        data: ByteArray,
        algorithm: PublicKeyEncryptionAlgorithm,
    ): ByteArray

    /**
     * Encrypts the given data with the specified public key.
     *
     * @param key [ByteArray] Raw key bytes of the public key to use for encryption.
     * The key must be in RSA Public Key format (PKCS#1).
     * @param data [ByteArray] Data to encrypt.
     * @param algorithm [PublicKeyEncryptionAlgorithm] The encryption algorithm to use.
     * @return encrypted data.
     * @throws KeyManagerException Which might contain an exception from java.security.
     */
    @Throws(KeyManagerException::class)
    fun encryptWithPublicKey(
        key: ByteArray,
        data: ByteArray,
        algorithm: PublicKeyEncryptionAlgorithm,
    ): ByteArray = encryptWithPublicKey(key, data, PublicKeyFormat.RSA_PUBLIC_KEY, algorithm)

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
    fun encryptWithPublicKey(
        key: ByteArray,
        data: ByteArray,
        format: PublicKeyFormat,
        algorithm: PublicKeyEncryptionAlgorithm,
    ): ByteArray

    /**
     * Decrypts the given data with the specified private key.
     *
     * @param name name of the private key to use for decryption.
     * @param data data to decrypt.
     * @return decrypted data.
     * @throws KeyManagerException which might contain an exception from java.security.
     */
    @Throws(KeyManagerException::class)
    fun decryptWithPrivateKey(
        name: String,
        data: ByteArray,
    ): ByteArray

    /**
     * Decrypts the given data with the specified private key.
     *
     * @param name name of the private key to use for decryption.
     * @param data data to decrypt.
     * @param algorithm the decryption algorithm to use.
     * @return decrypted data.
     * @throws KeyManagerException which might contain an exception from java.security.
     */
    @Throws(KeyManagerException::class)
    fun decryptWithPrivateKey(
        name: String,
        data: ByteArray,
        algorithm: PublicKeyEncryptionAlgorithm,
    ): ByteArray

    /**
     * Creates random data.
     *
     * @param size size (in bytes) of the random data to create.
     * @return random data.
     */
    fun createRandomData(size: Int): ByteArray

    /**
     * Removes all keys associated with this KeyManager.
     *
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    @Throws(KeyManagerException::class)
    fun removeAllKeys()

    /**
     * Closes the Keymanager freeing any associated system resources.
     *
     * @throws Exception if the closing failed
     */
    @Throws(Exception::class)
    override fun close()

    /**
     * Export all the keys.
     *
     * @return a [Map] with the key name as the map key and the exported key type and bytes as the value.
     * The map may be empty but it will not be null.
     * @throws StoreNotExportable if the key store does not permit keys to be exported.
     * @throws KeyManagerException if the key cannot be exported from the store.
     */
    @Throws(KeyManagerException::class)
    fun exportKeys(): List<KeyComponents>
}
