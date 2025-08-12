/*
 * Copyright © 2024 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sudoplatform.sudokeymanager

import org.spongycastle.asn1.pkcs.PrivateKeyInfo
import org.spongycastle.asn1.pkcs.RSAPrivateKey
import org.spongycastle.asn1.pkcs.RSAPublicKey
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo
import java.io.IOException
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.RSAPrivateCrtKeySpec
import java.security.spec.RSAPublicKeySpec
import java.util.Objects

open class KeyService {
    private var keyFactory: KeyFactory = KeyFactory.getInstance("RSA")

    /**
     * Deserializes encoded PrivateKeyInfo bytes to a PrivateKey object.
     *
     * @param keyBytes encoded key bytes.
     * @return private key object.
     * @throws KeyManagerException on failure, which will probably contain an exception from java.security.
     */
    @Throws(KeyManagerException::class)
    fun keyInfoBytesToPrivateKey(keyBytes: ByteArray): PrivateKey {
        Objects.requireNonNull(keyBytes, KEY_BYTES_NULL_ERROR_MSG)
        val privateKey: PrivateKey =
            try {
                val privateKeyInfoKeyInfo = PrivateKeyInfo.getInstance(keyBytes)
                val pkcs1PrivateKey = RSAPrivateKey.getInstance(privateKeyInfoKeyInfo.parsePrivateKey())
                val modulus = pkcs1PrivateKey.modulus
                val privateExponent = pkcs1PrivateKey.privateExponent
                val publicExponent = pkcs1PrivateKey.publicExponent
                val prime1 = pkcs1PrivateKey.prime1
                val prime2 = pkcs1PrivateKey.prime2
                val exp1 = pkcs1PrivateKey.exponent1
                val exp2 = pkcs1PrivateKey.exponent2
                val coef = pkcs1PrivateKey.coefficient
                val keySpec =
                    RSAPrivateCrtKeySpec(
                        modulus,
                        publicExponent,
                        privateExponent,
                        prime1,
                        prime2,
                        exp1,
                        exp2,
                        coef,
                    )
                keyFactory.generatePrivate(keySpec)
            } catch (e: InvalidKeySpecException) {
                throw KeyManagerException(PRIVATE_KEY_CREATION_ERROR_MSG, e)
            } catch (e: IOException) {
                throw KeyManagerException(PRIVATE_KEY_CREATION_ERROR_MSG, e)
            }
        return privateKey
    }

    /**
     * Serializes a private key object into a byte array. For compatibility with iOS, we are using
     * PKCS1.
     *
     * @param privateKey private key object.
     * @return byte array representing PKCS1 DER encoded private key.
     * @throws KeyManagerException on failure, which will probably contain an exception from java.security.
     */
    @Throws(KeyManagerException::class)
    fun privateKeyToBytes(privateKey: PrivateKey): ByteArray {
        Objects.requireNonNull(privateKey, PRIVATE_KEY_NULL_ERROR_MSG)
        val privateKeyPKCS1: ByteArray =
            try {
                val privateKeyInfo = PrivateKeyInfo.getInstance(privateKey.encoded)
                val privateKeyPKCS1ASN1Encodable = privateKeyInfo.parsePrivateKey()
                val privateKeyPKCS1ASN1 = privateKeyPKCS1ASN1Encodable.toASN1Primitive()
                privateKeyPKCS1ASN1.encoded
            } catch (e: IOException) {
                throw KeyManagerException(PRIVATE_KEY_SERIALIZATION_ERROR_MSG, e)
            }
        return privateKeyPKCS1
    }

    /**
     * Deserializes encoded private key bytes to a PrivateKey object.
     *
     * @param keyBytes encoded key bytes.
     * @return private key object.
     * @throws KeyManagerException on failure, which will probably contain an exception from java.security.
     */
    @Throws(KeyManagerException::class)
    fun bytesToPrivateKey(keyBytes: ByteArray): PrivateKey {
        Objects.requireNonNull(keyBytes, KEY_BYTES_NULL_ERROR_MSG)
        val privateKey: PrivateKey =
            try {
                val pkcs1PrivateKey = RSAPrivateKey.getInstance(keyBytes)
                val modulus = pkcs1PrivateKey.modulus
                val privateExponent = pkcs1PrivateKey.privateExponent
                val publicExponent = pkcs1PrivateKey.publicExponent
                val prime1 = pkcs1PrivateKey.prime1
                val prime2 = pkcs1PrivateKey.prime2
                val exp1 = pkcs1PrivateKey.exponent1
                val exp2 = pkcs1PrivateKey.exponent2
                val coef = pkcs1PrivateKey.coefficient
                val keySpec =
                    RSAPrivateCrtKeySpec(
                        modulus,
                        publicExponent,
                        privateExponent,
                        prime1,
                        prime2,
                        exp1,
                        exp2,
                        coef,
                    )
                keyFactory.generatePrivate(keySpec)
            } catch (e: InvalidKeySpecException) {
                throw KeyManagerException(PRIVATE_KEY_CREATION_ERROR_MSG, e)
            }
        return privateKey
    }

    /**
     * Deserializes encoded SubjectPublicKeyInfo bytes to a PublicKey object.
     *
     * @param keyBytes encoded key bytes.
     * @return public key object.
     * @throws KeyManagerException on failure, which will probably contain an exception from java.security.
     */
    @Throws(KeyManagerException::class)
    fun keyInfoBytesToPublicKey(keyBytes: ByteArray): PublicKey {
        Objects.requireNonNull(keyBytes, KEY_BYTES_NULL_ERROR_MSG)
        val publicKey: PublicKey =
            try {
                val subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(keyBytes)
                val pkcs1PublicKey = RSAPublicKey.getInstance(subjectPublicKeyInfo.parsePublicKey())
                val modulus = pkcs1PublicKey.modulus
                val publicExponent = pkcs1PublicKey.publicExponent
                val keySpec = RSAPublicKeySpec(modulus, publicExponent)
                keyFactory.generatePublic(keySpec)
            } catch (e: InvalidKeySpecException) {
                throw KeyManagerException(PUBLIC_KEY_CREATION_ERROR_MSG, e)
            } catch (e: IOException) {
                throw KeyManagerException(PUBLIC_KEY_CREATION_ERROR_MSG, e)
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
    fun publicKeyToBytes(publicKey: PublicKey): ByteArray {
        Objects.requireNonNull(publicKey, PUBLIC_KEY_NULL_ERROR_MSG)
        val publicKeyPKCS1: ByteArray =
            try {
                val publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.encoded)
                val publicKeyPKCS1ASN1 = publicKeyInfo.parsePublicKey()
                publicKeyPKCS1ASN1.encoded
            } catch (e: IOException) {
                throw KeyManagerException(PUBLIC_KEY_SERIALIZATION_ERROR_MSG, e)
            }
        return publicKeyPKCS1
    }

    companion object {
        // Errors
        private const val PRIVATE_KEY_CREATION_ERROR_MSG = "Failed to create a private key from key bytes."
        private const val PRIVATE_KEY_SERIALIZATION_ERROR_MSG = "Failed to serialize the private key."
        private const val PUBLIC_KEY_CREATION_ERROR_MSG = "Failed to create a public key from key bytes."
        private const val PUBLIC_KEY_SERIALIZATION_ERROR_MSG = "Failed to serialize the private key."
        private const val PUBLIC_KEY_NULL_ERROR_MSG = "publicKey can't be null."
        private const val PRIVATE_KEY_NULL_ERROR_MSG = "privateKey can't be null."
        private const val KEY_BYTES_NULL_ERROR_MSG = "keyBytes can't be null."
    }
}
