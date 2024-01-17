/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sudoplatform.sudokeymanager

/**
 * Interface for encrypting and decrypting key data so keys can be stored securely even if it's
 * stored outside a system keystore.
 */
interface SecureKeyDelegateInterface {
    /**
     * Encrypts the specified key.
     *
     * @param key key to encrypt.
     * @return encrypted key.
     * @throws KeyManagerException
     */
    @Throws(KeyManagerException::class)
    fun encryptKey(key: ByteArray): ByteArray

    /**
     * Decrypts the specified key.
     *
     * @param key key to decrypt.
     * @return decrypted key.
     * @throws KeyManagerException
     */
    @Throws(KeyManagerException::class)
    fun decryptKey(key: ByteArray): ByteArray
}
