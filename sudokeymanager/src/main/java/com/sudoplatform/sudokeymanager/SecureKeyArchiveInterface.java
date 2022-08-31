/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sudoplatform.sudokeymanager;

import java.util.Map;
import java.util.Set;

/**
 * A set of methods required for creating and processing an encrypted archive
 * containing a set of cryptographic keys and passwords.
 */
public interface SecureKeyArchiveInterface {

    /**
     * Loads keys from the secure store into the archive.
     *
     * @throws KeyManagerException if the keys could not be exported.
     * @throws StoreNotExportable if the key store does not permit keys to be exported.
     */
    void loadKeys() throws KeyManagerException;

    /**
     * Saves the keys in this archive to the secure store.
     *
     * @throws SecureKeyArchiveException with one of the following reasons:
     * {@link SecureKeyArchiveException#ARCHIVE_EMPTY},
     * {@link SecureKeyArchiveException#FATAL_ERROR}
     */
    void saveKeys() throws SecureKeyArchiveException;

    /**
     * Archives and encrypts the keys loaded into this archive.
     *
     * @param password the password to use to encrypt the archive.
     * @return encrypted archive data.
     * @throws SecureKeyArchiveException with one of the following reasons:
     * {@link SecureKeyArchiveException#INVALID_PASSWORD},
     * {@link SecureKeyArchiveException#ARCHIVE_EMPTY},
     * {@link SecureKeyArchiveException#FATAL_ERROR}
     */
    byte[] archive(String password) throws SecureKeyArchiveException;

    /**
     * Decrypts and unarchives the keys in this archive.
     *
     * @param password the password to use to decrypt the archive.
     * @throws SecureKeyArchiveException with one of the following reasons:
     * {@link SecureKeyArchiveException#INVALID_PASSWORD},
     * {@link SecureKeyArchiveException#ARCHIVE_EMPTY},
     * {@link SecureKeyArchiveException#INVALID_ARCHIVE_DATA},
     * {@link SecureKeyArchiveException#FATAL_ERROR}
     */
    void unarchive(String password) throws SecureKeyArchiveException;

    /**
     * Resets the archive by clearing loaded keys and archive data.
     */
    void reset();

    /**
     * Determines whether or not the archive contains the key with the
     * specified name and type. The archive must be unarchived before the
     * key can be searched.
     *
     * @param name the key name.
     * @param type the key type.
     * @return true if the specified key exists in the archive.
     */
    boolean containsKey(String name, KeyType type);

    /**
     * Retrieves the specified key data from the archive. The archive must
     * be unarchived before the key data can be retrieved.
     *
     * @param name the key name.
     * @param type the key type.
     * @return a byte array containing the specified key data or null if it was not found.
     */
    byte[] getKeyData(String name, KeyType type);

    /** @return the Key manager used for managing keys and performing cryptographic operations. */
    KeyManagerInterface getKeyManager();

    /**
     * Sets the Key manager used for managing keys and performing cryptographic operations.
     *
     * @param keyManager the Key manager used for managing keys and performing cryptographic operations.
     */
    void setKeyManager(KeyManagerInterface keyManager);

    /** @return the key names to exclude from the archive in an unmodifiable set. */
    Set<String> getExcludedKeys();

    /**
     * Sets the key names to exclude from the archive.
     *
     * @param excludedKeys the key names to exclude from the archive.
     */
    void setExcludedKeys(Set<String> excludedKeys);

    /** @return the meta-information associated with this archive in an unmodifiable map. */
    Map<String, String> getMetaInfo();

    /**
     * Sets the meta-information associated with this archive.
     *
     * @param metaInfo the meta-information associated with this archive.
     */
    void setMetaInfo(Map<String, String> metaInfo);

    /** @return the archive version. */
    int getVersion();
}
