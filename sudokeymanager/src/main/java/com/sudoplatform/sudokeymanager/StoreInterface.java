package com.sudoplatform.sudokeymanager;

import java.util.Set;

/**
 * Defines a set of interface for persistent storage and lifecycle management of crytographic keys and
 * secure data.
 */
public interface StoreInterface extends AutoCloseable {

    /**
     * Inserts a new key.
     *
     * @param keyBytes raw key bytes.
     * @param name key name.
     * @param type key type. See {@link com.sudoplatform.sudokeymanager.KeyType}.
     * @param isExportable true if the key should be exportable.
     * @throws KeyManagerException
     */
    void insertKey(byte[] keyBytes, String name, KeyType type, boolean isExportable) throws KeyManagerException;

    /**
     * Updates an existing key.
     *
     * @param keyBytes raw key bytes.
     * @param name key name.
     * @param type key type. See {@link com.sudoplatform.sudokeymanager.KeyType}.
     */
    void updateKey(byte[] keyBytes, String name, KeyType type);

    /**
     * Retrieves the specified key.
     *
     * @param name key name.
     * @param type key type. See {@link com.sudoplatform.sudokeymanager.KeyType}.
     * @return raw key bytes of the specified key. null if the key is not found.
     * @throws KeyManagerException
     */
    byte[] getKey(String name, KeyType type) throws KeyManagerException;

    /**
     * Deletes the specified key.
     *
     * @param name key name.
     * @param type key type. See {@link com.sudoplatform.sudokeymanager.KeyType}.
     * @throws KeyManagerException
     */
    void deleteKey(String name, KeyType type) throws KeyManagerException;

    /**
     * Resets the store by removing all keys.
     *
     * @throws KeyManagerException
     */
    void reset() throws KeyManagerException;

    /**
     * Closes the store and frees up any system resource associated with the store.
     *
     * @throws Exception if closing failed
     */
    @Override
    public void close() throws Exception;

    /**
     * Determines whether or not the store supports exporting keys.
     *
     * @return true if the store supports exporting keys.
     */
    boolean isExportable();

    /**
     * Sets a delegate for encrypting/decrypting the keys stored.
     *
     * @param secureKeyDelegate delegate for securing the keys.
     */
    void setSecureKeyDelegate(SecureKeyDelegateInterface secureKeyDelegate);

    /**
     * Returns the names of the keys in this key store.
     *
     * @return set containing the key names.
     * @throws KeyManagerException if a failure occurred while fetching the key names.
     */
    public Set<String> getKeyNames() throws KeyManagerException;
}
