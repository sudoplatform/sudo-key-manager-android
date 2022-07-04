package com.sudoplatform.sudokeymanager;

import java.io.InputStream;
import java.util.List;
import java.util.Map;

/**
 * Interface encapsulating a set of methods for securely storing keys and performing cryptographic
 * operations.
 */
public interface KeyManagerInterface extends AutoCloseable {

    /** The public key encryption algorithms supported by KeyManagerAndroid kit */
    enum PublicKeyEncryptionAlgorithm {
        RSA_ECB_PKCS1,
        RSA_ECB_OAEPSHA1;
    }

    /** The symmetric encryption algorithms supported by KeyManagerAndroid kit */
    enum SymmetricEncryptionAlgorithm {
        AES_CBC_PKCS7_256,
        AES_GCM_256;
    }

    /**
     * Adds a password or other generic data to the secure store.
     *
     * @param password password or other data to store securely.
     * @param name name of the secure data to store.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    void addPassword(byte[] password, String name) throws KeyManagerException;

    /**
     * Adds a password or other generic data to the secure store.
     *
     * @param password password or other data to store securely.
     * @param name name of the secure data to store.
     * @param isExportable indicates whether or not the password is exportable.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    void addPassword(byte[] password, String name, boolean isExportable) throws KeyManagerException;

    /**
     * Retrieves a password or other generic data from the secure store.
     *
     * @param name name of the secure data to retrieve.
     * @return requested secure data or null if it is not found.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    byte[] getPassword(String name) throws KeyManagerException;

    /**
     * Deletes a password or other generic data from the secure store.
     *
     * @param name name of the secure data to delete.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    void deletePassword(String name) throws KeyManagerException;

    /**
     * Updates a password or other generic data stored in the secure store.
     *
     * @param password updated password.
     * @param name name of the secure data to update.
     */
    void updatePassword(byte[] password, String name);

    /**
     * Generates and securely stores a symmetric key,
     *
     * @param name name of the symmetric key to generate.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    void generateSymmetricKey(String name) throws KeyManagerException;

    /**
     * Generates and securely stores a symmetric key,
     *
     * @param name name of the symmetric key to generate.
     * @param isExportable indicates whether or not the symmetric key is exportable.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    void generateSymmetricKey(String name, boolean isExportable) throws KeyManagerException;

    /**
     * Adds a symmetric key to the secure store.
     *
     * @param key symmetric key to store securely.
     * @param name name of the symmetric key to store.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    void addSymmetricKey(byte[] key, String name) throws KeyManagerException;

    /**
     * Adds a symmetric key to the secure store.
     *
     * @param key symmetric key to store securely.
     * @param name name of the symmetric key to store.
     * @param isExportable indicates whether or not the symmetric key is exportable.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    void addSymmetricKey(byte[] key, String name, boolean isExportable) throws KeyManagerException;

    /**
     * Retrieves a symmetric key from the secure store.
     *
     * @param name name of the symmetric key to retrieve.
     * @return requested symmetric key or null if the key was not found.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    byte[] getSymmetricKeyData(String name) throws KeyManagerException;

    /**
     * Deletes a symmetric key from the secure store.
     *
     * @param name name of the symmetric key to delete.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    void deleteSymmetricKey(String name) throws KeyManagerException;

    /**
     * Encrypts the given data with the specified symmetric key stored in the secure store.
     *
     * @param name name of the symmetric key to use to encrypt.
     * @param data data to encrypt.
     * @return encrypted data.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    byte[] encryptWithSymmetricKey(String name, byte[] data) throws KeyManagerException;

    /**
     * Encrypts the given data with the specified symmetric key stored in the secure store.
     *
     * @param name name of the symmetric key to use to encrypt.
     * @param data data to encrypt.
     * @param algorithm the encryption algorithm to use.
     * @return encrypted data.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    byte[] encryptWithSymmetricKey(String name, byte[] data, SymmetricEncryptionAlgorithm algorithm) throws KeyManagerException;

    /**
     * Encrypts the given data with the specified symmetric key stored in the secure store.
     *
     * @param name name of the symmetric key to use to encrypt.
     * @param data data to encrypt.
     * @param iv initialization vector. Must be 128 bit in size for AES-CBC and 96 for AES-GCM.
     * @return encrypted data.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    byte[] encryptWithSymmetricKey(String name, byte[] data, byte[] iv) throws KeyManagerException;

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
    byte[] encryptWithSymmetricKey(String name, byte[] data, byte[] iv, SymmetricEncryptionAlgorithm algorithm) throws KeyManagerException;

    /**
     * Encrypts the given data with the specified symmetric key stored in the secure store.
     *
     * @param key raw key bytes of the symmetric key to use to encrypt.
     * @param data data to encrypt.
     * @return encrypted data.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    byte[] encryptWithSymmetricKey(byte[] key, byte[] data) throws KeyManagerException;

    /**
     * Encrypts the given data with the specified symmetric key stored in the secure store.
     *
     * @param key raw key bytes of the symmetric key to use to encrypt.
     * @param data data to encrypt.
     * @param algorithm the encryption algorithm to use.
     * @return encrypted data.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    byte[] encryptWithSymmetricKey(byte[] key, byte[] data, SymmetricEncryptionAlgorithm algorithm) throws KeyManagerException;

    /**
     * Encrypts the given data with the specified symmetric key stored in the secure store.
     *
     * @param key raw key bytes of the symmetric key to use to encrypt.
     * @param data data to encrypt.
     * @param iv initialization vector. Must be 128 bit in size for AES-CBC and 96 for AES-GCM.
     * @return encrypted data.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    byte[] encryptWithSymmetricKey(byte[] key, byte[] data, byte[] iv) throws KeyManagerException;

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
    byte[] encryptWithSymmetricKey(byte[] key, byte[] data, byte[] iv, SymmetricEncryptionAlgorithm algorithm) throws KeyManagerException;

    /**
     * Decrypts the given data with the specified symmetric key stored in the secure store.
     *
     * @param name name of the symmetric key to use to decrypt.
     * @param data data to decrypt.
     * @return decrypted data.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    byte[] decryptWithSymmetricKey(String name, byte[] data) throws KeyManagerException;

    /**
     * Decrypts the given data with the specified symmetric key stored in the secure store.
     *
     * @param name name of the symmetric key to use to decrypt.
     * @param data data to decrypt.
     * @param algorithm the decryption algorithm to use.
     * @return decrypted data.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    byte[] decryptWithSymmetricKey(String name, byte[] data, SymmetricEncryptionAlgorithm algorithm) throws KeyManagerException;

    /**
     * Decrypts the given data stream with the specified symmetric key stored in the secure store.
     *
     * @param name name of the symmetric key to use to decrypt.
     * @param stream input stream to decrypt.
     * @return decrypted data stream.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    InputStream decryptWithSymmetricKey(String name, InputStream stream) throws KeyManagerException;

    /**
     * Decrypts the given data stream with the specified symmetric key stored in the secure store.
     *
     * @param name name of the symmetric key to use to decrypt.
     * @param stream input stream to decrypt.
     * @param algorithm the decryption algorithm to use.
     * @return decrypted data stream.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    InputStream decryptWithSymmetricKey(String name, InputStream stream, SymmetricEncryptionAlgorithm algorithm) throws KeyManagerException;

    /**
     * Decrypts the given data with the specified symmetric key stored in the secure store.
     *
     * @param name name of the symmetric key to use to decrypt.
     * @param data data to decrypt.
     * @param iv initialization vector. Must be 128 bit in size for AES-CBC and 96 for AES-GCM.
     * @return decrypted data.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    byte[] decryptWithSymmetricKey(String name, byte[] data, byte[] iv) throws KeyManagerException;

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
    byte[] decryptWithSymmetricKey(String name, byte[] data, byte[] iv, SymmetricEncryptionAlgorithm algorithm) throws KeyManagerException;

    /**
     * Decrypts the given data stream with the specified symmetric key stored in the secure store.
     *
     * @param name name of the symmetric key to use to decrypt.
     * @param stream input stream to decrypt.
     * @param iv initialization vector. Must be 128 bit in size for AES-CBC and 96 for AES-GCM.
     * @return decrypted data stream.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    InputStream decryptWithSymmetricKey(String name, InputStream stream, byte[] iv) throws KeyManagerException;

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
    InputStream decryptWithSymmetricKey(String name, InputStream stream, byte[] iv, SymmetricEncryptionAlgorithm algorithm) throws KeyManagerException;

    /**
     * Decrypts the given data with the specified symmetric key stored in the secure store.
     *
     * @param key raw key bytes of the symmetric key to use to encrypt.
     * @param data data to decrypt.
     * @return decrypted data.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    byte[] decryptWithSymmetricKey(byte[] key, byte[] data) throws KeyManagerException;

    /**
     * Decrypts the given data with the specified symmetric key stored in the secure store.
     *
     * @param key raw key bytes of the symmetric key to use to encrypt.
     * @param data data to decrypt.
     * @param algorithm the decryption algorithm to use.
     * @return decrypted data.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    byte[] decryptWithSymmetricKey(byte[] key, byte[] data, SymmetricEncryptionAlgorithm algorithm) throws KeyManagerException;

    /**
     * Decrypts the given data source with the given symmetric key on the fly.
     *
     * @param key raw key bytes of the symmetric key to use to encrypt.
     * @param source input stream to decrypt.
     * @return decrypted data source.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    InputStream decryptWithSymmetricKey(byte[] key, InputStream source) throws KeyManagerException;

    /**
     * Decrypts the given data source with the given symmetric key on the fly.
     *
     * @param key raw key bytes of the symmetric key to use to encrypt.
     * @param source input stream to decrypt.
     * @param algorithm the decryption algorithm to use.
     * @return decrypted data source.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    InputStream decryptWithSymmetricKey(byte[] key, InputStream source, SymmetricEncryptionAlgorithm algorithm) throws KeyManagerException;

    /**
     * Decrypts the given data stream with the given symmetric key.
     *
     * @param key raw key bytes of the symmetric key to use to encrypt.
     * @param data data to decrypt.
     * @param iv initialization vector. Must be 128 bit in size for AES-CBC and 96 for AES-GCM.
     * @return decrypted data.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    byte[] decryptWithSymmetricKey(byte[] key, byte[] data, byte[] iv) throws KeyManagerException;

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
    byte[] decryptWithSymmetricKey(byte[] key, byte[] data, byte[] iv, SymmetricEncryptionAlgorithm algorithm) throws KeyManagerException;

    /**
     * Decrypts the given data stream with the given symmetric key.
     *
     * @param key symmetric key reference.
     * @param stream data to decrypt.
     * @param iv Initialization vector. Must be 128 bit in size for AES-CBC and 96 for AES-GCM.
     * @return decrypted data stream
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    InputStream decryptWithSymmetricKey(byte[] key, InputStream stream, byte[] iv) throws KeyManagerException;

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
    InputStream decryptWithSymmetricKey(byte[] key, InputStream stream, byte[] iv, SymmetricEncryptionAlgorithm algorithm) throws KeyManagerException;

    /**
     * Creates a symmetric key from the specified password.
     *
     * @param password password.
     * @return key, salt and pseudo-random rounds used to generate the key.
     * @throws KeyManagerException if the key could not be created.
     */
    KeyComponents createSymmetricKeyFromPassword(String password) throws KeyManagerException;

    /**
     * Creates a symmetric key from the specified password.
     *
     * @param password password as String.
     * @param salt salt to use for generating the key.
     * @param rounds number of pseudo-random rounds to use for generating the key.
     * @return generated symmetric key.
     * @throws KeyManagerException if the key could not be created.
     */
    byte[] createSymmetricKeyFromPassword(String password, byte[] salt, int rounds) throws KeyManagerException;

    /**
     * Creates a symmetric key from the specified password.
     *
     * @param password password as character array.
     * @param salt salt to use for generating the key.
     * @param rounds number of pseudo-random rounds to use for generating the key.
     * @return generated symmetric key.
     * @throws KeyManagerException if the key could not be created.
     */
    byte[] createSymmetricKeyFromPassword(char[] password, byte[] salt, int rounds) throws KeyManagerException;

    /**
     * Creates a symmetric key from the specified password.
     *
     * @param password password as byte array.
     * @param salt salt to use for generating the key.
     * @param rounds number of pseudo-random rounds to use for generating the key.
     * @return generated symmetric key.
     * @throws KeyManagerException if the key could not be created.
     */
    byte[] createSymmetricKeyFromPassword(byte[] password, byte[] salt, int rounds) throws KeyManagerException;

    /**
     * Creates a SHA256 hash of the specified data.
     *
     * @param data data to hash.
     * @return hash of the specified data.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    byte[] generateHash(byte[] data) throws KeyManagerException;

    /**
     * Generates and securely stores a key pair for public key cryptography.
     *
     * @param name name of the key pair to generate.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    void generateKeyPair(String name) throws KeyManagerException;

    /**
     * Generates and securely stores a key pair for public key cryptography.
     *
     * @param name name of the key pair to generate.
     * @param isExportable indicates whether or not the key pair is exportable.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    void generateKeyPair(String name, boolean isExportable) throws KeyManagerException;

    /**
     * Adds a private key to the secure store.
     *
     * @param key private key to store securely.
     * @param name name of the private key to store.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    void addPrivateKey(byte[] key, String name) throws KeyManagerException;

    /**
     * Adds a private key to the secure store.
     *
     * @param key private key to store securely.
     * @param name name of the private key to store.
     * @param isExportable indicates whether or not the private key is exportable.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    void addPrivateKey(byte[] key, String name, boolean isExportable) throws KeyManagerException;

    /**
     * Retrieves a private key from the secure store.
     *
     * @param name name of the private key to retrieve.
     * @return requested private key or null if the key was not found.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    byte[] getPrivateKeyData(String name) throws KeyManagerException;

    /**
     * Retrieves a private key from the secure store.
     *
     * @param name name of the private key to retrieve.
     * @return requested private key or null if the key was not found.
     * @throws KeyManagerException if an error occurred while retrieving the key.
     */
    java.security.PrivateKey getPrivateKey(String name) throws KeyManagerException;

    /**
     * Add a public key to the secure store.
     *
     * @param key public key to store securely.
     * @param name name of the public key to store.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    void addPublicKey(byte[] key, String name) throws KeyManagerException;

    /**
     * Add a public key to the secure store.
     *
     * @param key public key to store securely.
     * @param name name of the public key to store.
     * @param isExportable indicates whether or not the public key is exportable.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    void addPublicKey(byte[] key, String name, boolean isExportable) throws KeyManagerException;

    /**
     * Retrieves a public key from the secure store.
     *
     * @param name name of the public key to retrieve.
     * @return requested public key or null if the key was not found.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    byte[] getPublicKeyData(String name) throws KeyManagerException;

    /**
     * Retrieves a platform specific public key reference.
     *
     * @param name name of the public key to retrieve.
     * @return requested public key or null if the key was not found.
     * @throws KeyManagerException if an error occurred while retrieving the key.
     */
    java.security.PublicKey getPublicKey(String name) throws KeyManagerException;

    /**
     * Adds a key pair to the secure store.
     *
     * @param privateKey private key to store securely.
     * @param publicKey public key to store securely.
     * @param name name of the key pair to store.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    void addKeyPair(byte[] privateKey, byte[] publicKey, String name) throws KeyManagerException;

    /**
     * Adds a key pair to the secure store.
     *
     * @param privateKey private key to store securely.
     * @param publicKey public key to store securely.
     * @param name name of the key pair to store.
     * @param isExportable indicates whether or not the key pair is exportable.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    void addKeyPair(byte[] privateKey, byte[] publicKey, String name, boolean isExportable) throws KeyManagerException;

    /**
     * Deletes a key pair from the secure store.
     *
     * @param name name of the key pair to delete.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    void deleteKeyPair(String name) throws KeyManagerException;

    /**
     * Generates a singature for the given data with the specified private key.
     *
     * @param name name of the private key to use for signing.
     * @param data data to sign.
     * @return generated signature.
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    byte[] generateSignatureWithPrivateKey(String name, byte[] data) throws KeyManagerException;

    /**
     * Verifies the signature for the given data.
     *
     * @param name name of the public key to use for verifying the signature.
     * @param data data associated with the signature.
     * @param signature signature to verify.
     * @return true if the signature is valid.
     * @throws KeyManagerException on failure that may contain a java.security exception.
     */
    boolean verifySignatureWithPublicKey(String name, byte[] data, byte[] signature) throws KeyManagerException;

    /**
     * Encrypts the given data with the specified public key.
     *
     * @param name name of the public key to use for encryption.
     * @param data data to encrypt.
     * @return encrypted data.
     * @throws KeyManagerException which might contain an exception from java.security.
     */
    byte[] encryptWithPublicKey(String name, byte[] data) throws KeyManagerException;

    /**
     * Encrypts the given data with the specified public key.
     *
     * @param name name of the public key to use for encryption.
     * @param data data to encrypt.
     * @param algorithm the encryption algorithm to use.
     * @return encrypted data.
     * @throws KeyManagerException which might contain an exception from java.security.
     */
    byte[] encryptWithPublicKey(String name, byte[] data, PublicKeyEncryptionAlgorithm algorithm) throws KeyManagerException;

    /**
     * Decrypts the given data with the specified private key.
     *
     * @param name name of the private key to use for decryption.
     * @param data data to decrypt.
     * @return decrypted data.
     * @throws KeyManagerException which might contain an exception from java.security.
     */
    byte[] decryptWithPrivateKey(String name, byte[] data) throws KeyManagerException;

    /**
     * Decrypts the given data with the specified private key.
     *
     * @param name name of the private key to use for decryption.
     * @param data data to decrypt.
     * @param algorithm the decryption algorithm to use.
     * @return decrypted data.
     * @throws KeyManagerException which might contain an exception from java.security.
     */
    byte[] decryptWithPrivateKey(String name, byte[] data, PublicKeyEncryptionAlgorithm algorithm) throws KeyManagerException;

    /**
     * Creates random data.
     *
     * @param size size (in bytes) of the random data to create.
     * @return random data.
     */
    byte[] createRandomData(int size);

    /**
     * Removes all keys associated with this KeyManager.
     *
     * @throws KeyManagerException on failure which might contain a java.security exception.
     */
    void removeAllKeys() throws KeyManagerException;

    /**
     * Closes the Keymanager freeing any associated system resources.
     *
     * @throws Exception if the closing failed
     */
    @Override
    void close() throws Exception;

    /**
     * Export all the keys.
     *
     * @return a {@link Map} with the key name as the map key and the exported key type and bytes as the value.
     * The map may be empty but it will not be null.
     * @throws StoreNotExportable if the key store does not permit keys to be exported.
     * @throws KeyManagerException if the key cannot be exported from the store.
     */
    List<KeyComponents> exportKeys() throws KeyManagerException;
}
