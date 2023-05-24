/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sudoplatform.sudokeymanager;

import androidx.annotation.Keep;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;

import org.spongycastle.util.encoders.Base64;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.sudoplatform.sudologging.LogLevel;
import com.sudoplatform.sudologging.Logger;
import com.sudoplatform.sudologging.AndroidUtilsLogDriver;

import static com.sudoplatform.sudokeymanager.SecureKeyArchiveException.ARCHIVE_EMPTY;
import static com.sudoplatform.sudokeymanager.SecureKeyArchiveException.FATAL_ERROR;
import static com.sudoplatform.sudokeymanager.SecureKeyArchiveException.INVALID_ARCHIVE_DATA;
import static com.sudoplatform.sudokeymanager.SecureKeyArchiveException.INVALID_PASSWORD;
import static com.sudoplatform.sudokeymanager.SecureKeyArchiveException.MALFORMED_ARCHIVEDATA;
import static com.sudoplatform.sudokeymanager.SecureKeyArchiveException.MALFORMED_KEYSET_DATA;
import static com.sudoplatform.sudokeymanager.SecureKeyArchiveException.VERSION_MISMATCH;


/**
 * A class that can read, write and process an encrypted archive
 * containing a set of cryptographic keys that are themselves
 * encrypted with a symmetric key derived from a password.
 */

public class SecureKeyArchive implements SecureKeyArchiveInterface {

    /** Secure key archive format version */
    private static final int     ARCHIVE_VERSION = 2;

    /** Secure key entry format version */
    private static final int     KEY_VERSION = 1;

    private static final Charset UTF8 = Charset.forName("UTF-8");

    private static final Logger logger = new Logger(
        "SudoKeyManager",
        new AndroidUtilsLogDriver(LogLevel.INFO)
    );

    enum SecureKeyArchiveType {
        INSECURE,
        SECURE;

        @Override
        public String toString() {
            switch (this) {
                case SECURE: return "Secure";
                case INSECURE: return "Insecure";
                default: return null;
            }
        }
    }

    private KeyManagerInterface keyManager;
    private KeyArchive          keyArchive;
    private final Set<String>   excludedKeys = new HashSet<>();
    private final Set<KeyInfo>  keys         = new HashSet<>();
    private final Gson          gson;

    private SecureKeyArchive(KeyManagerInterface keyManager) {
        this.keyManager = keyManager;

        gson = new GsonBuilder()
            .registerTypeAdapter(KeyType.class, new KeyTypeJsonAdapter())
            .disableHtmlEscaping()
            .create();
    }

    private SecureKeyArchive(byte[] archiveData, KeyManagerInterface keyManager) throws SecureKeyArchiveException {
        this(keyManager);

        // Meta info might be needed before the archive is unarchived.
        if (hasValue(archiveData)) {
            loadArchive(archiveData);
        }
    }

    /** Reads the base64 data and converts it to JSON and then deserialises it into a KeyArchive */
    private void loadArchive(byte[] archiveData) throws SecureKeyArchiveException {
        if (hasNoValue(archiveData)) {
            throw new SecureKeyArchiveException(ARCHIVE_EMPTY, "Archive data is empty");
        }
        String keyArchiveJson = new String(Base64.decode(archiveData), UTF8).trim();
        keyArchive = gson.fromJson(keyArchiveJson, KeyArchive.class);
        if (keyArchive == null) {
            throw new SecureKeyArchiveException(MALFORMED_ARCHIVEDATA, "Unable to deserialise the JSON of the archive");
        }
        if (keyArchive.Version != ARCHIVE_VERSION) {
            throw new SecureKeyArchiveException(VERSION_MISMATCH,
                String.format("Version %d in the archive data is incompatible with expected version %d",
                    keyArchive.Version, ARCHIVE_VERSION));
        }
        if (hasNoValue(keyArchive.Type)) {
            // Default to secure archive to account for archives created prior to introduction of `Type`
            // These are secured by default because type was introduced with insecure archives feature.
            keyArchive.Type = SecureKeyArchiveType.SECURE.toString();
        }
    }

    /**
     * Returns an instance of a SecureKeyArchiveInterface.
     *
     * @param keyManager the key manager instance that will be used to encrypt the keys in this archive.
     * @return a secure key archive that uses the nominated key manager.
     */
    public static SecureKeyArchiveInterface getInstance(KeyManagerInterface keyManager) {
        return new SecureKeyArchive(keyManager);
    }

    /**
     * Returns an instance of a SecureKeyArchiveInterface initaliased with the
     * encrypted archive data.
     *
     * @param archiveData: encrypted key archive data.
     * @param keyManager the key manager instance that will be used to encrypt the keys in this archive.
     * @return a secure key archive that uses the nominated key manager.
     * @throws SecureKeyArchiveException if the loading failed with one of the following reasons:
     * {@link SecureKeyArchiveException#MALFORMED_ARCHIVEDATA},
     * {@link SecureKeyArchiveException#FATAL_ERROR}
     */
    public static SecureKeyArchiveInterface getInstance(byte[] archiveData,
                                                        KeyManagerInterface keyManager)
                                                        throws SecureKeyArchiveException {
        return new SecureKeyArchive(archiveData, keyManager);
    }

    /**
     * Loads keys from the secure store into the archive.
     *
     * @throws KeyManagerException if the keys could not be exported.
     * @throws StoreNotExportable if the key store does not permit keys to be exported.
     */
    @Override
    public void loadKeys() throws KeyManagerException {
        List<KeyComponents> exportedKeys = keyManager.exportKeys();
        for (KeyComponents keyComponents : exportedKeys) {
            if (excludedKeys.contains(keyComponents.name)) {
                continue;
            }
            if (hasValue(keyComponents.key)) {
                keys.add(KeyInfo.make(keyComponents.name, keyComponents.keyType, keyComponents.key));
            }
        }
    }

    /**
     * Saves the keys in this archive to the secure store.
     *
     * @throws SecureKeyArchiveException with one of the following reasons:
     * {@link SecureKeyArchiveException#ARCHIVE_EMPTY},
     * {@link SecureKeyArchiveException#FATAL_ERROR}
     */
    @Override
    public void saveKeys() throws SecureKeyArchiveException {
        if (keys.isEmpty()) {
            throw new SecureKeyArchiveException(ARCHIVE_EMPTY, "Key archive is empty. Have you called loadKeys?");
        }
        try {
            // Remove all keys first to avoid any conflicts.
            keyManager.removeAllKeys();
        } catch (KeyManagerException e) {
            throw new SecureKeyArchiveException(FATAL_ERROR, e.toString(), e);
        }
        try {
            Map<String, Set<KeyInfo>> keyPairs = new HashMap<>();
            for (KeyInfo keyInfo : keys) {
                if (keyInfo.Name == null || excludedKeys.contains(keyInfo.Name) ||
                        keyInfo.Type == null || keyInfo.data == null) {
                    continue;
                }
                switch (keyInfo.Type) {
                    case PASSWORD:
                        keyManager.addPassword(keyInfo.data, keyInfo.Name, true);
                        break;
                    case SYMMETRIC_KEY:
                        keyManager.addSymmetricKey(keyInfo.data, keyInfo.Name, true);
                        break;
                    case PRIVATE_KEY:
                    case PUBLIC_KEY:
                        // Collect the public and private keys so they can be matched up into pairs
                        if (!keyPairs.containsKey(keyInfo.Name)) {
                            keyPairs.put(keyInfo.Name, new HashSet<>());
                        }
                        keyPairs.get(keyInfo.Name).add(keyInfo);
                        break;
                    default:
                        break;
                }
            }

            // Match the private and public keys with the same name and add them as a key pair.
            for (Map.Entry<String, Set<KeyInfo>> entry : keyPairs.entrySet()) {
                if (entry.getValue().size() == 2) {
                    // A public and private key
                    addKeyPair(entry.getKey(), entry.getValue());
                } else if (entry.getValue().size() == 1) {
                    // Possibly a public key on its own
                    addKey(entry.getValue());
                } else {
                    throw new AssertionError("Programming error, logic inconsistency 1");
                }
            }
        } catch (KeyManagerException e) {
            throw new SecureKeyArchiveException(FATAL_ERROR, e.toString(), e);
        }
    }

    private void addKeyPair(String keyName, Collection<KeyInfo> keys) throws KeyManagerException {
        KeyInfo publicKey = null;
        KeyInfo privateKey = null;
        for (KeyInfo key : keys) {
            if (key.Type == KeyType.PRIVATE_KEY) {
                privateKey = key;
            } else if (key.Type == KeyType.PUBLIC_KEY) {
                publicKey = key;
            } else {
                throw new AssertionError("Programming error, logic inconsistency 2");
            }
        }
        if (publicKey == null || privateKey == null || !publicKey.Name.equals(privateKey.Name)) {
            throw new AssertionError("Programming error, logic inconsistency 3");
        }
        keyManager.addKeyPair(privateKey.data, publicKey.data, keyName, true);
    }

    private void addKey(Collection<KeyInfo> keys) throws KeyManagerException {
        for (KeyInfo key : keys) {
            if (key.Type == KeyType.PRIVATE_KEY) {
                logger.error("Orphaned private key found in key archive");
            } else if (key.Type == KeyType.PUBLIC_KEY) {
                keyManager.addPublicKey(key.data, key.Name, true);
            } else {
                throw new AssertionError("Programming error, logic inconsistency 4");
            }
        }
    }

    /**
     * Setup the key archive container if needed.
     */
    private void setupKeyArchiveContainer() {
        if (keyArchive == null) {
            keyArchive = new KeyArchive();
        }
    }

    /**
     * Archives, in plaintext, the keys loaded into this archive.
     *
     * @return encrypted archive data.
     * @throws SecureKeyArchiveException with one of the following reasons:
     * {@link SecureKeyArchiveException#ARCHIVE_EMPTY},
     * {@link SecureKeyArchiveException#FATAL_ERROR}
     */
    public byte[] archive() throws SecureKeyArchiveException {
        if (keys.isEmpty()) {
            throw new SecureKeyArchiveException(ARCHIVE_EMPTY, "Key archive is empty. Have you called loadKeys?");
        }
        // Set up the key archive container
        setupKeyArchiveContainer();

        String keysJson = gson.toJson(keys);
        String encodedKeys = new String(Base64.encode(keysJson.getBytes(StandardCharsets.UTF_8)));
        return this.archiveKeys(encodedKeys, SecureKeyArchiveType.INSECURE);
    }

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
    @Override
    public byte[] archive(String password) throws SecureKeyArchiveException {
        if (keys.isEmpty()) {
            throw new SecureKeyArchiveException(ARCHIVE_EMPTY, "Key archive is empty. Have you called loadKeys?");
        }

        setupKeyArchiveContainer();

        // Create a symmetric key from the password for encrypting the keys
        byte[] symmetricKey = null;
        try {
            KeyComponents keyComponents = keyManager.createSymmetricKeyFromPassword(password);
            symmetricKey = keyComponents.key;
            keyArchive.Rounds = keyComponents.rounds;
            keyArchive.Salt = new String(Base64.encode(keyComponents.salt), UTF8);
        } catch (KeyManagerException e) {
            throw new SecureKeyArchiveException(INVALID_PASSWORD,
                    "Unable to create a key from the password", e);
        }

        // Convert the array of keys to JSON and then encrypt them
        try {
            String keysJson = gson.toJson(keys);
            byte[] keysEncrypted = keyManager.encryptWithSymmetricKey(symmetricKey, keysJson.getBytes(UTF8));
            String encodedKeys = new String(Base64.encode(keysEncrypted));
            return this.archiveKeys(encodedKeys, SecureKeyArchiveType.SECURE);
        } catch (KeyManagerException e) {
            throw new SecureKeyArchiveException(INVALID_PASSWORD,
                    "Unable to encrypt the keys with the password", e);
        }
    }

    /**
     * Internal function to build a key archive for export
     * @param keysJson Base64 encoded keys json. Could be encrypted or plaintext.
     * @param type Archive type, secure or insecure.
     * @return key archive
     */
    private byte[] archiveKeys(String keysJson, SecureKeyArchiveType type) {
        // add values to archive
        keyArchive.Version = ARCHIVE_VERSION;
        keyArchive.Type = type.toString();
        keyArchive.Keys = keysJson;

        // Convert the entire keyArchive to JSON and base64 encode it.
        String keyArchiveJson = gson.toJson(keyArchive);
        return Base64.encode(keyArchiveJson.getBytes(UTF8));
    }

    /**
     * Unarchives plaintext keys in this archive.
     *
     * @throws SecureKeyArchiveException with one of the following reasons:
     * {@link SecureKeyArchiveException#ARCHIVE_EMPTY},
     * {@link SecureKeyArchiveException#INVALID_ARCHIVE_DATA},
     * {@link SecureKeyArchiveException#FATAL_ERROR}
     */
    public void unarchive() throws SecureKeyArchiveException {
        byte[] keyData = this.decodeKeyData();
        String keyArrayJson = new String(keyData);
        this.loadKeysFromDecodedPayload(keyArrayJson);
    }

    /**
     * Decrypts and unarchives the keys in this archive.
     *
     * @param password the password to use to decrypt the archive.
     * @throws SecureKeyArchiveException with one of the following reasons:
     * {@link SecureKeyArchiveException#INVALID_PASSWORD},
     * {@link SecureKeyArchiveException#ARCHIVE_EMPTY},
     * {@link SecureKeyArchiveException#INVALID_ARCHIVE_DATA},
     * {@link SecureKeyArchiveException#MALFORMED_ARCHIVEDATA},
     * {@link SecureKeyArchiveException#FATAL_ERROR}
     */
    @Override
    public void unarchive(String password) throws SecureKeyArchiveException {
        // Fetch decoded key data first before doing encryption work so this can fail early
        byte[] keyDataEncrypted = this.decodeKeyData();

        // Validate decryption inputs and generate a key
        if (hasNoValue(keyArchive.Salt) || keyArchive.Rounds < 1) {
            throw new SecureKeyArchiveException(INVALID_ARCHIVE_DATA, "The archive lacks a Salt or Rounds value.");
        }

        if (hasNoValue(password)) {
            throw new SecureKeyArchiveException(INVALID_PASSWORD, "Invalid password, it must not be null or empty.");
        }

        byte[] salt = Base64.decode(keyArchive.Salt);

        byte[] symmetricKey = null;
        try {
            symmetricKey = keyManager.createSymmetricKeyFromPassword(password, salt, keyArchive.Rounds);
        } catch (KeyManagerException e) {
            throw new SecureKeyArchiveException(INVALID_PASSWORD,
                    "Unable to create a key from the password", e);
        }

        try {
            // decrypt payload and load keys when finished
            byte[] iv = null;
            if (hasValue(keyArchive.IV)) {
                iv = Base64.decode(keyArchive.IV);
            }
            byte[] keyDataClear;
            if (iv != null) {
                keyDataClear = keyManager.decryptWithSymmetricKey(symmetricKey, keyDataEncrypted, iv);
            } else {
                keyDataClear = keyManager.decryptWithSymmetricKey(symmetricKey, keyDataEncrypted);
            }
            String keyArrayJson = new String(keyDataClear);
            this.loadKeysFromDecodedPayload(keyArrayJson);
        } catch (KeyManagerException e) {
            throw new SecureKeyArchiveException(MALFORMED_KEYSET_DATA,
                    "Unable to decrypt keys from the archive", e);
        }
    }

    /**
     * Internal function to decode and validate keys in the key archive. This is part of multi-step
     * process to load keys from an archive.
     * @return
     * @throws SecureKeyArchiveException
     */
    private byte[] decodeKeyData() throws SecureKeyArchiveException {
        if (hasNoValue(keyArchive.Keys)) {
            throw new SecureKeyArchiveException(INVALID_ARCHIVE_DATA, "The Keys in the archive are empty");
        }

        byte[] keyData = Base64.decode(keyArchive.Keys);
        if (hasNoValue(keyData)) {
            throw new SecureKeyArchiveException(INVALID_ARCHIVE_DATA, "The Keys in the archive, after base64 decoding, are empty");
        }

        return keyData;
    }

    /**
     * Internal function to load decoded (possibly decrypted) keyarchive json data.
     * Part of a multi-step process to load keys from an archive.
     * @param keyArrayJson
     * @throws SecureKeyArchiveException
     */
    private void loadKeysFromDecodedPayload(String keyArrayJson) throws SecureKeyArchiveException {
        KeyInfo[] keyInfoArray = gson.fromJson(keyArrayJson, KeyInfo[].class);
        if (keyInfoArray == null) {
            throw new SecureKeyArchiveException(MALFORMED_KEYSET_DATA,
                    "Unable to deserialise decrypted keys from the archive");
        }
        keys.clear();
        for (KeyInfo keyInfo : keyInfoArray) {
            keyInfo.data = Base64.decode(keyInfo.base64Data);
            keys.add(keyInfo);
        }
    }

    /**
     * Resets the archive by clearing loaded keys and archive data.
     */
    @Override
    public void reset() {
        keys.clear();
        keyArchive = null;
    }

    /**
     * Determines whether or not the archive contains the key with the
     * specified name and type. The archive must be unarchived before the
     * key can be searched.
     *
     * @param name the key name.
     * @param type the key type.
     * @return true if the specified key exists in the archive.
     */
    @Override
    public boolean containsKey(String name, KeyType type) {
        return findKey(name, type) != null;
    }

    private KeyInfo findKey(String name, KeyType type) {
        for (KeyInfo keyInfo : keys) {
            if (keyInfo.Name.equals(name) && keyInfo.Type == type) {
                return keyInfo;
            }
        }
        return null;
    }

    /**
     * Retrieves the specified key data from the archive. The archive must
     * be unarchived before the key data can be retrieved.
     *
     * @param name the key name.
     * @param type the key type.
     * @return a byte array containing the specified key data or null if it was not found.
     */
    @Override
    public byte[] getKeyData(String name, KeyType type) {
        KeyInfo keyInfo = findKey(name, type);
        return keyInfo != null ? keyInfo.data : null;
    }

    /** @return the Key manager used for managing keys and performing cryptographic operations. */
    @Override
    public KeyManagerInterface getKeyManager() {
        return keyManager;
    }

    /**
     * Sets the Key manager used for managing keys and performing cryptographic operations.
     *
     * @param keyManager the Key manager used for managing keys and performing cryptographic operations.
     */
    @Override
    public void setKeyManager(KeyManagerInterface keyManager) {
        this.keyManager = keyManager;
    }

    /** @return the key names to exclude from the archive. */
    @Override
    public Set<String> getExcludedKeys() {
        return Collections.unmodifiableSet(excludedKeys);
    }

    /**
     * Sets the key names to exclude from the archive.
     *
     * @param excludedKeys the key names to exclude from the archive.
     */
    @Override
    public void setExcludedKeys(Set<String> excludedKeys) {
        this.excludedKeys.clear();
        this.excludedKeys.addAll(excludedKeys);
    }

    /** @return the meta-information associated with this archive. */
    @Override
    public Map<String, String> getMetaInfo() {
        if (keyArchive == null || keyArchive.MetaInfo == null) {
            return Collections.emptyMap();
        }
        return Collections.unmodifiableMap(keyArchive.MetaInfo);
    }

    /**
     * Sets the meta-information associated with this archive.
     *
     * @param metaInfo the meta-information associated with this archive.
     */
    @Override
    public void setMetaInfo(Map<String, String> metaInfo) {
        setupKeyArchiveContainer();
        if (keyArchive.MetaInfo == null) {
            keyArchive.MetaInfo = new HashMap<>();
        }
        keyArchive.MetaInfo.clear();
        keyArchive.MetaInfo.putAll(metaInfo);
    }

    /** @return the archive version. */
    @Override
    public int getVersion() {
        return ARCHIVE_VERSION;
    }

    /**
     * @return the type of archive, secure or insecure. Must read archive first by calling `unarchive`, otherwise returns null.
     */
    public String getType() {
        if (keyArchive == null) {
            // type only makes sense in the context of a archive that has been read by
            // calling unarchive and null seems the best response as there isn't a value.
            return null;
        }
        return keyArchive.Type;
    }

    /** The JSON format of the key archive when converted by Gson */
    @Keep
    private static final class KeyArchive {
        Map<String, String> MetaInfo;
        int                 Rounds;
        String              Salt;
        String              Keys;
        String              IV;
        int                 Version;
        String              Type;
    }

    /** The JSON format of a single key within the archive when converted by Gson */
    @Keep
    private static final class KeyInfo {
        int     Version;
        boolean Synchronizable;
        String  NameSpace;
        KeyType Type;
        String  Name;
        @SerializedName("Data")
        String  base64Data;
        @SerializedName("data")
        byte[]  data;

        private static KeyInfo make(String name, KeyType keyType, byte[] data) {
            KeyInfo keyInfo = new KeyInfo();
            keyInfo.Name = name;
            keyInfo.Type = keyType;
            keyInfo.data = Arrays.copyOf(data, data.length);
            keyInfo.base64Data = new String(Base64.encode(keyInfo.data), UTF8);
            keyInfo.Version = KEY_VERSION;
            keyInfo.Synchronizable = false;
            return keyInfo;
        }

        @Override
        public String toString() {
            final StringBuilder sb = new StringBuilder(getClass().getSimpleName());
            sb.append("{ Version=").append(Version);
            sb.append(", Synchronizable=").append(Synchronizable);
            sb.append(", NameSpace='").append(NameSpace).append('\'');
            sb.append(", Type='").append(Type).append('\'');
            sb.append(", Name='").append(Name).append('\'');
            sb.append(", Data='").append(base64Data).append('\'');
            sb.append(", data.len='").append(data != null ? data.length : 0).append('\'');
            sb.append('}');
            return sb.toString();
        }
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder(getClass().getSimpleName());
        sb.append("{ keyArchive=").append(keyArchive);
        sb.append(", excludedKeys=").append(excludedKeys);
        sb.append(", keys=").append(keys);
        sb.append('}');
        return sb.toString();
    }

    private final boolean hasValue(String s) {
        // I would have used !TextUtils.isEmpty(s) but it isn't available in unit tests
        return s != null && !s.isEmpty();
    }

    private final boolean hasNoValue(String s) {
        return !hasValue(s);
    }

    private final boolean hasValue(byte[] b) {
        return b != null && b.length > 0;
    }

    private final boolean hasNoValue(byte[] b) {
        return !hasValue(b);
    }
}
