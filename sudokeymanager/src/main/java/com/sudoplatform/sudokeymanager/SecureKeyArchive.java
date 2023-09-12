/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sudoplatform.sudokeymanager;

import static com.sudoplatform.sudokeymanager.SecureKeyArchiveException.ARCHIVE_EMPTY;
import static com.sudoplatform.sudokeymanager.SecureKeyArchiveException.FATAL_ERROR;
import static com.sudoplatform.sudokeymanager.SecureKeyArchiveException.INVALID_ARCHIVE_DATA;
import static com.sudoplatform.sudokeymanager.SecureKeyArchiveException.INVALID_PASSWORD;
import static com.sudoplatform.sudokeymanager.SecureKeyArchiveException.MALFORMED_ARCHIVEDATA;
import static com.sudoplatform.sudokeymanager.SecureKeyArchiveException.MALFORMED_KEYSET_DATA;
import static com.sudoplatform.sudokeymanager.SecureKeyArchiveException.VERSION_MISMATCH;

import androidx.annotation.Keep;
import androidx.annotation.NonNull;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.annotations.SerializedName;
import com.google.gson.reflect.TypeToken;
import com.sudoplatform.sudologging.AndroidUtilsLogDriver;
import com.sudoplatform.sudologging.LogLevel;
import com.sudoplatform.sudologging.Logger;

import org.spongycastle.asn1.DERNull;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.pkcs.PrivateKeyInfo;
import org.spongycastle.asn1.pkcs.RSAPrivateKey;
import org.spongycastle.asn1.pkcs.RSAPublicKey;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.util.encoders.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.Deflater;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;


/**
 * A class that can read, write and process an encrypted archive
 * containing a set of cryptographic keys that are themselves
 * encrypted with a symmetric key derived from a password.
 */

public class SecureKeyArchive implements SecureKeyArchiveInterface {

    /**
     * Secure key archive format versions.
     */
    private static final int ARCHIVE_VERSION_V2 = 2;
    private static final int ARCHIVE_VERSION_V3 = 3;

    /**
     * Secure key entry format version
     */
    private static final int KEY_VERSION = 1;

    private static final Charset UTF8 = StandardCharsets.UTF_8;

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
                case SECURE:
                    return "Secure";
                case INSECURE:
                    return "Insecure";
                default:
                    return null;
            }
        }
    }

    private KeyManagerInterface keyManager;
    private KeyArchive keyArchive;
    private final Set<String> excludedKeys = new HashSet<>();
    private final Set<KeyInfo> keys = new HashSet<>();
    private final Gson gson;
    private final boolean zip;

    private SecureKeyArchive(KeyManagerInterface keyManager, boolean zip) {
        this.keyManager = keyManager;
        this.zip = zip;

        this.gson = new GsonBuilder()
                .registerTypeAdapter(KeyType.class, new KeyTypeJsonAdapter())
                .registerTypeAdapter(KeyArchive.class, new KeyArchive.KeyArchiveDeserializer())
                .disableHtmlEscaping()
                .create();
    }

    private SecureKeyArchive(byte[] archiveData, KeyManagerInterface keyManager, boolean zip) throws SecureKeyArchiveException {
        this(keyManager, zip);

        // Meta info might be needed before the archive is unarchived.
        if (hasValue(archiveData)) {
            loadArchive(archiveData);
        }
    }

    /**
     * Gzip decompress the input data
     *
     * @param zipped zipped data.
     * @return unzipped data.
     * @throws IOException
     */
    private byte[] unzip(byte[] zipped) throws IOException {
            byte[] buffer = new byte[1024];
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ByteArrayInputStream bis = new ByteArrayInputStream(zipped);
            GZIPInputStream gzis = new GZIPInputStream(bis);
            int len;
            while ((len = gzis.read(buffer)) > 0) {
                bos.write(buffer, 0, len);
            }

            bis.close();
            gzis.close();
            bos.close();

            return bos.toByteArray();
    }

    /**
     * Gzip compress the input data
     *
     * @param data data to compress.
     * @return zipped data.
     * @throws IOException
     */
    private byte[] zip(byte[] data) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(data.length);
        GZIPOutputStream gzos = new GZIPOutputStream(bos)  {
            {
                this.def.setLevel(Deflater.BEST_COMPRESSION);
            }
        };

        gzos.write(data);

        gzos.close();
        bos.close();

        return bos.toByteArray();
    }

    /**
     * Reads the base64 data and converts it to JSON and then deserialises it into a KeyArchive
     */
    private void loadArchive(byte[] archiveData) throws SecureKeyArchiveException {
        if (hasNoValue(archiveData)) {
            throw new SecureKeyArchiveException(ARCHIVE_EMPTY, "Archive data is empty");
        }

        if(this.getVersion() == ARCHIVE_VERSION_V3) {
            // V3 archive is always gzip compressed so we need decompress it first.
            byte[] unzipped;
            try {
                unzipped = this.unzip(archiveData);
            } catch(IOException e) {
                throw new SecureKeyArchiveException(MALFORMED_ARCHIVEDATA, "Archive data is not a valid gzipped data: " + e.getMessage());
            }

            String keyArchiveJson = new String(unzipped, UTF8);
            keyArchive = gson.fromJson(keyArchiveJson, KeyArchive.class);

            if (keyArchive == null) {
                throw new SecureKeyArchiveException(MALFORMED_ARCHIVEDATA, "Unable to deserialise the JSON of the archive");
            }
            if (keyArchive.Version != ARCHIVE_VERSION_V3) {
                throw new SecureKeyArchiveException(VERSION_MISMATCH,
                        String.format("Version %d in the archive data is incompatible with expected version %d",
                                keyArchive.Version, ARCHIVE_VERSION_V3));
            }
        } else {
            String keyArchiveJson = new String(archiveData, UTF8);
            keyArchive = gson.fromJson(keyArchiveJson, KeyArchive.class);

            if (keyArchive == null) {
                throw new SecureKeyArchiveException(MALFORMED_ARCHIVEDATA, "Unable to deserialise the JSON of the archive");
            }
            if (keyArchive.Version != ARCHIVE_VERSION_V2) {
                throw new SecureKeyArchiveException(VERSION_MISMATCH,
                        String.format("Version %d in the archive data is incompatible with expected version %d",
                                keyArchive.Version, ARCHIVE_VERSION_V2));
            }
            if (hasNoValue(keyArchive.Type)) {
                // Default to secure archive to account for archives created prior to introduction of `Type`
                // These are secured by default because type was introduced with insecure archives feature.
                keyArchive.Type = SecureKeyArchiveType.SECURE.toString();
            }
        }
    }

    /**
     * Returns an instance of a SecureKeyArchiveInterface.
     *
     * @param keyManager the key manager instance that will be used to encrypt the keys in this archive.
     * @return a secure key archive that uses the nominated key manager.
     */
    public static SecureKeyArchiveInterface getInstance(KeyManagerInterface keyManager) {
        return new SecureKeyArchive(keyManager, false);
    }

    /**
     * Returns an instance of a SecureKeyArchiveInterface. This method should be used for
     * creating V3 archive i.e. gzip compressed archive.
     *
     * @param keyManager the key manager instance that will be used to encrypt the keys in this archive.
     * @return a secure key archive that uses the nominated key manager.
     */
    public static SecureKeyArchiveInterface getInstanceV3(KeyManagerInterface keyManager) {
        return new SecureKeyArchive(keyManager, true);
    }

    /**
     * Returns an instance of a SecureKeyArchiveInterface initaliased with the
     * encrypted archive data.
     *
     * @param archiveData: encrypted key archive data.
     * @param keyManager   the key manager instance that will be used to encrypt the keys in this archive.
     * @return a secure key archive that uses the nominated key manager.
     * @throws SecureKeyArchiveException if the loading failed with one of the following reasons:
     *                                   {@link SecureKeyArchiveException#MALFORMED_ARCHIVEDATA},
     *                                   {@link SecureKeyArchiveException#FATAL_ERROR}
     */
    public static SecureKeyArchiveInterface getInstance(byte[] archiveData,
                                                        KeyManagerInterface keyManager)
            throws SecureKeyArchiveException {
        return new SecureKeyArchive(archiveData, keyManager, false);
    }

    /**
     * Returns an instance of a SecureKeyArchiveInterface initaliased with the
     * encrypted archive data. This method should be used when the input archive
     * data is V3 archive i.e. gzip compressed.
     *
     * @param archiveData: encrypted key archive data.
     * @param keyManager   the key manager instance that will be used to encrypt the keys in this archive.
     * @return a secure key archive that uses the nominated key manager.
     * @throws SecureKeyArchiveException if the loading failed with one of the following reasons:
     *                                   {@link SecureKeyArchiveException#MALFORMED_ARCHIVEDATA},
     *                                   {@link SecureKeyArchiveException#FATAL_ERROR}
     */
    public static SecureKeyArchiveInterface getInstanceV3(byte[] archiveData,
                                                          KeyManagerInterface keyManager)
            throws SecureKeyArchiveException {
        return new SecureKeyArchive(archiveData, keyManager, true);
    }

    /**
     * Loads keys from the secure store into the archive.
     *
     * @throws KeyManagerException if the keys could not be exported.
     * @throws StoreNotExportable  if the key store does not permit keys to be exported.
     */
    @Override
    public void loadKeys() throws KeyManagerException {
        List<KeyComponents> exportedKeys = keyManager.exportKeys();
        for (KeyComponents keyComponents : exportedKeys) {
            if (excludedKeys.contains(keyComponents.name)) {
                continue;
            }
            if (hasValue(keyComponents.key)) {
                if(this.getVersion() == ARCHIVE_VERSION_V2) {
                    keys.add(KeyInfo.make(keyComponents.name, keyComponents.keyType, keyComponents.key));
                } else {
                    // If we are dealing with v3 archive then we need to convert the
                    // format of public and private keys since JS SDK uses different
                    // formats.
                    byte[] keyData = keyComponents.key;
                    if(keyComponents.keyType == KeyType.PUBLIC_KEY) {
                        RSAPublicKey rsaPublicKey = RSAPublicKey.getInstance(keyComponents.key);
                        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
                        try {
                            SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(algorithmIdentifier, rsaPublicKey);
                            keyData = subjectPublicKeyInfo.getEncoded();
                        }catch (Exception e) {
                            throw new KeyManagerException("Failed to convert RSAPublicKey to SubjectPublicKeyInfo: " + e.getMessage());
                        }                    } else if(keyComponents.keyType == KeyType.PRIVATE_KEY) {
                        RSAPrivateKey rsaPrivateKey = RSAPrivateKey.getInstance(keyComponents.key);
                        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
                        try {
                            PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(algorithmIdentifier, rsaPrivateKey);
                            keyData = privateKeyInfo.getEncoded();
                        }catch (Exception e) {
                            throw new KeyManagerException("Failed to convert RSAPrivateKey to PrivateKeyInfo: " + e.getMessage());
                        }
                    }
                    keys.add(KeyInfo.make(keyComponents.name, keyComponents.keyType, keyData));
                }
            }
        }
    }

    /**
     * Saves the keys in this archive to the secure store.
     *
     * @throws SecureKeyArchiveException with one of the following reasons:
     *                                   {@link SecureKeyArchiveException#ARCHIVE_EMPTY},
     *                                   {@link SecureKeyArchiveException#FATAL_ERROR}
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

        if(this.getVersion() == ARCHIVE_VERSION_V2) {
            keyManager.addKeyPair(privateKey.data, publicKey.data, keyName, true);
        } else {
            keyManager.addKeyPairFromKeyInfo(privateKey.data, publicKey.data, keyName, true);
        }
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
     *                                   {@link SecureKeyArchiveException#ARCHIVE_EMPTY},
     *                                   {@link SecureKeyArchiveException#FATAL_ERROR}
     */
    public byte[] archive() throws SecureKeyArchiveException {
        if (keys.isEmpty()) {
            throw new SecureKeyArchiveException(ARCHIVE_EMPTY, "Key archive is empty. Have you called loadKeys?");
        }
        // Set up the key archive container
        setupKeyArchiveContainer();

        byte[] data;
        if(this.getVersion() == ARCHIVE_VERSION_V2) {
            String keysJson = gson.toJson(keys);
            String encodedKeys = new String(Base64.encode(keysJson.getBytes(StandardCharsets.UTF_8)));
            keyArchive.Version = ARCHIVE_VERSION_V2;
            data = this.archiveKeys(encodedKeys, SecureKeyArchiveType.INSECURE);
        } else {
            keyArchive.Version = ARCHIVE_VERSION_V3;
            keyArchive.Type = SecureKeyArchiveType.INSECURE.toString();
            keyArchive.KeysAsList = new ArrayList<KeyInfo>(this.keys);

            String keyArchiveJson = gson.toJson(keyArchive);
            try {
                data = this.zip(keyArchiveJson.getBytes(UTF8));
            } catch(IOException e) {
                throw new SecureKeyArchiveException(MALFORMED_ARCHIVEDATA, "Archive data could not be compressed: " + e.getMessage());
            }
        }
        return data;
    }

    /**
     * Archives and encrypts the keys loaded into this archive.
     *
     * @param password the password to use to encrypt the archive.
     * @return encrypted archive data.
     * @throws SecureKeyArchiveException with one of the following reasons:
     *                                   {@link SecureKeyArchiveException#INVALID_PASSWORD},
     *                                   {@link SecureKeyArchiveException#ARCHIVE_EMPTY},
     *                                   {@link SecureKeyArchiveException#FATAL_ERROR}
     */
    @Override
    public byte[] archive(String password) throws SecureKeyArchiveException {
        if (keys.isEmpty()) {
            throw new SecureKeyArchiveException(ARCHIVE_EMPTY, "Key archive is empty. Have you called loadKeys?");
        }

        setupKeyArchiveContainer();

        // Create a symmetric key from the password for encrypting the keys
        byte[] symmetricKey;
        try {
            KeyComponents keyComponents = keyManager.createSymmetricKeyFromPassword(password);
            symmetricKey = keyComponents.key;
            keyArchive.Rounds = keyComponents.rounds;
            keyArchive.Salt = new String(Base64.encode(keyComponents.salt), UTF8);
        } catch (KeyManagerException e) {
            throw new SecureKeyArchiveException(INVALID_PASSWORD,
                    "Unable to create a key from the password", e);
        }

        String keysJson = gson.toJson(keys);
        byte[] keysData = keysJson.getBytes(UTF8);

        if(this.getVersion() == ARCHIVE_VERSION_V2) {
            try {
                byte[] keysEncrypted = keyManager.encryptWithSymmetricKey(symmetricKey, keysData);
                String encodedKeys = new String(Base64.encode(keysEncrypted));
                keyArchive.Version = ARCHIVE_VERSION_V2;
                return this.archiveKeys(encodedKeys, SecureKeyArchiveType.SECURE);
            } catch (KeyManagerException e) {
                throw new SecureKeyArchiveException(INVALID_PASSWORD,
                        "Unable to encrypt the keys with the password", e);
            }
        } else {
            // V3 archive requires you to zip the input to encryption.
            try {
                keysData = this.zip(keysData);
            } catch (IOException e) {
                throw new SecureKeyArchiveException(MALFORMED_ARCHIVEDATA, "Keys data could not be compressed: " + e.getMessage());
            }

            try {
                // Random IV is not necessary for secure archives but JS SDK uses it so we need to
                // be consistent for interop. The use of non default IV also makes V3 secure archive
                // not compatible with AES-GCM.
                byte[] iv = keyManager.createRandomData(16);
                byte[] keysEncrypted = keyManager.encryptWithSymmetricKey(symmetricKey, keysData, iv);
                String encodedKeys = new String(Base64.encode(keysEncrypted));
                keyArchive.Version = ARCHIVE_VERSION_V3;
                keyArchive.IV = new String(Base64.encode(iv));
                byte[] archiveData = this.archiveKeys(encodedKeys, SecureKeyArchiveType.SECURE);

                try {
                    return this.zip(archiveData);
                } catch (IOException e) {
                    throw new SecureKeyArchiveException(MALFORMED_ARCHIVEDATA, "Keys data could not be compressed: " + e.getMessage());
                }
            } catch (KeyManagerException e) {
                throw new SecureKeyArchiveException(INVALID_PASSWORD,
                        "Unable to encrypt the keys with the password", e);
            }
        }
    }

    /**
     * Internal function to build a key archive for export
     *
     * @param keysJson Base64 encoded keys json. Could be encrypted or plaintext.
     * @param type     Archive type, secure or insecure.
     * @return key archive
     */
    private byte[] archiveKeys(String keysJson, SecureKeyArchiveType type) {
        // add values to archive
        keyArchive.Type = type.toString();
        keyArchive.KeysAsString = keysJson;

        String keyArchiveJson = gson.toJson(keyArchive);
        return keyArchiveJson.getBytes(UTF8);
    }

    /**
     * Unarchives plaintext keys in this archive.
     *
     * @throws SecureKeyArchiveException with one of the following reasons:
     *                                   {@link SecureKeyArchiveException#ARCHIVE_EMPTY},
     *                                   {@link SecureKeyArchiveException#INVALID_ARCHIVE_DATA},
     *                                   {@link SecureKeyArchiveException#FATAL_ERROR}
     */
    public void unarchive() throws SecureKeyArchiveException {
        if(this.getVersion() == ARCHIVE_VERSION_V2) {
            byte[] keyData = this.decodeKeyData();
            String keyArrayJson = new String(keyData);
            this.loadKeysFromDecodedPayload(keyArrayJson);
        } else {
            keys.clear();
            for (KeyInfo keyInfo : keyArchive.KeysAsList) {
                keyInfo.data = Base64.decode(keyInfo.base64Data);
                keys.add(keyInfo);
            }
        }
    }

    /**
     * Decrypts and unarchives the keys in this archive.
     *
     * @param password the password to use to decrypt the archive.
     * @throws SecureKeyArchiveException with one of the following reasons:
     *                                   {@link SecureKeyArchiveException#INVALID_PASSWORD},
     *                                   {@link SecureKeyArchiveException#ARCHIVE_EMPTY},
     *                                   {@link SecureKeyArchiveException#INVALID_ARCHIVE_DATA},
     *                                   {@link SecureKeyArchiveException#MALFORMED_ARCHIVEDATA},
     *                                   {@link SecureKeyArchiveException#FATAL_ERROR}
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

        byte[] symmetricKey;
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

            if(this.getVersion() == ARCHIVE_VERSION_V3) {
                // V3 encrypted archive is zipped twice so we need to unzip one more time.
                try {
                    keyDataClear = this.unzip(keyDataClear);
                } catch(IOException e) {
                    throw new SecureKeyArchiveException(MALFORMED_ARCHIVEDATA, "Key data is not a valid gzipped data: " + e.getMessage());
                }
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
     *
     * @return decoded key.
     * @throws SecureKeyArchiveException
     */
    private byte[] decodeKeyData() throws SecureKeyArchiveException {
        if (hasNoValue(keyArchive.KeysAsString)) {
            throw new SecureKeyArchiveException(INVALID_ARCHIVE_DATA, "The Keys in the archive are empty");
        }

        byte[] keyData = Base64.decode(keyArchive.KeysAsString);
        if (hasNoValue(keyData)) {
            throw new SecureKeyArchiveException(INVALID_ARCHIVE_DATA, "The Keys in the archive, after base64 decoding, are empty");
        }

        return keyData;
    }

    /**
     * Internal function to load decoded (possibly decrypted) key archive json data.
     * Part of a multi-step process to load keys from an archive.
     *
     * @param keyArrayJson A string representing a JSON array of keys.
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

    /**
     * @return the Key manager used for managing keys and performing cryptographic operations.
     */
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

    /**
     * @return the key names to exclude from the archive.
     */
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

    /**
     * @return the meta-information associated with this archive.
     */
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

    /**
     * @return the archive version.
     */
    @Override
    public int getVersion() {
        if(this.zip) {
            return ARCHIVE_VERSION_V3;
        } else {
            return ARCHIVE_VERSION_V2;
        }
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

    /**
     * The JSON format of the key archive when converted by Gson
     */
    @Keep
    private static final class KeyArchive {
        @SerializedName("MetaInfo")
        Map<String, String> MetaInfo;
        @SerializedName("Rounds")
        int Rounds;
        @SerializedName("Salt")
        String Salt;
        String KeysAsString;
        List<KeyInfo> KeysAsList;
        @SerializedName("IV")
        String IV;
        @SerializedName("Version")
        int Version;
        @SerializedName("Type")
        String Type;

        public static class KeyArchiveDeserializer implements JsonDeserializer<KeyArchive> {
            @Override
            public KeyArchive deserialize(JsonElement json, java.lang.reflect.Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
                KeyArchive keyArchive = new GsonBuilder()
                        .disableHtmlEscaping()
                        .create().fromJson(json, KeyArchive.class);
                JsonObject jsonObject = json.getAsJsonObject();

                if (jsonObject.has("Keys")) {
                    JsonElement element = jsonObject.get("Keys");
                    if (element.isJsonArray()) {
                        keyArchive.KeysAsList = new GsonBuilder()
                                .registerTypeAdapter(KeyType.class, new KeyTypeJsonAdapter())
                                .create()
                                .fromJson(element, new TypeToken<ArrayList<KeyInfo>>() {}.getType());
                    } else {
                        keyArchive.KeysAsString = element.getAsString();
                    }
                }

                return keyArchive;
            }
        }
    }

    /**
     * The JSON format of a single key within the archive when converted by Gson
     */
    @Keep
    private static final class KeyInfo {
        int Version;
        boolean Synchronizable;
        String NameSpace;
        KeyType Type;
        String Name;
        @SerializedName("Data")
        String base64Data;
        @SerializedName("data")
        byte[] data;

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

        @NonNull
        @Override
        public String toString() {
            return getClass().getSimpleName() + "{ Version=" + Version +
                    ", Synchronizable=" + Synchronizable +
                    ", NameSpace='" + NameSpace + '\'' +
                    ", Type='" + Type + '\'' +
                    ", Name='" + Name + '\'' +
                    ", Data='" + base64Data + '\'' +
                    ", data.len='" + (data != null ? data.length : 0) + '\'' +
                    '}';
        }
    }

    @NonNull
    @Override
    public String toString() {
        return getClass().getSimpleName() + "{ keyArchive=" + keyArchive +
                ", excludedKeys=" + excludedKeys +
                ", keys=" + keys +
                '}';
    }

    private boolean hasValue(String s) {
        // I would have used !TextUtils.isEmpty(s) but it isn't available in unit tests
        return s != null && !s.isEmpty();
    }

    private boolean hasNoValue(String s) {
        return !hasValue(s);
    }

    private boolean hasValue(byte[] b) {
        return b != null && b.length > 0;
    }

    private boolean hasNoValue(byte[] b) {
        return !hasValue(b);
    }
}
