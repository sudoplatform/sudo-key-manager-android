/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sudoplatform.sudokeymanager;

import android.content.Context;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Exportable Android keystore. Android Keystore does not allow the keys to be exported once they
 * are generated or imported. The purpose for this class is to provide a way to maintain copies of
 * keys that are exportable while still leveraging the security benefits of using Android Keystore.
 */
public final class ExportableAndroidStore implements StoreInterface {

    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";

    private static final String NAME_CANT_BE_NULL = "name can't be null.";
    private static final String TYPE_CANT_BE_NULL = "type can't be null.";

    // Exportable store to store the copies of keys that can be exported.
    final private StoreInterface exportableStore;

    // Android Keystore. This is where crypto will be done so keys are not leaked into user space.
    final private KeyStore androidKeyStore;

    // Android Keystore requires the keys to be stored with metadata indicating what their purposes
    // are so we will need to let consumer of this store specify the intent and store them for
    // future use.
    final private String symmetricKeyAlgorithm;

    // Key namespace used to prevent name clashes between keys used by multiple consumers of the
    // underlying key store such as Android Keystore.
    private String keyNamespace;

    /**
     * Instantiates a ExportableAndroidStore.
     *
     * @param context Android app context.
     * @param symmetricKeyAlgorithm symmetric key algorithm.
     * @throws KeyManagerException
     */
    public ExportableAndroidStore(Context context,
                                  String symmetricKeyAlgorithm) throws KeyManagerException {
        Objects.requireNonNull(context, "context can't be null.");
        Objects.requireNonNull(symmetricKeyAlgorithm, "symmetricKeyAlgorithm can't be null.");

        this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
        this.exportableStore = new AndroidSQLiteStore(context);
        try {
            this.androidKeyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            this.androidKeyStore.load(null);
        } catch (KeyStoreException| CertificateException | NoSuchAlgorithmException | IOException e) {
            throw new KeyManagerException("Failed to load Android Keystore.", e);
        }
    }

    /**
     * Instantiates a ExportableAndroidStore.
     *
     * @param context Android app context.
     * @param symmetricKeyAlgorithm symmetric key algorithm.
     * @param keyNamespace key namespace to use to prevent name clashes when multiple consumers are
     *                     using the same underlying key store.
     * @throws KeyManagerException
     */
    public ExportableAndroidStore(Context context,
                                  String symmetricKeyAlgorithm,
                                  String keyNamespace) throws KeyManagerException {
        Objects.requireNonNull(context, "context can't be null.");
        Objects.requireNonNull(symmetricKeyAlgorithm, "symmetricKeyAlgorithm can't be null.");

        this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
        this.exportableStore = new AndroidSQLiteStore(context, keyNamespace);
        this.keyNamespace = keyNamespace;
        try {
            this.androidKeyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            this.androidKeyStore.load(null);
        } catch (KeyStoreException| CertificateException | NoSuchAlgorithmException | IOException e) {
            throw new KeyManagerException("Failed to load Android Keystore.", e);
        }
    }

    /**
     * Instantiates a ExportableAndroidStore.
     *
     * @param context Android app context.
     * @param symmetricKeyAlgorithm symmetric key algorithm.
     * @param keyNamespace key namespace to use to prevent name clashes when multiple consumers are
     *                     using the same underlying key store.
     * @param databaseName database name to use for the SQLite database based key store.
     * @throws KeyManagerException
     */
    public ExportableAndroidStore(Context context,
                                  String symmetricKeyAlgorithm,
                                  String keyNamespace,
                                  String databaseName) throws KeyManagerException {
        Objects.requireNonNull(context, "context can't be null.");
        Objects.requireNonNull(symmetricKeyAlgorithm, "symmetricKeyAlgorithm can't be null.");

        this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
        this.exportableStore = new AndroidSQLiteStore(context, keyNamespace, databaseName);
        this.keyNamespace = keyNamespace;
        try {
            this.androidKeyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            this.androidKeyStore.load(null);
        } catch (KeyStoreException| CertificateException | NoSuchAlgorithmException | IOException e) {
            throw new KeyManagerException("Failed to load Android Keystore.", e);
        }
    }

    @Override
    public void insertKey(byte[] keyBytes, String name, KeyType type, boolean isExportable) throws KeyManagerException {
        Objects.requireNonNull(keyBytes, "keyBytes can't be null.");
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);
        Objects.requireNonNull(type, TYPE_CANT_BE_NULL);

        this.exportableStore.insertKey(keyBytes, name, type, isExportable);

        switch (type) {
            case PRIVATE_KEY:
            case KEY_PAIR:
                // Android Keystore does not allow the private key to be inserted by itself.
                break;
            case PUBLIC_KEY:
                // Android Keystore does not allow the public key to be inserted. We can insert a
                // certificate but then it requires the private key to sign.
                break;
            case SYMMETRIC_KEY:
                SecretKey secretKey = new SecretKeySpec(keyBytes, 0, keyBytes.length, this.symmetricKeyAlgorithm);
                KeyProtection.Builder builder = new KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);
                builder.setRandomizedEncryptionRequired(false);

                if (this.symmetricKeyAlgorithm.equals(KeyManager.SYMMETRIC_KEY_ALGORITHM_AES)) {
                    builder.setBlockModes(KeyProperties.BLOCK_MODE_CBC, KeyProperties.BLOCK_MODE_GCM);
                    builder.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7, KeyProperties.ENCRYPTION_PADDING_NONE);
                }

                try {
                    this.androidKeyStore.setEntry(
                            this.toNamespacedName(name),
                            new KeyStore.SecretKeyEntry(secretKey),
                            builder.build());
                } catch (KeyStoreException e) {
                    throw new KeyManagerException("Failed to add a symmetric key to the store.", e);
                }
                break;
            case PASSWORD:
                // Nothing to be done since the password is already encrypted in the exportable
                // store and we don't have any need to use it to perform crypto operations within
                // Android Keytore.
                break;
        }
    }

    @Override
    public void updateKey(byte[] data, String name, KeyType type) {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);
        Objects.requireNonNull(type, TYPE_CANT_BE_NULL);

    }

    @Override
    public byte[] getKey(String name, KeyType type) throws KeyManagerException {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);
        Objects.requireNonNull(type, TYPE_CANT_BE_NULL);

        return this.exportableStore.getKey(name, type);
    }

    @Override
    public void deleteKey(String name, KeyType type) throws KeyManagerException {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);
        Objects.requireNonNull(type, TYPE_CANT_BE_NULL);

        this.exportableStore.deleteKey(name, type);
        try {
            this.androidKeyStore.deleteEntry(this.toNamespacedName(name));
        } catch (KeyStoreException e) {
            throw new KeyManagerException("Failed to delete a key.", e);
        }
    }

    @Override
    public void reset() throws KeyManagerException {
        this.exportableStore.reset();
        try {
            Enumeration<String> aliases = this.androidKeyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if(this.keyNamespace != null) {
                    if (alias.startsWith(this.keyNamespace + ".")) {
                        this.androidKeyStore.deleteEntry(alias);
                    }
                } else {
                    this.androidKeyStore.deleteEntry(alias);
                }
            }
        } catch (KeyStoreException e) {
            throw new KeyManagerException("Failed to reset Android keystore.", e);
        }
    }

    @Override
    public boolean isExportable() {
        return true;
    }

    @Override
    public void close() throws Exception {
        this.exportableStore.close();
    }

    /**
     * Returns Android Keystore associated with this store.
     *
     * @return Android Keystore.
     */
    public KeyStore getAndroidKeyStore() {
        return this.androidKeyStore;
    }

    @Override
    public void setSecureKeyDelegate(SecureKeyDelegateInterface secureKeyDelegate) {
        this.exportableStore.setSecureKeyDelegate(secureKeyDelegate);
    }

    /**
     * Returns the names of the keys in this key store.
     *
     * @return set containing the key names.
     * @throws KeyManagerException if a failure occurred while fetching the key names.
     */
    @Override
    public Set<String> getKeyNames() throws KeyManagerException {
        Set<String> aliasSet = new HashSet<>(exportableStore.getKeyNames());
        try {
            Enumeration<String> aliases = androidKeyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (this.keyNamespace != null) {
                    aliasSet.add(alias.substring((this.keyNamespace + ".").length()));
                } else {
                    aliasSet.add(alias);
                }
            }
        } catch (KeyStoreException e) {
            throw new KeyManagerException("Failed to query Android keystore for key aliases.", e);
        }
        return aliasSet;
    }

    private String toNamespacedName(String name) {
        return this.keyNamespace != null ? this.keyNamespace + "." + name : name;
    }

}
