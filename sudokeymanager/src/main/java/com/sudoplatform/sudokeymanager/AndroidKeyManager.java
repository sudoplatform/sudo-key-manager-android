package com.sudoplatform.sudokeymanager;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import org.jetbrains.annotations.NotNull;
import org.spongycastle.cert.X509v3CertificateBuilder;
import org.spongycastle.cert.jcajce.JcaX509CertificateConverter;
import org.spongycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

/**
 * KeyManager implementation using Android Keystore. Android Keystore provides system level
 * (or hardware level if supported by the device) key management and crypto. Keys in the
 * Android Keystore is only accessible by the app that had created them and all cryptographic
 * operations are performed at system level and keys are never passed to the user space.
 */
public final class AndroidKeyManager extends KeyManager implements SecureKeyDelegateInterface {

    private static final String TAG = "AndroidKeyManager";

    // Constants for certificate generation.
    private static final String CERTIFICATE_SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String CERTIFICATE_GENERATOR_PROVIDER = "BC";
    private static final String CERTIFICATE_PRINCIPAL_ANONYOME = "cn=Anonyome";

    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String MASTER_KEY_NAME = "com.anonyome.android.masterkey";

    private static final String NAME_CANT_BE_NULL = "name can't be null.";

    // Android Keystore. All crypto operations will be performed within this system level
    // store.
    private final KeyStore androidKeyStore;

    /**
     * Instantiate AndroidKeyManager.
     *
     * @throws KeyManagerException
     */
    public AndroidKeyManager(StoreInterface storeInterface, KeyStore androidKeyStore) throws KeyManagerException {
        super(storeInterface);
        this.keyManagerStore.setSecureKeyDelegate(this);
        this.androidKeyStore = androidKeyStore;
        createMasterKey();
    }

    /** Create a non exportable symmetric key that will be used to secure the exportable keys. */
    private void createMasterKey() throws KeyManagerException {
        if (getSymmetricKey(MASTER_KEY_NAME) != null) {
            return;
        }
        try {
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(MASTER_KEY_NAME,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);
            KeyGenParameterSpec keySpec = builder
                .setKeySize(KeyManager.SYMMETRIC_KEY_SIZE)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .setRandomizedEncryptionRequired(false)
                .build();
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);
            keyGenerator.init(keySpec);
            keyGenerator.generateKey();
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new KeyManagerException("Failed to create the master key.", e);
        }
    }

    @Override
    public void addKeyPair(byte[] privateKey, byte[] publicKey, String name, boolean isExportable) throws KeyManagerException {
        PublicKey publicKeyObj = this.bytesToPublicKey(publicKey);
        PrivateKey privateKeyObj = this.bytesToPrivateKey(privateKey);

        try {
            // Android Keystore requires the private key to be accompanied by a certificate. We have
            // to use BouncyCastle (SpongyCastle in Android land) here since there's no security
            // provider on Android that supports generating a self-signed certificate.
            ContentSigner signer = getContentSignerBuilder().build(privateKeyObj);

            // 99 years should be long enough since key lifetime should be less then that.
            long now = System.currentTimeMillis();
            long oneDay = TimeUnit.DAYS.toMillis(1);
            long ninetyNineYears = TimeUnit.DAYS.toMillis(99 * 365L);
            Date startDate = new Date(now - oneDay);
            Date endDate = new Date(now + ninetyNineYears);

            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    new X500Principal(CERTIFICATE_PRINCIPAL_ANONYOME),
                    BigInteger.ONE,
                    startDate, endDate,
                    new X500Principal(CERTIFICATE_PRINCIPAL_ANONYOME),
                    publicKeyObj);

            X509Certificate certificate = getCertificateConverter().getCertificate(builder.build(signer));

            this.androidKeyStore.setKeyEntry(name, privateKeyObj, null, new Certificate[] { certificate });
            // Now store the exportable copies of the keys since we can't extract keys from Android Keystore.
            this.keyManagerStore.insertKey(privateKey, name, KeyType.PRIVATE_KEY,isExportable);
            this.keyManagerStore.insertKey(publicKey, name, KeyType.PUBLIC_KEY,isExportable);
        } catch (CertificateException | OperatorCreationException e) {
            throw new KeyManagerException("Failed to create a certificate.", e);
        } catch (GeneralSecurityException e) {
            throw new KeyManagerException("Failed to add a key pair.", e);
        }
    }

    private JcaContentSignerBuilder getContentSignerBuilder() {
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(CERTIFICATE_SIGNATURE_ALGORITHM);
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            // SHA256WITHRSA from BC provider deprecated in Android P and later.
            // https://android-developers.googleblog.com/2018/03/cryptography-changes-in-android-p.html
            signerBuilder.setProvider(CERTIFICATE_GENERATOR_PROVIDER);
        }
        return signerBuilder;
    }

    private JcaX509CertificateConverter getCertificateConverter() {
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            // SHA256WITHRSA from BC provider deprecated in Android P and later.
            // https://android-developers.googleblog.com/2018/03/cryptography-changes-in-android-p.html
            converter.setProvider(CERTIFICATE_GENERATOR_PROVIDER);
        }
        return converter;
    }

    @Override
    public void addPrivateKey(byte[] key, String name, boolean isExportable) throws KeyManagerException {
        throw new UnsupportedOperationException("Cannot add a private key on its own to an Android key store.");
    }

    private KeyStore.Entry getAndroidKeyStoreEntry(@NotNull String name, KeyStore.ProtectionParameter param)
            throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException {
        // Workaround for "java.security.UnrecoverableKeyException: Failed to obtain information about key"
        // caused by "android.security.KeyStoreException: System error"
        // https://anonyome.atlassian.net/browse/NPFA-9542
        for (int attempt = 1; ; attempt++) {
            try {
                return androidKeyStore.getEntry(name, param);
            } catch (UnrecoverableEntryException ex) {
                if (attempt < 5 && isSystemError(ex)) {
                    Log.w(TAG, "Error getting AndroidKeyStore entry. Attempt=" + attempt, ex);
                } else {
                    Log.e(TAG, "Can't get AndroidKeyStore entry", ex);
                    throw ex;
                }
            }
        }
    }

    private static boolean isSystemError(UnrecoverableEntryException ex) {
        Throwable cause = ex.getCause();
        if (cause != null) {
            String message = cause.getMessage();
            return message != null && message.contains("System error");
        }
        return false;
    }

    @Override
    public PrivateKey getPrivateKey(String name) throws KeyManagerException {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);

        PrivateKey privateKey = null;

        try {
            KeyStore.Entry entry = getAndroidKeyStoreEntry(name, null);
            if (entry instanceof KeyStore.PrivateKeyEntry) {
                privateKey = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
            }
        } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableEntryException e) {
            throw new KeyManagerException("Failed to retrieve the private key.", e);
        }

        return privateKey;
    }

    @Override
    public void addPublicKey(byte[] publicKeyBytes, String name, boolean isExportable) throws KeyManagerException {
        // Validate the key bytes by converting them
        bytesToPublicKey(publicKeyBytes);
        // A public key without a private key cannot be stored in the AndroidKeyStore, so store it outside.
        keyManagerStore.insertKey(publicKeyBytes, name, KeyType.PUBLIC_KEY, isExportable);
    }

    @Override
    public PublicKey getPublicKey(String name) throws KeyManagerException {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);

        PublicKey publicKey = null;
        try {
            KeyStore.Entry entry = getAndroidKeyStoreEntry(name, null);
            if (entry instanceof KeyStore.PrivateKeyEntry) {
                publicKey = ((KeyStore.PrivateKeyEntry) entry).getCertificate().getPublicKey();
            } else if (entry == null) {
                byte[] publicKeyBytes = keyManagerStore.getKey(name, KeyType.PUBLIC_KEY);
                if (publicKeyBytes != null) {
                    publicKey = bytesToPublicKey(publicKeyBytes);
                }
            }
        } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableEntryException e) {
            throw new KeyManagerException("Failed to retrieve the public key.", e);
        }

        return publicKey;
    }

    @Override
    protected SecretKey getSymmetricKey(String name) throws KeyManagerException {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);

        SecretKey secretKey = null;
        try {
            KeyStore.Entry entry = getAndroidKeyStoreEntry(name, null);
            if (entry instanceof KeyStore.SecretKeyEntry) {
                secretKey = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
            }
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            throw new KeyManagerException("Failed to retrieve the symmetric key.", e);
        }

        return secretKey;
    }

    @Override
    public byte[] encryptKey(byte[] key) throws KeyManagerException {
        return this.encryptWithSymmetricKey(MASTER_KEY_NAME, key);
    }

    @Override
    public byte[] decryptKey(byte[] key) throws KeyManagerException {
        return this.decryptWithSymmetricKey(MASTER_KEY_NAME, key);
    }

    @Override
    public void removeAllKeys() throws KeyManagerException {
        super.removeAllKeys();
        createMasterKey();
    }
}
