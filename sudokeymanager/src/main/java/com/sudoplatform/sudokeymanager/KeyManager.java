package com.sudoplatform.sudokeymanager;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Primitive;
import org.spongycastle.asn1.pkcs.PrivateKeyInfo;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.spongycastle.crypto.params.KeyParameter;

import static com.sudoplatform.sudokeymanager.KeyManagerInterface.PublicKeyEncryptionAlgorithm.RSA_ECB_OAEPSHA1;
import static com.sudoplatform.sudokeymanager.KeyManagerInterface.PublicKeyEncryptionAlgorithm.RSA_ECB_PKCS1;
import static com.sudoplatform.sudokeymanager.KeyManagerInterface.SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256;

/**
 * Basic KeyManager implementation. It implements key management and cryptographic operations common
 * to all its subclasses without a specific knowledge about the underlying technology used to store
 * the keys.
 */

public class KeyManager implements KeyManagerInterface {

    // Constants related to symmetric key crypto.
    static final String SYMMETRIC_KEY_ALGORITHM = "AES";
    static final String SYMMETRIC_KEY_ALGORITHM_BLOCK_MODE = "CBC";
    static final String SYMMETRIC_KEY_ALGORITHM_ENCRYPTION_PADDING = "PKCS7Padding";
    protected static final String SYMMETRIC_KEY_CIPHER = SYMMETRIC_KEY_ALGORITHM + "/" + SYMMETRIC_KEY_ALGORITHM_BLOCK_MODE + "/" + SYMMETRIC_KEY_ALGORITHM_ENCRYPTION_PADDING;
    protected static final int SYMMETRIC_KEY_SIZE = 256;
    protected static final int SYMMETRIC_KEY_ALGORITHM_BLOCK_SIZE = 128;
    protected static final int SYMMETRIC_KEY_ALGORITHM_BLOCK_SIZE_IN_BYTES = SYMMETRIC_KEY_ALGORITHM_BLOCK_SIZE >> 3;
    private static final byte[] DEFAULT_SYMMETRIC_IV = new byte[SYMMETRIC_KEY_ALGORITHM_BLOCK_SIZE_IN_BYTES];

    // Constants related to password key crypto.
    protected static final int PASSWORD_KEY_SIZE = 256;
    protected static final String PASSWORD_KEY_ALGORITHM = "PBKDF2WithHmacSHA256"; //NOSONAR
    protected static final int PASSWORD_DEFAULT_ROUNDS = 10_000;
    protected static final int PASSWORD_SALT_SIZE = 16;

    // Constants related to public key crypto.
    protected static final String PRIVATE_PUBLIC_KEY_ALGORITHM = "RSA";
    protected static final String PRIVATE_PUBLIC_KEY_ALGORITHM_BLOCK_MODE = "ECB";
    protected static final String PRIVATE_PUBLIC_KEY_ALGORITHM_ENCRYPTION_PADDING = "PKCS1Padding";
    protected static final String PRIVATE_PUBLIC_KEY_CIPHER_PKCS1 = PRIVATE_PUBLIC_KEY_ALGORITHM + "/" + PRIVATE_PUBLIC_KEY_ALGORITHM_BLOCK_MODE + "/" + PRIVATE_PUBLIC_KEY_ALGORITHM_ENCRYPTION_PADDING;
    protected static final String PRIVATE_PUBLIC_KEY_ALGORITHM_ENCRYPTION_PADDING_OAEP = "OAEPwithSHA-1andMGF1Padding";
    protected static final String PRIVATE_PUBLIC_KEY_CIPHER_OAEP_SHA1 = PRIVATE_PUBLIC_KEY_ALGORITHM + "/" + PRIVATE_PUBLIC_KEY_ALGORITHM_BLOCK_MODE + "/" + PRIVATE_PUBLIC_KEY_ALGORITHM_ENCRYPTION_PADDING_OAEP;
    protected static final int PRIVATE_PUBLIC_KEY_SIZE = 2048;
    protected static final String PRIVATE_PUBLIC_KEY_SIGNATURE_ALGORITHM = "SHA256withRSA";

    // Constants related to message digest.
    private static final String MESSAGE_DIGEST_ALGORITHM = "SHA-256";

    // Constants related to cipher.
    /**
     * For all tested devices chunking into 16384 bytes was successful. If problems arise
     * we can reduce this limit (see CIPHER_CHUNK_SIZE). Note: Reducing the size of the processed
     * chunks will result in slower processing speeds.
     */
    private static final int CIPHER_CHUNK_SIZE = 16 * 1024;

    // Errors
    private static final String PASSWORD_CANT_BE_NULL = "password can't be null."; //NOSONAR
    private static final String NAME_CANT_BE_NULL = "name can't be null.";
    private static final String KEY_CANT_BE_NULL = "key can't be null.";
    private static final String DATA_CANT_BE_NULL = "data can't be null.";
    private static final String ALGORITHM_CANT_BE_NULL = "algorithm can't be null.";
    private static final String KEY_NOT_FOUND = "Key \"%s\" not found.";
    private static final String FAILED_TO_DECRYPT = "Failed to decrypt using the symmetric key.";
    private static final String FAILED_TO_ENCRYPT = "Failed to encrypt using the symmetric key.";

    // KeyManager store responsible for providing basic lifecycle management operations for keys.
    protected final StoreInterface keyManagerStore;

    // Key generators.
    protected KeyGenerator keyGenerator;
    protected KeyPairGenerator keyPairGenerator;
    protected KeyFactory keyFactory;
    protected SecretKeyFactory passwordKeyFactory;

    @SuppressWarnings("squid:S4787") // Use of encryption is safe here
    private static final ThreadLocal<Cipher> symmetricKeyCipher = new ThreadLocal<Cipher>() {

        @Override
        protected Cipher initialValue() {
            try {
                return Cipher.getInstance(SYMMETRIC_KEY_CIPHER);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    };

    @SuppressWarnings("squid:S4787") // Use of encryption is safe here
    private static final ThreadLocal<Map<PublicKeyEncryptionAlgorithm, Cipher>> privatePublicKeyCipher = new ThreadLocal<Map<PublicKeyEncryptionAlgorithm, Cipher>>() {

        @Override
        protected Map<PublicKeyEncryptionAlgorithm, Cipher> initialValue() {
            try {
                EnumMap<PublicKeyEncryptionAlgorithm, Cipher> ciphers = new EnumMap<>(PublicKeyEncryptionAlgorithm.class);
                ciphers.put(RSA_ECB_PKCS1, Cipher.getInstance(PRIVATE_PUBLIC_KEY_CIPHER_PKCS1));
                ciphers.put(RSA_ECB_OAEPSHA1, Cipher.getInstance(PRIVATE_PUBLIC_KEY_CIPHER_OAEP_SHA1));
                return ciphers;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    };

    /**
     * Instantiates a KeyManager with the specified store.
     *
     * @param keyManagerStore KeyManager store responsible persistent storage of keys.
     * @throws KeyManagerException if key generation failed. Will contain a java.security exception.
     */
    public KeyManager(StoreInterface keyManagerStore) throws KeyManagerException {
        Objects.requireNonNull(keyManagerStore, "keyManagerStore can't be null.");

        this.keyManagerStore = keyManagerStore;
        SecurityProviders.installSpongyCastleProvider();
        setupKeyGenerators();
    }

    /**
     * Initializes key generators. A subclass should override this method to provide their own
     * key generators.
     *
     * @throws KeyManagerException if key generation failed. Will contain a java.security exception.
     */
    @SuppressWarnings("squid:S4790") // Use of hashing is safe here
    protected void setupKeyGenerators() throws KeyManagerException {
        try {
            this.keyGenerator = KeyGenerator.getInstance(SYMMETRIC_KEY_ALGORITHM);
            this.keyGenerator.init(SYMMETRIC_KEY_SIZE);
            this.keyPairGenerator = KeyPairGenerator.getInstance(PRIVATE_PUBLIC_KEY_ALGORITHM);
            this.keyPairGenerator.initialize(PRIVATE_PUBLIC_KEY_SIZE);
            this.keyFactory = KeyFactory.getInstance(PRIVATE_PUBLIC_KEY_ALGORITHM);
            this.passwordKeyFactory = SecretKeyFactory.getInstance(PASSWORD_KEY_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyManagerException("Failed to generate a symmetric key.", e);
        }
    }

    @Override
    public void addPassword(byte[] password, String name) throws KeyManagerException {
        this.addPassword(password, name, true);
    }

    @Override
    public void addPassword(byte[] password, String name, boolean isExportable) throws KeyManagerException {
        Objects.requireNonNull(password, PASSWORD_CANT_BE_NULL);
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);

        this.keyManagerStore.insertKey(password, name, KeyType.PASSWORD, isExportable);
    }

    @Override
    public byte[] getPassword(String name) throws KeyManagerException {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);

        return this.keyManagerStore.getKey(name, KeyType.PASSWORD);
    }

    @Override
    public void deletePassword(String name) throws KeyManagerException {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);

        this.keyManagerStore.deleteKey(name, KeyType.PASSWORD);
    }

    @Override
    public void updatePassword(byte[] password, String name) {
        Objects.requireNonNull(password, PASSWORD_CANT_BE_NULL);
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);

        this.keyManagerStore.updateKey(password, name, KeyType.PASSWORD);
    }

    @Override
    public void generateSymmetricKey(String name) throws KeyManagerException {
        this.generateSymmetricKey(name, true);
    }

    @Override
    public void generateSymmetricKey(String name, boolean isExportable) throws KeyManagerException {
        SecretKey secretKey = keyGenerator.generateKey();
        this.addSymmetricKey(secretKey.getEncoded(), name, isExportable);
    }

    @Override
    public void addSymmetricKey(byte[] key, String name) throws KeyManagerException {
        this.addSymmetricKey(key, name, true);
    }

    @Override
    public void addSymmetricKey(byte[] key, String name, boolean isExportable) throws KeyManagerException {
        Objects.requireNonNull(key, KEY_CANT_BE_NULL);
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);

        this.keyManagerStore.insertKey(key, name, KeyType.SYMMETRIC_KEY, isExportable);
    }

    @Override
    public byte[] getSymmetricKeyData(String name) throws KeyManagerException {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);

        return this.keyManagerStore.getKey(name, KeyType.SYMMETRIC_KEY);
    }

    @Override
    public void deleteSymmetricKey(String name) throws KeyManagerException {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);

        this.keyManagerStore.deleteKey(name, KeyType.SYMMETRIC_KEY);
    }

    @Override
    public byte[] encryptWithSymmetricKey(String name, byte[] data) throws KeyManagerException {
        return encryptWithSymmetricKey(name, data, DEFAULT_SYMMETRIC_IV, AES_CBC_PKCS7_256);
    }

    @Override
    public byte[] encryptWithSymmetricKey(String name, byte[] data, SymmetricEncryptionAlgorithm algorithm) throws KeyManagerException {
        return encryptWithSymmetricKey(name, data, DEFAULT_SYMMETRIC_IV, algorithm);
    }

    @Override
    public byte[] encryptWithSymmetricKey(String name, byte[] data, byte[] iv) throws KeyManagerException {
        return encryptWithSymmetricKey(name, data, iv, AES_CBC_PKCS7_256);
    }

    @Override
    public byte[] encryptWithSymmetricKey(String name, byte[] data, byte[] iv, SymmetricEncryptionAlgorithm algorithm) throws KeyManagerException {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);

        return this.encryptWithSymmetricKey(this.getSymmetricKey(name), data, iv, algorithm);
    }

    @Override
    public byte[] encryptWithSymmetricKey(byte[] key, byte[] data) throws KeyManagerException {
        return encryptWithSymmetricKey(key, data, DEFAULT_SYMMETRIC_IV, AES_CBC_PKCS7_256);
    }

    @Override
    public byte[] encryptWithSymmetricKey(byte[] key, byte[] data, SymmetricEncryptionAlgorithm algorithm) throws KeyManagerException {
        return this.encryptWithSymmetricKey(key, data, DEFAULT_SYMMETRIC_IV, algorithm);
    }

    @Override
    public byte[] encryptWithSymmetricKey(byte[] key, byte[] data, byte[] iv) throws KeyManagerException {
        return encryptWithSymmetricKey(key, data, iv, AES_CBC_PKCS7_256);
    }

    @Override
    public byte[] encryptWithSymmetricKey(byte[] key, byte[] data, byte[] iv, SymmetricEncryptionAlgorithm algorithm) throws KeyManagerException {
        Objects.requireNonNull(key, KEY_CANT_BE_NULL);

        SecretKeySpec keySpec = new SecretKeySpec(key, SYMMETRIC_KEY_ALGORITHM);
        return this.encryptWithSymmetricKey(keySpec, data, iv, algorithm);
    }

    @Override
    public byte[] decryptWithSymmetricKey(String name, byte[] data) throws KeyManagerException {
        return this.decryptWithSymmetricKey(name, data, DEFAULT_SYMMETRIC_IV, AES_CBC_PKCS7_256);
    }

    @Override
    public byte[] decryptWithSymmetricKey(String name, byte[] data, SymmetricEncryptionAlgorithm algorithm) throws KeyManagerException {
        return this.decryptWithSymmetricKey(name, data, DEFAULT_SYMMETRIC_IV, algorithm);
    }

    @Override
    public byte[] decryptWithSymmetricKey(String name, byte[] data, byte[] iv, SymmetricEncryptionAlgorithm algorithm) throws KeyManagerException {
        Objects.requireNonNull(name, KEY_CANT_BE_NULL);

        return decryptWithSymmetricKey(getSymmetricKey(name), data, iv, algorithm);
    }

    @Override
    public InputStream decryptWithSymmetricKey(String name, InputStream stream) throws KeyManagerException {
        return decryptWithSymmetricKey(name, stream, DEFAULT_SYMMETRIC_IV, AES_CBC_PKCS7_256);
    }

    @Override
    public InputStream decryptWithSymmetricKey(String name, InputStream stream, SymmetricEncryptionAlgorithm algorithm) throws KeyManagerException {
        return this.decryptWithSymmetricKey(name, stream, DEFAULT_SYMMETRIC_IV, algorithm);
    }

    @Override
    public byte[] decryptWithSymmetricKey(String name, byte[] data, byte[] iv) throws KeyManagerException {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);

        return this.decryptWithSymmetricKey(this.getSymmetricKey(name), data, iv, AES_CBC_PKCS7_256);
    }

    @Override
    public InputStream decryptWithSymmetricKey(String name, InputStream stream, byte[] iv) throws KeyManagerException {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);

        return this.decryptWithSymmetricKey(this.getSymmetricKey(name), stream, iv,
                AES_CBC_PKCS7_256);
    }

    @Override
    public InputStream decryptWithSymmetricKey(String name, InputStream stream, byte[] iv, SymmetricEncryptionAlgorithm algorithm) throws KeyManagerException {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);

        return this.decryptWithSymmetricKey(this.getSymmetricKey(name), stream, iv, algorithm);
    }

    @Override
    public byte[] decryptWithSymmetricKey(byte[] key, byte[] data) throws KeyManagerException {
        return this.decryptWithSymmetricKey(key, data, DEFAULT_SYMMETRIC_IV, AES_CBC_PKCS7_256);
    }

    @Override
    public byte[] decryptWithSymmetricKey(byte[] key, byte[] data, SymmetricEncryptionAlgorithm algorithm) throws KeyManagerException {
        return this.decryptWithSymmetricKey(key, data, DEFAULT_SYMMETRIC_IV, algorithm);
    }

    @Override
    public byte[] decryptWithSymmetricKey(byte[] key, byte[] data, byte[] iv, SymmetricEncryptionAlgorithm algorithm) throws KeyManagerException {
        Objects.requireNonNull(key, KEY_CANT_BE_NULL);

        SecretKeySpec keySpec = new SecretKeySpec(key, SYMMETRIC_KEY_ALGORITHM);
        return this.decryptWithSymmetricKey(keySpec, data, iv, algorithm);
    }

    @Override
    public InputStream decryptWithSymmetricKey(byte[] key, InputStream stream) throws KeyManagerException {
        return this.decryptWithSymmetricKey(key, stream, DEFAULT_SYMMETRIC_IV, AES_CBC_PKCS7_256);
    }

    @Override
    public InputStream decryptWithSymmetricKey(byte[] key, InputStream stream, SymmetricEncryptionAlgorithm algorithm) throws KeyManagerException {
        return this.decryptWithSymmetricKey(key, stream, DEFAULT_SYMMETRIC_IV, AES_CBC_PKCS7_256);
    }

    @Override
    public byte[] decryptWithSymmetricKey(byte[] key, byte[] data, byte[] iv) throws KeyManagerException {
        Objects.requireNonNull(key, KEY_CANT_BE_NULL);

        SecretKeySpec keySpec = new SecretKeySpec(key, SYMMETRIC_KEY_ALGORITHM);
        return this.decryptWithSymmetricKey(keySpec, data, iv, AES_CBC_PKCS7_256);
    }

    @Override
    public InputStream decryptWithSymmetricKey(byte[] key, InputStream stream, byte[] iv) throws KeyManagerException {
        Objects.requireNonNull(key, KEY_CANT_BE_NULL);

        SecretKeySpec keySpec = new SecretKeySpec(key, SYMMETRIC_KEY_ALGORITHM);
        return this.decryptWithSymmetricKey(keySpec, stream, iv, AES_CBC_PKCS7_256);
    }

    @Override
    public InputStream decryptWithSymmetricKey(byte[] key, InputStream stream, byte[] iv, SymmetricEncryptionAlgorithm algorithm) throws KeyManagerException {
        Objects.requireNonNull(key, KEY_CANT_BE_NULL);

        SecretKeySpec keySpec = new SecretKeySpec(key, SYMMETRIC_KEY_ALGORITHM);
        return this.decryptWithSymmetricKey(keySpec, stream, iv, algorithm);
    }

    @Override
    public KeyComponents createSymmetricKeyFromPassword(String password) throws KeyManagerException {
        KeyComponents keyComponents = new KeyComponents();
        keyComponents.salt = createRandomData(PASSWORD_SALT_SIZE);
        keyComponents.rounds = PASSWORD_DEFAULT_ROUNDS;
        keyComponents.key = createSymmetricKeyFromPassword(password, keyComponents.salt, keyComponents.rounds);
        return keyComponents;
    }

    @Override
    public byte[] createSymmetricKeyFromPassword(String password, byte[] salt, int rounds) throws KeyManagerException {
        Objects.requireNonNull(password, PASSWORD_CANT_BE_NULL);
        return this.createSymmetricKeyFromPassword(password.toCharArray(), salt, rounds);
    }

    @Override
    public byte[] createSymmetricKeyFromPassword(char[] password, byte[] salt, int rounds) throws KeyManagerException {
        Objects.requireNonNull(password, PASSWORD_CANT_BE_NULL);
        Objects.requireNonNull(salt, "salt can't be null.");

        SecretKey secretKey;
        try {
            KeySpec keySpec = new PBEKeySpec(password, salt, rounds, PASSWORD_KEY_SIZE);
            secretKey = passwordKeyFactory.generateSecret(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new KeyManagerException("Failed to create password based symmetric key", e);
        }
        return secretKey != null ? secretKey.getEncoded() : null;
    }

    @Override
    public byte[] createSymmetricKeyFromPassword(byte[] password, byte[] salt, int rounds) throws KeyManagerException {
        Objects.requireNonNull(password, PASSWORD_CANT_BE_NULL);
        Objects.requireNonNull(salt, "salt can't be null.");

        PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA256Digest());
        generator.init(password, salt, rounds);
        KeyParameter secretKey = (KeyParameter)generator.generateDerivedMacParameters(PASSWORD_KEY_SIZE);
        return secretKey.getKey();
    }

    @Override
    @SuppressWarnings("squid:S4790") // Use of hashing is safe here
    public byte[] generateHash(byte[] data) throws KeyManagerException {
        Objects.requireNonNull(data, DATA_CANT_BE_NULL);

        byte[] hash;
        try {
            MessageDigest digest = MessageDigest.getInstance(MESSAGE_DIGEST_ALGORITHM);
            hash = digest.digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyManagerException(String.format("Failed to generate a hash because %s was not found.", MESSAGE_DIGEST_ALGORITHM), e);
        }
        return hash;
    }

    @Override
    public void generateKeyPair(String name) throws KeyManagerException {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);

        this.generateKeyPair(name, true);
    }

    @Override
    public void generateKeyPair(String name, boolean isExportable) throws KeyManagerException {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);

        KeyPair keyPair = this.keyPairGenerator.generateKeyPair();

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        this.addKeyPair(this.privateKeyToBytes(privateKey), this.publicKeyToBytes(publicKey), name, isExportable);
    }

    @Override
    public void addPrivateKey(byte[] key, String name) throws KeyManagerException {
        this.addPrivateKey(key, name, true);
    }

    @Override
    public void addPrivateKey(byte[] key, String name, boolean isExportable) throws KeyManagerException {
        Objects.requireNonNull(key, KEY_CANT_BE_NULL);
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);

        this.keyManagerStore.insertKey(key, name, KeyType.PRIVATE_KEY, isExportable);
    }

    @Override
    public byte[] getPrivateKeyData(String name) throws KeyManagerException {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);

        return this.keyManagerStore.getKey(name, KeyType.PRIVATE_KEY);
    }

    @Override
    public void addPublicKey(byte[] key, String name) throws KeyManagerException {
        this.addPublicKey(key, name, true);
    }

    @Override
    public void addPublicKey(byte[] key, String name, boolean isExportable) throws KeyManagerException {
        Objects.requireNonNull(key, KEY_CANT_BE_NULL);
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);

        this.keyManagerStore.insertKey(key, name, KeyType.PUBLIC_KEY, isExportable);
    }

    @Override
    public byte[] getPublicKeyData(String name) throws KeyManagerException {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);

        return this.keyManagerStore.getKey(name, KeyType.PUBLIC_KEY);
    }

    @Override
    public void addKeyPair(byte[] privateKey, byte[] publicKey, String name) throws KeyManagerException {
        this.addKeyPair(privateKey, publicKey, name, true);
    }

    @Override
    public void addKeyPair(byte[] privateKey, byte[] publicKey, String name, boolean isExportable) throws KeyManagerException {
        this.addPrivateKey(privateKey, name, isExportable);
        this.addPublicKey(publicKey, name, isExportable);
    }

    @Override
    public void deleteKeyPair(String name) throws KeyManagerException {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);

        this.keyManagerStore.deleteKey(name, KeyType.PRIVATE_KEY);
        this.keyManagerStore.deleteKey(name, KeyType.PUBLIC_KEY);
    }

    @Override
    public byte[] generateSignatureWithPrivateKey(String name, byte[] data) throws KeyManagerException {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);
        Objects.requireNonNull(data, DATA_CANT_BE_NULL);

        byte[] signatureBytes;

        PrivateKey privateKey = this.getPrivateKey(name);
        if (privateKey != null) {
            // Spongy/BouncyCastle are incompatible with keys from the Android key store for signing.
            // Use the special Android provider, if it's present, that works around this problem.
            Provider preferredProvider = Security.getProvider("AndroidKeyStoreBCWorkaround");
            try {
                Signature signature;
                if (preferredProvider != null) {
                    signature = Signature.getInstance(PRIVATE_PUBLIC_KEY_SIGNATURE_ALGORITHM, preferredProvider);
                } else {
                    signature = Signature.getInstance(PRIVATE_PUBLIC_KEY_SIGNATURE_ALGORITHM);
                }
                signature.initSign(privateKey);
                signature.update(data);
                signatureBytes = signature.sign();
            } catch (NoSuchAlgorithmException e) {
                throw new KeyManagerException(String.format("Failed to generate a signature because %s was not found.", PRIVATE_PUBLIC_KEY_SIGNATURE_ALGORITHM), e);
            } catch (SignatureException e) {
                throw new KeyManagerException("Signature generation failed.", e);
            } catch (InvalidKeyException e) {
                throw new KeyManagerException(String.format("Key \"%s\" cannot be used to generate a signature.", name), e);
            }
        } else {
            throw new KeyNotFoundException(String.format(KEY_NOT_FOUND, name));
        }

        return signatureBytes;
    }

    @Override
    public boolean verifySignatureWithPublicKey(String name, byte[] data, byte[] signature) throws KeyManagerException {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);
        Objects.requireNonNull(data, DATA_CANT_BE_NULL);
        Objects.requireNonNull(signature, "signature can't be null.");

        boolean status;

        PublicKey publicKey = this.getPublicKey(name);
        if (publicKey != null) {
            try {
                Signature signatureObject = Signature.getInstance(PRIVATE_PUBLIC_KEY_SIGNATURE_ALGORITHM);
                signatureObject.initVerify(publicKey);
                signatureObject.update(data);
                status = signatureObject.verify(signature);
            } catch (NoSuchAlgorithmException e) {
                throw new KeyManagerException(String.format("Failed to verify the signature because %s was not found.", PRIVATE_PUBLIC_KEY_SIGNATURE_ALGORITHM), e);
            } catch (SignatureException e) {
                throw new KeyManagerException("Failed to verify the signature.", e);
            } catch (InvalidKeyException e) {
                throw new KeyManagerException(String.format("Key \"%s\" cannot be used to verify a signature.", name), e);
            }
        } else {
            throw new KeyNotFoundException(String.format(KEY_NOT_FOUND, name));
        }

        return status;
    }

    /**
     * Encrypts the given data with the specified public key.
     *
     * @param name name of the public key to use for encryption.
     * @param data data to encrypt with the default algorithm {@link PublicKeyEncryptionAlgorithm#RSA_ECB_PKCS1}.
     * @return encrypted data.
     * @throws KeyManagerException on failure, which will probably contain an exception from java.security.
     */
    @Override
    public byte[] encryptWithPublicKey(String name, byte[] data) throws KeyManagerException {
        return encryptWithPublicKey(name, data, RSA_ECB_PKCS1);
    }

    /**
     * Encrypts the given data with the specified public key.
     *
     * @param name      name of the public key to use for encryption.
     * @param data      data to encrypt.
     * @param algorithm the encryption algorithm to use.
     * @return encrypted data.
     * @throws KeyManagerException on failure, which will probably contain an exception from java.security.
     */
    @Override
    public byte[] encryptWithPublicKey(String name, byte[] data, PublicKeyEncryptionAlgorithm algorithm) throws KeyManagerException {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);
        Objects.requireNonNull(data, DATA_CANT_BE_NULL);
        Objects.requireNonNull(algorithm, ALGORITHM_CANT_BE_NULL);

        byte[] encrypted;

        PublicKey publicKey = this.getPublicKey(name);
        if (publicKey != null) {
            try {
                Cipher cipher;
                synchronized (KeyManager.class) {
                    cipher = getCipher(algorithm);
                    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
                }
                encrypted = cipher.doFinal(data);
            } catch (BadPaddingException | IllegalBlockSizeException e) {
                throw new KeyManagerException("Failed to encrypt with a public key.", e);
            } catch (InvalidKeyException e) {
                throw new KeyManagerException(String.format("Key \"%s\" cannot be used to encrypt.", name), e);
            }
        } else {
            throw new KeyNotFoundException(String.format(KEY_NOT_FOUND, name));
        }

        return encrypted;
    }

    /**
     * Decrypts the given data with the specified private key.
     *
     * @param name name of the private key to use for decryption.
     * @param data data to decrypt with the default algorithm {@link PublicKeyEncryptionAlgorithm#RSA_ECB_PKCS1}.
     * @return decrypted data.
     * @throws KeyManagerException on failure, which will probably contain an exception from java.security.
     */
    @Override
    public byte[] decryptWithPrivateKey(String name, byte[] data) throws KeyManagerException {
        return decryptWithPrivateKey(name, data, RSA_ECB_PKCS1);
    }

    /**
     * Decrypts the given data with the specified private key.
     *
     * @param name      name of the private key to use for decryption.
     * @param data      data to decrypt.
     * @param algorithm the decryption algorithm to use.
     * @return decrypted data.
     * @throws KeyManagerException on failure, which will probably contain an exception from java.security.
     */
    @Override
    public byte[] decryptWithPrivateKey(String name, byte[] data, PublicKeyEncryptionAlgorithm algorithm) throws KeyManagerException {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);
        Objects.requireNonNull(data, DATA_CANT_BE_NULL);
        Objects.requireNonNull(algorithm, ALGORITHM_CANT_BE_NULL);

        byte[] decrypted;

        PrivateKey privateKey = this.getPrivateKey(name);
        if (privateKey != null) {
            try {
                Cipher cipher;
                synchronized (KeyManager.class) {
                    cipher = getCipher(algorithm);
                    cipher.init(Cipher.DECRYPT_MODE, privateKey);
                }
                decrypted = cipher.doFinal(data);
            } catch (BadPaddingException | IllegalBlockSizeException e) {
                throw new KeyManagerException("Failed to decrypt with a private key.", e);
            } catch (InvalidKeyException e) {
                throw new KeyManagerException("Key \"" + name + "\" cannot be used to decrypt.", e);
            }
        } else {
            throw new KeyNotFoundException("Key \"" + name + "\" not found.");
        }

        return decrypted;
    }

    private static Cipher getCipher(PublicKeyEncryptionAlgorithm algorithm) {
        if (algorithm == RSA_ECB_OAEPSHA1) {
            return privatePublicKeyCipher.get().get(RSA_ECB_OAEPSHA1);
        } else {
            return privatePublicKeyCipher.get().get(RSA_ECB_PKCS1);
        }
    }

    @Override
    public byte[] createRandomData(int size) {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[size];
        random.nextBytes(bytes);
        return bytes;
    }

    @Override
    public void removeAllKeys() throws KeyManagerException {
        this.keyManagerStore.reset();
    }

    @Override
    public void close() throws Exception {
        this.keyManagerStore.close();
        SecurityProviders.removeSpongyCastleProvider();
    }

    /**
     * Deserializes encoded private key bytes to a PrivateKey object.
     *
     * @param keyBytes encoded key bytes.
     * @return private key object.
     * @throws KeyManagerException on failure, which will probably contain an exception from java.security.
     */
    protected PrivateKey bytesToPrivateKey(byte[] keyBytes) throws KeyManagerException {
        Objects.requireNonNull(keyBytes, "keyBytes can't be null.");

        PrivateKey privateKey;

        try {
            org.spongycastle.asn1.pkcs.RSAPrivateKey pkcs1PrivateKey = org.spongycastle.asn1.pkcs.RSAPrivateKey.getInstance(keyBytes);

            BigInteger modulus = pkcs1PrivateKey.getModulus();
            BigInteger privateExponent = pkcs1PrivateKey.getPrivateExponent();
            BigInteger publicExponent = pkcs1PrivateKey.getPublicExponent();
            BigInteger prime1 = pkcs1PrivateKey.getPrime1();
            BigInteger prime2 = pkcs1PrivateKey.getPrime2();
            BigInteger exp1 = pkcs1PrivateKey.getExponent1();
            BigInteger exp2 = pkcs1PrivateKey.getExponent2();
            BigInteger coef = pkcs1PrivateKey.getCoefficient();

            RSAPrivateCrtKeySpec keySpec =
                    new RSAPrivateCrtKeySpec(modulus, publicExponent, privateExponent, prime1, prime2,
                            exp1, exp2, coef);
            privateKey = this.keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new KeyManagerException("Failed to create a private key from key bytes.", e);
        }

        return privateKey;
    }

    /**
     * Serializes a private key object into a byte array. For compatibility with iOS, we are using
     * PKCS1.
     *
     * @param privateKey private key object.
     * @return byte array representing PKCS1 DER encoded private key.
     * @throws KeyManagerException on failure, which will probably contain an exception from java.security.
     */
    protected byte[] privateKeyToBytes(PrivateKey privateKey) throws KeyManagerException {
        Objects.requireNonNull(privateKey, "privateKey can't be null.");

        byte[] privateKeyPKCS1;

        try {
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(privateKey.getEncoded());
            ASN1Encodable privateKeyPKCS1ASN1Encodable = privateKeyInfo.parsePrivateKey();
            ASN1Primitive privateKeyPKCS1ASN1 = privateKeyPKCS1ASN1Encodable.toASN1Primitive();
            privateKeyPKCS1 = privateKeyPKCS1ASN1.getEncoded();
        } catch (IOException e) {
            throw new KeyManagerException("Failed to serialize the private key.", e);
        }

        return privateKeyPKCS1;
    }

    /**
     * Retrieves a platform specific private key.
     *
     * @param name name of the key to retrieve.
     * @return private key object.
     * @throws KeyManagerException on failure, which will probably contain an exception from java.security.
     */
    @Override
    public PrivateKey getPrivateKey(String name) throws KeyManagerException {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);

        return this.bytesToPrivateKey(this.getPrivateKeyData(name));
    }

    /**
     * Deserializes encoded public key bytes to a PublicKey object.
     *
     * @param keyBytes encoded key bytes.
     * @return public key object.
     * @throws KeyManagerException on failure, which will probably contain an exception from java.security.
     */
    protected PublicKey bytesToPublicKey(byte[] keyBytes) throws KeyManagerException {
        Objects.requireNonNull(keyBytes, "keyBytes can't be null.");

        PublicKey publicKey;

        try {
            org.spongycastle.asn1.pkcs.RSAPublicKey pkcs1PublicKey = org.spongycastle.asn1.pkcs.RSAPublicKey.getInstance(keyBytes);
            BigInteger modulus = pkcs1PublicKey.getModulus();
            BigInteger publicExponent = pkcs1PublicKey.getPublicExponent();
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, publicExponent);
            publicKey = this.keyFactory.generatePublic(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new KeyManagerException("Failed to create a public key from key bytes.", e);
        }

        return publicKey;
    }

    /**
     * Serializes a public key object into a byte array. For compatibility with iOS, we are using
     * PKCS1.
     *
     * @param publicKey public key object.
     * @return byte array representing PKCS1 DER encoded public key.
     * @throws KeyManagerException on failure, which will probably contain an exception from java.security.
     */
    protected byte[] publicKeyToBytes(PublicKey publicKey) throws KeyManagerException {
        Objects.requireNonNull(publicKey, "publicKey can't be null.");

        byte[] publicKeyPKCS1;
        try {
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
            ASN1Primitive publicKeyPKCS1ASN1 = publicKeyInfo.parsePublicKey();
            publicKeyPKCS1 = publicKeyPKCS1ASN1.getEncoded();
        } catch (IOException e) {
            throw new KeyManagerException("Failed to serialize the public key.", e);
        }

        return publicKeyPKCS1;
    }

    /**
     * Retrieves a platform specific public key reference.
     *
     * @param name name of the key to retrieve.
     * @return public key object.
     * @throws KeyManagerException on failure, which will probably contain an exception from java.security.
     */
    @Override
    public PublicKey getPublicKey(String name) throws KeyManagerException {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);

        byte[] publicKeyBytes = getPublicKeyData(name);
        if (publicKeyBytes != null) {
            return bytesToPublicKey(publicKeyBytes);
        }
        return null;
    }

    /**
     * Retrieves a platform specific symmetric key reference.
     *
     * @param name name of the key to retrieve.
     * @return symmetric key object.
     * @throws KeyManagerException on failure, which will probably contain an exception from java.security.
     */
    protected SecretKey getSymmetricKey(String name) throws KeyManagerException {
        Objects.requireNonNull(name, NAME_CANT_BE_NULL);

        byte[] keyBytes = this.getSymmetricKeyData(name);
        return new SecretKeySpec(keyBytes, 0, keyBytes.length, SYMMETRIC_KEY_ALGORITHM);
    }

    /**
     * Encrypts the given data with the given symmetric key reference.
     *
     * @param key       symmetric key reference.
     * @param data      data to encrypt.
     * @param iv        Initialization vector. Must be 128 bit in size.
     * @param algorithm the symmetric encryption algorithm to use.
     * @return encrypted data.
     * @throws KeyManagerException on failure, which will probably contain an exception from java.security.
     */
    protected byte[] encryptWithSymmetricKey(SecretKey key, byte[] data, byte[] iv, SymmetricEncryptionAlgorithm algorithm) throws KeyManagerException {
        Objects.requireNonNull(data, DATA_CANT_BE_NULL);

        byte[] encrypted;
        try {
            synchronized (KeyManager.class) {
                Cipher cipher = setupSymmetricCipher(key, iv, Cipher.ENCRYPT_MODE, algorithm);
                encrypted = performChunkCipherOperation(data, cipher);
            }
        } catch (Exception e) {
            throw new KeyManagerException(FAILED_TO_ENCRYPT, e);
        }
        return encrypted;
    }

    private Cipher setupSymmetricCipher(SecretKey key, byte[] iv, int mode, SymmetricEncryptionAlgorithm algorithm) throws InvalidAlgorithmParameterException, InvalidKeyException {
        Objects.requireNonNull(key, KEY_CANT_BE_NULL);
        Objects.requireNonNull(iv, "iv can't be null.");
        Objects.requireNonNull(algorithm, ALGORITHM_CANT_BE_NULL);
        if (algorithm != SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256) {
            throw new IllegalArgumentException("Algorithm " + algorithm + " is not supported");
        }

        synchronized (KeyManager.class) {
            Cipher cipher = symmetricKeyCipher.get();
            cipher.init(mode, key, new IvParameterSpec(iv));
            return cipher;
        }
    }

    /**
     * Decrypts the given data with the given symmetric key reference.
     *
     * @param key       symmetric key reference.
     * @param data      data to decrypt.
     * @param iv        Initialization vector. Must be 128 bit in size.
     * @param algorithm the symmetric decryption algorithm to use.
     * @return decrypted data.
     * @throws KeyManagerException on failure, which will probably contain an exception from java.security.
     */
    protected byte[] decryptWithSymmetricKey(SecretKey key, byte[] data, byte[] iv, SymmetricEncryptionAlgorithm algorithm) throws KeyManagerException {
        Objects.requireNonNull(data, DATA_CANT_BE_NULL);

        byte[] decrypted;
        try {
            synchronized (KeyManager.class) {
                Cipher cipher = setupSymmetricCipher(key, iv, Cipher.DECRYPT_MODE, algorithm);
                decrypted = performChunkCipherOperation(data, cipher);
            }
        } catch (Exception e) {
            throw new KeyManagerException(FAILED_TO_DECRYPT, e);
        }
        return decrypted;
    }

    /**
     * Decrypts the given data stream with the given symmetric key reference on the fly.
     *
     * @param key       symmetric key reference.
     * @param stream    data to decrypt.
     * @param iv        Initialization vector. Must be 128 bit in size.
     * @param algorithm the symmetric decryption algorithm to use.
     * @return decrypted data stream
     * @throws KeyManagerException on failure, which will probably contain an exception from java.security.
     */
    protected InputStream decryptWithSymmetricKey(SecretKey key, InputStream stream, byte[] iv, SymmetricEncryptionAlgorithm algorithm) throws KeyManagerException {
        Objects.requireNonNull(stream, "stream can't be null.");

        try {
            Cipher cipher = setupSymmetricCipher(key, iv, Cipher.DECRYPT_MODE, algorithm);
            return new CipherInputStream(stream, cipher);
        } catch (Exception e) {
            throw new KeyManagerException(FAILED_TO_DECRYPT, e);
        }
    }

    /**
     * Performs a chunked update / doFinal operation on a byte array of data.
     * Originally cipher operations were performed with doFinal only. This was okay
     * for small data sets however for larger ones data would be lost.
     *
     * @param data   data to process through the cipher in chunks if necessary.
     * @param cipher cipher to process data through.
     * @return processed cipher data
     */
    private byte[] performChunkCipherOperation(byte[] data, Cipher cipher) throws KeyManagerException {
        try {
            ByteArrayOutputStream dataOutputStream = new ByteArrayOutputStream();
            ByteArrayInputStream dataInputStream = new ByteArrayInputStream(data);

            final int chunkSize = CIPHER_CHUNK_SIZE;
            byte[] buffer = new byte[chunkSize];

            // Process the cipher updates until the remaining available data is less than
            // the accepted chunk size.
            while (dataInputStream.available() > chunkSize) {
                int readBytes = dataInputStream.read(buffer);
                dataOutputStream.write(cipher.update(buffer, 0, readBytes));
            }

            // Read the remainder of the bytes and perform doFinal on the cipher.
            int readBytes = dataInputStream.read(buffer);
            dataOutputStream.write(cipher.doFinal(buffer, 0, readBytes));

            // Returns the data processed by the cipher.
            return dataOutputStream.toByteArray();
        } catch (Exception e) {
            throw new KeyManagerException(FAILED_TO_DECRYPT, e);
        }
    }

    /**
     * Export all the keys.
     *
     * @return a {@link Map} with the key name as the map key and the exported key type and bytes
     * as the value. The map may be empty but it will not be null.
     * @throws StoreNotExportable  if the key store does not permit keys to be exported.
     * @throws KeyManagerException if the key cannot be exported from the store.
     */
    @Override
    public List<KeyComponents> exportKeys() throws KeyManagerException {
        if (!keyManagerStore.isExportable()) {
            throw new StoreNotExportable("Key store is not exportable");
        }
        Set<String> keyNames = keyManagerStore.getKeyNames();
        List<KeyComponents> keyList = new ArrayList<>(keyNames.size());
        for (String name : keyNames) {
            for (KeyType keyType : KeyType.values()) {
                byte[] keyData = keyManagerStore.getKey(name, keyType);
                if (keyData != null) {
                    KeyComponents keyComponents = new KeyComponents();
                    keyComponents.name = name;
                    keyComponents.keyType = keyType;
                    keyComponents.key = keyData;
                    keyList.add(keyComponents);
                }
            }
        }
        return keyList;
    }
}
