/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sudoplatform.sudokeymanager

import androidx.annotation.Keep
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonDeserializationContext
import com.google.gson.JsonDeserializer
import com.google.gson.JsonElement
import com.google.gson.JsonParseException
import com.google.gson.annotations.SerializedName
import com.google.gson.reflect.TypeToken
import com.sudoplatform.sudokeymanager.SecureKeyArchive.KeyArchive.KeyArchiveDeserializer
import com.sudoplatform.sudologging.AndroidUtilsLogDriver
import com.sudoplatform.sudologging.LogLevel
import com.sudoplatform.sudologging.Logger
import org.spongycastle.asn1.DERNull
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.spongycastle.asn1.pkcs.PrivateKeyInfo
import org.spongycastle.asn1.pkcs.RSAPrivateKey
import org.spongycastle.asn1.pkcs.RSAPublicKey
import org.spongycastle.asn1.x509.AlgorithmIdentifier
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo
import org.spongycastle.util.encoders.Base64
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.lang.reflect.Type
import java.nio.charset.StandardCharsets
import java.util.Collections
import java.util.zip.Deflater
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream

/**
 * A class that can read, write and process an encrypted archive
 * containing a set of cryptographic keys that are themselves
 * encrypted with a symmetric key derived from a password.
 */
class SecureKeyArchive private constructor(
    override var keyManager: KeyManagerInterface,
    private val zip: Boolean
) : SecureKeyArchiveInterface {
    internal enum class SecureKeyArchiveType {
        INSECURE,
        SECURE;

        override fun toString(): String {
            return when (this) {
                SECURE -> "Secure"
                INSECURE -> "Insecure"
            }
        }
    }

    private var keyArchive: KeyArchive? = null
    override var excludedKeys: MutableSet<String> = HashSet()
        get() {
            return Collections.unmodifiableSet(field)
        }
        set(excludedKeys) {
            field.clear()
            field.addAll(excludedKeys)
        }
    private val keys: MutableSet<KeyInfo> = HashSet()
    private val gson: Gson

    init {
        gson = GsonBuilder()
            .registerTypeAdapter(KeyType::class.java, KeyTypeJsonAdapter())
            .registerTypeAdapter(KeyArchive::class.java, KeyArchiveDeserializer())
            .disableHtmlEscaping()
            .create()
    }

    private constructor(
        archiveData: ByteArray,
        keyManager: KeyManagerInterface,
        zip: Boolean
    ) : this(keyManager, zip) {

        // Meta info might be needed before the archive is unarchived.
        if (hasValue(archiveData)) {
            loadArchive(archiveData)
        }
    }

    /**
     * Gzip decompress the input data
     *
     * @param zipped zipped data.
     * @return unzipped data.
     * @throws IOException
     */
    @Throws(IOException::class)
    private fun unzip(zipped: ByteArray?): ByteArray {
        val buffer = ByteArray(1024)
        val bos = ByteArrayOutputStream()
        val bis = ByteArrayInputStream(zipped)
        val gzis = GZIPInputStream(bis)
        var len: Int
        while (gzis.read(buffer).also { len = it } > 0) {
            bos.write(buffer, 0, len)
        }
        bis.close()
        gzis.close()
        bos.close()
        return bos.toByteArray()
    }

    /**
     * Gzip compress the input data
     *
     * @param data data to compress.
     * @return zipped data.
     * @throws IOException
     */
    @Throws(IOException::class)
    private fun zip(data: ByteArray): ByteArray {
        val bos = ByteArrayOutputStream(data.size)
        val gzos: GZIPOutputStream = object : GZIPOutputStream(bos) {
            init {
                def.setLevel(Deflater.BEST_COMPRESSION)
            }
        }
        gzos.write(data)
        gzos.close()
        bos.close()
        return bos.toByteArray()
    }

    /**
     * Reads the base64 data and converts it to JSON and then deserializes it into a KeyArchive
     */
    @Throws(SecureKeyArchiveException::class)
    private fun loadArchive(archiveData: ByteArray) {
        if (hasNoValue(archiveData)) {
            throw SecureKeyArchiveException(
                SecureKeyArchiveException.ARCHIVE_EMPTY,
                "Archive data is empty"
            )
        }
        if (this.version == ARCHIVE_VERSION_V3) {
            // V3 archive is always gzip compressed so we need decompress it first.
            val unzipped: ByteArray = try {
                this.unzip(archiveData)
            } catch (e: IOException) {
                throw SecureKeyArchiveException(
                    SecureKeyArchiveException.MALFORMED_ARCHIVEDATA,
                    "Archive data is not a valid gzipped data: " + e.message
                )
            }
            val keyArchiveJson = String(unzipped, UTF8)
            keyArchive = gson.fromJson(keyArchiveJson, KeyArchive::class.java)
            if (keyArchive == null) {
                throw SecureKeyArchiveException(
                    SecureKeyArchiveException.MALFORMED_ARCHIVEDATA,
                    "Unable to deserialize the JSON of the archive"
                )
            }
            if (keyArchive!!.version != ARCHIVE_VERSION_V3) {
                throw SecureKeyArchiveException(
                    SecureKeyArchiveException.VERSION_MISMATCH, String.format(
                        "Version %d in the archive data is incompatible with expected version %d",
                        keyArchive!!.version, ARCHIVE_VERSION_V3
                    )
                )
            }
        } else {
            val keyArchiveJson = String(archiveData, UTF8)
            keyArchive = gson.fromJson(keyArchiveJson, KeyArchive::class.java)
            if (keyArchive == null) {
                throw SecureKeyArchiveException(
                    SecureKeyArchiveException.MALFORMED_ARCHIVEDATA,
                    "Unable to deserialise the JSON of the archive"
                )
            }
            if (keyArchive!!.version != ARCHIVE_VERSION_V2) {
                throw SecureKeyArchiveException(
                    SecureKeyArchiveException.VERSION_MISMATCH, String.format(
                        "Version %d in the archive data is incompatible with expected version %d",
                        keyArchive!!.version, ARCHIVE_VERSION_V2
                    )
                )
            }
            if (hasNoValue(keyArchive!!.type)) {
                // Default to secure archive to account for archives created prior to introduction of `Type`
                // These are secured by default because type was introduced with insecure archives feature.
                keyArchive!!.type = SecureKeyArchiveType.SECURE.toString()
            }
        }
    }

    /**
     * Loads keys from the secure store into the archive.
     *
     * @throws KeyManagerException if the keys could not be exported.
     * @throws StoreNotExportable  if the key store does not permit keys to be exported.
     */
    @Throws(KeyManagerException::class)
    override fun loadKeys() {
        val exportedKeys = keyManager.exportKeys()
        for (keyComponents in exportedKeys) {
            if (excludedKeys.contains(keyComponents.name)) {
                continue
            }
            if (hasValue(keyComponents.key)) {
                if (this.version == ARCHIVE_VERSION_V2) {
                    keys.add(
                        KeyInfo.make(
                            keyComponents.name, keyComponents.keyType, keyComponents.key
                        )
                    )
                } else {
                    // If we are dealing with v3 archive then we need to convert the
                    // format of public and private keys since JS SDK uses different
                    // formats.
                    var keyData = keyComponents.key
                    if (keyComponents.keyType === KeyType.PUBLIC_KEY) {
                        val rsaPublicKey = RSAPublicKey.getInstance(
                            keyComponents.key
                        )
                        val algorithmIdentifier = AlgorithmIdentifier(
                            PKCSObjectIdentifiers.rsaEncryption,
                            DERNull.INSTANCE
                        )
                        keyData = try {
                            val subjectPublicKeyInfo =
                                SubjectPublicKeyInfo(algorithmIdentifier, rsaPublicKey)
                            subjectPublicKeyInfo.encoded
                        } catch (e: Exception) {
                            throw KeyManagerException("Failed to convert RSAPublicKey to SubjectPublicKeyInfo: " + e.message)
                        }
                    } else if (keyComponents.keyType === KeyType.PRIVATE_KEY) {
                        val rsaPrivateKey = RSAPrivateKey.getInstance(
                            keyComponents.key
                        )
                        val algorithmIdentifier = AlgorithmIdentifier(
                            PKCSObjectIdentifiers.rsaEncryption,
                            DERNull.INSTANCE
                        )
                        keyData = try {
                            val privateKeyInfo = PrivateKeyInfo(algorithmIdentifier, rsaPrivateKey)
                            privateKeyInfo.encoded
                        } catch (e: Exception) {
                            throw KeyManagerException("Failed to convert RSAPrivateKey to PrivateKeyInfo: " + e.message)
                        }
                    }
                    keys.add(
                        KeyInfo.make(
                            keyComponents.name, keyComponents.keyType, keyData
                        )
                    )
                }
            }
        }
    }

    /**
     * Saves the keys in this archive to the secure store.
     *
     * @throws SecureKeyArchiveException with one of the following reasons:
     * [SecureKeyArchiveException.ARCHIVE_EMPTY],
     * [SecureKeyArchiveException.FATAL_ERROR]
     */
    @Throws(SecureKeyArchiveException::class)
    override fun saveKeys() {
        if (keys.isEmpty()) {
            throw SecureKeyArchiveException(
                SecureKeyArchiveException.ARCHIVE_EMPTY,
                "Key archive is empty. Have you called loadKeys?"
            )
        }
        try {
            // Remove all keys first to avoid any conflicts.
            keyManager.removeAllKeys()
        } catch (e: KeyManagerException) {
            throw SecureKeyArchiveException(SecureKeyArchiveException.FATAL_ERROR, e.toString(), e)
        }
        try {
            val keyPairs: MutableMap<String, MutableSet<KeyInfo>> = HashMap()
            for (keyInfo in keys) {
                if (excludedKeys.contains(keyInfo.Name)) {
                    continue
                }
                when (keyInfo.Type) {
                    KeyType.PASSWORD -> keyManager.addPassword(keyInfo.data, keyInfo.Name, true)
                    KeyType.SYMMETRIC_KEY -> keyManager.addSymmetricKey(
                        keyInfo.data,
                        keyInfo.Name,
                        true
                    )

                    KeyType.PRIVATE_KEY, KeyType.PUBLIC_KEY -> {
                        // Collect the public and private keys so they can be matched up into pairs
                        if (!keyPairs.containsKey(keyInfo.Name)) {
                            keyPairs[keyInfo.Name] = HashSet()
                        }
                        keyPairs[keyInfo.Name]!!.add(keyInfo)
                    }

                    else -> {}
                }
            }

            // Match the private and public keys with the same name and add them as a key pair.
            for ((key, value) in keyPairs) {
                when (value.size) {
                    2 -> {
                        // A public and private key
                        addKeyPair(key, value)
                    }
                    1 -> {
                        // Possibly a public key on its own
                        addKey(value)
                    }
                    else -> {
                        throw AssertionError("Programming error, logic inconsistency 1")
                    }
                }
            }
        } catch (e: KeyManagerException) {
            throw SecureKeyArchiveException(SecureKeyArchiveException.FATAL_ERROR, e.toString(), e)
        }
    }

    @Throws(KeyManagerException::class)
    private fun addKeyPair(keyName: String, keys: Collection<KeyInfo>) {
        var publicKey: KeyInfo? = null
        var privateKey: KeyInfo? = null
        for (key in keys) {
            if (key.Type === KeyType.PRIVATE_KEY) {
                privateKey = key
            } else if (key.Type === KeyType.PUBLIC_KEY) {
                publicKey = key
            } else {
                throw AssertionError("Programming error, logic inconsistency 2")
            }
        }
        if (publicKey == null || privateKey == null || publicKey.Name != privateKey.Name) {
            throw AssertionError("Programming error, logic inconsistency 3")
        }
        if (this.version == ARCHIVE_VERSION_V2) {
            keyManager.addKeyPair(privateKey.data, publicKey.data, keyName, true)
        } else {
            keyManager.addKeyPairFromKeyInfo(privateKey.data, publicKey.data, keyName, true)
        }
    }

    @Throws(KeyManagerException::class)
    private fun addKey(keys: Collection<KeyInfo>) {
        for (key in keys) {
            if (key.Type === KeyType.PRIVATE_KEY) {
                logger.error("Orphaned private key found in key archive")
            } else if (key.Type === KeyType.PUBLIC_KEY) {
                keyManager.addPublicKey(key.data, key.Name, true)
            } else {
                throw AssertionError("Programming error, logic inconsistency 4")
            }
        }
    }

    /**
     * Setup the key archive container if needed.
     */
    private fun setupKeyArchiveContainer() {
        if (keyArchive == null) {
            keyArchive = KeyArchive()
        }
    }

    /**
     * Archives, in plaintext, the keys loaded into this archive.
     *
     * @return encrypted archive data.
     * @throws SecureKeyArchiveException with one of the following reasons:
     * [SecureKeyArchiveException.ARCHIVE_EMPTY],
     * [SecureKeyArchiveException.FATAL_ERROR]
     */
    @Throws(SecureKeyArchiveException::class)
    override fun archive(): ByteArray {
        if (keys.isEmpty()) {
            throw SecureKeyArchiveException(
                SecureKeyArchiveException.ARCHIVE_EMPTY,
                "Key archive is empty. Have you called loadKeys?"
            )
        }
        // Set up the key archive container
        setupKeyArchiveContainer()
        val data: ByteArray
        if (this.version == ARCHIVE_VERSION_V2) {
            val keysJson = gson.toJson(keys)
            val encodedKeys = String(Base64.encode(keysJson.toByteArray(StandardCharsets.UTF_8)))
            keyArchive!!.version = ARCHIVE_VERSION_V2
            data = archiveKeys(encodedKeys, SecureKeyArchiveType.INSECURE)
        } else {
            keyArchive!!.version = ARCHIVE_VERSION_V3
            keyArchive!!.type = SecureKeyArchiveType.INSECURE.toString()
            keyArchive!!.keysAsList = ArrayList(keys)
            val keyArchiveJson = gson.toJson(keyArchive)
            data = try {
                this.zip(keyArchiveJson.toByteArray(UTF8))
            } catch (e: IOException) {
                throw SecureKeyArchiveException(
                    SecureKeyArchiveException.MALFORMED_ARCHIVEDATA,
                    "Archive data could not be compressed: " + e.message
                )
            }
        }
        return data
    }

    /**
     * Archives and encrypts the keys loaded into this archive.
     *
     * @param password the password to use to encrypt the archive.
     * @return encrypted archive data.
     * @throws SecureKeyArchiveException with one of the following reasons:
     * [SecureKeyArchiveException.INVALID_PASSWORD],
     * [SecureKeyArchiveException.ARCHIVE_EMPTY],
     * [SecureKeyArchiveException.FATAL_ERROR]
     */
    @Throws(SecureKeyArchiveException::class)
    override fun archive(password: String): ByteArray {
        if (keys.isEmpty()) {
            throw SecureKeyArchiveException(
                SecureKeyArchiveException.ARCHIVE_EMPTY,
                "Key archive is empty. Have you called loadKeys?"
            )
        }
        setupKeyArchiveContainer()

        // Create a symmetric key from the password for encrypting the keys
        val symmetricKey: ByteArray
        try {
            val keyComponents = keyManager.createSymmetricKeyFromPassword(password)
            symmetricKey = keyComponents.key
            keyArchive!!.rounds = keyComponents.rounds
            keyArchive!!.salt = String(
                Base64.encode(
                    keyComponents.salt
                ), UTF8
            )
        } catch (e: KeyManagerException) {
            throw SecureKeyArchiveException(
                SecureKeyArchiveException.INVALID_PASSWORD,
                "Unable to create a key from the password", e
            )
        }
        val keysJson = gson.toJson(keys)
        var keysData = keysJson.toByteArray(UTF8)
        return if (this.version == ARCHIVE_VERSION_V2) {
            try {
                val keysEncrypted = keyManager.encryptWithSymmetricKey(symmetricKey, keysData)
                val encodedKeys = String(Base64.encode(keysEncrypted))
                keyArchive!!.version = ARCHIVE_VERSION_V2
                archiveKeys(encodedKeys, SecureKeyArchiveType.SECURE)
            } catch (e: KeyManagerException) {
                throw SecureKeyArchiveException(
                    SecureKeyArchiveException.INVALID_PASSWORD,
                    "Unable to encrypt the keys with the password", e
                )
            }
        } else {
            // V3 archive requires you to zip the input to encryption.
            keysData = try {
                this.zip(keysData)
            } catch (e: IOException) {
                throw SecureKeyArchiveException(
                    SecureKeyArchiveException.MALFORMED_ARCHIVEDATA,
                    "Keys data could not be compressed: " + e.message
                )
            }
            try {
                // Random IV is not necessary for secure archives but JS SDK uses it so we need to
                // be consistent for interop. The use of non default IV also makes V3 secure archive
                // not compatible with AES-GCM.
                val iv = keyManager.createRandomData(16)
                val keysEncrypted = keyManager.encryptWithSymmetricKey(symmetricKey, keysData, iv)
                val encodedKeys = String(Base64.encode(keysEncrypted))
                keyArchive!!.version = ARCHIVE_VERSION_V3
                keyArchive!!.iv = String(Base64.encode(iv))
                val archiveData = archiveKeys(encodedKeys, SecureKeyArchiveType.SECURE)
                try {
                    this.zip(archiveData)
                } catch (e: IOException) {
                    throw SecureKeyArchiveException(
                        SecureKeyArchiveException.MALFORMED_ARCHIVEDATA,
                        "Keys data could not be compressed: " + e.message
                    )
                }
            } catch (e: KeyManagerException) {
                throw SecureKeyArchiveException(
                    SecureKeyArchiveException.INVALID_PASSWORD,
                    "Unable to encrypt the keys with the password", e
                )
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
    private fun archiveKeys(keysJson: String, type: SecureKeyArchiveType): ByteArray {
        // add values to archive
        keyArchive!!.type = type.toString()
        keyArchive!!.keysAsString = keysJson
        val keyArchiveJson = gson.toJson(keyArchive)
        return keyArchiveJson.toByteArray(UTF8)
    }

    /**
     * Unarchives plaintext keys in this archive.
     *
     * @throws SecureKeyArchiveException with one of the following reasons:
     * [SecureKeyArchiveException.ARCHIVE_EMPTY],
     * [SecureKeyArchiveException.INVALID_ARCHIVE_DATA],
     * [SecureKeyArchiveException.FATAL_ERROR]
     */
    @Throws(SecureKeyArchiveException::class)
    override fun unarchive() {
        if (this.version == ARCHIVE_VERSION_V2) {
            val keyData = decodeKeyData()
            val keyArrayJson = String(keyData)
            loadKeysFromDecodedPayload(keyArrayJson)
        } else {
            keys.clear()
            for (keyInfo in keyArchive!!.keysAsList!!) {
                keyInfo.data = Base64.decode(keyInfo.base64Data)
                keys.add(keyInfo)
            }
        }
    }

    /**
     * Decrypts and unarchives the keys in this archive.
     *
     * @param password the password to use to decrypt the archive.
     * @throws SecureKeyArchiveException with one of the following reasons:
     * [SecureKeyArchiveException.INVALID_PASSWORD],
     * [SecureKeyArchiveException.ARCHIVE_EMPTY],
     * [SecureKeyArchiveException.INVALID_ARCHIVE_DATA],
     * [SecureKeyArchiveException.MALFORMED_ARCHIVEDATA],
     * [SecureKeyArchiveException.FATAL_ERROR]
     */
    @Throws(SecureKeyArchiveException::class)
    override fun unarchive(password: String) {
        // Fetch decoded key data first before doing encryption work so this can fail early
        val keyDataEncrypted = decodeKeyData()

        // Validate decryption inputs and generate a key
        if (hasNoValue(keyArchive!!.salt) || keyArchive!!.rounds < 1) {
            throw SecureKeyArchiveException(
                SecureKeyArchiveException.INVALID_ARCHIVE_DATA,
                "The archive lacks a Salt or Rounds value."
            )
        }
        if (hasNoValue(password)) {
            throw SecureKeyArchiveException(
                SecureKeyArchiveException.INVALID_PASSWORD,
                "Invalid password, it must not be null or empty."
            )
        }
        val salt = Base64.decode(keyArchive!!.salt)
        val symmetricKey: ByteArray = try {
            keyManager.createSymmetricKeyFromPassword(password, salt, keyArchive!!.rounds)
        } catch (e: KeyManagerException) {
            throw SecureKeyArchiveException(
                SecureKeyArchiveException.INVALID_PASSWORD,
                "Unable to create a key from the password", e
            )
        }
        try {
            // decrypt payload and load keys when finished
            var iv: ByteArray? = null
            if (hasValue(keyArchive!!.iv)) {
                iv = Base64.decode(keyArchive!!.iv)
            }
            var keyDataClear: ByteArray?
            keyDataClear = if (iv != null) {
                keyManager.decryptWithSymmetricKey(symmetricKey, keyDataEncrypted, iv)
            } else {
                keyManager.decryptWithSymmetricKey(symmetricKey, keyDataEncrypted)
            }
            if (this.version == ARCHIVE_VERSION_V3) {
                // V3 encrypted archive is zipped twice so we need to unzip one more time.
                keyDataClear = try {
                    this.unzip(keyDataClear)
                } catch (e: IOException) {
                    throw SecureKeyArchiveException(
                        SecureKeyArchiveException.MALFORMED_ARCHIVEDATA,
                        "Key data is not a valid gzipped data: " + e.message
                    )
                }
            }
            val keyArrayJson = String(keyDataClear!!)
            loadKeysFromDecodedPayload(keyArrayJson)
        } catch (e: KeyManagerException) {
            throw SecureKeyArchiveException(
                SecureKeyArchiveException.MALFORMED_KEYSET_DATA,
                "Unable to decrypt keys from the archive", e
            )
        }
    }

    /**
     * Internal function to decode and validate keys in the key archive. This is part of multi-step
     * process to load keys from an archive.
     *
     * @return decoded key.
     * @throws SecureKeyArchiveException
     */
    @Throws(SecureKeyArchiveException::class)
    private fun decodeKeyData(): ByteArray {
        if (hasNoValue(keyArchive!!.keysAsString)) {
            throw SecureKeyArchiveException(
                SecureKeyArchiveException.INVALID_ARCHIVE_DATA,
                "The Keys in the archive are empty"
            )
        }
        val keyData = Base64.decode(keyArchive!!.keysAsString)
        if (hasNoValue(keyData)) {
            throw SecureKeyArchiveException(
                SecureKeyArchiveException.INVALID_ARCHIVE_DATA,
                "The Keys in the archive, after base64 decoding, are empty"
            )
        }
        return keyData
    }

    /**
     * Internal function to load decoded (possibly decrypted) key archive json data.
     * Part of a multi-step process to load keys from an archive.
     *
     * @param keyArrayJson A string representing a JSON array of keys.
     * @throws SecureKeyArchiveException
     */
    @Throws(SecureKeyArchiveException::class)
    private fun loadKeysFromDecodedPayload(keyArrayJson: String) {
        val keyInfoArray = gson.fromJson(keyArrayJson, Array<KeyInfo>::class.java)
            ?: throw SecureKeyArchiveException(
                SecureKeyArchiveException.MALFORMED_KEYSET_DATA,
                "Unable to deserialise decrypted keys from the archive"
            )
        keys.clear()
        for (keyInfo in keyInfoArray) {
            keyInfo.data = Base64.decode(keyInfo.base64Data)
            keys.add(keyInfo)
        }
    }

    /**
     * Resets the archive by clearing loaded keys and archive data.
     */
    override fun reset() {
        keys.clear()
        keyArchive = null
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
    override fun containsKey(name: String, type: KeyType): Boolean {
        return findKey(name, type) != null
    }

    private fun findKey(name: String, type: KeyType): KeyInfo? {
        for (keyInfo in keys) {
            if (keyInfo.Name == name && keyInfo.Type === type) {
                return keyInfo
            }
        }
        return null
    }

    /**
     * Retrieves the specified key data from the archive. The archive must
     * be unarchived before the key data can be retrieved.
     *
     * @param name the key name.
     * @param type the key type.
     * @return a byte array containing the specified key data or null if it was not found.
     */
    override fun getKeyData(name: String, type: KeyType): ByteArray? {
        return findKey(name, type)?.data
    }

    /**
     * @return the meta-information associated with this archive.
     */
    override fun getMetaInfo(): Map<String, String> {
        return if (keyArchive == null) {
            emptyMap()
        } else keyArchive!!.metaInfo
    }

    /**
     * Sets the meta-information associated with this archive.
     *
     * @param metaInfo the meta-information associated with this archive.
     */
    override fun setMetaInfo(metaInfo: Map<String, String>) {
        setupKeyArchiveContainer()
        keyArchive!!.metaInfo.clear()
        keyArchive!!.metaInfo.putAll(metaInfo)
    }

    /**
     * @return the archive version.
     */
    override val version: Int
        get() {
            return if (zip) {
                ARCHIVE_VERSION_V3
            } else {
                ARCHIVE_VERSION_V2
            }
        }

    /**
     * @return the type of archive, secure or insecure. Must read archive first by calling
     * `unarchive`, otherwise returns null.
     */
    override val type: String?
        get() {
            return if (keyArchive == null) {
                // type only makes sense in the context of a archive that has been read by
                // calling unarchive and null seems the best response as there isn't a value.
                null
            } else keyArchive!!.type
        }

    /**
     * The JSON format of the key archive when converted by Gson
     */
    @Keep
    private class KeyArchive {
        @SerializedName("MetaInfo")
        var metaInfo = HashMap<String, String>()

        @SerializedName("Rounds")
        var rounds = 0

        @SerializedName("Salt")
        var salt: String? = null
        var keysAsString: String? = null
        var keysAsList: List<KeyInfo>? = null

        @SerializedName("IV")
        var iv: String? = null

        @SerializedName("Version")
        var version = 0

        @SerializedName("Type")
        var type: String? = null

        class KeyArchiveDeserializer : JsonDeserializer<KeyArchive> {
            @Throws(JsonParseException::class)
            override fun deserialize(
                json: JsonElement,
                typeOfT: Type,
                context: JsonDeserializationContext
            ): KeyArchive {
                val keyArchive = GsonBuilder()
                    .disableHtmlEscaping()
                    .create().fromJson(json, KeyArchive::class.java)
                val jsonObject = json.asJsonObject
                if (jsonObject.has("Keys")) {
                    val element = jsonObject["Keys"]
                    if (element.isJsonArray) {
                        keyArchive.keysAsList = GsonBuilder()
                            .registerTypeAdapter(KeyType::class.java, KeyTypeJsonAdapter())
                            .create()
                            .fromJson(element, object : TypeToken<ArrayList<KeyInfo?>?>() {}.type)
                    } else {
                        keyArchive.keysAsString = element.asString
                    }
                }
                return keyArchive
            }
        }
    }

    /**
     * The JSON format of a single key within the archive when converted by Gson
     */
    @Keep
    private class KeyInfo {
        var Version = 0
        var Synchronizable = false
        var NameSpace: String? = null
        lateinit var Type: KeyType
        lateinit var Name: String

        @SerializedName("Data")
        var base64Data: String? = null

        @SerializedName("data")
        lateinit var data: ByteArray
        override fun toString(): String {
            return javaClass.simpleName + "{ Version=" + Version +
                    ", Synchronizable=" + Synchronizable +
                    ", NameSpace='" + NameSpace + '\'' +
                    ", Type='" + Type + '\'' +
                    ", Name='" + Name + '\'' +
                    ", Data='" + base64Data + '\'' +
                    ", data.len='" + (data.size) + '\'' +
                    '}'
        }

        companion object {
            fun make(name: String, keyType: KeyType, data: ByteArray): KeyInfo {
                val keyInfo = KeyInfo()
                keyInfo.Name = name
                keyInfo.Type = keyType
                keyInfo.data = data.copyOf(data.size)
                keyInfo.base64Data = String(Base64.encode(keyInfo.data), UTF8)
                keyInfo.Version = KEY_VERSION
                keyInfo.Synchronizable = false
                return keyInfo
            }
        }
    }

    override fun toString(): String {
        return javaClass.simpleName + "{ keyArchive=" + keyArchive +
                ", excludedKeys=" + excludedKeys +
                ", keys=" + keys +
                '}'
    }

    private fun hasValue(s: String?): Boolean {
        // I would have used !TextUtils.isEmpty(s) but it isn't available in unit tests
        return !s.isNullOrEmpty()
    }

    private fun hasNoValue(s: String?): Boolean {
        return !hasValue(s)
    }

    private fun hasValue(b: ByteArray?): Boolean {
        return b != null && b.isNotEmpty()
    }

    private fun hasNoValue(b: ByteArray): Boolean {
        return !hasValue(b)
    }

    companion object {
        /**
         * Secure key archive format versions.
         */
        private const val ARCHIVE_VERSION_V2 = 2
        private const val ARCHIVE_VERSION_V3 = 3

        /**
         * Secure key entry format version
         */
        private const val KEY_VERSION = 1
        private val UTF8 = StandardCharsets.UTF_8
        private val logger = Logger(
            "SudoKeyManager",
            AndroidUtilsLogDriver(LogLevel.INFO)
        )

        /**
         * Returns an instance of a SecureKeyArchiveInterface.
         *
         * @param keyManager the key manager instance that will be used to encrypt the keys in this archive.
         * @return a secure key archive that uses the nominated key manager.
         */
        @JvmStatic
        fun getInstance(keyManager: KeyManagerInterface): SecureKeyArchiveInterface {
            return SecureKeyArchive(keyManager, false)
        }

        /**
         * Returns an instance of a SecureKeyArchiveInterface. This method should be used for
         * creating V3 archive i.e. gzip compressed archive.
         *
         * @param keyManager the key manager instance that will be used to encrypt the keys in this archive.
         * @return a secure key archive that uses the nominated key manager.
         */
        @JvmStatic
        fun getInstanceV3(keyManager: KeyManagerInterface): SecureKeyArchiveInterface {
            return SecureKeyArchive(keyManager, true)
        }

        /**
         * Returns an instance of a SecureKeyArchiveInterface initaliased with the
         * encrypted archive data.
         *
         * @param archiveData: encrypted key archive data.
         * @param keyManager   the key manager instance that will be used to encrypt the keys in this archive.
         * @return a secure key archive that uses the nominated key manager.
         * @throws SecureKeyArchiveException if the loading failed with one of the following reasons:
         * [SecureKeyArchiveException.MALFORMED_ARCHIVEDATA],
         * [SecureKeyArchiveException.FATAL_ERROR]
         */
        @JvmStatic
        @Throws(SecureKeyArchiveException::class)
        fun getInstance(
            archiveData: ByteArray,
            keyManager: KeyManagerInterface
        ): SecureKeyArchiveInterface {
            return SecureKeyArchive(archiveData, keyManager, false)
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
         * [SecureKeyArchiveException.MALFORMED_ARCHIVEDATA],
         * [SecureKeyArchiveException.FATAL_ERROR]
         */
        @JvmStatic
        @Throws(SecureKeyArchiveException::class)
        fun getInstanceV3(
            archiveData: ByteArray,
            keyManager: KeyManagerInterface
        ): SecureKeyArchiveInterface {
            return SecureKeyArchive(archiveData, keyManager, true)
        }
    }
}
