package com.sudoplatform.sudokeymanager

import android.content.Context

class KeyManagerFactory(private val context: Context) {

    @Throws(KeyManagerException::class)
    fun createAndroidKeyManager(): KeyManagerInterface {
        val storeInterface = ExportableAndroidStore(
            context,
            KeyManager.SYMMETRIC_KEY_ALGORITHM_AES
        )
        val androidKeyStore = storeInterface.androidKeyStore
        return AndroidKeyManager(storeInterface, androidKeyStore)
    }

    /**
     * Creates a `KeyManager` instance that's backed by Android Keystore and using the specified
     * the namespace.
     *
     * @param keyNamespace key namespace to use to prevent name clashes when multiple consumers are
     *                     using the same underlying key store.
     */
    @Throws(KeyManagerException::class)
    fun createAndroidKeyManager(keyNamespace: String): KeyManagerInterface {
        val storeInterface = ExportableAndroidStore(
            context,
            KeyManager.SYMMETRIC_KEY_ALGORITHM_AES,
            keyNamespace
        )
        val androidKeyStore = storeInterface.androidKeyStore
        return AndroidKeyManager(storeInterface, androidKeyStore, keyNamespace)
    }

}
