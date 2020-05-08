package com.sudoplatform.sudokeymanager

import android.content.Context

class KeyManagerFactory(private val context: Context) {

    @Throws(KeyManagerException::class)
    fun createAndroidKeyManager(): KeyManagerInterface {
        val storeInterface = ExportableAndroidStore(context,
                KeyManager.SYMMETRIC_KEY_ALGORITHM,
                KeyManager.SYMMETRIC_KEY_ALGORITHM_BLOCK_MODE,
                KeyManager.SYMMETRIC_KEY_ALGORITHM_ENCRYPTION_PADDING
        )
        val androidKeyStore = storeInterface.androidKeyStore
        return AndroidKeyManager(storeInterface, androidKeyStore)
    }

}
