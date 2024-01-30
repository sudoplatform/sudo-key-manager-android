/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sudoplatform.sudokeymanager

import android.os.Build
import org.spongycastle.jce.provider.BouncyCastleProvider
import java.security.Provider
import java.security.Security

/**
 * Management of security providers. Chiefly the insertion of Spongy Castle into the right
 * place in the list of system security providers. Spongy Castle provides a more modern
 * implementation of the ancient Bouncy Castle implementation that is baked into the
 * Android platform.
 *
 * It's no longer necessary to call this class before initialising the [KeyManager] or
 * [AndroidKeyManager] because this class is now invoked by the constructors
 * of those classes.
 *
 */
object SecurityProviders {
    const val NOT_FOUND = -1
    const val SPONGY_CASTLE = "SC"
    const val BOUNCY_CASTLE = "BC"

    /**
     * There is a bug in Spongy Castle. It declares that it handles key types that it actually
     * doesn't, such as Android KeyStore keys. To avoid this insert the Spongy Castle provider
     * in the security provider list just above the existing Bouncy Castle provider. This will
     * ensure that the Android system gets a chance to declare its correct support for Android
     * KeyStore keys before Spongy Castle erroneously declares its support.
     *
     * https://groups.google.com/forum/#!msg/android-developers/gDb8cJoSzqc/9uAdzaLsCwAJ
     * https://www.bouncycastle.org/jira/browse/BJA-543
     */
    @JvmStatic
    fun installSpongyCastleProvider() {
        if (!isSpongyCastleProviderRequired) {
            // Spongy Castle is not needed in Android P and above.
            return
        }
        val providers = Security.getProviders()
        var bouncyCastleIndex = getProviderIndex(providers, BOUNCY_CASTLE)
        var spongyCastleIndex = getProviderIndex(providers, SPONGY_CASTLE)
        if (bouncyCastleIndex == NOT_FOUND) {
            bouncyCastleIndex = 1
        }
        if (spongyCastleIndex == bouncyCastleIndex + 1) {
            // Already installed in the right position
            return
        }
        spongyCastleIndex = bouncyCastleIndex + 1

        // Security provider indices are 1 based
        Security.insertProviderAt(BouncyCastleProvider(), spongyCastleIndex)
    }

    @JvmStatic
    fun getProviderIndex(providers: Array<Provider>, providerName: String): Int {
        for (i in providers.indices) {
            if (providerName == providers[i].name) {
                return i
            }
        }
        return NOT_FOUND
    }

    @JvmStatic
    fun removeSpongyCastleProvider() {
        if (isSpongyCastleProviderRequired) {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        }
    }

    @JvmStatic
    val isSpongyCastleProviderRequired: Boolean
        get() = // Spongy Castle is not needed on Android O and above.
            Build.VERSION.SDK_INT < Build.VERSION_CODES.O
}
