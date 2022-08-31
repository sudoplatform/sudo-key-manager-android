/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sudoplatform.sudokeymanager;

import android.os.Build;

import org.spongycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;

/**
 * Management of security providers. Chiefly the insertion of Spongy Castle into the right
 * place in the list of system security providers. Spongy Castle provides a more modern
 * implementation of the ancient Bouncy Castle implementation that is baked into the
 * Android platform.
 *
 * It's no longer necessary to call this class before initialising the {@link KeyManager} or
 * {@link AndroidKeyManager} because this class is now invoked by the constructors
 * of those classes.
 *
 */

public class SecurityProviders {

    static final int    NOT_FOUND = -1;
    static final String SPONGY_CASTLE = "SC";
    static final String BOUNCY_CASTLE = "BC";

    private SecurityProviders() {
        // Instantiation prohibited
    }

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
    public static void installSpongyCastleProvider() {

        if (!isSpongyCastleProviderRequired()) {
            // Spongy Castle is not needed in Android P and above.
            return;
        }

        Provider[] providers = Security.getProviders();
        int bouncyCastleIndex = getProviderIndex(providers, BOUNCY_CASTLE);
        int spongyCastleIndex = getProviderIndex(providers, SPONGY_CASTLE);

        if (bouncyCastleIndex == NOT_FOUND) {
            bouncyCastleIndex = 1;
        }
        if (spongyCastleIndex == bouncyCastleIndex + 1) {
            // Already installed in the right position
            return;
        }

        spongyCastleIndex = bouncyCastleIndex + 1;

        // Security provider indices are 1 based
        Security.insertProviderAt(new BouncyCastleProvider(), spongyCastleIndex);
    }

    static int getProviderIndex(Provider[] providers, String providerName) {
        for (int i = 0; i < providers.length; i++) {
            if (providerName.equals(providers[i].getName())) {
                return i;
            }
        }
        return NOT_FOUND;
    }

    public static void removeSpongyCastleProvider() {
        if (isSpongyCastleProviderRequired()) {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        }
    }

    static boolean isSpongyCastleProviderRequired() {
        // Spongy Castle is not needed on Android O and above.
        return Build.VERSION.SDK_INT < Build.VERSION_CODES.O;
    }
}
