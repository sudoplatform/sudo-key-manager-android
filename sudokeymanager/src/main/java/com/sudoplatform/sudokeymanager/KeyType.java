/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sudoplatform.sudokeymanager;

import androidx.annotation.Keep;

/**
 * Key types supported by KeyManager.
 */
@Keep
public enum KeyType {

    PASSWORD(1),
    PRIVATE_KEY(2),
    PUBLIC_KEY(3),
    SYMMETRIC_KEY(4),
    KEY_PAIR(5);

    private final int value;

    private KeyType(int value) {
        this.value = value;
    }

    /**
     * Returns serializable value of the enum.
     *
     * @return integer representation of enum.
     */
    public int getValue() {
        return value;
    }

}
