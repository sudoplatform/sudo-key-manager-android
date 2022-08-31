/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sudoplatform.sudokeymanager;

/**
 * Exception related to errors in KeyManager's store implementation.
 */
public class StoreException extends KeyManagerException {
    public StoreException(String message) {
        super(message);
    }

    public StoreException(Throwable cause) {
        super(cause);
    }

    public StoreException(String message, Throwable cause) {
        super(message, cause);
    }
}
