/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sudoplatform.sudokeymanager;

/**
 * Thrown if the store does not support exporting keys.
 */
public final class StoreNotExportable extends KeyManagerException {

    public StoreNotExportable(String msg) {
        super(msg);
    }

    public StoreNotExportable(String message, Throwable cause) {
        super(message, cause);
    }

    public StoreNotExportable(Throwable cause) {
        super(cause);
    }

}
