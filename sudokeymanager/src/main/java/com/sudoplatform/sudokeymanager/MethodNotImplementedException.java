/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sudoplatform.sudokeymanager;

/**
 * Thrown if the method is intentionally not implemented.
 */
public final class MethodNotImplementedException extends KeyManagerException {
    public MethodNotImplementedException() {
        super("This method is not implemented!");
    }
}
