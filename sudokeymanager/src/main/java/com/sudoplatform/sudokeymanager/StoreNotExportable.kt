/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sudoplatform.sudokeymanager

/**
 * Thrown if the store does not support exporting keys.
 */
class StoreNotExportable : KeyManagerException {
    constructor(msg: String?) : super(msg)
    constructor(message: String?, cause: Throwable?) : super(message, cause)
    constructor(cause: Throwable?) : super(cause)
}
