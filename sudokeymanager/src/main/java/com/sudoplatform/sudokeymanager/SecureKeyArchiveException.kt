/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sudoplatform.sudokeymanager

/**
 * An exception thrown when a problem was detected with a [SecureKeyArchiveInterface].
 */
class SecureKeyArchiveException @JvmOverloads constructor(
    /**
     * Returns the reason why this exception was thrown.
     *
     * @return the reason why this exception was thrown.
     */
    val reason: Int,
    message: String?,
    cause: Throwable? = null,
) : Exception(message, cause) {

    constructor(message: String?) : this(NO_REASON, message, null)
    constructor(message: String?, cause: Throwable?) : this(NO_REASON, message, cause)

    companion object {
        /** Indicates that duplicate keys were found while saving the keys to the secure store. */
        const val DUPLICATE_KEY = Short.MAX_VALUE.toInt()

        /** Indicates that unarchive or archive operation was requested but the archive was empty.  */
        const val ARCHIVE_EMPTY = Short.MAX_VALUE + 1

        /** Indicates the password invalid, e.g. empty string.  */
        const val INVALID_PASSWORD = Short.MAX_VALUE + 2

        /** Indicates the archive contained invalid key attribute.  */
        const val INVALID_KEY_ATTRIBUTE = Short.MAX_VALUE + 3

        /** Indicates the archive was not a valid JSON document.  */
        const val MALFORMED_ARCHIVEDATA = Short.MAX_VALUE + 4

        /** Indicates the archive data was invalid, e.g. was not JSON or was missing mandatory fields.  */
        const val INVALID_ARCHIVE_DATA = Short.MAX_VALUE + 5

        /** Indicates the archive contained an invalid set of keys.  */
        const val MALFORMED_KEYSET_DATA = Short.MAX_VALUE + 6

        /** Indicates the archive being unarchived is not a support version.  */
        const val VERSION_MISMATCH = Short.MAX_VALUE + 7

        /**
         * Indicates that a fatal error occurred. This could be due to
         * coding error, out-of-memory condition or other conditions that is
         * beyond control of [SecureKeyArchiveInterface] implementation.
         */
        const val FATAL_ERROR = Short.MAX_VALUE + 8
        const val NO_REASON = Short.MAX_VALUE + 99
    }
}
