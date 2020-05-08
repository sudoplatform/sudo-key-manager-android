/*
 * Copyright 2018 - Anonyome Labs, Inc. - All rights reserved
 */
package com.sudoplatform.sudokeymanager;

/**
 * An exception thrown when a problem was detected with a {@link SecureKeyArchiveInterface}.
 */
public class SecureKeyArchiveException extends Exception {

    /** Indicates that duplicate keys were found while saving the keys to the secure store.*/
    public static final int DUPLICATE_KEY         = Short.MAX_VALUE;

    /** Indicates that unarchive or archive operation was requested but the archive was empty. */
    public static final int ARCHIVE_EMPTY         = Short.MAX_VALUE + 1;

    /** Indicates the password invalid, e.g. empty string. */
    public static final int INVALID_PASSWORD      = Short.MAX_VALUE + 2;

    /** Indicates the archive contained invalid key attribute. */
    public static final int INVALID_KEY_ATTRIBUTE = Short.MAX_VALUE + 3;

    /** Indicates the archive was not a valid JSON document. */
    public static final int MALFORMED_ARCHIVEDATA = Short.MAX_VALUE + 4;

    /** Indicates the archive data was invalid, e.g. was not JSON or was missing mandatory fields. */
    public static final int INVALID_ARCHIVE_DATA  = Short.MAX_VALUE + 5;

    /** Indicates the archive contained an invalid set of keys. */
    public static final int MALFORMED_KEYSET_DATA = Short.MAX_VALUE + 6;

    /** Indicates the archive being unarchived is not a support version. */
    public static final int VERSION_MISMATCH      = Short.MAX_VALUE + 7;

    /**
     * Indicates that a fatal error occurred. This could be due to
     * coding error, out-of-memory condition or other conditions that is
     * beyond control of {@link SecureKeyArchiveInterface} implementation.
     */
    public static final int FATAL_ERROR           = Short.MAX_VALUE + 8;

    public static final int NO_REASON             = Short.MAX_VALUE + 99;

    private final int reason;

    public SecureKeyArchiveException(String message) {
        this(NO_REASON, message, null);
    }

    public SecureKeyArchiveException(String message, Throwable cause) {
        this(NO_REASON, message, cause);
    }

    public SecureKeyArchiveException(int reason, String message) {
        this(reason, message, null);
    }

    public SecureKeyArchiveException(int reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    /**
     * Returns the reason why this exception was thrown.
     *
     * @return the reason why this exception was thrown.
     */
    public int getReason() {
        return reason;
    }
}
