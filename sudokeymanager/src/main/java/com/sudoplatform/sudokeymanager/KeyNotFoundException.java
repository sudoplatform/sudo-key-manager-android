package com.sudoplatform.sudokeymanager;

/**
 * Thrown if a key is not found but the method expects the key to present.
 */
public final class KeyNotFoundException extends KeyManagerException {

    public KeyNotFoundException(String message) {
        super(message);
    }

    public KeyNotFoundException(Throwable cause) {
        super(cause);
    }

    public KeyNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }

}
