package com.sudoplatform.sudokeymanager;

/**
 * Exception related to errors in KeyManager implementation.
 */
public class KeyManagerException extends Exception {

    public KeyManagerException(String message) {
        super(message);
    }

    public KeyManagerException(Throwable cause) {
        super(cause);
    }

    public KeyManagerException(String message, Throwable cause) {
        super(message, cause);
    }

}
