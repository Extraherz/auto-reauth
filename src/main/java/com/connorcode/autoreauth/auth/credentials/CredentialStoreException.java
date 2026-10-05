package com.connorcode.autoreauth.auth.credentials;

public final class CredentialStoreException
        extends RuntimeException {

    public CredentialStoreException(
            String message,
            Throwable cause
    ) {
        super(message, cause);
    }
}