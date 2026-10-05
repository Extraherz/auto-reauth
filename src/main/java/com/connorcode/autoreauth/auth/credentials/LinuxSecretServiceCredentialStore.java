package com.connorcode.autoreauth.auth.credentials;

import java.util.Optional;
import java.util.UUID;

public final class LinuxSecretServiceCredentialStore
        implements CredentialStore {

    @Override
    public void save(UUID accountId, String refreshToken) {
        throw unsupported();
    }

    @Override
    public Optional<String> load(UUID accountId) {
        throw unsupported();
    }

    @Override
    public void delete(UUID accountId) {
        throw unsupported();
    }

    private UnsupportedOperationException unsupported() {
        return new UnsupportedOperationException(
                "Linux Secret Service credential storage is not implemented yet"
        );
    }
}