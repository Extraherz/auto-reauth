package com.connorcode.autoreauth.auth.credentials;

import java.util.Optional;
import java.util.UUID;

public interface CredentialStore {

    void save(UUID accountId, String refreshToken);

    Optional<String> load(UUID accountId);

    void delete(UUID accountId);
}