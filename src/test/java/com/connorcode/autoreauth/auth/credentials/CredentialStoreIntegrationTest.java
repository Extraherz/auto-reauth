package com.connorcode.autoreauth.auth.credentials;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class CredentialStoreIntegrationTest {

    @Test
    void credentialRoundTripWorks() throws Exception {
        var baseDirectory =
                Files.createTempDirectory(
                        "auto-reauth-test"
                );

        var store =
                CredentialStores.create(
                        baseDirectory
                );

        var accountId =
                UUID.randomUUID();

        var secret =
                "test-refresh-token-"
                        + UUID.randomUUID();

        try {
            store.save(
                    accountId,
                    secret
            );

            var loaded =
                    store.load(accountId);

            assertTrue(
                    loaded.isPresent()
            );

            assertEquals(
                    secret,
                    loaded.get()
            );

            store.delete(accountId);

            assertTrue(
                    store.load(accountId)
                            .isEmpty()
            );
        } finally {
            store.delete(accountId);
        }
    }
}