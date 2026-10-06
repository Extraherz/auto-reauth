package com.connorcode.autoreauth.auth.credentials;

import de.swiesend.secretservice.functional.Collection;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

public final class LinuxSecretServiceCredentialStore
        implements CredentialStore {

    private static final String APPLICATION =
            "auto-reauth";

    private static final String ATTRIBUTE_APPLICATION =
            "application";

    private static final String ATTRIBUTE_ACCOUNT_ID =
            "account-id";

    @Override
    public void save(
            UUID accountId,
            String refreshToken
    ) {
        try (var collection = openCollection()) {
            var attributes =
                    attributes(accountId);

            var existingItems =
                    collection.getItems(attributes)
                            .orElseGet(java.util.List::of);

            if (!existingItems.isEmpty()) {
                var first =
                        existingItems.getFirst();

                var updated =
                        collection.updateItem(
                                first,
                                label(accountId),
                                refreshToken,
                                attributes
                        );

                if (!updated) {
                    throw new CredentialStoreException(
                            "Failed to update Linux Secret Service credential",
                            null
                    );
                }

                for (int i = 1;
                     i < existingItems.size();
                     i++) {

                    collection.deleteItem(
                            existingItems.get(i)
                    );
                }

                var remainingItems =
                        collection.getItems(
                                attributes
                        ).orElseGet(java.util.List::of);

                if (remainingItems.size() > 1) {
                    throw new CredentialStoreException(
                            "Failed to remove duplicate Linux Secret Service credentials",
                            null
                    );
                }

                return;
            }

            var created =
                    collection.createItem(
                            label(accountId),
                            refreshToken,
                            attributes
                    );

            if (created.isEmpty()) {
                throw new CredentialStoreException(
                        "Failed to create Linux Secret Service credential",
                        null
                );
            }
        } catch (CredentialStoreException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new CredentialStoreException(
                    "Failed to store credential in Linux Secret Service",
                    exception
            );
        }
    }

    @Override
    public Optional<String> load(
            UUID accountId
    ) {
        try (var collection = openCollection()) {
            var items =
                    collection.getItems(
                            attributes(accountId)
                    ).orElseGet(java.util.List::of);

            if (items.isEmpty()) {
                return Optional.empty();
            }

            var chars =
                    collection.getSecret(
                            items.getFirst()
                    );

            if (chars.isEmpty()) {
                return Optional.empty();
            }

            var secret =
                    chars.get();

            try {
                return Optional.of(
                        new String(secret)
                );
            } finally {
                Arrays.fill(
                        secret,
                        '\0'
                );
            }
        } catch (Exception exception) {
            throw new CredentialStoreException(
                    "Failed to load credential from Linux Secret Service",
                    exception
            );
        }
    }

    @Override
    public void delete(
            UUID accountId
    ) {
        try (var collection = openCollection()) {
            var attributes =
                    attributes(accountId);

            var items =
                    collection.getItems(
                            attributes
                    ).orElseGet(java.util.List::of);

            for (var item : items) {
                collection.deleteItem(item);
            }

            var remainingItems =
                    collection.getItems(
                            attributes
                    ).orElseGet(java.util.List::of);

            if (!remainingItems.isEmpty()) {
                throw new CredentialStoreException(
                        "Failed to delete Linux Secret Service credential",
                        null
                );
            }
        } catch (CredentialStoreException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new CredentialStoreException(
                    "Failed to delete credential from Linux Secret Service",
                    exception
            );
        }
    }

    private CollectionInterface openCollection() {
        return Collection.openDefault()
                .orElseThrow(
                        () ->
                                new CredentialStoreException(
                                        "Linux Secret Service is not available",
                                        null
                                )
                );
    }

    private Map<String, String> attributes(
            UUID accountId
    ) {
        return Map.of(
                ATTRIBUTE_APPLICATION,
                APPLICATION,
                ATTRIBUTE_ACCOUNT_ID,
                accountId.toString()
        );
    }

    private String label(
            UUID accountId
    ) {
        return "Auto Reauth - "
                + accountId;
    }
}