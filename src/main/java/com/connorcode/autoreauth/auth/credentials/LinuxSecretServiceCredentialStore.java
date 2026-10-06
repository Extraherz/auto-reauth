package com.connorcode.autoreauth.auth.credentials;

import de.swiesend.secretservice.Item;
import de.swiesend.secretservice.Prompt;
import de.swiesend.secretservice.Service;
import de.swiesend.secretservice.functional.Collection;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.connections.impl.DBusConnectionBuilder;

import java.util.*;

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

                if (existingItems.size() > 1) {
                    throw new CredentialStoreException(
                            "Multiple Linux Secret Service credentials exist for the same account",
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
        var attributes =
                attributes(accountId);

        try (var connection =
                     DBusConnectionBuilder
                             .forSessionBus()
                             .build()) {

            var service =
                    new Service(
                            connection
                    );

            var searchResult =
                    service.searchItems(
                            attributes
                    );

            if (searchResult.isEmpty()) {
                return;
            }

            var unlockedItems =
                    new ArrayList<DBusPath>(
                            searchResult.get().a
                    );

            var lockedItems =
                    new ArrayList<DBusPath>(
                            searchResult.get().b
                    );

            if (!lockedItems.isEmpty()) {
                var unlockResult =
                        service.unlock(
                                lockedItems
                        ).orElseThrow(
                                () ->
                                        new CredentialStoreException(
                                                "Failed to unlock Linux Secret Service credentials",
                                                null
                                        )
                        );

                unlockedItems.addAll(
                        unlockResult.a
                );

                var promptPath =
                        unlockResult.b;

                if (promptPath != null
                        && !"/".equals(
                        promptPath.getPath()
                )) {

                    var prompt =
                            new Prompt(
                                    service
                            );

                    var completed =
                            prompt.await(
                                    promptPath
                            );

                    if (completed == null
                            || completed.dismissed) {
                        throw new CredentialStoreException(
                                "Linux Secret Service unlock prompt was not completed",
                                null
                        );
                    }
                }

                /*
                 * Search again after unlocking so we operate on the actual
                 * current state reported by the Secret Service.
                 */
                var refreshed =
                        service.searchItems(
                                attributes
                        ).orElseThrow(
                                () ->
                                        new CredentialStoreException(
                                                "Failed to refresh Linux Secret Service credentials after unlock",
                                                null
                                        )
                        );

                unlockedItems.clear();
                unlockedItems.addAll(
                        refreshed.a
                );
                unlockedItems.addAll(
                        refreshed.b
                );
            }

            for (var itemPath : unlockedItems) {
                var item =
                        new Item(
                                itemPath,
                                service
                        );

                var deletePrompt =
                        item.delete()
                                .orElseThrow(
                                        () ->
                                                new CredentialStoreException(
                                                        "Failed to request deletion of Linux Secret Service credential",
                                                        null
                                                )
                                );

                if (!"/".equals(
                        deletePrompt.getPath()
                )) {
                    var prompt =
                            new Prompt(
                                    service
                            );

                    var completed =
                            prompt.await(
                                    deletePrompt
                            );

                    if (completed == null
                            || completed.dismissed) {
                        throw new CredentialStoreException(
                                "Linux Secret Service delete prompt was not completed",
                                null
                        );
                    }
                }
            }

            var remaining =
                    service.searchItems(
                            attributes
                    );

            if (remaining.isPresent()
                    && (!remaining.get().a.isEmpty()
                    || !remaining.get().b.isEmpty())) {
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