package com.connorcode.autoreauth.auth.credentials;

import com.sun.jna.platform.win32.Crypt32Util;
import com.sun.jna.platform.win32.WinCrypt;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

public final class WindowsDpapiCredentialStore implements CredentialStore {

    private final Path directory;

    public WindowsDpapiCredentialStore(Path directory) {
        this.directory = directory;
    }

    @Override
    public void save(UUID accountId, String refreshToken) {
        var plaintext = refreshToken.getBytes(StandardCharsets.UTF_8);

        try {
            var encrypted = Crypt32Util.cryptProtectData(
                    plaintext,
                    WinCrypt.CRYPTPROTECT_UI_FORBIDDEN
            );

            Files.createDirectories(directory);

            var target = credentialPath(accountId);
            var temporary = directory.resolve(
                    accountId + ".token.tmp"
            );

            Files.write(
                    temporary,
                    encrypted,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE
            );

            try {
                Files.move(
                        temporary,
                        target,
                        StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE
                );
            } catch (IOException e) {
                Files.move(
                        temporary,
                        target,
                        StandardCopyOption.REPLACE_EXISTING
                );
            }
        } catch (IOException e) {
            throw new CredentialStoreException(
                    "Failed to store credentials",
                    e
            );
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    @Override
    public Optional<String> load(UUID accountId) {
        var path = credentialPath(accountId);

        if (Files.notExists(path)) {
            return Optional.empty();
        }

        byte[] decrypted = null;

        try {
            var encrypted = Files.readAllBytes(path);

            decrypted = Crypt32Util.cryptUnprotectData(
                    encrypted,
                    WinCrypt.CRYPTPROTECT_UI_FORBIDDEN
            );

            return Optional.of(
                    new String(
                            decrypted,
                            StandardCharsets.UTF_8
                    )
            );
        } catch (IOException e) {
            throw new CredentialStoreException(
                    "Failed to load credentials",
                    e
            );
        } finally {
            if (decrypted != null) {
                Arrays.fill(decrypted, (byte) 0);
            }
        }
    }

    @Override
    public void delete(UUID accountId) {
        try {
            Files.deleteIfExists(
                    credentialPath(accountId)
            );
        } catch (IOException e) {
            throw new CredentialStoreException(
                    "Failed to delete credentials",
                    e
            );
        }
    }

    private Path credentialPath(UUID accountId) {
        return directory.resolve(
                accountId + ".token"
        );
    }
}