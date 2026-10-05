package com.connorcode.autoreauth.auth.credentials;

import java.nio.file.Path;
import java.util.Locale;

public final class CredentialStores {

    private CredentialStores() {
    }

    public static CredentialStore create(
            Path baseDirectory
    ) {
        var osName = System.getProperty(
                "os.name",
                ""
        ).toLowerCase(Locale.ROOT);

        if (osName.contains("win")) {
            return new WindowsDpapiCredentialStore(
                    baseDirectory.resolve("credentials")
            );
        }

        if (osName.contains("mac")) {
            return new MacOsKeychainCredentialStore();
        }

        if (osName.contains("linux")) {
            return new LinuxSecretServiceCredentialStore();
        }

        throw new UnsupportedOperationException(
                "Secure credential storage is not supported on this operating system: "
                        + osName
        );
    }
}