package com.connorcode.autoreauth;

import com.connorcode.autoreauth.auth.MicrosoftAuth;
import com.connorcode.autoreauth.auth.credentials.CredentialStore;
import com.connorcode.autoreauth.auth.credentials.CredentialStores;
import net.minecraft.client.User;
import net.minecraft.nbt.CompoundTag;
import net.minecraft.nbt.ListTag;
import net.minecraft.nbt.NbtIo;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Optional;
import java.util.UUID;

import static com.connorcode.autoreauth.Main.directory;

public class Config {
    private static final Path CONFIG_PATH = directory.resolve("config.nbt");

    private static final CredentialStore CREDENTIAL_STORE =
            CredentialStores.create(directory);

    public boolean debug = false;
    public boolean auto = true;
    public Account defaultAccount = null;
    public ArrayList<Account> accounts = new ArrayList<>();

    public Config() {
    }

    public void addAccount(Account account) {
        for (int i = 0; i < accounts.size(); i++) {
            if (accounts.get(i).uuid.equals(account.uuid)) {
                accounts.set(i, account);
                return;
            }
        }

        accounts.add(account);
    }

    public void removeAccount(Account account) {
        if (account.equals(defaultAccount)) {
            defaultAccount = null;
        }

        deleteRefreshToken(account);
        accounts.removeIf(a -> a.equals(account));

        save();
    }

    public Optional<Account> getAccount(UUID uuid) {
        for (var account : accounts)
            if (account.uuid.equals(uuid)) return Optional.of(account);
        if (defaultAccount != null) return Optional.of(defaultAccount);
        if (!accounts.isEmpty()) return Optional.of(accounts.getFirst());
        return Optional.empty();
    }

    public boolean isDefault(Config.Account account) {
        return this.defaultAccount == null ? (!this.accounts.isEmpty() && this.accounts.getFirst()
                .equals(account)) : this.defaultAccount.equals(account);
    }

    public boolean load() {
        if (Files.notExists(CONFIG_PATH)) return false;

        try {
            var tag = NbtIo.read(CONFIG_PATH);
            assert tag != null;

            this.debug = tag.getBoolean("debug").orElse(false);
            this.auto = tag.getBoolean("auto").orElse(true);
            var accountTags = tag.getList("accounts").orElse(new ListTag());

            var loadedAccounts = new ArrayList<Account>();

            for (var element : accountTags) {
                var accountTag = element.asCompound().orElseThrow();

                var account = new Account(accountTag);

                loadedAccounts.add(account);

                var legacyRefreshToken = accountTag.getString("refreshToken");

                if (legacyRefreshToken.isPresent()) {
                    saveRefreshToken(account, legacyRefreshToken.get());
                }
            }

            this.accounts = loadedAccounts;

            int defaultIdx = tag.getInt("default").orElse(-1);
            this.defaultAccount = defaultIdx >= 0 && defaultIdx < accounts.size() ? this.accounts.get(defaultIdx) : null;

            save();
            return true;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void save() {
        var tag = new CompoundTag();
        tag.putBoolean("debug", debug);
        tag.putBoolean("auto", auto);
        tag.putInt("default", accounts.indexOf(defaultAccount));

        var accounts = new ListTag();
        for (var account : this.accounts)
            accounts.add(account.serialize());

        tag.put("accounts", accounts);

        try {
            Files.createDirectories(CONFIG_PATH.getParent());
            NbtIo.write(tag, CONFIG_PATH);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public Optional<String> getRefreshToken(Account account) {
        return CREDENTIAL_STORE.load(account.uuid());
    }

    public void saveRefreshToken(Account account, String refreshToken) {
        CREDENTIAL_STORE.save(account.uuid(), refreshToken);
    }

    public void deleteRefreshToken(Account account) {
        CREDENTIAL_STORE.delete(account.uuid());
    }

    public record Account(UUID uuid, String username) {
        public Account(User session) {
            this(session.getProfileId(), session.getName());
        }

        public Account(CompoundTag nbt) {
            this(Misc.parseUUID(nbt.getString("uuid").orElseThrow()),
                    nbt.getString("username").orElseThrow());
        }

        public CompoundTag serialize() {
            var tag = new CompoundTag();
            tag.putString("uuid", uuid.toString());
            tag.putString("username", username);
            return tag;
        }

        @Override
        public boolean equals(Object obj) {
            return obj instanceof Account account && this.uuid.equals(account.uuid);
        }
    }
}
