package com.connorcode.autoreauth.auth.credentials;

import com.sun.jna.Memory;
import com.sun.jna.NativeLibrary;
import com.sun.jna.Pointer;
import com.sun.jna.platform.mac.CoreFoundation;
import com.sun.jna.ptr.PointerByReference;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

public final class MacOsKeychainCredentialStore
        implements CredentialStore {

    private static final String SERVICE_NAME =
            "auto-reauth";

    private static final int ERR_SEC_SUCCESS = 0;
    private static final int ERR_SEC_DUPLICATE_ITEM = -25299;
    private static final int ERR_SEC_ITEM_NOT_FOUND = -25300;

    private static final CoreFoundation CORE_FOUNDATION =
            CoreFoundation.INSTANCE;

    private static final NativeLibrary SECURITY =
            NativeLibrary.getInstance(
                    "/System/Library/Frameworks/Security.framework/Security"
            );

    private static final NativeLibrary CORE_FOUNDATION_LIBRARY =
            NativeLibrary.getInstance(
                    "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
            );

    private static final CoreFoundation.CFTypeRef KEY_CLASS =
            securityConstant("kSecClass");

    private static final CoreFoundation.CFTypeRef CLASS_GENERIC_PASSWORD =
            securityConstant("kSecClassGenericPassword");

    private static final CoreFoundation.CFTypeRef KEY_SERVICE =
            securityConstant("kSecAttrService");

    private static final CoreFoundation.CFTypeRef KEY_ACCOUNT =
            securityConstant("kSecAttrAccount");

    private static final CoreFoundation.CFTypeRef KEY_VALUE_DATA =
            securityConstant("kSecValueData");

    private static final CoreFoundation.CFTypeRef KEY_RETURN_DATA =
            securityConstant("kSecReturnData");

    private static final CoreFoundation.CFTypeRef CF_BOOLEAN_TRUE =
            coreFoundationConstant("kCFBooleanTrue");

    @Override
    public void save(
            UUID accountId,
            String refreshToken
    ) {
        var service =
                CoreFoundation.CFStringRef.createCFString(
                        SERVICE_NAME
                );

        var account =
                CoreFoundation.CFStringRef.createCFString(
                        accountId.toString()
                );

        var bytes =
                refreshToken.getBytes(
                        StandardCharsets.UTF_8
                );

        var memory = new Memory(bytes.length);

        CoreFoundation.CFDataRef data = null;
        CoreFoundation.CFMutableDictionaryRef query = null;
        CoreFoundation.CFMutableDictionaryRef update = null;

        try {
            memory.write(
                    0,
                    bytes,
                    0,
                    bytes.length
            );

            data = CORE_FOUNDATION.CFDataCreate(
                    null,
                    memory,
                    new CoreFoundation.CFIndex(bytes.length)
            );

            query = createBaseQuery(
                    service,
                    account
            );

            update = createDictionary();

            update.setValue(
                    KEY_VALUE_DATA,
                    data
            );

            var status =
                    MacSecurity.INSTANCE.SecItemUpdate(
                            query,
                            update
                    );

            if (status == ERR_SEC_ITEM_NOT_FOUND) {
                var add = createBaseQuery(
                        service,
                        account
                );

                try {
                    add.setValue(
                            KEY_VALUE_DATA,
                            data
                    );

                    status =
                            MacSecurity.INSTANCE.SecItemAdd(
                                    add,
                                    null
                            );
                } finally {
                    add.release();
                }
            }

            if (status != ERR_SEC_SUCCESS) {
                throw keychainError(
                        "Failed to store credentials",
                        status
                );
            }
        } finally {
            Arrays.fill(bytes, (byte) 0);
            memory.clear();

            if (data != null) {
                data.release();
            }

            if (update != null) {
                update.release();
            }

            if (query != null) {
                query.release();
            }

            service.release();
            account.release();
        }
    }

    @Override
    public Optional<String> load(
            UUID accountId
    ) {
        var service =
                CoreFoundation.CFStringRef.createCFString(
                        SERVICE_NAME
                );

        var account =
                CoreFoundation.CFStringRef.createCFString(
                        accountId.toString()
                );

        CoreFoundation.CFMutableDictionaryRef query = null;

        try {
            query = createBaseQuery(
                    service,
                    account
            );

            query.setValue(
                    KEY_RETURN_DATA,
                    CF_BOOLEAN_TRUE
            );

            var result =
                    new PointerByReference();

            var status =
                    MacSecurity.INSTANCE.SecItemCopyMatching(
                            query,
                            result
                    );

            if (status == ERR_SEC_ITEM_NOT_FOUND) {
                return Optional.empty();
            }

            if (status != ERR_SEC_SUCCESS) {
                throw keychainError(
                        "Failed to load credentials",
                        status
                );
            }

            var pointer = result.getValue();

            if (pointer == null) {
                return Optional.empty();
            }

            var data =
                    new CoreFoundation.CFDataRef(
                            pointer
                    );

            try {
                var length =
                        data.getLength();

                var bytes =
                        data.getBytePtr()
                                .getByteArray(
                                        0,
                                        length
                                );

                try {
                    return Optional.of(
                            new String(
                                    bytes,
                                    StandardCharsets.UTF_8
                            )
                    );
                } finally {
                    Arrays.fill(bytes, (byte) 0);
                }
            } finally {
                data.release();
            }
        } finally {
            if (query != null) {
                query.release();
            }

            service.release();
            account.release();
        }
    }

    @Override
    public void delete(
            UUID accountId
    ) {
        var service =
                CoreFoundation.CFStringRef.createCFString(
                        SERVICE_NAME
                );

        var account =
                CoreFoundation.CFStringRef.createCFString(
                        accountId.toString()
                );

        CoreFoundation.CFMutableDictionaryRef query = null;

        try {
            query = createBaseQuery(
                    service,
                    account
            );

            var status =
                    MacSecurity.INSTANCE.SecItemDelete(
                            query
                    );

            if (status != ERR_SEC_SUCCESS
                    && status != ERR_SEC_ITEM_NOT_FOUND) {
                throw keychainError(
                        "Failed to delete credentials",
                        status
                );
            }
        } finally {
            if (query != null) {
                query.release();
            }

            service.release();
            account.release();
        }
    }

    private CoreFoundation.CFMutableDictionaryRef createBaseQuery(
            CoreFoundation.CFStringRef service,
            CoreFoundation.CFStringRef account
    ) {
        var query =
                createDictionary();

        query.setValue(
                KEY_CLASS,
                CLASS_GENERIC_PASSWORD
        );

        query.setValue(
                KEY_SERVICE,
                service
        );

        query.setValue(
                KEY_ACCOUNT,
                account
        );

        return query;
    }

    private CoreFoundation.CFMutableDictionaryRef createDictionary() {
        return CORE_FOUNDATION.CFDictionaryCreateMutable(
                null,
                new CoreFoundation.CFIndex(0),
                null,
                null
        );
    }

    private CredentialStoreException keychainError(
            String message,
            int status
    ) {
        return new CredentialStoreException(
                message + " (OSStatus " + status + ")",
                null
        );
    }

    private static CoreFoundation.CFTypeRef securityConstant(
            String name
    ) {
        return new CoreFoundation.CFTypeRef(
                dereferenceConstant(
                        SECURITY,
                        name
                )
        );
    }

    private static CoreFoundation.CFTypeRef coreFoundationConstant(
            String name
    ) {
        return new CoreFoundation.CFTypeRef(
                dereferenceConstant(
                        CORE_FOUNDATION_LIBRARY,
                        name
                )
        );
    }

    private static Pointer dereferenceConstant(
            NativeLibrary library,
            String name
    ) {
        var address =
                library.getGlobalVariableAddress(
                        name
                );

        return address.getPointer(0);
    }
}