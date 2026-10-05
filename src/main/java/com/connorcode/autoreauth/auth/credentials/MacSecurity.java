package com.connorcode.autoreauth.auth.credentials;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.platform.mac.CoreFoundation;
import com.sun.jna.ptr.PointerByReference;

interface MacSecurity extends Library {

    MacSecurity INSTANCE = Native.load(
            "/System/Library/Frameworks/Security.framework/Security",
            MacSecurity.class
    );

    int SecItemAdd(
            CoreFoundation.CFDictionaryRef attributes,
            PointerByReference result
    );

    int SecItemCopyMatching(
            CoreFoundation.CFDictionaryRef query,
            PointerByReference result
    );

    int SecItemUpdate(
            CoreFoundation.CFDictionaryRef query,
            CoreFoundation.CFDictionaryRef attributesToUpdate
    );

    int SecItemDelete(
            CoreFoundation.CFDictionaryRef query
    );
}