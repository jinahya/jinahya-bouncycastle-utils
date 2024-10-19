package io.github.jinahya.util.bouncycastle.crypto.params;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.params.KeyParameter;

import java.util.Objects;

@Slf4j
public final class _KeyParametersTestUtils {

    // -----------------------------------------------------------------------------------------------------------------
    static String keyName(final byte[] key) {
        return String.format("key: %1$d 0x%2$02X", key.length << 3, key[0]);
    }

    public static String paramsName(final KeyParameter params) {
        Objects.requireNonNull(params, "params is null");
        return keyName(params.getKey());
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _KeyParametersTestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
