package io.github.jinahya.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.util.Objects;

public class JinahyaKeyParametersUtils {

    // -----------------------------------------------------------------------------------------------------------------
    private static byte[] getKey_(final KeyParameter params) {
        assert params != null;
        return params.getKey();
    }

    public static byte[] getKey(final KeyParameter params) {
        return getKey_(Objects.requireNonNull(params, "params is null"));
    }

    public static byte[] getKey(final CipherParameters params) {
        if (!(Objects.requireNonNull(params, "params is null") instanceof KeyParameter)) {
            throw new IllegalArgumentException(
                    "not an instance of " + KeyParameter.class.getSimpleName() + ": " + params
            );
        }
        return getKey_((KeyParameter) params);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaKeyParametersUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
