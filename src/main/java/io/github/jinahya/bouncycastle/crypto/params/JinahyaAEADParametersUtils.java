package io.github.jinahya.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.AEADParameters;

import java.util.Objects;

public class JinahyaAEADParametersUtils {

    // -----------------------------------------------------------------------------------------------------------------
    public static byte[] getKey(final AEADParameters params) {
        Objects.requireNonNull(params, "params is null");
        return JinahyaKeyParametersUtils.getKey(params.getKey());
    }

    public static byte[] getKey(final CipherParameters params) {
        if (!(Objects.requireNonNull(params, "params is null") instanceof AEADParameters)) {
            throw new IllegalArgumentException(
                    "not an instance of " + AEADParameters.class.getSimpleName() + ": " + params);
        }
        return getKey((AEADParameters) params);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaAEADParametersUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
