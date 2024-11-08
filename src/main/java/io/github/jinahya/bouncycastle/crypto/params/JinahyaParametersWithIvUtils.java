package io.github.jinahya.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.util.Objects;

public class JinahyaParametersWithIvUtils {

    // -----------------------------------------------------------------------------------------------------------------
    public static byte[] getIv(final ParametersWithIV params) {
        Objects.requireNonNull(params, "params is null");
        return params.getIV();
    }

    public static byte[] getIv(final CipherParameters params) {
        if (!(Objects.requireNonNull(params, "params is null") instanceof ParametersWithIV)) {
            throw new IllegalArgumentException(
                    "not an instance of " + ParametersWithIV.class.getSimpleName() + ": " + params);
        }
        return getIv((ParametersWithIV) params);
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static byte[] getKey(final ParametersWithIV params) {
        Objects.requireNonNull(params, "params is null");
        return JinahyaKeyParametersUtils.getKey(params.getParameters());
    }

    public static byte[] getKey(final CipherParameters params) {
        if (!(Objects.requireNonNull(params, "params is null") instanceof ParametersWithIV)) {
            throw new IllegalArgumentException(
                    "not an instance of " + ParametersWithIV.class.getSimpleName() + ": " + params);
        }
        return getKey((ParametersWithIV) params);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaParametersWithIvUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
