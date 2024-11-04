package io.github.jinahya.util.bouncycastle.crypto;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.util.Objects;

public class JinahyaCipherParametersUtils {

    // -----------------------------------------------------------------------------------------------------------------
    public static byte[] getKey(final CipherParameters params) {
        Objects.requireNonNull(params, "params is null");
        if (params instanceof ParametersWithIV) {
            final var parameters = ((ParametersWithIV) params).getParameters();
            return getKey(parameters);
        }
        if (params instanceof KeyParameter) {
            return ((KeyParameter) params).getKey();
        }
        if (params instanceof AEADParameters) {
            return getKey(((AEADParameters) params).getKey());
        }
        throw new IllegalArgumentException("failed to get key from " + params);
    }

    public static byte[] getIv(final CipherParameters params) {
        Objects.requireNonNull(params, "params is null");
        if (params instanceof ParametersWithIV) {
            return ((ParametersWithIV) params).getIV();
        }
        throw new IllegalArgumentException("failed to get iv from " + params);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaCipherParametersUtils() {
        throw new AssertionError("instantiation is not allowed");
    }

}
