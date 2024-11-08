package io.github.jinahya.bouncycastle.crypto;

import io.github.jinahya.bouncycastle.crypto.params.JinahyaAEADParametersUtils;
import io.github.jinahya.bouncycastle.crypto.params.JinahyaKeyParametersUtils;
import io.github.jinahya.bouncycastle.crypto.params.JinahyaParametersWithIvUtils;
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
            return JinahyaParametersWithIvUtils.getKey(params);
        }
        if (params instanceof KeyParameter) {
            return JinahyaKeyParametersUtils.getKey(params);
        }
        if (params instanceof AEADParameters) {
            return JinahyaAEADParametersUtils.getKey(params);
        }
        throw new IllegalArgumentException("failed to get key from " + params);
    }

    public static byte[] getIv(final CipherParameters params) {
        Objects.requireNonNull(params, "params is null");
        if (params instanceof ParametersWithIV) {
            return JinahyaParametersWithIvUtils.getIv(params);
        }
        throw new IllegalArgumentException("failed to get iv from " + params);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaCipherParametersUtils() {
        throw new AssertionError("instantiation is not allowed");
    }

}
