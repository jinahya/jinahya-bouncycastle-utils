package io.github.jinahya.util.bouncycastle.crypto;

import io.github.jinahya.util.bouncycastle.crypto.params._KeyParametersTestUtils;
import io.github.jinahya.util.bouncycastle.crypto.params._ParametersWithIVTestUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.util.Objects;

@Slf4j
public final class _CipherParameters_TestUtils {

    // -----------------------------------------------------------------------------------------------------------------
    public static String paramsName(final CipherParameters params) {
        Objects.requireNonNull(params, "params is null");
        if (params instanceof ParametersWithIV p) {
            return _ParametersWithIVTestUtils.paramsName(p);
        }
        if (params instanceof KeyParameter p) {
            return _KeyParametersTestUtils.paramsName(p);
        }
        throw new RuntimeException("failed to get key from " + params);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _CipherParameters_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
