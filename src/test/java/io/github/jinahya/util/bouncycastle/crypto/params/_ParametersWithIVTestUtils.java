package io.github.jinahya.util.bouncycastle.crypto.params;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.util.Objects;

@Slf4j
public final class _ParametersWithIVTestUtils {

    // -----------------------------------------------------------------------------------------------------------------
    static String ivName(final byte[] iv) {
        return String.format("iv: %1$d 0x%2$02X", iv.length << 3, iv[0]);
    }

    public static String paramsName(final ParametersWithIV params) {
        Objects.requireNonNull(params, "params is null");
        return String.format("%1$s, %2$s", _KeyParametersTestUtils.paramsName((KeyParameter) params.getParameters()),
                             ivName(params.getIV()));
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _ParametersWithIVTestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
