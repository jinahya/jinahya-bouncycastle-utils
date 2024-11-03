package _org.bouncycastle.crypto;

import _org.bouncycastle.crypto.params._AEADParameters_TestUtils;
import _org.bouncycastle.crypto.params._KeyParameters_TestUtils;
import _org.bouncycastle.crypto.params._ParametersWithIV_TestUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.util.Objects;

@Slf4j
public final class _CipherParameters_TestUtils {

    // -----------------------------------------------------------------------------------------------------------------
    public static String paramsName(final CipherParameters params) {
        Objects.requireNonNull(params, "params is null");
        if (params instanceof KeyParameter p) {
            return _KeyParameters_TestUtils.paramsName(p);
        }
        if (params instanceof ParametersWithIV p) {
            return _ParametersWithIV_TestUtils.paramsName(p);
        }
        if (params instanceof AEADParameters p) {
            return _AEADParameters_TestUtils.paramsName(p);
        }
        throw new RuntimeException("failed to get name of " + params);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _CipherParameters_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
