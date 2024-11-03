package _org.bouncycastle.crypto;

import _org.bouncycastle.crypto.params._KeyParameters_TestUtils;
import _org.bouncycastle.crypto.params._ParametersWithIV_TestUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.util.Objects;

@Slf4j
public final class _BlockCipher_TestUtils {

    // -----------------------------------------------------------------------------------------------------------------
    static String cipherName(final BlockCipher cipher, final int keySize) {
        return String.format("%1$s/%2$d", cipher.getAlgorithmName(), keySize);
    }

    public static String cipherName(final BlockCipher cipher, final BlockCipherPadding padding) {
        return String.format("%1$s/%2$s", cipher.getAlgorithmName(), padding.getPaddingName());
    }

    static String keyName(final byte[] key) {
        return String.format("%1$d 0x%2$02X", key.length << 3, key[0]);
    }

    public static String paramsName(final CipherParameters parameters) {
        Objects.requireNonNull(parameters, "parameters is null");
        if (parameters instanceof KeyParameter p) {
            return _KeyParameters_TestUtils.paramsName(p);
        }
        if (parameters instanceof ParametersWithIV p) {
            return _ParametersWithIV_TestUtils.paramsName(p);
        }
        throw new RuntimeException("failed to get key from " + parameters);
    }

    public static String cipherName(final BlockCipher cipher) {
        Objects.requireNonNull(cipher, "cipher is null");
        return String.format("%1$s", cipher.getAlgorithmName());
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _BlockCipher_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
