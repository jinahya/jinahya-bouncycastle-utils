package io.github.jinahya.util;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.util.Objects;

@Slf4j
public final class _TestUtils {

    // -----------------------------------------------------------------------------------------------------------------
    static String cipherName(final BlockCipher cipher, final int keysize) {
        return String.format("%1$s/%2$d", cipher.getAlgorithmName(), keysize);
    }

    public static String cipherName(final BlockCipher cipher) {
        return cipherName(cipher, cipher.getBlockSize());
    }

    public static String cipherName(final BufferedBlockCipher cipher) {
        return cipherName(Objects.requireNonNull(cipher, "cipher is null").getUnderlyingCipher());
    }

    public static String cipherName(final StreamBlockCipher cipher) {
        return cipherName(Objects.requireNonNull(cipher, "cipher is null").getUnderlyingCipher());
    }

    public static String cipherName(final BlockCipher cipher, final BlockCipherPadding padding) {
        return String.format("%1$s/%2$s", cipher.getAlgorithmName(), padding.getPaddingName());
    }

    public static String cipherName(final BufferedBlockCipher cipher, final BlockCipherPadding padding) {
        return cipherName(
                Objects.requireNonNull(cipher, "cipher is null").getUnderlyingCipher(),
                padding
        );
    }

    static String keyName(final byte[] key) {
        return String.format("%1$d 0x%2$02X", key.length << 3, key[0]);
    }

    public static String paramsName(final CipherParameters parameters) {
        Objects.requireNonNull(parameters, "parameters is null");
        if (parameters instanceof KeyParameter p) {
            return keyName(p.getKey());
        }
        if (parameters instanceof ParametersWithIV p) {
            return paramsName(p.getParameters());
        }
        throw new RuntimeException("failed to get key from " + parameters);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
