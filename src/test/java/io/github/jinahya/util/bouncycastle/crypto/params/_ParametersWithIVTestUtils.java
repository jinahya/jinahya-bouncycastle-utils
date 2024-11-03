package io.github.jinahya.util.bouncycastle.crypto.params;

import io.github.jinahya.util.bouncycastle.crypto.JinahyaBlockCipherUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.util.Objects;
import java.util.Random;

@Slf4j
public final class _ParametersWithIVTestUtils {

    // -----------------------------------------------------------------------------------------------------------------
    public static byte[] newRandomIv(Random random, final int length) {
        if (random == null) {
            random = _KeyParametersTestUtils.random();
        }
        if (length < 0) {
            throw new IllegalArgumentException("negative length: " + length);
        }
        final var iv = new byte[length >> 3];
        random.nextBytes(iv);
        return iv;
    }

    public static byte[] newRandomIv(Random random, final BlockCipher cipher) {
        return newRandomIv(random, JinahyaBlockCipherUtils.getBlockSizeInBits(cipher));
    }

    /**
     * Returns a new instance of {@link ParametersWithIV} with specified arguments.
     *
     * @param random        a random.
     * @param keySizeInBits a key size in bits.
     * @param ivSizeInBits  a block size in bits.
     * @return a new instance of {@link ParametersWithIV}.
     * @see _ParametersWithIVTestUtils#newRandomIv(Random, int)
     */
    public static CipherParameters newRandomInstanceOfParametersWithIV(final Random random, final int keySizeInBits,
                                                                       final int ivSizeInBits) {
        return new ParametersWithIV(
                _KeyParametersTestUtils.newRandomInstanceOfKeyParameter(random, keySizeInBits),
                newRandomIv(random, ivSizeInBits)
        );
    }

    public static CipherParameters newRandomInstanceOfParametersWithIV(final Random random, final int keySizeInBits,
                                                                       final BlockCipher cipher) {
        return newRandomInstanceOfParametersWithIV(
                random,
                keySizeInBits,
                JinahyaBlockCipherUtils.getBlockSizeInBits(cipher)
        );
    }

    public static CipherParameters newRandomInstanceOfParametersWithIV(final Random random, final int keySizeInBits,
                                                                       final BufferedBlockCipher cipher) {
        return newRandomInstanceOfParametersWithIV(
                random,
                keySizeInBits,
                Objects.requireNonNull(cipher, "cipher is null").getUnderlyingCipher()
        );
    }

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
