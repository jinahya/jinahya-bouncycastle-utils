package io.github.jinahya.util.bouncycastle.crypto;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.Random;

public class JinahyaCipherParametersUtils {

    private static Random random() {
        try {
            return SecureRandom.getInstanceStrong();
        } catch (final NoSuchAlgorithmException nsae) {
            throw new RuntimeException("failed to get a strong instance of " + SecureRandom.class, nsae);
        }
    }

    private static <T> T requireNonNull(final T cipher) {
        return Objects.requireNonNull(cipher, "cipher is null");
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static byte[] newRandomKey(Random random, final int keySize) {
        if (random == null) {
            random = random();
        }
        if (keySize <= 0) {
            throw new IllegalArgumentException("non-positive keySize: " + keySize);
        }
        final var key = new byte[keySize >> 3];
        random.nextBytes(key);
        return key;
    }

    public static byte[] newRandomIv(Random random, final int blockSize) {
        if (random == null) {
            random = random();
        }
        if (blockSize <= 0) {
            throw new IllegalArgumentException("non-positive blockSize: " + blockSize);
        }
        final var iv = new byte[blockSize >> 3];
        random.nextBytes(iv);
        return iv;
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static CipherParameters newRandomKeyParameter(final Random random, final int keySize) {
        return new KeyParameter(newRandomKey(random, keySize));
    }

    /**
     * Returns a new instance of {@link ParametersWithIV} with specified arguments.
     *
     * @param random    a random.
     * @param keySize   a key size in bits.
     * @param blockSize a block size in bits.
     * @return a new instance of {@link ParametersWithIV}.
     * @see #newRandomKeyParameter(Random, int)
     * @see #newRandomIv(Random, int)
     */
    public static CipherParameters newRandomParametersWithIV(final Random random, final int keySize,
                                                             final int blockSize) {
        return new ParametersWithIV(
                newRandomKeyParameter(random, keySize),
                newRandomIv(random, blockSize)
        );
    }

    public static CipherParameters newRandomParametersWithIV(final Random random, final int keySize,
                                                             final BlockCipher cipher) {
        return newRandomParametersWithIV(
                random,
                keySize,
                JinahyaBlockCipherUtils.getBlockSizeInBits(cipher)
        );
    }

    public static CipherParameters newRandomParametersWithIV(final Random random, final int keySize,
                                                             final BufferedBlockCipher cipher) {
        return newRandomParametersWithIV(
                random,
                keySize,
                Objects.requireNonNull(cipher, "cipher is null").getUnderlyingCipher()
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static byte[] getKey(final CipherParameters params) {
        Objects.requireNonNull(params, "params is null");
        if (params instanceof KeyParameter) {
            return ((KeyParameter) params).getKey();
        }
        if (params instanceof ParametersWithIV) {
            return getKey(((ParametersWithIV) params).getParameters());
        }
        throw new IllegalArgumentException("failed to get key from " + params);
    }

    public static byte[] getIV(final CipherParameters params) {
        Objects.requireNonNull(params, "params is null");
        if (params instanceof ParametersWithIV) {
            return ((ParametersWithIV) params).getIV();
        }
        throw new IllegalArgumentException("failed to get IV from " + params);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaCipherParametersUtils() {
        throw new AssertionError("instantiation is not allowed");
    }

}
