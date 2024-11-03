package io.github.jinahya.util.bouncycastle.crypto.params;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.Random;

public class JinahyaParametersWithIvUtils {

    private static Random random;

    private static Random random() {
        if (random == null) {
            try {
                random = SecureRandom.getInstanceStrong();
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("failed to get a " + SecureRandom.class.getSimpleName() + " object", e);
            }
        }
        return random;
    }

    public static byte[] newRandomIv(Random random, final int length) {
        if (random == null) {
            random = random();
        }
        if (length < 0) {
            throw new IllegalArgumentException("negative length: " + length);
        }
        final var result = new byte[length];
        random.nextBytes(result);
        return result;
    }

    public static byte[] newRandomIvFor(Random random, final BlockCipher cipher) {
        return newRandomIv(
                random,
                Objects.requireNonNull(cipher, "cipher is null").getBlockSize()
        );
    }

    public static ParametersWithIV newRandomInstance(final CipherParameters parameters, final Random random,
                                                     final int length) {
        return new ParametersWithIV(
                parameters,
                newRandomIv(random, length)
        );
    }

    public static ParametersWithIV newRandomInstanceFor(final CipherParameters params, final Random random,
                                                        final BlockCipher cipher) {
        return new ParametersWithIV(
                params,
                newRandomIvFor(random, cipher)
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static byte[] getIv(final CipherParameters params) {
        if (!(Objects.requireNonNull(params, "params is null") instanceof ParametersWithIV)) {
            throw new IllegalArgumentException(
                    "not an instance of " + ParametersWithIV.class.getSimpleName() + ": " + params
            );
        }
        return ((ParametersWithIV) params).getIV();
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaParametersWithIvUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
