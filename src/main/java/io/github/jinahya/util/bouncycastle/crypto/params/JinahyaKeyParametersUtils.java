package io.github.jinahya.util.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.Random;

public class JinahyaKeyParametersUtils {

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

    public static byte[] newRandomKey(Random random, final int length) {
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

    public static KeyParameter newRandomInstance(final Random random, final int length) {
        return new KeyParameter(
                newRandomKey(random, length)
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static byte[] getKey(final CipherParameters params) {
        if (!(Objects.requireNonNull(params, "params is null") instanceof KeyParameter)) {
            throw new IllegalArgumentException(
                    "not an instance of " + KeyParameter.class.getSimpleName() + ": " + params
            );
        }
        return ((KeyParameter) params).getKey();
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaKeyParametersUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
