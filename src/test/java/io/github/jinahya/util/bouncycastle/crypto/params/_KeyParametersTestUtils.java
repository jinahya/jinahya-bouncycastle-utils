package io.github.jinahya.util.bouncycastle.crypto.params;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.Random;

@Slf4j
public final class _KeyParametersTestUtils {

    static Random random() {
        try {
            return SecureRandom.getInstanceStrong();
        } catch (final NoSuchAlgorithmException nsae) {
            throw new RuntimeException("failed to get a strong instance of " + SecureRandom.class, nsae);
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static byte[] newRandomKey(Random random, final int keySizeInBits) {
        if (random == null) {
            random = random();
        }
        if (keySizeInBits <= 0) {
            throw new IllegalArgumentException("non-positive keySizeInBits: " + keySizeInBits);
        }
        final var key = new byte[keySizeInBits >> 3];
        random.nextBytes(key);
        return key;
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static CipherParameters newRandomInstanceOfKeyParameter(final Random random, final int keySizeInBits) {
        return new KeyParameter(newRandomKey(random, keySizeInBits));
    }

    // -----------------------------------------------------------------------------------------------------------------
    static String keyName(final byte[] key) {
        return String.format("key: %1$d 0x%2$02X", key.length << 3, key[0]);
    }

    public static String paramsName(final KeyParameter params) {
        Objects.requireNonNull(params, "params is null");
        return keyName(params.getKey());
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _KeyParametersTestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
