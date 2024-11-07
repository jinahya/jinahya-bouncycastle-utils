package _org.bouncycastle.crypto.params;

import _javax.security._Random_TestUtils;
import io.github.jinahya.bouncycastle.crypto.params.JinahyaKeyParametersUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.params.KeyParameter;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.Random;

@Slf4j
public final class _KeyParameters_TestUtils {

    static Random random() {
        try {
            return SecureRandom.getInstanceStrong();
        } catch (final NoSuchAlgorithmException nsae) {
            throw new RuntimeException("failed to get a strong instance of " + SecureRandom.class, nsae);
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Deprecated(forRemoval = true)
    public static byte[] newRandomKey(Random random, final int keyLengthInBits) {
        return _Random_TestUtils.newRandomBytes(keyLengthInBits >> 3);
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static KeyParameter newRandomInstanceOfKeyParameter(final Random random, final int keySizeInBits) {
        return new KeyParameter(newRandomKey(random, keySizeInBits));
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static String keyName(final byte[] key) {
        return String.format("%1$d-bit key(%2$02x, ...)", key.length << 3, key[0]);
    }

    public static String paramsName(final KeyParameter params) {
        Objects.requireNonNull(params, "params is null");
        final var key = JinahyaKeyParametersUtils.getKey(params);
        return keyName(key);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _KeyParameters_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
