package _org.junit.jupiter.api;

import io.github.jinahya.util.bouncycastle.crypto.JinahyaCipherParametersUtils;
import io.github.jinahya.util.bouncycastle.crypto._CipherParametersTestUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamBlockCipher;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.junit.jupiter.api.Named;

import java.util.Objects;

@Slf4j
public final class _Named_TestUtils {

    // -----------------------------------------------------------------------------------------------------------------
    static String cipherName(final StreamCipher cipher, final int keySize) {
        return String.format("%1$s/%2$d", cipher.getAlgorithmName(), keySize);
    }

    // -----------------------------------------------------------------------------------------------------------------
    static String cipherName(final BlockCipher cipher, final int blockSize) {
        return String.format("%1$s/%2$d", cipher.getAlgorithmName(), blockSize);
    }

    public static String cipherName(final BlockCipher cipher) {
        return cipherName(cipher, cipher.getBlockSize());
    }

    @Deprecated
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
        if (Objects.requireNonNull(key, "key is null").length == 0) {
            throw new IllegalArgumentException("empty key");
        }
        return String.format("key(%1$d) 0x%2$02X", key.length << 3, key[0]);
    }

    static String ivName(final byte[] iv) {
        if (Objects.requireNonNull(iv, "iv is null").length == 0) {
            throw new IllegalArgumentException("empty iv");
        }
        return String.format("iv(%1$d) 0x%2$02X", iv.length << 3, iv[0]);
    }

    public static String paramsName(final CipherParameters params) {
        Objects.requireNonNull(params, "params is null");
        if (params instanceof ParametersWithIV p) {
            final var parameters = p.getParameters();
            assert parameters instanceof KeyParameter;
            return paramsName(parameters) + ", " + ivName(JinahyaCipherParametersUtils.getIv(p));
        }
        if (params instanceof KeyParameter p) {
            final var key = JinahyaCipherParametersUtils.getKey(p);
            return keyName(key);
        }
        throw new RuntimeException("failed to get key from " + params);
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static <T extends BlockCipher> Named<T> namedOf(final T cipher) {
        return Named.of(cipherName(cipher), cipher);
    }

    public static <T extends CipherParameters> Named<T> namedOf(final T params) {
        return Named.of(_CipherParametersTestUtils.paramsName(params), params);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _Named_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
