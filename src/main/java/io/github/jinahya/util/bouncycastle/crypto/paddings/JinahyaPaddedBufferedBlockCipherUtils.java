package io.github.jinahya.util.bouncycastle.crypto.paddings;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.MultiBlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;

import java.lang.reflect.Field;
import java.util.Objects;
import java.util.function.Function;

public final class JinahyaPaddedBufferedBlockCipherUtils {

    private static final String FIELD_NAME_PADDING = "padding";

    private static final Field FIELD_PADDING;

    static {
        try {
            FIELD_PADDING = PaddedBufferedBlockCipher.class.getDeclaredField(FIELD_NAME_PADDING);
            FIELD_PADDING.setAccessible(true);
        } catch (final ReflectiveOperationException roe) {
            throw new ExceptionInInitializerError(roe.getCause());
        }
    }

    public static BlockCipherPadding getPadding(final PaddedBufferedBlockCipher cipher) {
        Objects.requireNonNull(cipher, "cipher is null");
        try {
            return (BlockCipherPadding) FIELD_PADDING.get(cipher);
        } catch (final IllegalAccessException iae) {
            throw new RuntimeException("failed to get '" + FIELD_NAME_PADDING + "' field from " + cipher);
        }
    }

    private static PaddedBufferedBlockCipher newInstance(final BlockCipher cipher, final BlockCipherPadding padding) {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(padding, "padding is null");
        return new PaddedBufferedBlockCipher(cipher, padding);
    }

    public static BufferedBlockCipher newInstance_AES(final byte[] key, final byte[] iv,
                                                      final Function<? super MultiBlockCipher, ? extends BlockCipher> mapper,
                                                      final BlockCipherPadding padding) {
        Objects.requireNonNull(key, "key is null");
        Objects.requireNonNull(iv, "iv is null");
        Objects.requireNonNull(mapper, "mapper is null");
        return newInstance(mapper.apply(AESEngine.newInstance()), padding);
    }

    // ------------------------------------------------------------------------------------------------------------- AES
    public static BufferedBlockCipher newInstance_AES(
            final Function<? super MultiBlockCipher, ? extends BlockCipher> mapper, final BlockCipherPadding padding) {
        Objects.requireNonNull(mapper, "mapper is null");
        return newInstance(mapper.apply(AESEngine.newInstance()), padding);
    }

    public static BufferedBlockCipher newInstance_AES_CBC(final BlockCipherPadding padding) {
        return newInstance_AES(CBCBlockCipher::newInstance, padding);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaPaddedBufferedBlockCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
