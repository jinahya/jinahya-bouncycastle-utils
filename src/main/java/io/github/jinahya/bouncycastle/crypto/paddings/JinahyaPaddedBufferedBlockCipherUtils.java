package io.github.jinahya.bouncycastle.crypto.paddings;

import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;

import java.lang.reflect.Field;
import java.util.Objects;

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

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaPaddedBufferedBlockCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
