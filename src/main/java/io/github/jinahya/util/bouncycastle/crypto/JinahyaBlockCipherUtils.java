package io.github.jinahya.util.bouncycastle.crypto;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;

import java.util.Objects;

/**
 * A utility class for {@link BufferedBlockCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
public final class JinahyaBlockCipherUtils {

    private static <T extends BlockCipher> T requireNonNull(final T cipher) {
        return Objects.requireNonNull(cipher, "cipher is null");
    }

    /**
     * Returns the block size of specified cipher in bits.
     *
     * @param cipher the cipher.
     * @return the block size of {@code cipher} in bits.
     */
    public static int getBlockSizeInBits(final BlockCipher cipher) {
        return requireNonNull(cipher).getBlockSize() << 3;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaBlockCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
