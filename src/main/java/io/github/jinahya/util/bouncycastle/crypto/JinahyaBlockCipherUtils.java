package io.github.jinahya.util.bouncycastle.crypto;

import org.bouncycastle.crypto.BlockCipher;

import java.util.Objects;

/**
 * A utility class for {@link BlockCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
public final class JinahyaBlockCipherUtils {

    static int getBlockSizeInBits_(final BlockCipher cipher) {
        assert cipher != null;
        return cipher.getBlockSize() << 3;
    }

    /**
     * Returns the block size of specified cipher in bits.
     *
     * @param cipher the cipher.
     * @return the block size of {@code cipher} in bits.
     */
    public static int getBlockSizeInBits(final BlockCipher cipher) {
        return getBlockSizeInBits_(Objects.requireNonNull(cipher, "cipher is null"));
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaBlockCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
