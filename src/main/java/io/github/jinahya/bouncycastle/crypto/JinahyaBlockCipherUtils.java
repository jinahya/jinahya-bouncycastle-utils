package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.BlockCipher;

import java.util.Objects;

/**
 * A utility class for {@link BlockCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 * @see <a
 * href="https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/org/bouncycastle/crypto/BlockCipher.html">org.bouncycastle.crypto.BlockCipher</a>
 * (bcprov-jdk18on-javadoc)
 */
public final class JinahyaBlockCipherUtils {

    /**
     * Returns the block size of specified cipher, in bits.
     *
     * @param cipher the cipher.
     * @return the block size of {@code cipher} in bits.
     * @see BlockCipher#getBlockSize()
     */
    public static int getBlockSizeInBits(final BlockCipher cipher) {
        return Objects.requireNonNull(cipher, "cipher is null").getBlockSize() >> 3;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaBlockCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
