package io.github.jinahya.util.bouncycastle.crypto;

import org.bouncycastle.crypto.StreamBlockCipher;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * A utility class for {@link StreamBlockCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 * @see <a
 * href="https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/index.html?org/bouncycastle/crypto/StreamBlockCipher.html">org.bouncycastle.crypto.StreamBlockCipher</a>
 */
public final class JinahyaStreamBlockCipherUtils {

    public static byte[] processBytes(final StreamBlockCipher cipher, final byte[] in) {
        return JinahyaStreamCipherUtils.processBytes(cipher, in, new byte[cipher.getBlockSize()]);
    }

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Process, using specified cipher, all bytes from specified input stream, and writes processed bytes to specified
     * output stream.
     *
     * @param cipher the cipher.
     * @param source the input stream from which bytes to process are read.
     * @param target the output stream to which processed bytes are written.
     * @param <T>    cipher type parameter
     * @return given {@code cipher}.
     * @throws IOException if an I/O error occurs.
     * @see StreamBlockCipher#processBytes(byte[], int, int, byte[], int)
     * @see <a
     * href="https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/org/bouncycastle/crypto/StreamBlockCipher.html#processBytes-byte:A-int-int-byte:A-int-">StreamBlockCipher#processBytes(byte[],
     * int, int, byte[],int)</a>
     */
    public static <T extends StreamBlockCipher> T processAllBytes(final T cipher, final InputStream source,
                                                                  final OutputStream target)
            throws IOException {
        return JinahyaStreamCipherUtils.processAllBytes(
                cipher,
                source,
                target,
                new byte[cipher.getBlockSize()]
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaStreamBlockCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
