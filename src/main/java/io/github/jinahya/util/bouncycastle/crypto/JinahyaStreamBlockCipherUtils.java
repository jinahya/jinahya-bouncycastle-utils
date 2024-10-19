package io.github.jinahya.util.bouncycastle.crypto;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.StreamBlockCipher;
import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Objects;

/**
 * A utility class for {@link StreamBlockCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
public final class JinahyaStreamBlockCipherUtils {

    private static StreamBlockCipher requireNonNull(final StreamBlockCipher cipher) {
        return Objects.requireNonNull(cipher, "cipher is null");
    }

    /**
     * Returns the block size of specified cipher in bits.
     *
     * @param cipher the cipher.
     * @return the block size of {@code cipher} in bits.
     * @deprecated Use {@link JinahyaBlockCipherUtils#getBlockSizeInBits(BlockCipher)} method.
     */
    @Deprecated
    public static int getBlockSizeInBits(final StreamBlockCipher cipher) {
        return requireNonNull(cipher).getBlockSize() << 3;
    }

    public static byte[] processBytesAndDoFinal(final StreamBlockCipher cipher, final byte[] in) {
        for (var out = new byte[in.length]; ; ) {
            try {
                return Arrays.copyOf(out, cipher.processBytes(in, 0, in.length, out, 0));
            } catch (final DataLengthException dle) {
                out = new byte[out.length << 1];
            }
        }
    }

    /**
     * Process, using specified cipher, all bytes from specified input stream, and writes processed bytes to specified
     * output stream.
     *
     * @param cipher the cipher.
     * @param source the input stream from which bytes to process are read.
     * @param target the output stream to which processed bytes are written.
     * @param in     a buffer for reading bytes from {@code source} whose {@code length} should be positive.
     * @return an array of bytes suitable for the {@code out} of
     * @throws IOException if an I/O error occurs.
     * @see StreamBlockCipher#processBytes(byte[], int, int, byte[], int)
     * @see <a
     * href="https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/org/bouncycastle/crypto/StreamBlockCipher.html">org.bouncycastle.crypto.StreamBlockCipher</a>
     * (bcprov-jdk18on-javadoc)
     */
    public static byte[] processAllBytes(final StreamBlockCipher cipher, final InputStream source,
                                         final OutputStream target, final byte[] in)
            throws IOException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(source, "source is null");
        Objects.requireNonNull(target, "target is null");
        if (Objects.requireNonNull(in, "in is null").length == 0) {
            throw new IllegalArgumentException("in.length is zero");
        }
        var out = new byte[in.length];
        for (int r; (r = source.read(in)) != -1; ) {
            try {
                target.write(out, 0, cipher.processBytes(in, 0, r, out, 0));
            } catch (final DataLengthException dle) {
                out = new byte[out.length << 1];
            }
        }
        Arrays.clear(in);
        Arrays.clear(out);
        return out;
    }

    /**
     * Process, using specified cipher, all bytes from specified input stream, and writes processed bytes to specified
     * output stream.
     *
     * @param cipher the cipher.
     * @param source the input stream from which bytes to process are read.
     * @param target the output stream to which processed bytes are written.
     * @param buflen a length of a buffer for reading bytes from {@code source}; should be positive.
     * @return an array of bytes suitable for the {@code out} of
     * @throws IOException if an I/O error occurs.
     * @see StreamBlockCipher#processBytes(byte[], int, int, byte[], int)
     * @see <a
     * href="https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/org/bouncycastle/crypto/StreamBlockCipher.html">org.bouncycastle.crypto.StreamBlockCipher</a>
     * (bcprov-jdk18on-javadoc)
     */
    public static byte[] processAllBytes(final StreamBlockCipher cipher, final InputStream source,
                                         final OutputStream target, final int buflen)
            throws IOException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(source, "source is null");
        Objects.requireNonNull(target, "target is null");
        if (buflen <= 0) {
            throw new IllegalArgumentException("non-positive buflen: " + buflen);
        }
        return processAllBytes(cipher, source, target, new byte[buflen]);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaStreamBlockCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
