package io.github.jinahya.util.bouncycastle.crypto;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Objects;

/**
 * A utility class for {@link org.bouncycastle.crypto.StreamCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 * @see <a
 * href="https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/index.html?org/bouncycastle/crypto/StreamCipher.html">org.bouncycastle.crypto.StreamCipher</a>
 */
public final class JinahyaStreamCipherUtils {

    public static byte[] processBytes(final StreamCipher cipher, final byte[] in) {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(in, "in is null");
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
     * @param buffer a buffer for reading bytes from {@code source} whose {@code length} should be positive.
     * @throws IOException if an I/O error occurs.
     * @see StreamCipher#processBytes(byte[], int, int, byte[], int)
     * @see <a
     * href="https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/org/bouncycastle/crypto/StreamCipher.html#processBytes-byte:A-int-int-byte:A-int-">StreamCipher#processBytes(byte[],
     * int, int, byte[],int)</a>
     */
    public static void processAllBytes(final StreamCipher cipher, final InputStream source, final OutputStream target,
                                       final byte[] buffer)
            throws IOException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(source, "source is null");
        Objects.requireNonNull(target, "target is null");
        if (Objects.requireNonNull(buffer, "buffer is null").length == 0) {
            throw new IllegalArgumentException("buffer.length is zero");
        }
        for (int r; (r = source.read(buffer)) != -1; ) {
            for (var out = new byte[buffer.length]; ; ) {
                try {
                    target.write(out, 0, cipher.processBytes(buffer, 0, r, out, 0));
                    break;
                } catch (final DataLengthException dle) {
                    out = new byte[out.length << 1];
                }
            }
        }
        Arrays.clear(buffer);
    }

    public static void processAllBytes(final StreamCipher cipher, final InputStream source, final OutputStream target,
                                       final int buflen)
            throws IOException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(source, "source is null");
        Objects.requireNonNull(target, "target is null");
        if (buflen <= 0) {
            throw new IllegalArgumentException("non-positive buflen: " + buflen);
        }
        processAllBytes(cipher, source, target, new byte[buflen]);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaStreamCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
