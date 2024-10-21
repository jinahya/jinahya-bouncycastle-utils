package io.github.jinahya.util.bouncycastle.crypto;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Objects;

/**
 * A utility class for {@link StreamCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 * @see <a
 * href="https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/index.html?org/bouncycastle/crypto/StreamCipher.html">org.bouncycastle.crypto.StreamCipher</a>
 */
public final class JinahyaStreamCipherUtils {

    static byte[] processBytes(final StreamCipher cipher, final byte[] in, byte[] out) {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(in, "in is null");
        while (true) {
            try {
                return Arrays.copyOf(out, cipher.processBytes(in, 0, in.length, out, 0));
            } catch (final DataLengthException dle) {
                System.err.println("doubling up out.length from " + out.length);
                out = new byte[out.length << 1];
            }
        }
    }

    public static byte[] processBytes(final StreamCipher cipher, final byte[] in) {
        return processBytes(cipher, in, new byte[in.length]);
    }

    // -----------------------------------------------------------------------------------------------------------------
    static <T extends StreamCipher> T processAllBytes(final T cipher, final InputStream source,
                                                      final OutputStream target, final byte[] in, byte[] out)
            throws IOException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(source, "source is null");
        Objects.requireNonNull(target, "target is null");
        if (Objects.requireNonNull(in, "in is null").length == 0) {
            throw new IllegalArgumentException("in.length is zero");
        }
        if (Objects.requireNonNull(out, "out is null").length == 0) {
            throw new IllegalArgumentException("out.length is zero");
        }
        for (int r; (r = source.read(in)) != -1; ) {
            while (true) {
                try {
                    target.write(out, 0, cipher.processBytes(in, 0, r, out, 0));
                    break;
                } catch (final DataLengthException dle) {
                    System.err.println("doubling up out.length from " + out.length);
                    out = new byte[out.length << 1];
                }
            }
        }
        return cipher;
    }

    /**
     * Process, using specified cipher, all bytes from specified input stream, and writes processed bytes to specified
     * output stream.
     *
     * @param cipher the cipher.
     * @param source the input stream from which bytes to process are read.
     * @param target the output stream to which processed bytes are written.
     * @param in     aa array of bytes for reading bytes from {@code source} whose {@code length} should be positive.
     * @param <T>    cipher type parameter
     * @return given {@code cipher}.
     * @throws IOException if an I/O error occurs.
     * @see StreamCipher#processBytes(byte[], int, int, byte[], int)
     * @see <a
     * href="https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/org/bouncycastle/crypto/StreamCipher.html#processBytes-byte:A-int-int-byte:A-int-">StreamCipher#processBytes(byte[],
     * int, int, byte[],int)</a>
     */
    public static <T extends StreamCipher> T processAllBytes(final T cipher, final InputStream source,
                                                             final OutputStream target, final byte[] in)
            throws IOException {
        return processAllBytes(cipher, source, target, in, new byte[in.length]);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaStreamCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
