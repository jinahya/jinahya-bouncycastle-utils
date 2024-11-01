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
 * (bcprov-jdk18on-javadoc)
 */
public final class JinahyaStreamCipherUtils {

    static byte[] processBytes(final StreamCipher cipher, final byte[] in, byte[] out) {
        assert cipher != null : "cipher shouldn't be null";
        assert in != null : "in shouldn't be null";
        assert out != null : "out shouldn't be null";
        assert out.length > 0 : "out.length shouldn't be zero";
        while (true) {
            try {
                final var processed = cipher.processBytes(in, 0, in.length, out, 0);
                return Arrays.copyOf(out, processed);
            } catch (final DataLengthException dle) {
                System.err.println("doubling up out.length from " + out.length);
                out = Arrays.copyOf(out, out.length << 1);
            }
        }
    }

    public static byte[] processBytes(final StreamCipher cipher, final byte[] in) {
        return processBytes(cipher, in, new byte[1]);
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static <T extends StreamCipher> T processAllBytes(final T cipher, final InputStream source,
                                                             final OutputStream target, final byte[] in, byte[] out)
            throws IOException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(source, "source is null");
        Objects.requireNonNull(target, "target is null");
        if (Objects.requireNonNull(in, "in is null").length == 0) {
            throw new IllegalArgumentException("in.length shouldn't be zero");
        }
        if (Objects.requireNonNull(out, "out is null").length == 0) {
            throw new IllegalArgumentException("out.length shouldn't be zero");
        }
        for (int r; (r = source.read(in)) != -1; ) {
            while (true) {
                try {
                    final var processed = cipher.processBytes(in, 0, r, out, 0);
                    target.write(out, 0, processed);
                    break;
                } catch (final DataLengthException dle) {
                    System.err.println("doubling up out.length from " + out.length);
                    Arrays.fill(out, (byte) 0);
                    out = Arrays.copyOf(out, out.length << 1);
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
        if (Objects.requireNonNull(in, "in is null").length == 0) {
            throw new IllegalArgumentException("in.length shouldn't be zero");
        }
        return processAllBytes(
                cipher,
                source, target,
                in,
                new byte[in.length]
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaStreamCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
