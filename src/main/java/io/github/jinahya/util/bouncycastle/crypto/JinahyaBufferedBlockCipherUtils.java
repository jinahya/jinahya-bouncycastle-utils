package io.github.jinahya.util.bouncycastle.crypto;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Objects;

/**
 * A utility class for {@link BufferedBlockCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
public final class JinahyaBufferedBlockCipherUtils {

    /**
     * Processes and finalizes specified input using specified cipher.
     *
     * @param cipher the cipher.
     * @param in     the input to process and finalize.
     * @return an array of bytes processed.
     * @throws InvalidCipherTextException if padding is expected and not found.
     * @see BufferedBlockCipher#processBytes(byte[], int, int, byte[], int)
     * @see BufferedBlockCipher#doFinal(byte[], int)
     */
    public static byte[] processBytesAndDoFinal(final BufferedBlockCipher cipher, final byte[] in)
            throws InvalidCipherTextException {
        final var out = new byte[cipher.getOutputSize(in.length)];
        final var processed = cipher.processBytes(in, 0, in.length, out, 0);
        final var finalized = cipher.doFinal(out, processed);
        return Arrays.copyOf(out, (processed + finalized));
    }

    // -----------------------------------------------------------------------------------------------------------------
    private static byte[] processAllBytes(final BufferedBlockCipher cipher, final InputStream source,
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
        int outputSize;
        for (int r; (r = source.read(in)) != -1; ) {
            outputSize = cipher.getOutputSize(r);
            if (out.length < outputSize) {
                out = new byte[outputSize];
            }
            target.write(out, 0, cipher.processBytes(in, 0, r, out, 0));
        }
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
     * @param in     a buffer for reading bytes from {@code source} whose {@code length} should be positive.
     * @return an array of bytes suitable for the {@code out} of
     * @throws IOException if an I/O error occurs.
     * @see BufferedBlockCipher#processBytes(byte[], int, int, byte[], int)
     * @see <a
     * href="https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/org/bouncycastle/crypto/BufferedBlockCipher.html">org.bouncycastle.crypto.BufferedBlockCipher</a>
     * (bcprov-jdk18on-javadoc)
     */
    private static byte[] processAllBytes(final BufferedBlockCipher cipher, final InputStream source,
                                          final OutputStream target, final byte[] in)
            throws IOException {
        return processAllBytes(cipher, source, target, in, new byte[cipher.getOutputSize(in.length)]);
    }

    /**
     * Process, using specified cipher, all bytes from specified input stream, and writes processed bytes and
     * finalization result to specified output stream.
     *
     * @param cipher the cipher.
     * @param source the input stream from which bytes to process are read.
     * @param target the output stream to which processed bytes are written.
     * @throws IOException if an I/O error occurs.
     * @see #processAllBytes(BufferedBlockCipher, InputStream, OutputStream, byte[])
     * @see BufferedBlockCipher#doFinal(byte[], int)
     * @see <a
     * href="https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/org/bouncycastle/crypto/BufferedBlockCipher.html">org.bouncycastle.crypto.BufferedBlockCipher</a>
     * (bcprov-jdk18on-javadoc)
     */
    public static void processAllBytesAndDoFinal(final BufferedBlockCipher cipher, final InputStream source,
                                                 final OutputStream target)
            throws IOException, InvalidCipherTextException {
        for (var out = processAllBytes(cipher, source, target, new byte[cipher.getBlockSize()]); ; ) {
            try {
                target.write(out, 0, cipher.doFinal(out, 0));
                break;
            } catch (final DataLengthException dle) {
                out = new byte[out.length << 1];
            }
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaBufferedBlockCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
