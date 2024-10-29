package io.github.jinahya.util.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Objects;

/**
 * A utility class for {@link AEADCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
public final class JinahyaAEADCipherUtils {

    /**
     * Processes and finalizes specified input using specified cipher.
     *
     * @param cipher the cipher.
     * @param in     the input to process and finalize.
     * @return an array of bytes processed.
     * @throws InvalidCipherTextException if padding is expected and not found.
     * @see AEADCipher#processBytes(byte[], int, int, byte[], int)
     * @see AEADCipher#doFinal(byte[], int)
     */
    public static byte[] processBytesAndDoFinal(final AEADCipher cipher, final byte[] in)
            throws InvalidCipherTextException {
        final var out = new byte[cipher.getOutputSize(in.length)];
        final var processed = cipher.processBytes(in, 0, in.length, out, 0);
        final var finalized = cipher.doFinal(out, processed);
        return Arrays.copyOf(out, (processed + finalized));
    }

    // -----------------------------------------------------------------------------------------------------------------
    private static byte[] processAllBytes(final AEADCipher cipher, final InputStream source,
                                          final OutputStream target, final byte[] in, byte[] out)
            throws IOException {
        assert cipher != null : "cipher shouldn't be null";
        assert source != null : "source shouldn't be null";
        assert target != null : "target shouldn't be null";
        assert out != null : "out shouldn't be null";
        assert out.length > 0 : "out.length shouldn't be zero";
        for (int r; (r = source.read(in)) != -1; ) {
            final var outputSize = cipher.getOutputSize(r);
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
     * @see AEADCipher#processBytes(byte[], int, int, byte[], int)
     * @see <a
     * href="https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/org/bouncycastle/crypto/AEADCipher.html">org.bouncycastle.crypto.AEADCipher</a>
     * (bcprov-jdk18on-javadoc)
     */
    private static byte[] processAllBytes(final AEADCipher cipher, final InputStream source,
                                          final OutputStream target, final byte[] in)
            throws IOException {
        assert in != null;
        assert in.length > 0 : "out.length shouldn't be zero";
        return processAllBytes(
                cipher,
                source,
                target,
                in,
                new byte[cipher.getOutputSize(in.length)]
        );
    }

    public static <T extends AEADCipher> T processAllBytesAndDoFinal(final T cipher, final InputStream source,
                                                                     final OutputStream target, final int inlen)
            throws IOException, InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(source, "source is null");
        Objects.requireNonNull(target, "target is null");
        if (inlen < 1) {
            throw new IllegalArgumentException("non-positive length: " + inlen);
        }
        for (var out = processAllBytes(cipher, source, target, new byte[inlen]); ; ) {
            try {
                target.write(out, 0, cipher.doFinal(out, 0));
                break;
            } catch (final DataLengthException dle) {
                System.err.println("doubling up out.length from " + out.length);
                out = new byte[out.length << 1];
            }
        }
        return cipher;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaAEADCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
