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

    // -----------------------------------------------------------------------------------------------------------------

    private static int processBytes(final AEADCipher cipher, final byte[] in, final int inoff,
                                    final int inlen, final byte[] out, final int outoff) {
        return cipher.processBytes(in, inoff, inlen, out, outoff); // DataLengthException
    }

    public static int processBytesAndDoFinal(final AEADCipher cipher, final byte[] input, final byte[] output)
            throws InvalidCipherTextException {
        final var processed = processBytes(cipher, input, 0, input.length, output, 0);
        final var finalized = cipher.doFinal(output, processed); // InvalidCipherTextException
        return processed + finalized;
    }

    /**
     * Processes and finalizes specified input using specified cipher.
     *
     * @param cipher the cipher.
     * @param input  the input to process and finalize.
     * @return an array of result bytes.
     * @throws InvalidCipherTextException if thrown by {@link AEADCipher#doFinal(byte[], int)} method.
     * @see AEADCipher#processBytes(byte[], int, int, byte[], int)
     * @see AEADCipher#doFinal(byte[], int)
     */
    public static byte[] processBytesAndDoFinal(final AEADCipher cipher, final byte[] input)
            throws InvalidCipherTextException {
        final var output = new byte[cipher.getOutputSize(input.length)];
        final var outlen = processBytesAndDoFinal(cipher, input, output);
        return Arrays.copyOf(output, outlen);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private static byte[] processAllBytes(final AEADCipher cipher, final InputStream input,
                                          final OutputStream output, final byte[] inbuf, byte[] outbuf)
            throws IOException {
        assert cipher != null : "cipher shouldn't be null";
        assert input != null : "input shouldn't be null";
        assert output != null : "output shouldn't be null";
        assert inbuf != null;
        assert inbuf.length > 0;
        assert outbuf != null : "outbuf shouldn't be null";
        for (int r; (r = input.read(inbuf)) != -1; ) {
            final var outputSize = cipher.getOutputSize(r); // don't use <cipher.getUpdateOutputSize(r)>; finalization!!
            if (outbuf.length < outputSize) {
                outbuf = new byte[outputSize];
            }
            final var outlen = processBytes(cipher, inbuf, 0, r, outbuf, 0);
            output.write(outbuf, 0, outlen);
        }
        return outbuf;
    }

    private static byte[] processAllBytes(final AEADCipher cipher, final InputStream source,
                                          final OutputStream target, final byte[] inbuf)
            throws IOException {
        assert cipher != null;
        assert inbuf != null;
        assert inbuf.length > 0 : "inbuf.length shouldn't be zero";
        final var outbuf = new byte[cipher.getOutputSize(inbuf.length)];
        return processAllBytes(
                cipher,
                source,
                target,
                inbuf,
                outbuf
        );
    }

    public static int processAllBytesAndDoFinal(final AEADCipher cipher, final InputStream input,
                                                final OutputStream output, final byte[] inbuf)
            throws IOException, InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(input, "input is null");
        Objects.requireNonNull(output, "output is null");
        final var out = processAllBytes(cipher, input, output, inbuf);
        output.write(out, 0, cipher.doFinal(out, 0));
        return 0;
    }

    public static <T extends AEADCipher> T processAllBytesAndDoFinal(final T cipher, final InputStream source,
                                                                     final OutputStream target, final int inlen)
            throws IOException, InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(source, "source is null");
        Objects.requireNonNull(target, "target is null");
        if (inlen < 1) {
            throw new IllegalArgumentException("non-positive inlen: " + inlen);
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
