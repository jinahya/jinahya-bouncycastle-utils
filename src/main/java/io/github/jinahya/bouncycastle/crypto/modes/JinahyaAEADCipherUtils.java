package io.github.jinahya.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.AEADCipher;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

/**
 * A utility class for {@link AEADCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
public final class JinahyaAEADCipherUtils {

    private static <T extends AEADCipher> T initFor(final T cipher, final boolean encryption,
                                                    final CipherParameters params) {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(params, "params is null");
        cipher.init(encryption, params);
        return cipher;
    }

    public static <T extends AEADCipher> T initForEncryption(final T cipher, final CipherParameters params) {
        return initFor(cipher, true, params);
    }

    public static <T extends AEADCipher> T initForDecryption(final T cipher, final CipherParameters params) {
        return initFor(cipher, false, params);
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static int processBytesAndDoFinal(final AEADCipher cipher, final byte[] in, final int inoff, final int inlen,
                                             final byte[] out, final int outoff)
            throws InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        final var processed = cipher.processBytes(in, inoff, inlen, out, outoff); // DataLengthException
        final var finalized = cipher.doFinal(out, outoff + processed); // InvalidCipherTextException
        return processed + finalized;
    }

    /**
     * Processes and finalizes, using specified cipher, specified input array, and set processed bytes on specified
     * output array.
     *
     * @param cipher the cipher.
     * @param in     the input array to process.
     * @param out    the output array on which processed bytes are set.
     * @return the number of bytes processed, and set on the {@code output}.
     * @throws InvalidCipherTextException if thrown by {@link AEADCipher#doFinal(byte[], int)} method.
     * @see AEADCipher#processBytes(byte[], int, int, byte[], int)
     * @see AEADCipher#doFinal(byte[], int)
     */
    public static int processBytesAndDoFinal(final AEADCipher cipher, final byte[] in, final byte[] out)
            throws InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        int length = 0;
        length += cipher.processBytes(in, 0, in.length, out, length); // DataLengthException
        length += cipher.doFinal(out, length); // InvalidCipherTextException
        return length;
    }

    /**
     * Processes and finalizes, using specified cipher, specified input bytes, and returns the result.
     *
     * @param cipher the cipher.
     * @param input  the input bytes to process.
     * @return an array of result bytes.
     * @throws InvalidCipherTextException if thrown by {@link AEADCipher#doFinal(byte[], int)} method.
     */
    public static byte[] processBytesAndDoFinal(final AEADCipher cipher, final byte[] input)
            throws InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(input, "input is null");
        final var output = new byte[Math.max(cipher.getOutputSize(input.length), 1)];
        final var length = processBytesAndDoFinal(cipher, input, output);
        return Arrays.copyOf(output, length);
    }

    public static int processBytesAndDoFinal_(final AEADCipher cipher,
                                              final ByteBuffer input, final ByteBuffer output)
            throws InvalidCipherTextException {
        final byte[] in;
        final int inoff;
        final int inlen = input.remaining();
        if (input.hasArray()) {
            in = input.array();
            inoff = input.arrayOffset() + input.position();
        } else {
            in = new byte[inlen];
            input.get(0, in);
            inoff = 0;
        }
        final byte[] out;
        final int outoff;
        if (output.hasArray()) {
            out = output.array();
            outoff = output.arrayOffset() + output.position();
        } else {
            out = new byte[output.remaining()];
            outoff = 0;
        }
        final var outlen = processBytesAndDoFinal(cipher, in, inoff, inlen, out, outoff);
        input.position(input.position() + inlen);
        if (output.hasArray()) {
            output.position(output.position() + outlen);
        } else {
            output.put(out, outoff, outlen);
        }
        return outlen;
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static long processAllBytesAndDoFinal(final AEADCipher cipher, final InputStream in, final OutputStream out,
                                                 final byte[] inbuf, byte[] outbuf)
            throws IOException, InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(in, "in is null");
        Objects.requireNonNull(out, "out is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length is zero");
        }
        if (outbuf == null || outbuf.length == 0) {
            outbuf = new byte[cipher.getOutputSize(inbuf.length)];
        }
        var read = 0L;
        var written = 0L;
        for (int r; (r = in.read(inbuf)) != -1; read += r) {
            for (final var l = cipher.getUpdateOutputSize(r); outbuf.length < l; ) {
                System.err.println("doubling up outbuf.length(" + outbuf.length + ")");
                Arrays.fill(outbuf, (byte) 0);
                outbuf = new byte[outbuf.length << 1];
            }
            final var outlen = cipher.processBytes(inbuf, 0, r, outbuf, 0); // DataLengthException
            out.write(outbuf, 0, outlen);
            written += outlen;
        }
        for (final var l = cipher.getOutputSize(Math.toIntExact(read)); outbuf.length < l; ) {
            System.err.println("doubling up outbuf.length(" + outbuf.length + ")");
            Arrays.fill(outbuf, (byte) 0);
            outbuf = new byte[outbuf.length << 1];
        }
        final var outlen = cipher.doFinal(outbuf, 0);
        out.write(outbuf, 0, outlen);
        written += outlen;
        Arrays.fill(inbuf, (byte) 0);
        Arrays.fill(outbuf, (byte) 0);
        return written;
    }

    public static long processAllBytesAndDoFinal(final AEADCipher cipher, final InputStream in, final OutputStream out,
                                                 final byte[] inbuf)
            throws IOException, InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length is zero");
        }
        final var outbuf = new byte[Math.max(cipher.getOutputSize(inbuf.length), 1)];
        return processAllBytesAndDoFinal(cipher, in, out, inbuf, outbuf);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaAEADCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
