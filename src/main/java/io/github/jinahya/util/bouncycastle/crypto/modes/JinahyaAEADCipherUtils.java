package io.github.jinahya.util.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.AEADCipher;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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

    /**
     * Processes and finalizes, using specified cipher, specified input array, and set processed bytes on specified
     * output array.
     *
     * @param cipher the cipher.
     * @param input  the input array to process.
     * @param output the output array on which processed bytes are set.
     * @return the number of bytes processed, and set on the {@code output}.
     * @throws InvalidCipherTextException if thrown by {@link AEADCipher#doFinal(byte[], int)} method.
     * @see AEADCipher#processBytes(byte[], int, int, byte[], int)
     * @see AEADCipher#doFinal(byte[], int)
     */
    public static int processBytesAndDoFinal(final AEADCipher cipher, final byte[] input, final byte[] output)
            throws InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        int length = 0;
        length += cipher.processBytes(input, 0, input.length, output, length); // DataLengthException
        length += cipher.doFinal(output, length); // InvalidCipherTextException
        return length;
    }

    public static int encrypt(final AEADCipher cipher, final CipherParameters params, final byte[] input,
                              final byte[] output)
            throws InvalidCipherTextException {
        return processBytesAndDoFinal(
                initForEncryption(cipher, params),
                input,
                output
        );
    }

    public static int decrypt(final AEADCipher cipher, final CipherParameters params, final byte[] input,
                              final byte[] output)
            throws InvalidCipherTextException {
        return processBytesAndDoFinal(
                initForDecryption(cipher, params),
                input,
                output
        );
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

    public static byte[] encrypt(final AEADCipher cipher, final CipherParameters params, final byte[] input)
            throws InvalidCipherTextException {
        return processBytesAndDoFinal(
                initForEncryption(cipher, params),
                input
        );
    }

    public static byte[] decrypt(final AEADCipher cipher, final CipherParameters params, final byte[] input)
            throws InvalidCipherTextException {
        return processBytesAndDoFinal(
                initForDecryption(cipher, params),
                input
        );
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
        if (Objects.requireNonNull(outbuf, "outbuf is null").length == 0) {
            throw new IllegalArgumentException("outbuf.length is zero");
        }
        var read = 0L;
        var written = 0L;
        for (int r; (r = in.read(inbuf)) != -1; read += r) {
            for (final var l = cipher.getUpdateOutputSize(r); outbuf.length < l; ) {
                System.err.println("doubling up outbuf.length from " + outbuf.length);
                Arrays.fill(outbuf, (byte) 0);
                outbuf = new byte[outbuf.length << 1];
            }
            final var outlen = cipher.processBytes(inbuf, 0, r, outbuf, 0); // DataLengthException
            out.write(outbuf, 0, outlen);
            written += outlen;
        }
        for (final var l = cipher.getOutputSize(Math.toIntExact(read)); outbuf.length < l; ) {
            System.err.println("doubling up outbuf.length from " + outbuf.length);
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

    public static long encrypt(final AEADCipher cipher, final CipherParameters params, final InputStream in,
                               final OutputStream out, final byte[] inbuf, byte[] outbuf)
            throws IOException, InvalidCipherTextException {
        return processAllBytesAndDoFinal(
                initForEncryption(cipher, params),
                in,
                out,
                inbuf,
                outbuf
        );
    }

    public static long decrypt(final AEADCipher cipher, final CipherParameters params, final InputStream in,
                               final OutputStream out, final byte[] inbuf, byte[] outbuf)
            throws IOException, InvalidCipherTextException {
        return processAllBytesAndDoFinal(
                initForDecryption(cipher, params),
                in,
                out,
                inbuf,
                outbuf
        );
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

    public static long encrypt(final AEADCipher cipher, final CipherParameters params, final InputStream in,
                               final OutputStream out, final byte[] inbuf)
            throws IOException, InvalidCipherTextException {
        return processAllBytesAndDoFinal(
                initForEncryption(cipher, params),
                in,
                out,
                inbuf
        );
    }

    public static long decrypt(final AEADCipher cipher, final CipherParameters params, final InputStream in,
                               final OutputStream out, final byte[] inbuf)
            throws IOException, InvalidCipherTextException {
        return processAllBytesAndDoFinal(
                initForDecryption(cipher, params),
                in,
                out,
                inbuf
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaAEADCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
