package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

/**
 * A utility class for {@link BufferedBlockCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 * @see JinahyaBufferedBlockCipherCrypto
 */
public final class JinahyaBufferedBlockCipherUtils {

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Processes and finalizes, using specified cipher, bytes in specified range of specified input array, and set
     * processed bytes to specified output array starting at specified index.
     *
     * @param cipher the cipher.
     * @param in     the input array.
     * @param inoff  a starting index of {@code in}.
     * @param inlen  number of bytes to process in {@code in}.
     * @param out    the output array.
     * @param outoff the starting index of {@code out} on which processed bytes are set.
     * @return the number of bytes set on the {@code out}.
     * @throws InvalidCipherTextException if padding is expected and not found.
     * @see BufferedBlockCipher#processBytes(byte[], int, int, byte[], int)
     * @see BufferedBlockCipher#doFinal(byte[], int)
     */
    public static int processBytesAndDoFinal(final BufferedBlockCipher cipher, final byte[] in, final int inoff,
                                             final int inlen, final byte[] out, final int outoff)
            throws InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(in, "in is null");
        if (inoff < 0) {
            throw new IllegalArgumentException("inoff(" + inoff + ") is negative");
        }
        if (inlen < 0) {
            throw new IllegalArgumentException("inlen(" + inlen + ") is negative");
        }
        if (inoff + inlen > in.length) {
            throw new IllegalArgumentException(
                    "inoff(" + inoff + ") + inlen(" + inlen + ") > in.length(" + in.length + ")");
        }
        Objects.requireNonNull(out, "out is null");
        if (outoff < 0) {
            throw new IllegalArgumentException("outoff(" + outoff + ") is negative");
        }
        if (outoff > out.length) {
            throw new IllegalArgumentException("outoff(" + outoff + ") > out.length(" + out.length + ")");
        }
        var outlen = cipher.processBytes(in, inoff, inlen, out, outoff); // DataLengthException
        outlen += cipher.doFinal(out, outlen); // InvalidCipherTextException
        return outlen;
    }

    /**
     * Processes and finalizes, using specified cipher, all remaining bytes of specified input buffer, and put process
     * bytes to specified output buffer.
     *
     * @param cipher the cipher.
     * @param input  the input buffer whose remaining bytes are processed.
     * @param output the output buffer onto which processed bytes are put.
     * @return the number of bytes put on the output buffer.
     * @throws InvalidCipherTextException if padding is expected and not found.
     * @see #processBytesAndDoFinal(BufferedBlockCipher, byte[], int, int, byte[], int)
     */
    public static int processBytesAndDoFinal(final BufferedBlockCipher cipher, final ByteBuffer input,
                                             final ByteBuffer output)
            throws InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(input, "input is null");
        Objects.requireNonNull(output, "output is null");
        final byte[] in;
        final int inoff;
        final int inlen = input.remaining();
        if (input.hasArray()) {
            in = input.array();
            inoff = input.arrayOffset() + input.position();
        } else {
            in = new byte[inlen];
//            input.get(0, in); // Java 13
            for (int p = input.position(), i = 0; i < in.length; p++, i++) {
                in[i] = input.get(p);
            }
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

    /**
     * Processes and finalizes, using specified cipher, all bytes from specified input stream, and writes processed
     * bytes to specified output stream.
     *
     * @param cipher the cipher.
     * @param in     the input stream from which unprocessed bytes are read.
     * @param out    the output stream to which processed bytes are written.
     * @param inbuf  a buffer for reading bytes from the input stream.
     * @param outbuf a buffer for processed bytes.
     * @return the number of bytes written to the {@code out}.
     * @throws IOException                if an I/O error occurs.
     * @throws InvalidCipherTextException if padding is expected and not found.
     * @see BufferedBlockCipher#processBytes(byte[], int, int, byte[], int)
     * @see BufferedBlockCipher#doFinal(byte[], int)
     */
    public static long processAllBytesAndDoFinal(final BufferedBlockCipher cipher, final InputStream in,
                                                 final OutputStream out, final byte[] inbuf, byte[] outbuf)
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
        var bytes = 0L;
        int outlen;
        for (int r; (r = in.read(inbuf)) != -1; ) {
            for (final var uos = cipher.getUpdateOutputSize(r); outbuf.length < uos; ) {
                System.err.println(
                        "re-allocating outbuf(" + outbuf.length +
                                ") for an intermediate update-output-size(" + uos + ")"
                );
                Arrays.fill(outbuf, (byte) 0);
                outbuf = new byte[uos];
            }
            outlen = cipher.processBytes(inbuf, 0, r, outbuf, 0);
            out.write(outbuf, 0, outlen);
            bytes += outlen;
        }
        for (final var os = cipher.getOutputSize(0); outbuf.length < os; ) {
            System.err.println("re-allocating outbuf(" + outbuf.length + ") for the final output-size(" + os + ")");
            Arrays.fill(outbuf, (byte) 0);
            outbuf = new byte[os];
        }
        outlen = cipher.doFinal(outbuf, 0);
        out.write(outbuf, 0, outlen);
        bytes += outlen;
        return bytes;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaBufferedBlockCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
