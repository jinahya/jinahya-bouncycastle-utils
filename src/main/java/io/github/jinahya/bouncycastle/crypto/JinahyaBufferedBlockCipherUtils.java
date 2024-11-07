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
 */
public final class JinahyaBufferedBlockCipherUtils {

    // -----------------------------------------------------------------------------------------------------------------
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
        final var processed = cipher.processBytes(in, inoff, inlen, out, outoff);
        final var finalized = cipher.doFinal(out, processed);
        return processed + finalized;
    }

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
     * Processes and finalizes, using specified cipher, all bytes from specified input stream, and writes all processed
     * bytes to specified output stream.
     *
     * @param cipher the cipher.
     * @param in     the input stream from which unprocessed bytes are read.
     * @param out    the output stream to which processed bytes are written.
     * @param inbuf  a buffer for reading unprocessed bytes from the {@code in}.
     * @param outbuf a buffer for processing bytes, and writing those bytes to the {@code out}.
     * @return the number of bytes written to the {@code out}.
     * @throws IOException                if an I/O error occurs.
     * @throws InvalidCipherTextException if padding is expected and not found.
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
