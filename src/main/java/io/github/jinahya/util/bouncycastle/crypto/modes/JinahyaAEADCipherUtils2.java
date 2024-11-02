package io.github.jinahya.util.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.AEADCipher;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.util.Arrays;
import java.util.Objects;

/**
 * A utility class for {@link AEADCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
public final class JinahyaAEADCipherUtils2 {

    // -----------------------------------------------------------------------------------------------------------------

    private static int processBytes(final AEADCipher cipher, final byte[] in, final int inoff,
                                    final int inlen, final byte[] out, final int outoff) {
        return cipher.processBytes(in, inoff, inlen, out, outoff); // DataLengthException
    }

    public static int processBytesAndDoFinal(final AEADCipher cipher, final byte[] input, final byte[] output)
            throws InvalidCipherTextException {
        final var processed = processBytes(cipher, input, 0, input.length, output, 0); // DataLengthException
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
    private static long processAllBytes(final AEADCipher cipher, final InputStream input,
                                        final OutputStream output, final byte[] inbuf, final byte[] outbuf)
            throws IOException {
        assert cipher != null : "cipher shouldn't be null";
        assert input != null : "input shouldn't be null";
        assert output != null : "output shouldn't be null";
        assert inbuf != null : "inbuf shouldn't be null";
        assert inbuf.length > 0 : "inbuf.length shouldn't be zero";
        assert outbuf != null : "outbuf shouldn't be null";
        assert outbuf.length > 0 : "outbuf.length shouldn't be zero";
        long written = 0L;
        for (int r; (r = input.read(inbuf)) != -1; ) {
            final var outlen = processBytes(cipher, inbuf, 0, r, outbuf, 0);
            output.write(outbuf, 0, outlen);
            written += outlen;
        }
        return written;
    }

    private static long processAllBytes(final AEADCipher cipher, final InputStream input,
                                        final OutputStream output, final byte[] inbuf)
            throws IOException {
        assert inbuf != null;
        assert inbuf.length > 0 : "inbuf.length shouldn't be zero";
        final var outbuf = new byte[cipher.getOutputSize(inbuf.length)];
        return processAllBytes(
                cipher,
                input,
                output,
                inbuf,
                outbuf
        );
    }

    public static long processAllBytesAndDoFinal(final AEADCipher cipher, final InputStream input,
                                                 final OutputStream output, final byte[] inbuf, final byte[] outbuf)
            throws IOException, InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length is zero");
        }
        if (Objects.requireNonNull(outbuf, "outbuf is null").length == 0) {
            throw new IllegalArgumentException("outbuf.length is zero");
        }
        final var processed = processAllBytes(cipher, input, output, inbuf, outbuf);
        final var finalized = cipher.doFinal(outbuf, 0);
        output.write(outbuf, 0, finalized);
        return processed + finalized;
    }

    public static long processAllBytesAndDoFinal(final AEADCipher cipher, final InputStream input,
                                                 final OutputStream output, final byte[] inbuf)
            throws IOException, InvalidCipherTextException {
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length is zero");
        }
        var insum = 0L;
        var outsum = 0L;
        byte[] outbuf = new byte[0];
        int outlen;
        for (int r; (r = input.read(inbuf)) != -1; ) {
            final var updateOutputSize = cipher.getUpdateOutputSize(r);
            if (outbuf.length < updateOutputSize) {
                outbuf = Arrays.copyOf(outbuf, updateOutputSize);
            }
            outlen = cipher.processBytes(inbuf, 0, r, outbuf, 0);
            output.write(outbuf, 0, outlen);
            insum += r;
            outsum += outlen;
        }
        outbuf = Arrays.copyOf(outbuf, cipher.getOutputSize(Math.toIntExact(insum)));
        outlen = cipher.doFinal(outbuf, 0);
        output.write(outbuf, 0, outlen);
        return outsum;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private static int processBytes(final AEADCipher cipher, final ByteBuffer input,
                                    final ByteBuffer output) {
        final byte[] in;
        final int inoff;
        final int inlen;
        if (input.hasArray()) {
            in = input.array();
            inoff = input.arrayOffset() + input.position();
            inlen = input.remaining();
        } else {
            in = new byte[input.remaining()];
            input.get(input.position(), in);
            inoff = 0;
            inlen = in.length;
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
        // -------------------------------------------------------------------------------------------------------------
        final var outlen = processBytes(cipher, in, inoff, inlen, out, outoff);
        input.position(input.position() + inlen);
        assert !input.hasRemaining();
        if (output.hasArray()) {
            output.position(output.position() + outlen);
        } else {
            output.put(out, outoff, outlen);
        }
        return outlen;
    }

    private static int doFinal(final AEADCipher cipher, final ByteBuffer output)
            throws InvalidCipherTextException {
        final byte[] out;
        final int outoff;
        if (output.hasArray()) {
            out = output.array();
            outoff = output.arrayOffset() + output.position();
        } else {
            out = new byte[output.remaining()];
            outoff = 0;
        }
        final var outlen = cipher.doFinal(out, outoff);
        if (output.hasArray()) {
            output.position(output.position() + outlen);
        } else {
            output.put(out, outoff, outlen);
        }
        return outlen;
    }

    public static int processBytesAndDoFinal(final AEADCipher cipher, final ByteBuffer input,
                                             final ByteBuffer output)
            throws InvalidCipherTextException {
        Objects.requireNonNull(output, "output is null");
        final var processed = processBytes(cipher, input, output);
        final var finalized = doFinal(cipher, output);
        return processed + finalized;
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static long processAllBytesAndDoFinal(final AEADCipher cipher, final ReadableByteChannel input,
                                                 final WritableByteChannel output, final ByteBuffer inbuf,
                                                 final ByteBuffer outbuf)
            throws IOException, InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(input, "input is null");
        Objects.requireNonNull(output, "output is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").capacity() == 0) {
            throw new IllegalArgumentException("inbuf.capacity is zero");
        }
        final var outputSize = cipher.getOutputSize(inbuf.capacity());
        if (Objects.requireNonNull(outbuf, "outbuf is null").capacity() < outputSize) {
            throw new IllegalArgumentException(
                    "outbuf.capacity(" + outbuf.capacity() + ") shouldn't be less than the outputSize("
                            + outputSize + ") derived from inbuf.capacity(" + inbuf.capacity() + ")"
            );
        }
        long written = 0L;
        outbuf.clear();
        while (input.read(inbuf.clear()) != -1) {
            final var processed = processBytes(cipher, inbuf.flip(), outbuf);
            assert processed >= 0;
            outbuf.flip();
            for (final var l = outputSize - (outbuf.capacity() - outbuf.limit()); outbuf.position() < l; ) {
                written += output.write(outbuf);
            }
            outbuf.compact();
        }
        outbuf.flip();
        for (final var l = outputSize - (outbuf.capacity() - outbuf.limit()); outbuf.position() < l; ) {
            written += output.write(outbuf);
        }
        outbuf.compact();
        // finalize
        final var finalized = doFinal(cipher, outbuf);
        assert finalized >= 0;
        for (outbuf.flip(); outbuf.hasRemaining(); ) {
            written += output.write(outbuf);
        }
        outbuf.clear();
        return written;
    }

    /**
     * Processes and finalizes, using specified cipher, from specified input channel, and writes processed bytes to
     * specified output channel.
     *
     * @param cipher the cipher.
     * @param input  the inbuf channel from which bytes are read.
     * @param output the output channel to which processed bytes are written.
     * @param inbuf  a buffer for reading bytes from the {@code input}.
     * @return the number of bytes written the {@code output}.
     * @throws IOException                if an I/O error occurs.
     * @throws InvalidCipherTextException if padding is expected and not found.
     */
    public static long processAllBytesAndDoFinal(final AEADCipher cipher, final ReadableByteChannel input,
                                                 final WritableByteChannel output, final ByteBuffer inbuf)
            throws IOException, InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").capacity() == 0) {
            throw new IllegalArgumentException("inbuf.capacity is zero");
        }
        return processAllBytesAndDoFinal(
                cipher,
                input,
                output,
                inbuf,
                ByteBuffer.allocate(cipher.getOutputSize(inbuf.capacity()))
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaAEADCipherUtils2() {
        throw new AssertionError("instantiation is not allowed");
    }
}
