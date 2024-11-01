package io.github.jinahya.util.bouncycastle.crypto;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.util.Objects;

/**
 * A utility class for {@link BufferedBlockCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
public final class JinahyaBufferedBlockCipherUtils {

    private static int processBytes(final BufferedBlockCipher cipher, final byte[] in, final int inoff,
                                    final int inlen, final byte[] out, final int outoff) {
        assert cipher != null;
        assert in != null;
        assert inoff >= 0;
        assert inlen <= in.length - inoff;
        assert out != null;
        assert outoff >= 0;
        assert out.length - outoff >= cipher.getUpdateOutputSize(inlen);
        return cipher.processBytes(in, inoff, inlen, out, 0);
    }

    private static byte[] processBytesAndDoFinal(final BufferedBlockCipher cipher, final byte[] in, final int off,
                                                 final int len)
            throws InvalidCipherTextException {
        final var out = new byte[cipher.getOutputSize(in.length)];
        final var processed = processBytes(cipher, in, off, len, out, 0);
        final var finalized = cipher.doFinal(out, processed);
        return Arrays.copyOf(out, (processed + finalized));
    }

    /**
     * Processes and finalizes specified input using specified cipher, and returns the result.
     *
     * @param cipher the cipher.
     * @param in     the input to process and finalize.
     * @return an array of bytes processed and finalized.
     * @throws InvalidCipherTextException if padding is expected and not found.
     * @see BufferedBlockCipher#processBytes(byte[], int, int, byte[], int)
     * @see BufferedBlockCipher#doFinal(byte[], int)
     */
    public static byte[] processBytesAndDoFinal(final BufferedBlockCipher cipher, final byte[] in)
            throws InvalidCipherTextException {
        return processBytesAndDoFinal(cipher, in, 0, in.length);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private static byte[] processAllBytes(final BufferedBlockCipher cipher, final InputStream source,
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
            final var outputSize = cipher.getOutputSize(r);
            if (out.length < outputSize) {
                Arrays.fill(out, (byte) 0);
                out = new byte[outputSize];
            }
            final var processed = cipher.processBytes(in, 0, r, out, 0);
            target.write(out, 0, processed);
        }
        Arrays.fill(out, (byte) 0);
        return out;
    }

    private static <T extends BufferedBlockCipher> T processAllBytesAndDoFinal(final T cipher, final InputStream source,
                                                                               final OutputStream target,
                                                                               final byte[] in, byte[] out)
            throws IOException, InvalidCipherTextException {
        out = processAllBytes(cipher, source, target, in, out);
        final var finalized = cipher.doFinal(out, 0);
        target.write(out, 0, finalized);
        return cipher;
    }

    public static <T extends BufferedBlockCipher> T processAllBytesAndDoFinal(final T cipher, final InputStream source,
                                                                              final OutputStream target,
                                                                              final byte[] in)
            throws IOException, InvalidCipherTextException {
        if (Objects.requireNonNull(in, "in is null").length == 0) {
            throw new IllegalArgumentException("in.length shouldn't be zero");
        }
        return processAllBytesAndDoFinal(
                cipher,
                source,
                target,
                in,
                new byte[cipher.getOutputSize(in.length)]
        );
    }

    /**
     * Process, using specified cipher, all bytes from specified input stream, and writes processed bytes and
     * finalization result to specified output stream.
     *
     * @param cipher the cipher.
     * @param source the input stream from which bytes to process are read.
     * @param target the output stream to which processed bytes are written.
     * @param <T>    cipher type parameter
     * @throws IOException if an I/O error occurs.
     * @see BufferedBlockCipher#processBytes(byte[], int, int, byte[], int)
     * @see BufferedBlockCipher#doFinal(byte[], int)
     */
    public static <T extends BufferedBlockCipher> T processAllBytesAndDoFinal(final T cipher, final InputStream source,
                                                                              final OutputStream target)
            throws IOException, InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        return processAllBytesAndDoFinal(
                cipher,
                source,
                target,
                new byte[cipher.getBlockSize()]
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    private static int processBytes(final BufferedBlockCipher cipher, final ByteBuffer input,
                                    final ByteBuffer output) {
        final var updateSize = cipher.getUpdateOutputSize(Objects.requireNonNull(input, "input is null").remaining());
        if (Objects.requireNonNull(output, "output is null").remaining() < updateSize) {
            throw new IllegalArgumentException(
                    "output.remaining(" + output.remaining() + ") shouldn't be less than the updateSize("
                            + updateSize + ") derived from input.remaining(" + input.remaining() + ")"
            );
        }
        // -------------------------------------------------------------------------------------------------------------
        final byte[] in;
        final int inoff;
        final int inlen;
        if (input.hasArray()) {
            in = input.array();
            inoff = input.arrayOffset();
            inlen = input.remaining();
        } else {
            in = new byte[input.remaining()];
            var i = input.position();
            for (int j = 0; j < in.length; j++) {
                in[j] = input.get(i++);
            }
            inoff = 0;
            inlen = in.length;
        }
        // -------------------------------------------------------------------------------------------------------------
        final byte[] out;
        final int outoff;
        if (output.hasArray()) {
            out = output.array();
            outoff = output.arrayOffset();
        } else {
            out = new byte[updateSize];
            var i = output.position();
            for (int j = 0; j < in.length; j++) {
                in[j] = output.get(i++);
            }
            outoff = 0;
        }
        // -------------------------------------------------------------------------------------------------------------
        final var processed = processBytes(cipher, in, inoff, inlen, out, outoff);
        input.position(input.position() + inlen);
        assert !input.hasRemaining();
        output.position(output.position() + processed);
        return processed;
    }

    private static int doFinal(final BufferedBlockCipher cipher, final ByteBuffer output)
            throws InvalidCipherTextException {
        final byte[] out;
        final int outoff;
        if (output.hasArray()) {
            out = output.array();
            outoff = output.arrayOffset() + output.position();
        } else {
            out = new byte[output.remaining()];
            output.get(output.position(), out, 0, out.length);
            outoff = 0;
        }
        final var finalized = cipher.doFinal(out, outoff);
        output.position(output.position() + finalized);
        return finalized;
    }

    /**
     * .
     *
     * @param cipher .
     * @param input  .
     * @param output .
     * @return the number of bytes stored in {@code output}.
     * @throws InvalidCipherTextException if padding is expected and not found.
     */
    public static int processBytesAndDoFinal(final BufferedBlockCipher cipher, final ByteBuffer input,
                                             final ByteBuffer output)
            throws InvalidCipherTextException {
        Objects.requireNonNull(output, "output is null");
        final var processed = processBytes(cipher, input, output);
        final var finalized = doFinal(cipher, output);
//        final int outoff;
//        if (output.hasArray()) {
//            out = output.array();
//            outoff = output.arrayOffset() + output.position();
//        } else {
//            out = new byte[output.remaining()];
//            var i = output.position();
//            for (int j = 0; j < out.length; j++) {
//                out[j] = output.get(i++);
//            }
//            outoff = 0;
//        }
//        final var finalized = cipher.doFinal(out, outoff);
//        output.put(out, outoff, finalized);
        return processed + finalized;
    }

    public static long processAllBytesAndDoFinal(final BufferedBlockCipher cipher,
                                                 final ReadableByteChannel source,
                                                 final WritableByteChannel target,
                                                 final ByteBuffer input, final ByteBuffer output)
            throws IOException, InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(source, "source is null");
        Objects.requireNonNull(target, "target is null");
        if (Objects.requireNonNull(input, "input is null").capacity() == 0) {
            throw new IllegalArgumentException("input.capacity is zero");
        }
        final var outputSize = cipher.getOutputSize(input.capacity());
        if (Objects.requireNonNull(output, "output is null").capacity() < outputSize) {
            throw new IllegalArgumentException(
                    "output.capacity(" + output.capacity() + ") shouldn't be less than the outputSize("
                            + outputSize + ") derived from input.capacity(" + input.capacity() + ")"
            );
        }
        long written = 0L;
        input.clear();
        output.clear();
        while (source.read(input) != -1) {
            final var processed = processBytes(cipher, input.flip(), output);
            input.clear();
            for (output.flip(); output.hasRemaining(); ) {
                target.write(output);
            }
            output.clear();
            written += processed;
        }
        final var finalized = doFinal(cipher, output);
        for (output.flip(); output.hasRemaining(); ) {
            target.write(output);
        }
        output.clear();
        written += finalized;
        return written;
    }

    /**
     * Process and finalizes, using specified cipher, from specified input channel, and write all processed bytes to
     * specified output channel.
     *
     * @param cipher the cipher.
     * @param source the input channel from which bytes are read.
     * @param target the output channel to which processed bytes are written.
     * @param input  a buffer for reading bytes from the {@code source}.
     * @return the number of processed bytes written the {@code target}.
     * @throws IOException                if an I/O error occurs.
     * @throws InvalidCipherTextException if padding is expected and not found.
     */
    public static long processAllBytesAndDoFinal(final BufferedBlockCipher cipher,
                                                 final ReadableByteChannel source,
                                                 final WritableByteChannel target,
                                                 final ByteBuffer input)
            throws IOException, InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        return processAllBytesAndDoFinal(
                cipher,
                source,
                target,
                input,
                ByteBuffer.allocate(cipher.getOutputSize(input.capacity()))
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaBufferedBlockCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
