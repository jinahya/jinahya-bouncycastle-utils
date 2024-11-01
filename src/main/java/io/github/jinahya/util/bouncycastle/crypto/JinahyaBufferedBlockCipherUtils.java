package io.github.jinahya.util.bouncycastle.crypto;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.util.Arrays;

import javax.crypto.ShortBufferException;
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
//        final var processed = cipher.processBytes(in, off, len, out, 0);
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

//    public static ByteBuffer processBytesAndDoFinal(final BufferedBlockCipher cipher, final ByteBuffer input)
//            throws InvalidCipherTextException, ShortBufferException {
//        Objects.requireNonNull(input, "input is null");
//        final var output = ByteBuffer.allocate(cipher.getOutputSize(input.remaining()));
//        final var bytes = processBytesAndDoFinal(
//                cipher,
//                input,
//                output
//        );
//        return output.flip();
//    }

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

    public static <T extends BufferedBlockCipher> T processAllBytesAndDoFinal(final T cipher, final InputStream source,
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
//        for (var out = processAllBytes(cipher, source, target, new byte[cipher.getBlockSize()]); ; ) {
//            try {
//                target.write(out, 0, cipher.doFinal(out, 0));
//                break;
//            } catch (final DataLengthException dle) {
//                System.err.println("doubling up out.length from " + out.length);
//                out = new byte[out.length << 1];
//            }
//        }
        return processAllBytesAndDoFinal(cipher, source, target, new byte[cipher.getBlockSize()]);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private static int processBytes(final BufferedBlockCipher cipher, final ByteBuffer input,
                                    final ByteBuffer output)
            throws ShortBufferException {
        final var updateSize = cipher.getUpdateOutputSize(Objects.requireNonNull(input, "input is null").remaining());
        if (Objects.requireNonNull(output, "output is null").remaining() < updateSize) {
            throw new ShortBufferException(
                    "output.remaining(" + output.remaining() + ") shouldn't be less than "
                            + updateSize + " derived from input.remaining(" + input.remaining() + ")"
            );
        }
        final byte[] in;
        final int inoff;
        final int inlen;
        final var inputPosition = input.position(); // TODO: remove
        {
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
        }
        assert input.position() == inputPosition; // TODO: remove
        final byte[] out;
        final int outoff;
        final var outputPosition = output.position(); // TODO: remove
        {
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
        }
        assert output.position() == outputPosition; // TODO: remove
        final var processed = processBytes(cipher, in, inoff, inlen, out, outoff);
        input.position(input.position() + inlen);
        output.position(output.position() + processed);
        return processed;
    }

    /**
     * .
     *
     * @param cipher .
     * @param input  .
     * @param output .
     * @return the number of bytes stored in {@code output}.
     * @throws InvalidCipherTextException if padding is expected and not found.
     * @throws ShortBufferException       if there is insufficient space in the output buffer
     */
    public static int processBytesAndDoFinal(final BufferedBlockCipher cipher, final ByteBuffer input,
                                             final ByteBuffer output)
            throws InvalidCipherTextException, ShortBufferException {
        Objects.requireNonNull(input, "input is null");
        Objects.requireNonNull(output, "output is null");
        final var outputSize = cipher.getOutputSize(input.remaining());
        if (output.remaining() < outputSize) {
            throw new ShortBufferException(
                    "output.remaining(" + output.remaining() + ") shouldn't be less than "
                            + outputSize + " derived from input.remaining(" + input.remaining() + ")"
            );
        }
        if (true) {
            final var processed = processBytes(cipher, input, output);
            final byte[] out;
            int outoff;
            final var p = output.position(); // TODO: remove
            {
                if (output.hasArray()) {
                    out = output.array();
                    outoff = output.arrayOffset() + output.position();
                } else {
                    out = new byte[output.remaining()];
                    var i = output.position();
                    for (int j = 0; j < out.length; j++) {
                        out[j] = output.get(i++);
                    }
                    outoff = 0;
                }
            }
            assert output.position() == p; // TODO: remove
            final var finalized = cipher.doFinal(out, outoff);
            for (int i = 0; i < finalized; i++) {
                output.put(out[outoff++]);
            }
            return processed + finalized;
        }
        Objects.requireNonNull(input, "input is null");
        Objects.requireNonNull(output, "output is null");
        final byte[] in;
        final int off;
        final int len;
        final var inputPosition = input.position(); // TODO: remove
        {
            if (input.hasArray()) {
                in = input.array();
                off = input.arrayOffset();
                len = input.remaining();
            } else {
                in = new byte[input.remaining()];
                var i = input.position();
                for (int j = 0; j < in.length; j++) {
                    in[j] = input.get(i++);
                }
                off = 0;
                len = in.length;
            }
        }
        assert input.position() == inputPosition; // TODO: remove
        final var out = processBytesAndDoFinal(cipher, in, off, len);
        if (output.remaining() < out.length) {
            throw new ShortBufferException();
        }
        final var outputPosition = output.position(); // TODO: remove
        output.put(out);
        assert output.position() == outputPosition + out.length; // TODO: remove
        input.position(input.position() + input.remaining());
        return out.length;
    }

    public static long processAllBytesAndDoFinal(final BufferedBlockCipher cipher,
                                                 final ReadableByteChannel source,
                                                 final WritableByteChannel target,
                                                 final ByteBuffer input,
                                                 final ByteBuffer output)
            throws ShortBufferException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(source, "source is null");
        Objects.requireNonNull(target, "target is null");
        if (Objects.requireNonNull(input, "input is null").capacity() == 0) {
            throw new IllegalArgumentException("input.capacity is zero");
        }
        final var outputSize = cipher.getOutputSize(input.capacity());
        if (Objects.requireNonNull(output, "output is null").capacity() < outputSize) {
            throw new ShortBufferException(
                    "output.capacity(" + output.capacity() + ") shouldn't be less than "
                            + outputSize + " derived from input.capacity(" + input.capacity() + ")"
            );
        }
        long count = 0L;

        return count;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaBufferedBlockCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
