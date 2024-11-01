package io.github.jinahya.util.bouncycastle.crypto;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.StreamCipher;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

/**
 * A utility class for {@link StreamCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 * @see <a
 * href="https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/index.html?org/bouncycastle/crypto/StreamCipher.html">org.bouncycastle.crypto.StreamCipher</a>
 * (bcprov-jdk18on-javadoc)
 */
public final class JinahyaStreamCipherUtils {

    private static int processBytes(final StreamCipher cipher, final byte[] in, final int inoff, final int inlen,
                                    byte[] out, final int outoff) {
        return cipher.processBytes(in, inoff, inlen, out, outoff);
    }

    private static byte[] processBytes(final StreamCipher cipher, final byte[] in, byte[] out) {
        assert cipher != null : "cipher shouldn't be null";
        assert in != null : "in shouldn't be null";
        assert out != null : "out shouldn't be null";
        assert out.length > 0 : "out.length shouldn't be zero";
        while (true) {
            try {
                final var processed = processBytes(cipher, in, 0, in.length, out, 0);
                return Arrays.copyOf(out, processed);
            } catch (final DataLengthException dle) {
                System.err.println("doubling up out.length from " + out.length);
//                out = Arrays.copyOf(out, out.length << 1);
                out = new byte[out.length << 1];
            }
        }
    }

    /**
     * Processes, using specified cipher, specified input bytes.
     *
     * @param cipher the cipher.
     * @param input  the input bytes to process.
     * @return an array of processed bytes.
     */
    public static byte[] processBytes(final StreamCipher cipher, final byte[] input) {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(input, "input is null");
        return processBytes(
                cipher,
                input,
                new byte[input.length == 0 ? 1 : input.length]
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static <T extends StreamCipher> T processAllBytes(final T cipher, final InputStream input,
                                                             final OutputStream output, final byte[] inbuf,
                                                             byte[] outbuf)
            throws IOException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(input, "input is null");
        Objects.requireNonNull(output, "output is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length shouldn't be zero");
        }
        if (Objects.requireNonNull(outbuf, "outbuf is null").length == 0) {
            throw new IllegalArgumentException("outbuf.length shouldn't be zero");
        }
        for (int r; (r = input.read(inbuf)) != -1; ) {
            while (true) {
                try {
                    final var processed = processBytes(cipher, inbuf, 0, r, outbuf, 0);
                    output.write(outbuf, 0, processed);
                    break;
                } catch (final DataLengthException dle) {
                    System.err.println("doubling up outbuf.length from " + outbuf.length);
//                    Arrays.fill(outbuf, (byte) 0);
//                    outbuf = Arrays.copyOf(outbuf, outbuf.length << 1);
                    outbuf = new byte[outbuf.length << 1];
                }
            }
        }
        Arrays.fill(inbuf, (byte) 0);
        Arrays.fill(outbuf, (byte) 0);
        return cipher;
    }

    /**
     * Process, using specified cipher, all bytes from specified input stream, and writes processed bytes to specified
     * output stream.
     *
     * @param cipher the cipher.
     * @param input  the input stream from which bytes to process are read.
     * @param output the output stream to which processed bytes are written.
     * @param inbuf  aa array of bytes for reading bytes from {@code input} whose {@code length} should be positive.
     * @param <T>    cipher type parameter
     * @return given {@code cipher}.
     * @throws IOException if an I/O error occurs.
     * @see #processAllBytes(StreamCipher, InputStream, OutputStream, byte[], byte[])
     */
    public static <T extends StreamCipher> T processAllBytes(final T cipher, final InputStream input,
                                                             final OutputStream output, final byte[] inbuf)
            throws IOException {
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length shouldn't be zero");
        }
        return processAllBytes(
                cipher,
                input,
                output,
                inbuf,
                new byte[inbuf.length]
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    private static int processBytes(final StreamCipher cipher, final ByteBuffer input, final ByteBuffer output) {
        // -------------------------------------------------------------------------------------------------------------
        final byte[] in;
        final int inoff;
        final int inlen;
        if (input.hasArray()) {
            in = input.array();
            inoff = input.arrayOffset() + input.position();
            inlen = input.remaining();
        } else {
            in = new byte[input.remaining()];
            input.get(input.position(), in, 0, in.length);
            inoff = 0;
            inlen = in.length;
        }
        // -------------------------------------------------------------------------------------------------------------
        final byte[] out;
        final int outoff;
        if (output.hasArray()) {
            out = output.array();
            outoff = output.arrayOffset() + output.position();
        } else {
            out = new byte[in.length];
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

//    private static int doFinal(final BufferedBlockCipher cipher, final ByteBuffer output)
//            throws InvalidCipherTextException {
//        final byte[] out;
//        final int outoff;
//        if (output.hasArray()) {
//            out = output.array();
//            outoff = output.arrayOffset() + output.position();
//        } else {
//            out = new byte[output.remaining()];
//            output.get(output.position(), out, 0, out.length);
//            outoff = 0;
//        }
//        final var finalized = cipher.doFinal(out, outoff);
//        output.position(output.position() + finalized);
//        return finalized;
//    }
//
//    /**
//     * .
//     *
//     * @param cipher .
//     * @param input  .
//     * @param output .
//     * @return the number of bytes written to the {@code output}.
//     * @throws InvalidCipherTextException if padding is expected and not found.
//     */
//    public static int processBytesAndDoFinal(final BufferedBlockCipher cipher, final ByteBuffer input,
//                                             final ByteBuffer output)
//            throws InvalidCipherTextException {
//        Objects.requireNonNull(output, "output is null");
//        final var processed = processBytes(cipher, input, output);
//        final var finalized = doFinal(cipher, output);
//        return processed + finalized;
//    }
//
//    // -----------------------------------------------------------------------------------------------------------------
//    public static long processAllBytesAndDoFinal(final BufferedBlockCipher cipher,
//                                                 final ReadableByteChannel source,
//                                                 final WritableByteChannel target,
//                                                 final ByteBuffer input, final ByteBuffer output)
//            throws IOException, InvalidCipherTextException {
//        Objects.requireNonNull(cipher, "cipher is null");
//        Objects.requireNonNull(source, "source is null");
//        Objects.requireNonNull(target, "target is null");
//        if (Objects.requireNonNull(input, "input is null").capacity() == 0) {
//            throw new IllegalArgumentException("input.capacity is zero");
//        }
//        final var outputSize = cipher.getOutputSize(input.capacity());
//        if (Objects.requireNonNull(output, "output is null").capacity() < outputSize) {
//            throw new IllegalArgumentException(
//                    "output.capacity(" + output.capacity() + ") shouldn't be less than the outputSize("
//                            + outputSize + ") derived from input.capacity(" + input.capacity() + ")"
//            );
//        }
//        long written = 0L;
//        input.clear();
//        output.clear();
//        while (source.read(input) != -1) {
//            final var processed = processBytes(cipher, input.flip(), output);
//            assert processed >= 0;
//            input.clear();
//            output.flip();
//            for (final var l = outputSize - (output.capacity() - output.limit()); output.position() < l; ) {
//                written += target.write(output);
//            }
//            output.compact();
//        }
//        output.flip();
//        for (final var l = outputSize - (output.capacity() - output.limit()); output.position() < l; ) {
//            written += target.write(output);
//        }
//        output.compact();
//        // finalize
//        final var finalized = doFinal(cipher, output);
//        assert finalized >= 0;
//        for (output.flip(); output.hasRemaining(); ) {
//            written += target.write(output);
//        }
//        output.clear();
//        return written;
//    }
//
//    /**
//     * Process and finalizes, using specified cipher, from specified input channel, and write all processed bytes to
//     * specified output channel.
//     *
//     * @param cipher the cipher.
//     * @param source the input channel from which bytes are read.
//     * @param target the output channel to which processed bytes are written.
//     * @param input  a buffer for reading bytes from the {@code source}.
//     * @return the number of processed bytes written the {@code target}.
//     * @throws IOException                if an I/O error occurs.
//     * @throws InvalidCipherTextException if padding is expected and not found.
//     */
//    public static long processAllBytesAndDoFinal(final BufferedBlockCipher cipher,
//                                                 final ReadableByteChannel source,
//                                                 final WritableByteChannel target,
//                                                 final ByteBuffer input)
//            throws IOException, InvalidCipherTextException {
//        Objects.requireNonNull(cipher, "cipher is null");
//        return processAllBytesAndDoFinal(
//                cipher,
//                source,
//                target,
//                input,
//                ByteBuffer.allocate(cipher.getOutputSize(input.capacity()))
//        );
//    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaStreamCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
