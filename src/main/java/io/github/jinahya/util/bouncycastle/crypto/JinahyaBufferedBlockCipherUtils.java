package io.github.jinahya.util.bouncycastle.crypto;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Objects;

/**
 * A utility class for {@link BufferedBlockCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
public final class JinahyaBufferedBlockCipherUtils {

    // -----------------------------------------------------------------------------------------------------------------
//    private static int processBytes(final BufferedBlockCipher cipher, final byte[] in, final int inoff,
//                                    final int inlen, final byte[] out, final int outoff) {
//        assert cipher != null;
//        assert in != null;
//        assert inoff >= 0;
//        assert inlen <= in.length - inoff;
//        assert out != null;
//        assert outoff >= 0;
//        assert out.length - outoff >= cipher.getUpdateOutputSize(inlen);
//        return cipher.processBytes(in, inoff, inlen, out, 0);
//    }

//    private static byte[] processBytesAndDoFinal(final BufferedBlockCipher cipher, final byte[] in, final int off,
//                                                 final int len)
//            throws InvalidCipherTextException {
//        final var out = new byte[cipher.getOutputSize(in.length)];
//        final var processed = processBytes(cipher, in, off, len, out, 0);
//        final var finalized = cipher.doFinal(out, processed);
//        return Arrays.copyOf(out, (processed + finalized));
//    }

    /**
     * Processes and finalizes, using specified cipher, specified input bytes, and returns the result.
     *
     * @param cipher the cipher.
     * @param input  the input bytes to process and finalize.
     * @return an array of result bytes
     * @throws InvalidCipherTextException if padding is expected and not found.
     * @see BufferedBlockCipher#processBytes(byte[], int, int, byte[], int)
     * @see BufferedBlockCipher#doFinal(byte[], int)
     */
    public static byte[] processBytesAndDoFinal(final BufferedBlockCipher cipher, final byte[] input)
            throws InvalidCipherTextException {
        final var output = new byte[cipher.getOutputSize(input.length)];
        final var processed = cipher.processBytes(input, 0, input.length, output, 0);
        final var finalized = cipher.doFinal(output, processed);
        return Arrays.copyOf(output, processed + finalized);
    }

    // -----------------------------------------------------------------------------------------------------------------
//    private static byte[] processAllBytes(final BufferedBlockCipher cipher, final InputStream input,
//                                          final OutputStream output, final byte[] inbuf, byte[] outbuf)
//            throws IOException {
//        for (int r; (r = input.read(inbuf)) != -1; ) {
//            final var outputSize = cipher.getOutputSize(r); // don't use <cipher.getUpdateOutputSize(r)>; finalization!
//            if (outbuf.length < outputSize) {
//                System.err.println("recreating outbuf for the outputSize(" + outputSize + ")");
//                outbuf = new byte[outputSize];
//            }
//            final var processed = cipher.processBytes(inbuf, 0, r, outbuf, 0);
//            output.write(outbuf, 0, processed);
//        }
//        return outbuf;
//    }

//    private static <T extends BufferedBlockCipher> T processAllBytesAndDoFinal(final T cipher, final InputStream input,
//                                                                               final OutputStream output,
//                                                                               final byte[] inbuf, byte[] outbuf)
//            throws IOException, InvalidCipherTextException {
//        outbuf = processAllBytes(cipher, input, output, inbuf, outbuf);
//        final var finalized = cipher.doFinal(outbuf, 0);
//        output.write(outbuf, 0, finalized);
//        return cipher;
//    }

    public static long processAllBytesAndDoFinal(final BufferedBlockCipher cipher, final InputStream input,
                                                 final OutputStream output, final byte[] inbuf)
            throws IOException, InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(inbuf, "inbuf is null");
        Objects.requireNonNull(output, "output is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length shouldn't be zero");
        }
        var written = 0L;
        var outbuf = new byte[cipher.getOutputSize(inbuf.length)];
        for (int r; (r = input.read(inbuf)) != -1; ) {
//            while (true) {
//                try {
//                    final var processed = cipher.processBytes(inbuf, 0, r, outbuf, 0);
//                    output.write(outbuf, 0, processed);
//                    written += processed;
//                    break;
//                } catch (final DataLengthException dle) {
//                    Arrays.fill(outbuf, (byte) 0);
//                    outbuf = new byte[outbuf.length << 1];
//                }
//            }
            final var updateOutputSize = cipher.getUpdateOutputSize(r);
            if (outbuf.length < updateOutputSize) {
                System.err.println("recreating outbuf for the updateOutputSize(" + updateOutputSize + ")");
                Arrays.fill(outbuf, (byte) 0);
                outbuf = new byte[updateOutputSize];
            }
            final var processed = cipher.processBytes(inbuf, 0, r, outbuf, 0);
            output.write(outbuf, 0, processed);
            written += processed;
        }
        while (true) {
            try {
                final var finalized = cipher.doFinal(outbuf, 0);
                output.write(outbuf, 0, finalized);
                written += finalized;
                break;
            } catch (final DataLengthException dle) {
                System.out.println("doubling up outbuf.length from " + outbuf.length);
                Arrays.fill(outbuf, (byte) 0);
                outbuf = new byte[outbuf.length << 1];
            }
        }
        Arrays.fill(inbuf, (byte) 0);
        Arrays.fill(outbuf, (byte) 0);
        return written;
    }

//    /**
//     * Process, using specified cipher, all bytes from specified input stream, and writes processed bytes and
//     * finalization result to specified output stream.
//     *
//     * @param cipher the cipher.
//     * @param input  the input stream from which bytes to process are read.
//     * @param output the output stream to which processed bytes are written.
//     * @return the number of bytes written to {@code output}.
//     * @throws IOException if an I/O error occurs.
//     * @see #processAllBytesAndDoFinal(BufferedBlockCipher, InputStream, OutputStream, byte[])
//     */
//    public static long processAllBytesAndDoFinal(final BufferedBlockCipher cipher, final InputStream input,
//                                                 final OutputStream output)
//            throws IOException, InvalidCipherTextException {
//        Objects.requireNonNull(cipher, "cipher is null");
//        final var inbuf = new byte[cipher.getBlockSize()];
//        return processAllBytesAndDoFinal(cipher, input, output, inbuf);
//    }

//    // -----------------------------------------------------------------------------------------------------------------
//    private static int processBytes(final BufferedBlockCipher cipher, final ByteBuffer input,
//                                    final ByteBuffer output) {
//        Objects.requireNonNull(cipher, "cipher is null");
//        Objects.requireNonNull(input, "input is null");
//        Objects.requireNonNull(output, "output is null");
//        final byte[] inbuf;
//        final int inoff;
//        final int inlen = input.remaining();
//        if (input.hasArray()) {
//            inbuf = input.array();
//            inoff = input.arrayOffset() + input.position();
//        } else {
//            inbuf = new byte[input.remaining()];
//            input.get(input.position(), inbuf);
//            inoff = 0;
//        }
//        final byte[] outbuf;
//        final int outoff;
//        if (output.hasArray()) {
//            outbuf = output.array();
//            outoff = output.arrayOffset() + output.position();
//        } else {
//            outbuf = new byte[output.remaining()];
//            outoff = 0;
//        }
//        var outlen = cipher.processBytes(inbuf, inoff, inlen, outbuf, outoff);
//        input.position(input.position() + inlen);
//        if (output.hasArray()) {
//            output.position(output.position() + (outoff + outlen));
//        } else {
//            output.put(outbuf, outoff, outlen);
//        }
//        return outlen;
//    }
//
//    private static int doFinal(final BufferedBlockCipher cipher, final ByteBuffer output)
//            throws InvalidCipherTextException {
//        Objects.requireNonNull(cipher, "cipher is null");
//        Objects.requireNonNull(output, "output is null");
//        final byte[] outbuf;
//        final int outoff;
//        if (output.hasArray()) {
//            outbuf = output.array();
//            outoff = output.arrayOffset() + output.position();
//        } else {
//            outbuf = new byte[output.remaining()];
//            outoff = 0;
//        }
//        final var outlen = cipher.doFinal(outbuf, outoff);
//        if (output.hasArray()) {
//            output.position(output.position() + outlen);
//        } else {
//            output.put(outbuf, outoff, outlen);
//        }
//        return outlen;
//    }
//
//    // -----------------------------------------------------------------------------------------------------------------
//    public static int processBytesAndDoFinal(final BufferedBlockCipher cipher, final ByteBuffer input,
//                                             final ByteBuffer output)
//            throws InvalidCipherTextException {
//        Objects.requireNonNull(cipher, "cipher is null");
//        Objects.requireNonNull(input, "input is null");
//        Objects.requireNonNull(output, "output is null");
//        final var processed = processBytes(cipher, input, output);
//        final var finalized = doFinal(cipher, output);
//        return processed + finalized;
//    }
//
//    public static ByteBuffer processBytesAndDoFinal(final BufferedBlockCipher cipher, final ByteBuffer input)
//            throws InvalidCipherTextException {
//        Objects.requireNonNull(cipher, "cipher is null");
//        Objects.requireNonNull(input, "input is null");
//        final var outputSize = cipher.getOutputSize(input.remaining());
//        final var output = ByteBuffer.allocate(outputSize);
//        final var bytes = processBytesAndDoFinal(cipher, input, output);
//        return output;
//    }
//
//    // -----------------------------------------------------------------------------------------------------------------
//    private static long processAllBytes(final BufferedBlockCipher cipher, final ReadableByteChannel in,
//                                        final WritableByteChannel out, final ByteBuffer inbuf, final ByteBuffer outbuf)
//            throws IOException {
//        Objects.requireNonNull(cipher, "cipher is null");
//        Objects.requireNonNull(in, "in is null");
//        Objects.requireNonNull(out, "out is null");
//        Objects.requireNonNull(inbuf, "inbuf is null");
//        Objects.requireNonNull(outbuf, "outbuf is null");
//        long written = 0L;
//        inbuf.clear();
//        outbuf.clear();
//        while (in.read(inbuf) != -1) {
//            inbuf.flip();
//            final var processed = processBytes(cipher, inbuf, outbuf);
//            inbuf.compact();
//            for (outbuf.flip(); outbuf.hasRemaining(); ) {
//                written += out.write(outbuf);
//            }
//            outbuf.clear();
//        }
//        return written;
//    }
//
//    /**
//     * Processes and finalizes, using specified cipher, all bytes from specified input channel, and write result bytes
//     * to specified output channel.
//     *
//     * @param cipher the cipher.
//     * @param in     the input channel from which unprocessed bytes are read.
//     * @param out    the output channel to which processed bytes are written.
//     * @param inbuf  a buffer for reading bytes from the {@code in}.
//     * @param outbuf a buffer for writing bytes to the {@code out}.
//     * @return the number of bytes written to the {@code out}.
//     * @throws IOException                if an I/O occurs.
//     * @throws DataLengthException        when {@code outbuf} is too short.
//     * @throws InvalidCipherTextException if padding is expected and not found.
//     * @see #processAllBytesAndDoFinal(BufferedBlockCipher, ReadableByteChannel, WritableByteChannel, ByteBuffer,
//     * ByteBuffer)
//     */
//    public static long processAllBytesAndDoFinal(final BufferedBlockCipher cipher, final ReadableByteChannel in,
//                                                 final WritableByteChannel out, final ByteBuffer inbuf,
//                                                 final ByteBuffer outbuf)
//            throws IOException, InvalidCipherTextException {
//        Objects.requireNonNull(cipher, "cipher is null");
//        Objects.requireNonNull(inbuf, "inbuf is null");
//        Objects.requireNonNull(outbuf, "outbuf is null");
//        final var processed = processAllBytes(cipher, in, out, inbuf.clear(), outbuf.clear());
//        final var finalized = doFinal(cipher, outbuf.clear());
//        for (outbuf.flip(); outbuf.hasRemaining(); ) {
//            out.write(outbuf);
//        }
//        return processed + finalized;
//    }
//
//    /**
//     * Processes and finalizes, using specified cipher, all bytes from specified input channel, and write result bytes
//     * to specified output channel.
//     *
//     * @param cipher the cipher.
//     * @param in     the input channel from which unprocessed bytes are read.
//     * @param out    the output channel to which processed bytes are written.
//     * @param inbuf  a buffer for reading bytes from the {@code in}.
//     * @return the number of bytes written to the {@code out}.
//     * @throws IOException                if an I/O occurs.
//     * @throws InvalidCipherTextException if padding is expected and not found.
//     * @see #processAllBytesAndDoFinal(BufferedBlockCipher, ReadableByteChannel, WritableByteChannel, ByteBuffer,
//     * ByteBuffer)
//     */
//    public static long processAllBytesAndDoFinal(final BufferedBlockCipher cipher, final ReadableByteChannel in,
//                                                 final WritableByteChannel out, final ByteBuffer inbuf)
//            throws IOException, InvalidCipherTextException {
//        Objects.requireNonNull(cipher, "cipher is null");
//        if (Objects.requireNonNull(inbuf, "inbuf is null").capacity() == 0) {
//            throw new IllegalArgumentException("inbuf.capacity is zero");
//        }
//        final var outputSize = cipher.getUnderlyingCipher().getBlockSize();
//        final var outbuf = ByteBuffer.allocate(
//                // processAllBytes 후에 cipher 에 남아있는 데이터가 있을 수 있다
//                outputSize << 1
//        );
//        return processAllBytesAndDoFinal(cipher, in, out, inbuf, outbuf);
//    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaBufferedBlockCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
