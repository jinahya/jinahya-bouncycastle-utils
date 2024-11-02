package io.github.jinahya.util.bouncycastle.crypto;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.util.Arrays;

import java.io.File;
import java.io.FileOutputStream;
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

    // -----------------------------------------------------------------------------------------------------------------
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
        return java.util.Arrays.copyOf(output, processed + finalized);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private static byte[] processAllBytes(final BufferedBlockCipher cipher, final InputStream input,
                                          final OutputStream output, final byte[] inbuf, byte[] outbuf)
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
            final var outputSize = cipher.getOutputSize(r); // don't use <cipher.getUpdateOutputSize(r)>; finalization!
            if (outbuf.length < outputSize) {
                outbuf = new byte[outputSize];
            }
            final var processed = cipher.processBytes(inbuf, 0, r, outbuf, 0);
            output.write(outbuf, 0, processed);
        }
        return outbuf;
    }

    private static <T extends BufferedBlockCipher> T processAllBytesAndDoFinal(final T cipher, final InputStream input,
                                                                               final OutputStream output,
                                                                               final byte[] inbuf, byte[] outbuf)
            throws IOException, InvalidCipherTextException {
        outbuf = processAllBytes(cipher, input, output, inbuf, outbuf);
        final var finalized = cipher.doFinal(outbuf, 0);
        output.write(outbuf, 0, finalized);
        return cipher;
    }

    public static <T extends BufferedBlockCipher> T processAllBytesAndDoFinal(final T cipher, final InputStream input,
                                                                              final OutputStream output,
                                                                              final byte[] inbuf)
            throws IOException, InvalidCipherTextException {
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length shouldn't be zero");
        }
        return processAllBytesAndDoFinal(
                cipher,
                input,
                output,
                inbuf,
                new byte[cipher.getOutputSize(inbuf.length)]
        );
    }

    /**
     * Process, using specified cipher, all bytes from specified input stream, and writes processed bytes and
     * finalization result to specified output stream.
     *
     * @param cipher the cipher.
     * @param input  the input stream from which bytes to process are read.
     * @param output the output stream to which processed bytes are written.
     * @param <T>    cipher type parameter
     * @throws IOException if an I/O error occurs.
     * @see BufferedBlockCipher#processBytes(byte[], int, int, byte[], int)
     * @see BufferedBlockCipher#doFinal(byte[], int)
     */
    public static <T extends BufferedBlockCipher> T processAllBytesAndDoFinal(final T cipher, final InputStream input,
                                                                              final OutputStream output)
            throws IOException, InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(input, "input is null");
        Objects.requireNonNull(output, "output is null");
        return processAllBytesAndDoFinal(
                cipher,
                input,
                output,
                new byte[cipher.getBlockSize()]
        );
    }

    public static long encrypt(final BufferedBlockCipher cipher, final InputStream input,
                               final File target, final byte[] buffer)
            throws IOException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(input, "input is null");
        Objects.requireNonNull(target, "target is null");
        if (Objects.requireNonNull(buffer, "buffer is null").length == 0) {
            throw new IllegalArgumentException("buffer.length is zero");
        }
        var count = 0L;
        try (var output = new FileOutputStream(target);
             var cos = new CipherOutputStream(output, cipher)) {
            for (int r; (r = input.read(buffer)) != -1; count += r) {
                cos.write(buffer, 0, r);
            }
            cos.flush();
        }
        return count;
    }

    public static long decrypt(final BufferedBlockCipher cipher, final InputStream input,
                               final OutputStream output, final byte[] buffer)
            throws IOException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(input, "input is null");
        Objects.requireNonNull(output, "output is null");
        if (Objects.requireNonNull(buffer, "buffer is null").length == 0) {
            throw new IllegalArgumentException("buffer.length is zero");
        }
        var count = 0L;
        final var cis = new CipherInputStream(input, cipher);
        for (int r; (r = cis.read(buffer)) != -1; count += r) {
            output.write(buffer, 0, r);
        }
        output.flush();
        return count;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private static int processBytes(final BufferedBlockCipher cipher, final ByteBuffer input,
                                    final ByteBuffer output) {
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
            input.get(input.position(), in);
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

    private static int doFinal(final BufferedBlockCipher cipher, final ByteBuffer output)
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

    /**
     * .
     *
     * @param cipher .
     * @param input  .
     * @param output .
     * @return the number of bytes written to the {@code output}.
     * @throws InvalidCipherTextException if padding is expected and not found.
     */
    public static int processBytesAndDoFinal(final BufferedBlockCipher cipher, final ByteBuffer input,
                                             final ByteBuffer output)
            throws InvalidCipherTextException {
        Objects.requireNonNull(output, "output is null");
        final var processed = processBytes(cipher, input, output);
        final var finalized = doFinal(cipher, output);
        return processed + finalized;
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static long processAllBytesAndDoFinal(final BufferedBlockCipher cipher, final ReadableByteChannel input,
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
        inbuf.clear();
        outbuf.clear();
        while (input.read(inbuf) != -1) {
            final var processed = processBytes(cipher, inbuf.flip(), outbuf);
            assert processed >= 0;
            inbuf.clear();
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
    public static long processAllBytesAndDoFinal(final BufferedBlockCipher cipher, final ReadableByteChannel input,
                                                 final WritableByteChannel output, final ByteBuffer inbuf)
            throws IOException, InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        return processAllBytesAndDoFinal(
                cipher,
                input,
                output,
                inbuf,
                ByteBuffer.allocate(cipher.getOutputSize(inbuf.capacity()))
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaBufferedBlockCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
