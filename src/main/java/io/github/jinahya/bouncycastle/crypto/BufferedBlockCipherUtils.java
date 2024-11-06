package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.IntFunction;

/**
 * A utility class for {@link BufferedBlockCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
public final class BufferedBlockCipherUtils {

    private static <T extends BufferedBlockCipher> T initFor(final T cipher, final boolean encryption,
                                                             final CipherParameters params) {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(params, "params is null");
        cipher.init(encryption, params);
        return cipher;
    }

    /**
     * Initializes specified cipher with specified cipher parameters, for encryption, and returns the cipher.
     *
     * @param cipher the cipher to be initialized for encryption.
     * @param params the cipher parameters.
     * @param <T>    cipher type parameter
     * @return given {@code cipher}.
     * @see BufferedBlockCipher#init(boolean, CipherParameters)
     */
    public static <T extends BufferedBlockCipher> T initForEncryption(final T cipher, final CipherParameters params) {
        return initFor(cipher, true, params);
    }

    /**
     * Initializes specified cipher with specified cipher parameters, for decryption, and returns the cipher.
     *
     * @param cipher the cipher to be initialized for decryption.
     * @param params the cipher parameters.
     * @param <T>    cipher type parameter
     * @return given {@code cipher}.
     * @see BufferedBlockCipher#init(boolean, CipherParameters)
     */
    public static <T extends BufferedBlockCipher> T initForDecryption(final T cipher, final CipherParameters params) {
        return initFor(cipher, false, params);
    }

    // -----------------------------------------------------------------------------------------------------------------

    public static int processBytesAndDoFinal(final BufferedBlockCipher cipher, final byte[] input, final int inoff,
                                             final int inlen, final byte[] output, final int outoff)
            throws InvalidCipherTextException {
        final var processed = cipher.processBytes(input, inoff, inlen, output, outoff);
        final var finalized = cipher.doFinal(output, processed);
        return processed + finalized;
    }

//    /**
//     * Processes and finalizes, using specified cipher, specified input bytes, and set those processed bytes to
//     * specified output array.
//     *
//     * @param cipher the cipher.
//     * @param input  the input bytes to process and finalize.
//     * @param output the array to which processed bytes are set.
//     * @return the number of bytes set on the {@code output}.
//     * @throws DataLengthException        when the {@code output} is too short.
//     * @throws InvalidCipherTextException if padding is expected and not found.
//     * @see BufferedBlockCipher#getOutputSize(int)
//     * @see BufferedBlockCipher#processBytes(byte[], int, int, byte[], int)
//     * @see BufferedBlockCipher#doFinal(byte[], int)
//     */
//    public static int processBytesAndDoFinal(final BufferedBlockCipher cipher, final byte[] input,
//                                             final byte[] output)
//            throws InvalidCipherTextException {
//        final var processed = cipher.processBytes(input, 0, input.length, output, 0);
//        final var finalized = cipher.doFinal(output, processed);
//        return processed + finalized;
//    }

//    public static byte[] processBytesAndDoFinal(final BufferedBlockCipher cipher, final byte[] input, final int inoff,
//                                                final int inlen)
//            throws InvalidCipherTextException {
//        final var output = new byte[cipher.getOutputSize(input.length)];
//        final var outlen = processBytesAndDoFinal(cipher, input, inoff, inlen, output, 0);
//        return Arrays.copyOf(output, outlen);
//    }

//    public static byte[] encrypt(final BufferedBlockCipher cipher, final CipherParameters params, final byte[] input,
//                                 final int inoff, final int inlen)
//            throws InvalidCipherTextException {
//        Objects.requireNonNull(cipher, "cipher is null");
//        Objects.requireNonNull(params, "params is null");
//        return processBytesAndDoFinal(
//                initForEncryption(cipher, params),
//                input,
//                inoff,
//                inlen
//        );
//    }

//    public static byte[] decrypt(final BufferedBlockCipher cipher, final CipherParameters params, final byte[] input,
//                                 final int inoff, final int inlen)
//            throws InvalidCipherTextException {
//        Objects.requireNonNull(cipher, "cipher is null");
//        Objects.requireNonNull(params, "params is null");
//        return processBytesAndDoFinal(
//                initForDecryption(cipher, params),
//                input,
//                inoff,
//                inlen
//        );
//    }

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
//        if (Objects.requireNonNull(outbuf, "outbuf is null").length == 0) {
//            throw new IllegalArgumentException("outbuf.length is zero");
//        }
        var written = 0L;
        int outlen;
        for (int uos, r; (r = in.read(inbuf)) != -1; ) {
            if (outbuf.length < (uos = cipher.getUpdateOutputSize(r))) {
                System.err.println(
                        "re-allocating outbuf(" + outbuf.length + ") for an intermediate updateOutputSize(" + uos + ")"
                );
                Arrays.fill(outbuf, (byte) 0);
                outbuf = new byte[uos];
            }
            outlen = cipher.processBytes(inbuf, 0, r, outbuf, 0);
            out.write(outbuf, 0, outlen);
            written += outlen;
        }
        for (final var os = cipher.getOutputSize(0); outbuf.length < os; ) {
            System.err.println("re-allocating outbuf(" + outbuf.length + ") for the final outputSize(" + os + ")");
            Arrays.fill(outbuf, (byte) 0);
            outbuf = new byte[os];
        }
        outlen = cipher.doFinal(outbuf, 0);
        out.write(outbuf, 0, outlen);
        written += outlen;
        return written;
    }

//    public static long encrypt(final BufferedBlockCipher cipher, final CipherParameters params, final InputStream in,
//                               final OutputStream out, final byte[] inbuf, byte[] outbuf)
//            throws IOException, InvalidCipherTextException {
//        return processAllBytesAndDoFinal(
//                initForDecryption(cipher, params),
//                in,
//                out,
//                inbuf,
//                outbuf
//        );
//    }

//    public static long decrypt(final BufferedBlockCipher cipher, final CipherParameters params, final InputStream in,
//                               final OutputStream out, final byte[] inbuf, byte[] outbuf)
//            throws IOException, InvalidCipherTextException {
//        return processAllBytesAndDoFinal(
//                initForDecryption(cipher, params),
//                in,
//                out,
//                inbuf,
//                outbuf
//        );
//    }

//    public static long processAllBytesAndDoFinal(final BufferedBlockCipher cipher, final InputStream in,
//                                                 final OutputStream out, final byte[] inbuf)
//            throws IOException, InvalidCipherTextException {
//        Objects.requireNonNull(cipher, "cipher is null");
//        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
//            throw new IllegalArgumentException("inbuf.length shouldn't be zero");
//        }
//        return processAllBytesAndDoFinal(
//                cipher,
//                in,
//                out,
//                inbuf,
//                new byte[cipher.getOutputSize(inbuf.length)]
//        );
//    }

//    public static long encrypt(final BufferedBlockCipher cipher, final CipherParameters params,
//                               final InputStream in, final OutputStream out, final byte[] inbuf)
//            throws IOException, InvalidCipherTextException {
//        return processAllBytesAndDoFinal(
//                initForEncryption(cipher, params),
//                in,
//                out,
//                inbuf
//        );
//    }
//
//    public static long decrypt(final BufferedBlockCipher cipher, final CipherParameters params,
//                               final InputStream in, final OutputStream out, final byte[] inbuf)
//            throws IOException, InvalidCipherTextException {
//        return processAllBytesAndDoFinal(
//                initForDecryption(cipher, params),
//                in,
//                out,
//                inbuf
//        );
//    }

    // -----------------------------------------------------------------------------------------------------------------
    public static <T extends ByteBuffer> T processBytesAndDoFinal(final BufferedBlockCipher cipher,
                                                                  final ByteBuffer input, final T output)
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
        return output;
    }

    /**
     * Processes and finalizes, using specified cipher, all remaining bytes of specified input buffer, returns a byte
     * buffer of processed bytes.
     *
     * @param cipher   the cipher.
     * @param input    the input buffer whose remaining bytes are processed.
     * @param function a function for allocating an output buffer of specific capacity.
     * @param <T>      byte buffer type parameter
     * @return a byte buffer of processed bytes.
     * @throws InvalidCipherTextException if padding is expected and not found.
     * @see #processBytesAndDoFinal(BufferedBlockCipher, ByteBuffer, ByteBuffer)
     * @see #encrypt(BufferedBlockCipher, CipherParameters, ByteBuffer, IntFunction)
     * @see #decrypt(BufferedBlockCipher, CipherParameters, ByteBuffer, IntFunction)
     */
    public static <T extends ByteBuffer> T processBytesAndDoFinal(final BufferedBlockCipher cipher,
                                                                  final ByteBuffer input,
                                                                  final IntFunction<? extends T> function)
            throws InvalidCipherTextException {
        Objects.requireNonNull(input, "input is null");
        Objects.requireNonNull(function, "function is null");
        final var capacity = cipher.getOutputSize(input.remaining());
        final var output = function.apply(capacity);
        return processBytesAndDoFinal(
                cipher,
                input,
                output
        );
    }

    /**
     * Initializes specified cipher for encryption, encrypts all remaining bytes of specified input buffer, returns a
     * bytes buffer of encrypted bytes.
     *
     * @param cipher   the cipher to be initialized for encryption.
     * @param params   a cipher parameter for the initialization.
     * @param input    the byte buffer whose remaining bytes are encrypted.
     * @param function a function for allocating an output buffer of specific capacity.
     * @param <T>      byte buffer type parameter
     * @return a byte buffer of encrypted bytes.
     * @throws InvalidCipherTextException if padding is expected and not found.
     * @see #processBytesAndDoFinal(BufferedBlockCipher, ByteBuffer, IntFunction)
     * @see #decrypt(BufferedBlockCipher, CipherParameters, ByteBuffer, IntFunction)
     */
    public static <T extends ByteBuffer> T encrypt(final BufferedBlockCipher cipher, final CipherParameters params,
                                                   final ByteBuffer input, final IntFunction<? extends T> function)
            throws InvalidCipherTextException {
        return processBytesAndDoFinal(
                initForEncryption(cipher, params),
                input,
                function
        );
    }

    /**
     * Initializes specified cipher for decryption, decrypts all remaining bytes of specified input buffer, returns a
     * bytes buffer of decrypted bytes.
     *
     * @param cipher   the cipher to be initialized for decryption.
     * @param params   a cipher parameter for the initialization.
     * @param input    the byte buffer whose remaining bytes are decrypted.
     * @param function a function for allocating an output buffer of specific capacity.
     * @param <T>      byte buffer type parameter
     * @return a byte buffer of decrypted bytes.
     * @throws InvalidCipherTextException if padding is expected and not found.
     * @see #processBytesAndDoFinal(BufferedBlockCipher, ByteBuffer, IntFunction)
     * @see #encrypt(BufferedBlockCipher, CipherParameters, ByteBuffer, IntFunction)
     */
    public static <T extends ByteBuffer> T decrypt(final BufferedBlockCipher cipher, final CipherParameters params,
                                                   final ByteBuffer input, final IntFunction<? extends T> function)
            throws InvalidCipherTextException {
        return processBytesAndDoFinal(
                initForDecryption(cipher, params),
                input,
                function
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    private BufferedBlockCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
