package io.github.jinahya.util.bouncycastle.crypto;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
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

    /**
     * Initializes specified cipher, with specified cipher parameters, for encryption, and returns the cipher.
     *
     * @param cipher the cipher to be initialized for encryption.
     * @param params the cipher parameters.
     * @param <T>    cipher type parameter
     * @return given {@code cipher}.
     * @see BufferedBlockCipher#init(boolean, CipherParameters)
     */
    public static <T extends BufferedBlockCipher> T initForEncryption(final T cipher, final CipherParameters params) {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(params, "params is null");
        cipher.init(true, params);
        return cipher;
    }

    /**
     * Initializes specified cipher, with specified cipher parameters, for decryption, and returns the cipher.
     *
     * @param cipher the cipher to be initialized for decryption.
     * @param params the cipher parameters.
     * @param <T>    cipher type parameter
     * @return given {@code cipher}.
     * @see BufferedBlockCipher#init(boolean, CipherParameters)
     */
    public static <T extends BufferedBlockCipher> T initForDecryption(final T cipher, final CipherParameters params) {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(params, "params is null");
        cipher.init(false, params);
        return cipher;
    }

    // -----------------------------------------------------------------------------------------------------------------

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

    /**
     * Initializes specified cipher, using specified cipher parameters, for encryption, and encrypts specified input.
     *
     * @param cipher the cipher to be initialized for encryption.
     * @param params the cipher parameters.
     * @param input  the input data to encrypt.
     * @return an array of encrypted bytes.
     * @throws InvalidCipherTextException if padding is expected and not found.
     */
    public static byte[] encrypt(final BufferedBlockCipher cipher, final CipherParameters params, final byte[] input)
            throws InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(params, "params is null");
        return processBytesAndDoFinal(
                initForEncryption(cipher, params),
                input
        );
    }

    /**
     * Initializes specified cipher, using specified cipher parameters, for decryption, and decrypts specified input.
     *
     * @param cipher the cipher to be initialized for decryption.
     * @param params the cipher parameters.
     * @param input  the input data to encrypt.
     * @return an array of decrypted bytes.
     * @throws InvalidCipherTextException if padding is expected and not found.
     */
    public static byte[] decrypt(final BufferedBlockCipher cipher, final CipherParameters params, final byte[] input)
            throws InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(params, "params is null");
        return processBytesAndDoFinal(
                initForDecryption(cipher, params),
                input
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static long processAllBytesAndDoFinal(final BufferedBlockCipher cipher, final InputStream in,
                                                 final OutputStream out, final byte[] inbuf, byte[] outbuf)
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
        var written = 0L;
        for (int r; (r = in.read(inbuf)) != -1; ) {
            final var updateOutputSize = cipher.getUpdateOutputSize(r);
            if (outbuf.length < updateOutputSize) {
                System.err.println("recreating outbuf for an updateOutputSize(" + updateOutputSize + ")");
                outbuf = new byte[updateOutputSize];
            }
            final var processed = cipher.processBytes(inbuf, 0, r, outbuf, 0);
            out.write(outbuf, 0, processed);
            written += processed;
        }
        final var outputSize = cipher.getOutputSize(0);
        if (outbuf.length < outputSize) {
            System.err.println("recreating outbuf for the final outputSize(" + outputSize + ")");
            outbuf = new byte[outputSize];
        }
        final var finalized = cipher.doFinal(outbuf, 0);
        out.write(outbuf, 0, finalized);
        written += finalized;
        return written;
    }

    public static long processAllBytesAndDoFinal(final BufferedBlockCipher cipher, final InputStream in,
                                                 final OutputStream out, final byte[] inbuf)
            throws IOException, InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length shouldn't be zero");
        }
        return processAllBytesAndDoFinal(
                cipher,
                in,
                out,
                inbuf,
                new byte[cipher.getOutputSize(inbuf.length)]
        );
    }

    public static long encrypt(final BufferedBlockCipher cipher, final CipherParameters params, final InputStream in,
                               final OutputStream out, final byte[] inbuf, byte[] outbuf)
            throws IOException, InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        cipher.init(true, params);
        return processAllBytesAndDoFinal(cipher, in, out, inbuf, outbuf);
    }

    public static long decrypt(final BufferedBlockCipher cipher, final CipherParameters params, final InputStream in,
                               final OutputStream out, final byte[] inbuf, byte[] outbuf)
            throws IOException, InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        cipher.init(false, params);
        return processAllBytesAndDoFinal(cipher, in, out, inbuf, outbuf);
    }

    public static long encrypt(final BufferedBlockCipher cipher, final CipherParameters params,
                               final InputStream in, final OutputStream out, final byte[] inbuf)
            throws IOException, InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        cipher.init(true, params);
        return processAllBytesAndDoFinal(
                initForEncryption(cipher, params),
                in,
                out,
                inbuf
        );
    }

    public static long decrypt(final BufferedBlockCipher cipher, final CipherParameters params,
                               final InputStream in, final OutputStream out, final byte[] inbuf)
            throws IOException, InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        return processAllBytesAndDoFinal(
                initForDecryption(cipher, params),
                in,
                out,
                inbuf
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaBufferedBlockCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
