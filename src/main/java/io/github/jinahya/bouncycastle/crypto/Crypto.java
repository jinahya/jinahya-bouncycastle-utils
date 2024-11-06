package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.InvalidCipherTextException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.util.Objects;

public interface Crypto {

    /**
     * Encrypts a portion of specified input bytes, and returns an array of encrypted bytes.
     *
     * @param in    the input bytes to encrypt.
     * @param inoff starting position in {@code in}.
     * @param inlen number of bytes to encrypt.
     * @return an array of encrypted bytes.
     * @throws InvalidCipherTextException if padding is expected and not found.
     */
    byte[] encrypt(byte[] in, int inoff, int inlen) throws InvalidCipherTextException;

    /**
     * Encrypts specified input bytes, and returns the result.
     *
     * @param in the input bytes to encrypt.
     * @return an array of encrypted bytes.
     * @throws InvalidCipherTextException if padding is expected and not found.
     */
    default byte[] encrypt(final byte[] in) throws InvalidCipherTextException {
        Objects.requireNonNull(in, "in is null");
        return encrypt(in, 0, in.length);
    }

    byte[] decrypt(byte[] in, int inoff, int inlen) throws InvalidCipherTextException;

    /**
     * Decrypts specified input bytes, and returns the result.
     *
     * @param in the input bytes to decrypt.
     * @return an array of decrypted bytes.
     * @throws InvalidCipherTextException if padding is expected and not found.
     */
    default byte[] decrypt(final byte[] in) throws InvalidCipherTextException {
        Objects.requireNonNull(in, "in is null");
        return decrypt(in, 0, in.length);
    }

    /**
     * Encrypts all bytes from specified input stream, and writes all encrypted bytes to specified output stream.
     *
     * @param in    the input stream from which plain bytes are read.
     * @param out   the output stream to which encrypted bytes are written.
     * @param inbuf a buffer for reading bytes from the {@code in}.
     * @return the number of bytes written to the {@code out}.
     * @throws IOException                if an I/O error occurs.
     * @throws InvalidCipherTextException if padding is expected and not found.
     */
    long encrypt(InputStream in, OutputStream out, byte[] inbuf)
            throws IOException, InvalidCipherTextException;

    /**
     * Decrypts all bytes from specified input stream, and writes all decrypted bytes to specified output stream.
     *
     * @param in    the input stream from which plain bytes are read.
     * @param out   the output stream to which decrypted bytes are written.
     * @param inbuf a buffer for reading bytes from the {@code in}.
     * @return the number of bytes written to the {@code out}.
     * @throws IOException                if an I/O error occurs.
     * @throws InvalidCipherTextException if padding is expected and not found.
     */
    long decrypt(InputStream in, OutputStream out, byte[] inbuf)
            throws IOException, InvalidCipherTextException;
}
