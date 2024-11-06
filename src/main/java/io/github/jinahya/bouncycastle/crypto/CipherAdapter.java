package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.InvalidCipherTextException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Objects;

public interface CipherAdapter {

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * @param in
     * @param inoff
     * @param inlen
     * @param out
     * @param outoff
     * @return the number of bytes set on the {@code out}.
     * @throws InvalidCipherTextException
     */
    int encrypt(byte[] in, int inoff, int inlen, byte[] out, int outoff) throws InvalidCipherTextException;

    /**
     * @param in
     * @param inoff
     * @param inlen
     * @return an array of encrypted bytes.
     * @throws InvalidCipherTextException
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
        return encrypt(in, 0, in.length);
    }

    // -----------------------------------------------------------------------------------------------------------------
    int decrypt(byte[] in, int inoff, int inlen, byte[] out, int outoff) throws InvalidCipherTextException;

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

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * .
     *
     * @param in     .
     * @param out
     * @param inbuf
     * @param outbuf
     * @return the number of bytes written to the {@code out}.
     * @throws IOException                if an I/O error occurs.
     * @throws InvalidCipherTextException
     */
    long encrypt(InputStream in, OutputStream out, byte[] inbuf, byte[] outbuf)
            throws IOException, InvalidCipherTextException;

    /**
     *
     * @param in
     * @param out
     * @param inbuf
     * @return the number of bytes written to the {@code out}.
     * @throws IOException
     * @throws InvalidCipherTextException
     */
    long encrypt(InputStream in, OutputStream out, byte[] inbuf) throws IOException, InvalidCipherTextException;

    // -----------------------------------------------------------------------------------------------------------------
    long decrypt(InputStream in, OutputStream out, byte[] inbuf, byte[] outbuf)
            throws IOException, InvalidCipherTextException;

    long decrypt(InputStream in, OutputStream out, byte[] inbuf) throws IOException, InvalidCipherTextException;
}
