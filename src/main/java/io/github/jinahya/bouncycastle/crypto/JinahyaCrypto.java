package io.github.jinahya.bouncycastle.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;

public interface JinahyaCrypto {

//    /**
//     * Encrypts a portion of specified input bytes, and returns an array of encrypted bytes.
//     *
//     * @param in    the input bytes to encrypt.
//     * @param inoff starting position in {@code in}.
//     * @param inlen number of bytes to encrypt.
//     * @return an array of encrypted bytes.
//     * @throws InvalidCipherTextException if padding is expected and not found.
//     */
//    byte[] encrypt(byte[] in, int inoff, int inlen) throws InvalidCipherTextException;

    /**
     * Encrypts specified input bytes, and returns the result.
     *
     * @param in the input bytes to encrypt.
     * @return an array of encrypted bytes.
     */
    byte[] encrypt(final byte[] in);

    int encrypt(final ByteBuffer input, final ByteBuffer output);

    // -----------------------------------------------------------------------------------------------------------------

//    /**
//     * Decrypts a portion of specified input bytes, and returns an array of decrypted bytes.
//     *
//     * @param in    the input bytes to decrypt.
//     * @param inoff starting position in {@code in}.
//     * @param inlen number of bytes to decrypt.
//     * @return an array of decrypted bytes.
//     * @throws InvalidCipherTextException if padding is expected and not found.
//     */
//    byte[] decrypt(byte[] in, int inoff, int inlen) throws InvalidCipherTextException;

    /**
     * Decrypts specified input bytes, and returns the result.
     *
     * @param in the input bytes to decrypt.
     * @return an array of decrypted bytes.
     */
    byte[] decrypt(final byte[] in);

    int decrypt(final ByteBuffer input, final ByteBuffer output);

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Encrypts all bytes from specified input stream, and writes all encrypted bytes to specified output stream.
     *
     * @param in    the input stream from which plain bytes are read.
     * @param out   the output stream to which encrypted bytes are written.
     * @param inbuf a buffer for reading bytes from the {@code in}.
     * @return the number of bytes written to the {@code out}.
     * @throws IOException if an I/O error occurs.
     */
    long encrypt(InputStream in, OutputStream out, byte[] inbuf) throws IOException;

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Decrypts all bytes from specified input stream, and writes all decrypted bytes to specified output stream.
     *
     * @param in    the input stream from which plain bytes are read.
     * @param out   the output stream to which decrypted bytes are written.
     * @param inbuf a buffer for reading bytes from the {@code in}.
     * @return the number of bytes written to the {@code out}.
     * @throws IOException if an I/O error occurs.
     */
    long decrypt(InputStream in, OutputStream out, byte[] inbuf)
            throws IOException;
}
