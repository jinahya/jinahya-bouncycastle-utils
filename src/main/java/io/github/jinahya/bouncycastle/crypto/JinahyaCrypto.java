package io.github.jinahya.bouncycastle.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;

public interface JinahyaCrypto {

    /**
     * Encrypts specified input bytes, and returns the result.
     *
     * @param in the input bytes to encrypt.
     * @return an array of encrypted bytes.
     */
    byte[] encrypt(final byte[] in);

    /**
     * Encrypts all remaining bytes of specified input buffer, and put encrypted bytes to specified output buffer.
     *
     * @param input  the input buffer whose remaining bytes are encrypted.
     * @param output the output buffer onto which encrypted bytes are put.
     * @return the number of bytes put on the {@code output}.
     */
    int encrypt(final ByteBuffer input, final ByteBuffer output);

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Decrypts specified input bytes, and returns the result.
     *
     * @param in the input bytes to decrypt.
     * @return an array of decrypted bytes.
     */
    byte[] decrypt(final byte[] in);

    /**
     * Decrypts all remaining bytes of specified input buffer, and put decrypted bytes to specified output buffer.
     *
     * @param input  the input buffer whose remaining bytes are decrypted.
     * @param output the output buffer onto which decrypted bytes are put.
     * @return the number of bytes put on the {@code output}.
     */
    int decrypt(final ByteBuffer input, final ByteBuffer output);

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Encrypts all bytes from specified input stream, and writes encrypted bytes to specified output stream.
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
     * Decrypts all bytes from specified input stream, and writes decrypted bytes to specified output stream.
     *
     * @param in    the input stream from which plain bytes are read.
     * @param out   the output stream to which decrypted bytes are written.
     * @param inbuf a buffer for reading bytes from the {@code in}.
     * @return the number of bytes written to the {@code out}.
     * @throws IOException if an I/O error occurs.
     */
    long decrypt(InputStream in, OutputStream out, byte[] inbuf) throws IOException;
}
