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

public class JinahyaBufferedBlockCipherCrypto
        extends JinahyaCipherCrypto<BufferedBlockCipher> {

    public JinahyaBufferedBlockCipherCrypto(final BufferedBlockCipher cipher, final CipherParameters params) {
        super(cipher, params);
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    public byte[] encrypt(final byte[] in) {
        Objects.requireNonNull(in, "in is null");
        cipher.init(true, params);
        final var out = new byte[cipher.getOutputSize(in.length)];
        try {
            final var outlen = JinahyaBufferedBlockCipherUtils.processBytesAndDoFinal(cipher, in, 0, in.length, out, 0);
            return Arrays.copyOf(out, outlen);
        } catch (final InvalidCipherTextException icte) {
            throw new JinahyaCryptoException("failed to encrypt", icte);
        }
    }

    @Override
    public int encrypt(final ByteBuffer input, final ByteBuffer output) {
        cipher.init(false, params);
        try {
            return JinahyaBufferedBlockCipherUtils.processBytesAndDoFinal_(cipher, input, output);
        } catch (final InvalidCipherTextException icte) {
            throw new JinahyaCryptoException("failed to encrypt", icte);
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    public byte[] decrypt(byte[] in) {
        Objects.requireNonNull(in, "in is null");
        cipher.init(false, params);
        final var out = new byte[cipher.getOutputSize(in.length)];
        try {
            final var outlen = JinahyaBufferedBlockCipherUtils.processBytesAndDoFinal(cipher, in, 0, in.length, out, 0);
            return Arrays.copyOf(out, outlen);
        } catch (final InvalidCipherTextException icte) {
            throw new JinahyaCryptoException("failed to decrypt", icte);
        }
    }

    @Override
    public int decrypt(final ByteBuffer input, final ByteBuffer output) {
        cipher.init(false, params);
        try {
            return JinahyaBufferedBlockCipherUtils.processBytesAndDoFinal_(cipher, input, output);
        } catch (final InvalidCipherTextException icte) {
            throw new JinahyaCryptoException("failed to encrypt", icte);
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    public long encrypt(final InputStream in, final OutputStream out, final byte[] inbuf)
            throws IOException {
        cipher.init(true, params);
        try {
            return JinahyaBufferedBlockCipherUtils.processAllBytesAndDoFinal(
                    cipher,
                    in,
                    out,
                    inbuf,
                    null
            );
        } catch (final InvalidCipherTextException icte) {
            throw new JinahyaCryptoException("failed to encrypt", icte);
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    public long decrypt(final InputStream in, final OutputStream out, final byte[] inbuf) throws IOException {
        cipher.init(false, params);
        try {
            return JinahyaBufferedBlockCipherUtils.processAllBytesAndDoFinal(
                    cipher,
                    in,
                    out,
                    inbuf,
                    null
            );
        } catch (final InvalidCipherTextException icte) {
            throw new JinahyaCryptoException("failed to decrypt", icte);
        }
    }
}
