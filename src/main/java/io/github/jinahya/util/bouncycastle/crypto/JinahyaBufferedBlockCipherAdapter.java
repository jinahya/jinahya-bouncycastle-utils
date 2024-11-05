package io.github.jinahya.util.bouncycastle.crypto;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

public class JinahyaBufferedBlockCipherAdapter
        extends AbstractJinahyaCipherAdapter<BufferedBlockCipher> {

    public JinahyaBufferedBlockCipherAdapter(final BufferedBlockCipher cipher, final CipherParameters params) {
        super(cipher, params);
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    public int encrypt(final byte[] in, final int inoff, final int inlen, final byte[] out, final int outoff)
            throws InvalidCipherTextException {
        cipher.init(true, params);
        return JinahyaBufferedBlockCipherUtils.processBytesAndDoFinal(
                cipher,
                in,
                inoff,
                inlen,
                out,
                outoff
        );
    }

    @Override
    public byte[] encrypt(final byte[] in, final int inoff, final int inlen) throws InvalidCipherTextException {
        cipher.init(true, params);
        final var out = new byte[cipher.getOutputSize(inlen)];
        final var outlen = JinahyaBufferedBlockCipherUtils.processBytesAndDoFinal(
                cipher,
                in,
                inoff,
                inlen,
                out,
                0
        );
        return Arrays.copyOf(out, outlen);
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    public int decrypt(final byte[] in, final int inoff, final int inlen, final byte[] out, final int outoff)
            throws InvalidCipherTextException {
        cipher.init(false, params);
        return JinahyaBufferedBlockCipherUtils.processBytesAndDoFinal(
                cipher,
                in,
                inoff,
                inlen,
                out,
                outoff
        );
    }

    @Override
    public byte[] decrypt(byte[] in, int inoff, int inlen) throws InvalidCipherTextException {
        cipher.init(false, params);
        final var out = new byte[cipher.getOutputSize(inlen)];
        final var outlen = JinahyaBufferedBlockCipherUtils.processBytesAndDoFinal(
                cipher,
                in,
                inoff,
                inlen,
                out,
                0
        );
        return Arrays.copyOf(out, outlen);
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    public long encrypt(final InputStream in, final OutputStream out, final byte[] inbuf, final byte[] outbuf)
            throws IOException, InvalidCipherTextException {
        cipher.init(true, params);
        return JinahyaBufferedBlockCipherUtils.processAllBytesAndDoFinal(
                cipher,
                in,
                out,
                inbuf,
                outbuf
        );
    }

    @Override
    public long encrypt(final InputStream in, final OutputStream out, final byte[] inbuf)
            throws IOException, InvalidCipherTextException {
        cipher.init(true, params);
        return JinahyaBufferedBlockCipherUtils.processAllBytesAndDoFinal(
                cipher,
                in,
                out,
                inbuf,
                new byte[cipher.getOutputSize(inbuf.length)]
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    public long decrypt(final InputStream in, final OutputStream out, final byte[] inbuf, final byte[] outbuf)
            throws IOException, InvalidCipherTextException {
        cipher.init(false, params);
        return JinahyaBufferedBlockCipherUtils.processAllBytesAndDoFinal(
                cipher,
                in,
                out,
                inbuf,
                outbuf
        );
    }

    @Override
    public long decrypt(final InputStream in, final OutputStream out, final byte[] inbuf)
            throws IOException, InvalidCipherTextException {
        cipher.init(false, params);
        return JinahyaBufferedBlockCipherUtils.processAllBytesAndDoFinal(
                cipher,
                in,
                out,
                inbuf,
                new byte[cipher.getOutputSize(inbuf.length)]
        );
    }
}
