package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Objects;

public class BufferedBlockCipherAdapter
        extends AbstractCipherAdapter<BufferedBlockCipher> {

    public BufferedBlockCipherAdapter(final BufferedBlockCipher cipher, final CipherParameters params) {
        super(cipher, params);
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    public int encrypt(final byte[] in, final int inoff, final int inlen, final byte[] out, final int outoff)
            throws InvalidCipherTextException {
        cipher.init(true, params);
        final var processed = cipher.processBytes(in, inoff, inlen, out, outoff);
        final var finalized = cipher.doFinal(out, processed);
        return processed + finalized;
    }

    @Override
    public byte[] encrypt(final byte[] in, final int inoff, final int inlen) throws InvalidCipherTextException {
        cipher.init(true, params);
        final var out = new byte[cipher.getOutputSize(inlen)];
        final var outlen = encrypt(in, inoff, inlen, out, 0);
        return Arrays.copyOf(out, outlen);
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    public int decrypt(final byte[] in, final int inoff, final int inlen, final byte[] out, final int outoff)
            throws InvalidCipherTextException {
        cipher.init(false, params);
        final var processed = cipher.processBytes(in, inoff, inlen, out, outoff);
        final var finalized = cipher.doFinal(out, processed);
        return processed + finalized;
    }

    @Override
    public byte[] decrypt(byte[] in, int inoff, int inlen) throws InvalidCipherTextException {
        cipher.init(false, params);
        final var out = new byte[cipher.getOutputSize(inlen)];
        final var outlen = decrypt(in, inoff, inlen, out, 0);
        return Arrays.copyOf(out, outlen);
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    public long encrypt(final InputStream in, final OutputStream out, final byte[] inbuf, byte[] outbuf)
            throws IOException, InvalidCipherTextException {
        cipher.init(true, params);
        Objects.requireNonNull(in, "in is null");
        Objects.requireNonNull(out, "out is null");
        Objects.requireNonNull(inbuf, "inbuf is null");
//        Objects.requireNonNull(outbuf, "outbuf is null");
        if (outbuf == null) {
            outbuf = new byte[cipher.getOutputSize(inbuf.length)];
        }
        var written = 0L;
        int outlen;
        for (int uos, r; (r = in.read(inbuf)) != -1; ) {
            uos = cipher.getUpdateOutputSize(r);
            if (outbuf.length < uos) {
                System.err.println(
                        "reallocating outbuf(" + outbuf.length + ") for an intermediate updateOutputSize(" + uos + ")"
                );
                Arrays.fill(outbuf, (byte) 0);
                outbuf = new byte[uos];
            }
            outlen = cipher.processBytes(inbuf, 0, r, outbuf, 0);
            out.write(outbuf, 0, outlen);
            written += outlen;
        }
        for (final var os = cipher.getOutputSize(0); outbuf.length < os; ) {
            System.err.println("reallocating outbuf(" + outbuf.length + ") for the final outputSize(" + os + ")");
            Arrays.fill(outbuf, (byte) 0);
            outbuf = new byte[os];
        }
        outlen = cipher.doFinal(outbuf, 0);
        out.write(outbuf, 0, outlen);
        written += outlen;
        return written;
    }

    @Override
    public long encrypt(final InputStream in, final OutputStream out, final byte[] inbuf)
            throws IOException, InvalidCipherTextException {
        cipher.init(true, params);
        return encrypt(in, out, inbuf, null);
//        return BufferedBlockCipherUtils.processAllBytesAndDoFinal(
//                cipher,
//                in,
//                out,
//                inbuf,
//                null
////                new byte[cipher.getOutputSize(inbuf.length)]
//        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    public long decrypt(final InputStream in, final OutputStream out, final byte[] inbuf, final byte[] outbuf)
            throws IOException, InvalidCipherTextException {
        cipher.init(false, params);
        return BufferedBlockCipherUtils.processAllBytesAndDoFinal(
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
        return BufferedBlockCipherUtils.processAllBytesAndDoFinal(
                cipher,
                in,
                out,
                inbuf,
                new byte[cipher.getOutputSize(inbuf.length)]
        );
    }
}
