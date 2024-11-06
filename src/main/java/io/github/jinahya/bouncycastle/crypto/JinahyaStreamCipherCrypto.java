package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Objects;

public class JinahyaStreamCipherCrypto
        extends JinahyaCipherCrypto<StreamCipher> {

    public JinahyaStreamCipherCrypto(final StreamCipher cipher, final CipherParameters params) {
        super(cipher, params);
    }

    @Override
    public byte[] encrypt(final byte[] in) {
        Objects.requireNonNull(in, "in is null");
        cipher.init(true, params);
        return JinahyaStreamCipherUtils.processBytes(cipher, in, 0, in.length);
    }

    @Override
    public int encrypt(final ByteBuffer input, final ByteBuffer output) {
        cipher.init(true, params);
        JinahyaStreamCipherUtils.processBytes(cipher, input, output);
        return 0;
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    public byte[] decrypt(byte[] in) {
        Objects.requireNonNull(in, "in is null");
        cipher.init(false, params);
        return JinahyaStreamCipherUtils.processBytes(cipher, in, 0, in.length);
    }

    @Override
    public int decrypt(final ByteBuffer input, final ByteBuffer output) {
        cipher.init(false, params);
        JinahyaStreamCipherUtils.processBytes(cipher, input, output);
        return 0;
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    public long encrypt(final InputStream in, final OutputStream out, final byte[] inbuf) throws IOException {
        cipher.init(true, params);
        return JinahyaStreamCipherUtils.processAllBytes(
                cipher,
                in,
                out,
                inbuf,
                null
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    public long decrypt(final InputStream in, final OutputStream out, final byte[] inbuf) throws IOException {
        cipher.init(false, params);
        return JinahyaStreamCipherUtils.processAllBytes(
                cipher,
                in,
                out,
                inbuf,
                null
        );
    }
}
