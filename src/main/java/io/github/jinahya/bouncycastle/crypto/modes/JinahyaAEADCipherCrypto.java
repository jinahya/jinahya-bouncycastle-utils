package io.github.jinahya.bouncycastle.crypto.modes;

import io.github.jinahya.bouncycastle.crypto.JinahyaCipherCrypto;
import io.github.jinahya.bouncycastle.crypto.JinahyaCryptoException;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.AEADCipher;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

/**
 * A crypto for {@link AEADCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 * @see JinahyaAEADCipherUtils
 */
public class JinahyaAEADCipherCrypto
        extends JinahyaCipherCrypto<AEADCipher> {

    public JinahyaAEADCipherCrypto(final AEADCipher cipher, final CipherParameters params) {
        super(cipher, params);
    }

    // ---------------------------------------------------------------------------------------------------------- cipher
    @Override
    protected void initFor(final boolean encryption) {
        cipher.init(encryption, params);
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    public byte[] encrypt(final byte[] in) {
        Objects.requireNonNull(in, "in is null");
        initForEncryption();
        final var out = new byte[Math.max(cipher.getOutputSize(in.length), 1)];
        try {
            final var outlen = JinahyaAEADCipherUtils.processBytesAndDoFinal(
                    cipher,
                    in,
                    0,
                    in.length,
                    out,
                    0
            );
            return Arrays.copyOf(out, outlen);
        } catch (final InvalidCipherTextException icte) {
            throw JinahyaCryptoException.ofEncryptionFailure(icte);
        }
    }

    @Override
    public int encrypt(final ByteBuffer input, final ByteBuffer output) {
        initForEncryption();
        try {
            return JinahyaAEADCipherUtils.processBytesAndDoFinal(cipher, input, output);
        } catch (final InvalidCipherTextException icte) {
            throw JinahyaCryptoException.ofEncryptionFailure(icte);
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    public byte[] decrypt(byte[] in) {
        Objects.requireNonNull(in, "in is null");
        initForDecryption();
        final var out = new byte[Math.max(cipher.getOutputSize(in.length), 1)];
        try {
            final var outlen = JinahyaAEADCipherUtils.processBytesAndDoFinal(cipher, in, 0, in.length, out, 0);
            return Arrays.copyOf(out, outlen);
        } catch (final InvalidCipherTextException icte) {
            throw JinahyaCryptoException.ofDecryptionFailure(icte);
        }
    }

    @Override
    public int decrypt(final ByteBuffer input, final ByteBuffer output) {
        initForDecryption();
        try {
            return JinahyaAEADCipherUtils.processBytesAndDoFinal(cipher, input, output);
        } catch (final InvalidCipherTextException icte) {
            throw JinahyaCryptoException.ofDecryptionFailure(icte);
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    public long encrypt(final InputStream in, final OutputStream out, final byte[] inbuf) throws IOException {
        initForEncryption();
        try {
            return JinahyaAEADCipherUtils.processAllBytesAndDoFinal(
                    cipher,
                    in,
                    out,
                    inbuf,
                    null
            );
        } catch (final InvalidCipherTextException icte) {
            throw JinahyaCryptoException.ofEncryptionFailure(icte);
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    public long decrypt(final InputStream in, final OutputStream out, final byte[] inbuf) throws IOException {
        initForDecryption();
        try {
            return JinahyaAEADCipherUtils.processAllBytesAndDoFinal(
                    cipher,
                    in,
                    out,
                    inbuf,
                    null
            );
        } catch (final InvalidCipherTextException icte) {
            throw JinahyaCryptoException.ofDecryptionFailure(icte);
        }
    }
}
