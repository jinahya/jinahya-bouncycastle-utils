package _org.bouncycastle.crypto;

import _javax.security._Random_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto.JinahyaBufferedBlockCipherUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
public final class _BufferedBlockCipher_TestUtils {

    public static String cipherName(final BufferedBlockCipher cipher) {
        Objects.requireNonNull(cipher, "cipher is null");
        return _BlockCipher_TestUtils.cipherName(cipher.getUnderlyingCipher());
    }

    public static String cipherName(final BufferedBlockCipher cipher, final BlockCipherPadding padding) {
        return _BlockCipher_TestUtils.cipherName(
                Objects.requireNonNull(cipher, "cipher is null").getUnderlyingCipher(),
                padding
        );
    }

    public static void __(final BufferedBlockCipher cipher, final CipherParameters params, final byte[] plain)
            throws Exception {
        // ----------------------------------------------------------------------------------------------------- encrypt
        final var encrypted = JinahyaBufferedBlockCipherUtils.encrypt(cipher, params, plain);
        // ----------------------------------------------------------------------------------------------------- decrypt
        final var decrypted = JinahyaBufferedBlockCipherUtils.decrypt(cipher, params, encrypted);
        // -------------------------------------------------------------------------------------------------------- then
        assertThat(decrypted).isEqualTo(plain);
    }

    public static void __(final BufferedBlockCipher cipher, final CipherParameters params) throws Exception {
        __(cipher, params, new byte[0]); // empty
        __(cipher, params, new byte[1]); // single-zero
        __(cipher, params, _Random_TestUtils.newRandomBytes(1)); // single-random
        __(cipher, params, _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024)));
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static void __(final BufferedBlockCipher cipher, final CipherParameters params, final File dir,
                          final File plain)
            throws Exception {
        // ----------------------------------------------------------------------------------------------------- encrypt
        final var encrypted = File.createTempFile("tmp", null, dir);
        try (var in = new FileInputStream(plain);
             var out = new FileOutputStream(encrypted)) {
            final var bytes = JinahyaBufferedBlockCipherUtils.encrypt(
                    cipher,
                    params,
                    in,
                    out,
                    new byte[1]
            );
            out.flush();
        }
        // ----------------------------------------------------------------------------------------------------- decrypt
        final var decrypted = File.createTempFile("tmp", null, dir);
        try (var in = new FileInputStream(encrypted);
             var out = new FileOutputStream(decrypted)) {
            final var bytes = JinahyaBufferedBlockCipherUtils.decrypt(
                    cipher,
                    params,
                    in,
                    out,
                    new byte[1]
            );
        }
        // -------------------------------------------------------------------------------------------------------- then
        assertThat(decrypted).hasSize(plain.length());
        assertThat(decrypted).hasSameBinaryContentAs(plain);
    }

    public static void __(final BufferedBlockCipher cipher, final CipherParameters params, final File dir)
            throws Exception {
        __(cipher, params, dir, File.createTempFile("tmp", null, dir));
        __(cipher, params, dir, _Random_TestUtils.createTempFileWithRandomBytesWritten(dir));
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _BufferedBlockCipher_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
