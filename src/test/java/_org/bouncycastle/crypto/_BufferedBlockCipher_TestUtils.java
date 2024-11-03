package _org.bouncycastle.crypto;

import _javax.security._MessageDigest_TestUtils;
import _javax.security._Random_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto.JinahyaBufferedBlockCipherUtils;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThat;

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
        cipher.init(true, params);
        final var encrypted = JinahyaBufferedBlockCipherUtils.processBytesAndDoFinal(cipher, plain);
        // ----------------------------------------------------------------------------------------------------- decrypt
        cipher.init(false, params);
        final var decrypted = JinahyaBufferedBlockCipherUtils.processBytesAndDoFinal(cipher, encrypted);
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
        cipher.init(true, params);
        final var encrypted = File.createTempFile("tmp", null, dir);
        try (var out = new CipherOutputStream(new FileOutputStream(encrypted), cipher)) {
            final var bytes = Files.copy(plain.toPath(), out);
            out.flush();
        }
        // ----------------------------------------------------------------------------------------------------- decrypt
        cipher.init(false, params);
        final var decrypted = File.createTempFile("tmp", null, dir);
        try (var in = new CipherInputStream(new FileInputStream(encrypted), cipher)) {
            final var bytes = Files.copy(in, decrypted.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }
        // -------------------------------------------------------------------------------------------------------- then
        assertThat(decrypted).hasSize(plain.length());
        _MessageDigest_TestUtils.__(plain, decrypted);
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
