package _org.bouncycastle.crypto;

import _javax.security._Random_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto.JinahyaBufferedBlockCipherUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
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

    // -----------------------------------------------------------------------------------------------------------------
    public static void __(final BufferedBlockCipher cipher, final CipherParameters params, final ByteBuffer plain)
            throws Exception {
        // ----------------------------------------------------------------------------------------------------- encrypt
        final var encrypted = JinahyaBufferedBlockCipherUtils.encrypt(
                cipher, params,
                plain,
                ByteBuffer::allocate
        );
        // ----------------------------------------------------------------------------------------------------- decrypt
        cipher.init(false, params);
        final var decrypted = JinahyaBufferedBlockCipherUtils.decrypt(
                cipher,
                params,
                encrypted.flip(),
                ByteBuffer::allocate
        );
        // -------------------------------------------------------------------------------------------------------- then
        assertThat(decrypted.flip()).isEqualTo(plain.clear());
    }

    public static void __(final BufferedBlockCipher cipher, final CipherParameters params, final byte[] plain)
            throws Exception {
        // ----------------------------------------------------------------------------------------------------- encrypt
        final var encrypted = JinahyaBufferedBlockCipherUtils.encrypt(cipher, params, plain, 0, plain.length);
        // ----------------------------------------------------------------------------------------------------- decrypt
        final var decrypted = JinahyaBufferedBlockCipherUtils.decrypt(cipher, params, encrypted, 0, encrypted.length);
        // -------------------------------------------------------------------------------------------------------- then
        assertThat(decrypted).isEqualTo(plain);
        __(cipher, params, ByteBuffer.wrap(plain));
    }

    public static void __(final BufferedBlockCipher cipher, final CipherParameters params) throws Exception {
        __(cipher, params, new byte[0]); // empty
        __(cipher, params, new byte[1]); // single-zero
        __(cipher, params, _Random_TestUtils.newRandomBytes(1)); // single-random
        __(cipher, params, _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024)));
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static void __(final BufferedBlockCipher cipher, final CipherParameters params, final Path dir,
                          final Path plain)
            throws Exception {
        // ----------------------------------------------------------------------------------------------------- encrypt
        cipher.init(true, params);
        final var encrypted = Files.createTempFile(dir, null, null);
        try (var out = new CipherOutputStream(new FileOutputStream(encrypted.toFile()), cipher)) {
            final var bytes = Files.copy(plain, out);
            out.flush();
        }
        // ----------------------------------------------------------------------------------------------------- decrypt
        cipher.init(false, params);
        final var decrypted = Files.createTempFile(dir, null, null);
        try (var in = new CipherInputStream(new FileInputStream(encrypted.toFile()), cipher)) {
            final var bytes = Files.copy(in, decrypted, StandardCopyOption.REPLACE_EXISTING);
        }
        // -------------------------------------------------------------------------------------------------------- then
        assertThat(decrypted).hasSize(Files.size(plain));
        assertThat(decrypted).hasSameBinaryContentAs(plain);
    }

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
        __(cipher, params, dir.toPath(), plain.toPath());
    }

    public static void __(final BufferedBlockCipher cipher, final CipherParameters params, final File dir)
            throws Exception {
        __(cipher, params, dir, File.createTempFile("tmp", null, dir)); // empty
        __(cipher, params, dir, _Random_TestUtils.createTempFileWithRandomBytesWritten(dir)); // random
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _BufferedBlockCipher_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
