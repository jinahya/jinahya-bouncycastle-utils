package io.github.jinahya.util.bouncycastle.crypto;

import _javax.security._MessageDigest_TestUtils;
import _javax.security._Random_TestUtils;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThat;

public final class _BufferedBlockCipher_TestUtils {

    public static String cipherName(final BufferedBlockCipher cipher) {
        return _BlockCipher_TestUtils.cipherName(
                Objects.requireNonNull(cipher, "cipher is null").getUnderlyingCipher());
    }

    public static String cipherName(final BufferedBlockCipher cipher, final BlockCipherPadding padding) {
        return _BlockCipher_TestUtils.cipherName(
                Objects.requireNonNull(cipher, "cipher is null").getUnderlyingCipher(),
                padding
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    private static void __(final BufferedBlockCipher cipher, final CipherParameters params, final ByteBuffer plain)
            throws Exception {
        // ----------------------------------------------------------------------------------------------------- encrypt
        cipher.init(true, params);
        final var encrypted = ByteBuffer.allocate(cipher.getOutputSize(plain.remaining()));
        final var encryptedBytes = JinahyaBufferedBlockCipherUtils.processBytesAndDoFinal(
                cipher,
                plain,
                encrypted
        );
        assert !plain.hasRemaining();
        assertThat(encryptedBytes).isEqualTo(encrypted.position());
        // ----------------------------------------------------------------------------------------------------- decrypt
        cipher.init(false, params);
        final var decrypted = ByteBuffer.allocate(cipher.getOutputSize(encrypted.flip().remaining()));
        final var decryptedBytes = JinahyaBufferedBlockCipherUtils.processBytesAndDoFinal(
                cipher,
                encrypted,
                decrypted
        );
        assertThat(decryptedBytes).isEqualTo(decrypted.position());
        // -------------------------------------------------------------------------------------------------------- then
        assertThat(decrypted.flip()).isEqualTo(plain.flip());
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
        // -------------------------------------------------------------------------------------------------------------
        __(cipher, params, ByteBuffer.wrap(plain).asReadOnlyBuffer());
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
        try (var source = new FileInputStream(plain);
             var target = new FileOutputStream(encrypted)) {
            JinahyaBufferedBlockCipherUtils.processAllBytesAndDoFinal(
                    cipher,
                    source,
                    target,
                    new byte[ThreadLocalRandom.current().nextInt(1024) + 1]
            );
            target.flush();
        }
        // ----------------------------------------------------------------------------------------------------- decrypt
        cipher.init(false, params);
        final var decrypted = File.createTempFile("tmp", null, dir);
        try (var source = new FileInputStream(encrypted);
             var target = new FileOutputStream(decrypted)) {
            JinahyaBufferedBlockCipherUtils.processAllBytesAndDoFinal(
                    cipher,
                    source,
                    target,
                    new byte[ThreadLocalRandom.current().nextInt(1024) + 1]
            );
            target.flush();
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

    public static void __(final BufferedBlockCipher cipher, final CipherParameters params, final Path dir,
                          final Path plain)
            throws Exception {
        // ----------------------------------------------------------------------------------------------------- encrypt
        cipher.init(true, params);
        final var encrypted = Files.createTempFile(dir, null, null);
        try (var source = FileChannel.open(plain, StandardOpenOption.READ);
             var target = FileChannel.open(encrypted, StandardOpenOption.WRITE)) {
            JinahyaBufferedBlockCipherUtils.processAllBytesAndDoFinal(
                    cipher,
                    source,
                    target,
                    ByteBuffer.allocate(ThreadLocalRandom.current().nextInt(1024) + 1)
            );
            target.force(false);
        }
        // ----------------------------------------------------------------------------------------------------- decrypt
        cipher.init(false, params);
        final var decrypted = Files.createTempFile(dir, null, null);
        try (var source = FileChannel.open(encrypted, StandardOpenOption.READ);
             var target = FileChannel.open(decrypted, StandardOpenOption.WRITE)) {
            JinahyaBufferedBlockCipherUtils.processAllBytesAndDoFinal(
                    cipher,
                    source,
                    target,
                    ByteBuffer.allocate(ThreadLocalRandom.current().nextInt(1024) + 1)
            );
            target.force(false);
        }
        // -------------------------------------------------------------------------------------------------------- then
        assertThat(decrypted).hasSize(Files.size(plain));
        assertThat(decrypted).hasSameBinaryContentAs(plain);
    }

    public static void __(final BufferedBlockCipher cipher, final CipherParameters params, final Path dir)
            throws Exception {
        __(cipher, params, dir, Files.createTempFile(dir, null, null));
        __(cipher, params, dir, _Random_TestUtils.createTempFileWithRandomBytesWritten(dir));
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _BufferedBlockCipher_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
