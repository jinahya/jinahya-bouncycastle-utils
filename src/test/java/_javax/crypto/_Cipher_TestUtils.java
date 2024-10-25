package _javax.crypto;

import _javax.security._Random_TestUtils;
import io.github.jinahya.util._LogUtils;
import io.github.jinahya.util.bouncycastle.jce.provider.JinahyaBouncyCastleProviderUtils;

import javax.crypto.Cipher;
import javax.crypto.ShortBufferException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * .
 *
 * @see <a href="https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html">Java Security
 * Standard Algorithm Names</a> (JDK 21 Documentation)
 */
public final class _Cipher_TestUtils {

    public static void __(final Cipher cipher, final Key key, final AlgorithmParameterSpec params)
            throws Exception {
        JinahyaBouncyCastleProviderUtils.addBouncyCastleProvider();
        final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
        cipher.init(Cipher.ENCRYPT_MODE, key, params);
        final var encrypted = cipher.doFinal(plain);
        cipher.init(Cipher.DECRYPT_MODE, key, params);
        final var decrypted = cipher.doFinal(encrypted);
        _LogUtils.log(plain, encrypted, decrypted);
        assertThat(decrypted).isEqualTo(plain);
        JinahyaBouncyCastleProviderUtils.removeBouncyCastleProvider();
    }

    public static void __(final Cipher cipher, final Key key, final AlgorithmParameterSpec params, final Path dir)
            throws Exception {
        JinahyaBouncyCastleProviderUtils.addBouncyCastleProvider();
        // ------------------------------------------------------------------------------------------------------- plain
        final var plain = _Random_TestUtils.createTempFileWithRandomBytesWritten(dir);
        final var input = ByteBuffer.allocate(ThreadLocalRandom.current().nextInt(1024) + 1);
        var output = ByteBuffer.allocate(ThreadLocalRandom.current().nextInt(1024) + 1);
        // ----------------------------------------------------------------------------------------------------- encrypt
        input.clear();
        output.clear();
        cipher.init(Cipher.ENCRYPT_MODE, key, params);
        final var encrypted = Files.createTempFile(dir, null, null);
        try (var readable = FileChannel.open(plain, StandardOpenOption.READ);
             var writable = FileChannel.open(encrypted, StandardOpenOption.WRITE)) {
            while (readable.read(input) != -1) {
                input.flip();
                try {
                    final var stored = cipher.update(input, output);
                    assert stored >= 0;
                } catch (final ShortBufferException sbe) {
                    output = ByteBuffer.allocate(output.capacity() << 1);
                }
                for (output.flip(); output.hasRemaining(); ) {
                    final var written = writable.write(output);
                    assert written >= 0;
                }
                output.clear();
                input.compact();
            }
            try {
                final var stored = cipher.doFinal(input.flip(), output);
                assert stored >= 0;
            } catch (final ShortBufferException sbe) {
                output = ByteBuffer.allocate(output.capacity() << 1);
            }
            for (output.flip(); output.hasRemaining(); ) {
                final var written = writable.write(output);
                assert written >= 0;
            }
            writable.force(false);
        }
        // ----------------------------------------------------------------------------------------------------- decrypt
        input.clear();
        output.clear();
        cipher.init(Cipher.DECRYPT_MODE, key, params);
        final var decrypted = Files.createTempFile(dir, null, null);
        try (var readable = FileChannel.open(encrypted, StandardOpenOption.READ);
             var writable = FileChannel.open(decrypted, StandardOpenOption.WRITE)) {
            while (readable.read(input) != -1) {
                input.flip();
                try {
                    final var stored = cipher.update(input, output);
                    assert stored >= 0;
                } catch (final ShortBufferException sbe) {
                    output = ByteBuffer.allocate(output.capacity() << 1);
                }
                for (output.flip(); output.hasRemaining(); ) {
                    final var written = writable.write(output);
                    assert written >= 0;
                }
                output.clear();
                input.compact();
            }
            try {
                final var stored = cipher.doFinal(input.flip(), output);
                assert stored >= 0;
            } catch (final ShortBufferException sbe) {
                output = ByteBuffer.allocate(output.capacity() << 1);
            }
            for (output.flip(); output.hasRemaining(); ) {
                final var written = writable.write(output);
                assert written >= 0;
            }
            writable.force(false);
        }
        JinahyaBouncyCastleProviderUtils.removeBouncyCastleProvider();
    }

    public static void __(final Cipher cipher, final Key key)
            throws Exception {
        JinahyaBouncyCastleProviderUtils.addBouncyCastleProvider();
        // ------------------------------------------------------------------------------------------------------- plain
        final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
        cipher.init(Cipher.ENCRYPT_MODE, key);
        final var encrypted = cipher.doFinal(plain);
        cipher.init(Cipher.DECRYPT_MODE, key);
        final var decrypted = cipher.doFinal(encrypted);
        _LogUtils.log(plain, encrypted, decrypted);
        assertThat(decrypted).isEqualTo(plain);
        JinahyaBouncyCastleProviderUtils.removeBouncyCastleProvider();
    }

    public static void __(final Cipher cipher, final Key key, final Path dir)
            throws Exception {
        JinahyaBouncyCastleProviderUtils.addBouncyCastleProvider();
        // ------------------------------------------------------------------------------------------------------- plain
        final var plain = _Random_TestUtils.createTempFileWithRandomBytesWritten(dir);
        final var input = ByteBuffer.allocate(ThreadLocalRandom.current().nextInt(1024) + 1);
        var output = ByteBuffer.allocate(ThreadLocalRandom.current().nextInt(1024) + 1);
        // ----------------------------------------------------------------------------------------------------- encrypt
        input.clear();
        output.clear();
        cipher.init(Cipher.ENCRYPT_MODE, key);
        final var encrypted = Files.createTempFile(dir, null, null);
        try (var readable = FileChannel.open(plain, StandardOpenOption.READ);
             var writable = FileChannel.open(encrypted, StandardOpenOption.WRITE)) {
            while (readable.read(input) != -1) {
                input.flip();
                try {
                    final var stored = cipher.update(input, output);
                    assert stored >= 0;
                } catch (final ShortBufferException sbe) {
                    output = ByteBuffer.allocate(output.capacity() << 1);
                }
                for (output.flip(); output.hasRemaining(); ) {
                    final var written = writable.write(output);
                    assert written >= 0;
                }
                output.clear();
                input.compact();
            }
            try {
                final var stored = cipher.doFinal(input.flip(), output);
                assert stored >= 0;
            } catch (final ShortBufferException sbe) {
                output = ByteBuffer.allocate(output.capacity() << 1);
            }
            for (output.flip(); output.hasRemaining(); ) {
                final var written = writable.write(output);
                assert written >= 0;
            }
            writable.force(false);
        }
        // ----------------------------------------------------------------------------------------------------- decrypt
        input.clear();
        output.clear();
        cipher.init(Cipher.DECRYPT_MODE, key);
        final var decrypted = Files.createTempFile(dir, null, null);
        try (var readable = FileChannel.open(encrypted, StandardOpenOption.READ);
             var writable = FileChannel.open(decrypted, StandardOpenOption.WRITE)) {
            while (readable.read(input) != -1) {
                input.flip();
                try {
                    final var stored = cipher.update(input, output);
                    assert stored >= 0;
                } catch (final ShortBufferException sbe) {
                    output = ByteBuffer.allocate(output.capacity() << 1);
                }
                for (output.flip(); output.hasRemaining(); ) {
                    final var written = writable.write(output);
                    assert written >= 0;
                }
                output.clear();
                input.compact();
            }
            try {
                final var stored = cipher.doFinal(input.flip(), output);
                assert stored >= 0;
            } catch (final ShortBufferException sbe) {
                output = ByteBuffer.allocate(output.capacity() << 1);
            }
            for (output.flip(); output.hasRemaining(); ) {
                final var written = writable.write(output);
                assert written >= 0;
            }
            writable.force(false);
        }
        JinahyaBouncyCastleProviderUtils.removeBouncyCastleProvider();
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _Cipher_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
