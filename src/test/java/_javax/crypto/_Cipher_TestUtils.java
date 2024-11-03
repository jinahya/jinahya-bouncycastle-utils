package _javax.crypto;

import _javax.security._Random_TestUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
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

    // -----------------------------------------------------------------------------------------------------------------
    public static void __(final Cipher cipher, final Key key, final AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException,
                   BadPaddingException {
        final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
        cipher.init(Cipher.ENCRYPT_MODE, key, params);
        final var encrypted = cipher.doFinal(plain);
        cipher.init(Cipher.DECRYPT_MODE, key, params);
        final var decrypted = cipher.doFinal(encrypted);
        assertThat(decrypted).isEqualTo(plain);
    }

    public static void __(final Cipher cipher, final Key key, final AlgorithmParameterSpec params, final Path dir)
            throws IOException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException,
                   BadPaddingException {
        final var plain = _Random_TestUtils.createTempFileWithRandomBytesWritten(dir);
        final var inbuf = ByteBuffer.allocate(ThreadLocalRandom.current().nextInt(1024) + 1);
        var outbuf = ByteBuffer.allocate(ThreadLocalRandom.current().nextInt(1024) + 1);
        // ----------------------------------------------------------------------------------------------------- encrypt
        cipher.init(Cipher.ENCRYPT_MODE, key, params);
        final var encrypted = Files.createTempFile(dir, null, null);
        try (var input = FileChannel.open(plain, StandardOpenOption.READ);
             var output = FileChannel.open(encrypted, StandardOpenOption.WRITE)) {
            while (input.read(inbuf) != -1) {
                for (inbuf.flip(); ; ) {
                    try {
                        final var stored = cipher.update(inbuf, outbuf);
                        assert stored >= 0;
                        break;
                    } catch (final ShortBufferException sbe) {
                        outbuf = ByteBuffer.allocate(outbuf.capacity() << 1);
                    }
                }
                inbuf.compact();
                for (outbuf.flip(); outbuf.hasRemaining(); ) {
                    final var written = output.write(outbuf);
                    assert written >= 0;
                }
                outbuf.clear();
            }
            for (inbuf.flip(); ; ) {
                try {
                    final var stored = cipher.doFinal(inbuf, outbuf);
                    assert stored >= 0;
                    break;
                } catch (final ShortBufferException | IllegalBlockSizeException | BadPaddingException sbe) {
                    outbuf = ByteBuffer.allocate(outbuf.capacity() << 1);
                }
            }
            for (outbuf.flip(); outbuf.hasRemaining(); ) {
                final var written = output.write(outbuf);
                assert written >= 0;
            }
            output.force(false);
        }
        // ----------------------------------------------------------------------------------------------------- decrypt
        inbuf.clear();
        outbuf.clear();
        cipher.init(Cipher.DECRYPT_MODE, key, params);
        final var decrypted = Files.createTempFile(dir, null, null);
        try (var input = FileChannel.open(encrypted, StandardOpenOption.READ);
             var output = FileChannel.open(decrypted, StandardOpenOption.WRITE)) {
            while (input.read(inbuf) != -1) {
                for (inbuf.flip(); ; ) {
                    try {
                        final var stored = cipher.update(inbuf, outbuf);
                        assert stored >= 0;
                        break;
                    } catch (final ShortBufferException sbe) {
                        outbuf = ByteBuffer.allocate(outbuf.capacity() << 1);
                    }
                }
                inbuf.compact();
                for (outbuf.flip(); outbuf.hasRemaining(); ) {
                    final var written = output.write(outbuf);
                    assert written >= 0;
                }
                outbuf.clear();
            }
            for (inbuf.flip(); ; ) {
                try {
                    final var stored = cipher.doFinal(inbuf, outbuf);
                    assert stored >= 0;
                    break;
                } catch (final ShortBufferException sbe) {
                    outbuf = ByteBuffer.allocate(outbuf.capacity() << 1);
                }
            }
            for (outbuf.flip(); outbuf.hasRemaining(); ) {
                final var written = output.write(outbuf);
                assert written >= 0;
            }
            output.force(false);
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static void __(final Cipher cipher, final Key key)
            throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
        // ----------------------------------------------------------------------------------------------------- encrypt
        cipher.init(Cipher.ENCRYPT_MODE, key);
        final var encrypted = cipher.doFinal(plain);
        // ----------------------------------------------------------------------------------------------------- decrypt
        cipher.init(Cipher.DECRYPT_MODE, key);
        final var decrypted = cipher.doFinal(encrypted);
        assertThat(decrypted).isEqualTo(plain);
    }

    public static void __(final Cipher cipher, final Key key, final Path dir)
            throws IOException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException,
                   BadPaddingException {
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
            } catch (final ShortBufferException | IllegalBlockSizeException | BadPaddingException sbe) {
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
            final var stored = cipher.doFinal(input.flip(), output);
            assert stored >= 0;
            for (output.flip(); output.hasRemaining(); ) {
                final var written = writable.write(output);
                assert written >= 0;
            }
            writable.force(false);
        }
    }

    private _Cipher_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
