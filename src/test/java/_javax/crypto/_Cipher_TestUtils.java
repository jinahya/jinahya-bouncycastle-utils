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
    public static void __(final Cipher cipher, final Key key, final AlgorithmParameterSpec params, final byte[] aad,
                          final byte[] plain)
            throws InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException,
                   BadPaddingException {
        // ----------------------------------------------------------------------------------------------------- encrypt
        if (params != null) {
            cipher.init(Cipher.ENCRYPT_MODE, key, params);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        }
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        final var encrypted = cipher.doFinal(plain);
        // ----------------------------------------------------------------------------------------------------- decrypt
        if (params != null) {
            cipher.init(Cipher.DECRYPT_MODE, key, params);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key);
        }
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        final var decrypted = cipher.doFinal(encrypted);
        // ------------------------------------------------------------------------------------------------------ verify
        assertThat(decrypted).isEqualTo(plain);
    }

    public static void __(final Cipher cipher, final Key key, final AlgorithmParameterSpec params, final byte[] aad)
            throws InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException,
                   BadPaddingException {
        __(cipher, key, params, aad, new byte[0]);
        __(cipher, key, params, aad, new byte[1]);
        __(cipher, key, params, aad, new byte[]{(byte) ThreadLocalRandom.current().nextInt()});
        __(cipher, key, params, aad, _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024)));
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static void __(final Cipher cipher, final Key key, final AlgorithmParameterSpec params, final byte[] aad,
                          final Path dir, final Path plain)
            throws IOException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException,
                   BadPaddingException {
        final var input = ByteBuffer.allocate(ThreadLocalRandom.current().nextInt(1024) + 1);
        var output = ByteBuffer.allocate(1);
        // ----------------------------------------------------------------------------------------------------- encrypt
        if (params != null) {
            cipher.init(Cipher.ENCRYPT_MODE, key, params);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        }
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        final var encrypted = Files.createTempFile(dir, null, null);
        try (var readable = FileChannel.open(plain, StandardOpenOption.READ);
             var writable = FileChannel.open(encrypted, StandardOpenOption.WRITE)) {
            while (readable.read(input) != -1) {
                for (input.flip(); ; ) {
                    try {
                        final var stored = cipher.update(input, output);
                        assert stored >= 0;
                        break;
                    } catch (final ShortBufferException sbe) {
                        System.err.printf("doubling up output.capacity from %1$d%n", output.capacity());
                        output = ByteBuffer.allocate(output.capacity() << 1);
                    }
                }
                for (output.flip(); output.hasRemaining(); ) {
                    final var written = writable.write(output);
                    assert written >= 0;
                }
                output.clear();
                input.compact();
            }
            for (input.flip(); ; ) {
                try {
                    final var stored = cipher.doFinal(input, output);
                    assert stored >= 0;
                    break;
                } catch (final ShortBufferException sbe) {
                    System.err.printf("doubling up output.capacity from %1$d%n", output.capacity());
                    output = ByteBuffer.allocate(output.capacity() << 1);
                }
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
        if (params != null) {
            cipher.init(Cipher.DECRYPT_MODE, key, params);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key);
        }
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        final var decrypted = Files.createTempFile(dir, null, null);
        try (var readable = FileChannel.open(encrypted, StandardOpenOption.READ);
             var writable = FileChannel.open(decrypted, StandardOpenOption.WRITE)) {
            while (readable.read(input) != -1) {
                for (input.flip(); ; ) {
                    try {
                        final var stored = cipher.update(input, output);
                        assert stored >= 0;
                        break;
                    } catch (final ShortBufferException sbe) {
                        System.err.printf("doubling up output.capacity from %1$d%n", output.capacity());
                        output = ByteBuffer.allocate(output.capacity() << 1);
                    }
                }
                for (output.flip(); output.hasRemaining(); ) {
                    final var written = writable.write(output);
                    assert written >= 0;
                }
                output.clear();
                input.compact();
            }
            for (input.flip(); ; ) {
                try {
                    final var stored = cipher.doFinal(input, output);
                    assert stored >= 0;
                    break;
                } catch (final ShortBufferException sbe) {
                    System.err.printf("doubling up output.capacity from %1$d%n", output.capacity());
                    output = ByteBuffer.allocate(output.capacity() << 1);
                }
            }
            for (output.flip(); output.hasRemaining(); ) {
                final var written = writable.write(output);
                assert written >= 0;
            }
            writable.force(false);
        }
    }

    public static void __(final Cipher cipher, final Key key, final AlgorithmParameterSpec params, final byte[] aad,
                          final Path dir)
            throws IOException {
        _Random_TestUtils.getRandomFileStream(dir).forEach(p -> {
            try {
                __(cipher, key, params, aad, dir, p);
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    private _Cipher_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
