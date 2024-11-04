package _javax.crypto;

import _javax.security._Random_TestUtils;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.ShortBufferException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * .
 *
 * @see <a href="https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html">Java Security
 * Standard Algorithm Names</a> (JDK 21 Documentation)
 */
@Slf4j
public final class _Cipher_TestUtils {

    // -----------------------------------------------------------------------------------------------------------------
    public static void __(final Cipher cipher, final Key key, final AlgorithmParameterSpec params, final byte[] aad,
                          final byte[] plain)
            throws Exception {
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

    public static void __(@Nonnull final Cipher cipher, @Nonnull final Key key,
                          @Nullable final AlgorithmParameterSpec params, @Nullable final byte[] aad)
            throws Exception {
        assertThat(cipher.getProvider().getName()).isEqualTo(BouncyCastleProvider.PROVIDER_NAME);
        __(cipher, key, params, aad, new byte[0]);
        __(cipher, key, params, aad, new byte[1]);
        __(cipher, key, params, aad, new byte[]{(byte) ThreadLocalRandom.current().nextInt()});
        __(cipher, key, params, aad, _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024)));
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static void __(@Nonnull final Cipher cipher, @Nonnull final Key key,
                          @Nullable final AlgorithmParameterSpec params, @Nullable final byte[] aad,
                          @Nonnull final Path dir, @Nonnull final Path plain)
            throws Exception {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(key, "key is null");
        if (!Files.isDirectory(Objects.requireNonNull(dir, "dir is null"))) {
            throw new IllegalArgumentException("dir is not a directory: " + dir);
        }
        if (!Files.isRegularFile(Objects.requireNonNull(plain, "plain is null"))) {
            throw new IllegalArgumentException("plain is not a regular file: " + plain);
        }
        // ------------------------------------------------------------------------------------------------------- given
        final var inbuf = ByteBuffer.allocate(ThreadLocalRandom.current().nextInt(1024) + 1);
        var outbuf = ByteBuffer.allocate(1);
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
        try (var in = FileChannel.open(plain, StandardOpenOption.READ);
             var out = FileChannel.open(encrypted, StandardOpenOption.WRITE)) {
            while (in.read(inbuf) != -1) {
                for (inbuf.flip(); ; ) {
                    final var p = inbuf.position(); // TODO: remove!
                    try {
                        final var stored = cipher.update(inbuf, outbuf);
                        assert stored >= 0;
                        break;
                    } catch (final ShortBufferException sbe) {
                        assert inbuf.position() == p; // TODO: remove!
                        System.err.printf("doubling up outbuf.capacity from %1$d%n", outbuf.capacity());
                        outbuf = ByteBuffer.allocate(outbuf.capacity() << 1);
                    }
                }
                for (outbuf.flip(); outbuf.hasRemaining(); ) {
                    final var written = out.write(outbuf);
                    assert written >= 0;
                }
                outbuf.clear();
                inbuf.compact();
            }
            for (inbuf.flip(); ; ) {
                try {
                    final var stored = cipher.doFinal(inbuf, outbuf);
                    assert stored >= 0;
                    break;
                } catch (final ShortBufferException sbe) {
                    System.err.printf("doubling up outbuf.capacity from %1$d%n", outbuf.capacity());
                    outbuf = ByteBuffer.allocate(outbuf.capacity() << 1);
                }
            }
            for (outbuf.flip(); outbuf.hasRemaining(); ) {
                final var written = out.write(outbuf);
                assert written >= 0;
            }
            out.force(false);
        }
        // ----------------------------------------------------------------------------------------------------- decrypt
        inbuf.clear();
        outbuf.clear();
        if (params != null) {
            cipher.init(Cipher.DECRYPT_MODE, key, params);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key);
        }
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        final var decrypted = Files.createTempFile(dir, null, null);
        try (var in = FileChannel.open(encrypted, StandardOpenOption.READ);
             var out = FileChannel.open(decrypted, StandardOpenOption.WRITE)) {
            while (in.read(inbuf) != -1) {
                for (inbuf.flip(); ; ) {
                    final var p = inbuf.position(); // TODO: remove
                    try {
                        final var stored = cipher.update(inbuf, outbuf);
                        assert stored >= 0;
                        break;
                    } catch (final ShortBufferException sbe) {
                        assert inbuf.position() == p; // TODO: remove
                        System.err.printf("doubling up outbuf.capacity from %1$d%n", outbuf.capacity());
                        outbuf = ByteBuffer.allocate(outbuf.capacity() << 1);
                    }
                }
                for (outbuf.flip(); outbuf.hasRemaining(); ) {
                    final var written = out.write(outbuf);
                    assert written >= 0;
                }
                outbuf.clear();
                inbuf.compact();
            }
            for (inbuf.flip(); ; ) {
                final var p = inbuf.position(); // TODO: remove
                try {
                    final var stored = cipher.doFinal(inbuf, outbuf);
                    assert stored >= 0;
                    break;
                } catch (final ShortBufferException sbe) {
                    assert inbuf.position() == p; // TODO: remove
                    System.err.printf("doubling up outbuf.capacity from %1$d%n", outbuf.capacity());
                    outbuf = ByteBuffer.allocate(outbuf.capacity() << 1);
                }
            }
            for (outbuf.flip(); outbuf.hasRemaining(); ) {
                final var written = out.write(outbuf);
                assert written >= 0;
            }
            out.force(false);
        }
        // ------------------------------------------------------------------------------------------------------ verify
        assertThat(decrypted).hasSameBinaryContentAs(plain);
    }

    public static void __(@Nonnull final Cipher cipher, @Nonnull final Key key,
                          @Nullable final AlgorithmParameterSpec params, @Nullable final byte[] aad,
                          @Nonnull final Path dir)
            throws IOException {
        assertThat(cipher.getProvider().getName()).isEqualTo(BouncyCastleProvider.PROVIDER_NAME);
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
