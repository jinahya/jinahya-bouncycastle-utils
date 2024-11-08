package symmetric.aes.vanilla;

import _javax.security._Random_TestUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A class for testing {@value AES_ECB_PKCS5Padding_Test#TRANSFORMATION} with
 * {@value AES_ECB_PKCS5Padding_Test#PROVIDER_NAME_SUN_JCE} and
 * {@value AES_ECB_PKCS5Padding_Test#PROVIDER_NAME_BOUNCY_CASTLE}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class AES_ECB_PKCS5Padding_Test {

    // ------------------------------------------------------------------------------------------------------------- AES
    private static final String ALGORITHM = "AES";

    private static final String MODE = "ECB";

    private static final String PADDING = "PKCS5Padding";

    private static final String TRANSFORMATION = ALGORITHM + '/' + MODE + '/' + PADDING;

    private static final int BLOCK_SIZE = 128;

    private static IntStream getKeySizesStream() {
        return IntStream.of(128, 192, 256)
                .peek(ks -> {
                    assert ks % (BLOCK_SIZE >> 3) == 0;
                });
    }

    // -------------------------------------------------------------------------------------------------------- Security
    private static final String PROVIDER_NAME_SUN_JCE = "SunJCE";

    private static final String PROVIDER_NAME_BOUNCY_CASTLE = "BC";

    @BeforeAll
    static void addBouncyCastleProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @AfterAll
    static void removeBouncyCastleProvider() {
        Security.removeProvider(PROVIDER_NAME_BOUNCY_CASTLE);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private static Stream<Arguments> getProviderAndKeySizeArgumentsStream() {
        return Stream.of(PROVIDER_NAME_SUN_JCE, PROVIDER_NAME_BOUNCY_CASTLE)
                .flatMap(p -> getKeySizesStream().mapToObj(ks -> Arguments.of(p, ks)));
    }

    @MethodSource({"getProviderAndKeySizeArgumentsStream"})
    @ParameterizedTest(name = "[{index}] provider: {0}, keySize: {1}")
    void __(final String provider, final int keySize, @TempDir final Path dir)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
                   NoSuchProviderException,
                   InvalidKeyException,
                   IllegalBlockSizeException, BadPaddingException,
                   IOException {
        final Cipher cipher;
        {
            if (provider.equals(PROVIDER_NAME_SUN_JCE)) {
                if (ThreadLocalRandom.current().nextBoolean()) {
                    cipher = Cipher.getInstance(TRANSFORMATION);
                } else {
                    cipher = Cipher.getInstance(TRANSFORMATION, provider);
                }
            } else {
                cipher = Cipher.getInstance(TRANSFORMATION, provider);
            }
            assert cipher.getProvider().getName().equals(provider);
        }
        final SecretKeySpec key;
        {
            final var bytes = new byte[keySize >> 3];
            ThreadLocalRandom.current().nextBytes(bytes);
            key = new SecretKeySpec(bytes, ALGORITHM);
        }
        // --------------------------------------------------------------------------------------------------- bytes
        {
            final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8192));
            // --------------------------------------------------------------------------------------------- encrypt
            cipher.init(Cipher.ENCRYPT_MODE, key);
            final var encrypted = cipher.doFinal(plain);
            // --------------------------------------------------------------------------------------------- decrypt
            cipher.init(Cipher.DECRYPT_MODE, key);
            final var decrypted = cipher.doFinal(encrypted);
            // ---------------------------------------------------------------------------------------------- verify
            assertThat(decrypted).isEqualTo(plain);
        }
        // -------------------------------------------------------------------------------------------------- stream
        {
            final var plain = File.createTempFile("tmp", null, dir.toFile());
            try (final var out = new FileOutputStream(plain)) {
                final var bytes = new byte[ThreadLocalRandom.current().nextInt(8192)];
                ThreadLocalRandom.current().nextBytes(bytes);
                out.write(bytes);
            }
            // --------------------------------------------------------------------------------------------- encrypt
            final var encrypted = File.createTempFile("tmp", null, dir.toFile());
            cipher.init(Cipher.ENCRYPT_MODE, key);
            try (var in = new FileInputStream(plain);
                 var out = new javax.crypto.CipherOutputStream(new FileOutputStream(encrypted), cipher)) {
                final var buf = new byte[ThreadLocalRandom.current().nextInt(8192) + 1];
                for (int r; (r = in.read(buf)) != -1; ) {
                    out.write(buf, 0, r);
                }
                out.flush();
            }
            // --------------------------------------------------------------------------------------------- decrypt
            final var decrypted = File.createTempFile("tmp", null, dir.toFile());
            cipher.init(Cipher.DECRYPT_MODE, key);
            try (var in = new FileInputStream(encrypted);
                 var out = new javax.crypto.CipherOutputStream(new FileOutputStream(decrypted), cipher)) {
                final var buf = new byte[ThreadLocalRandom.current().nextInt(8192) + 1];
                for (int r; (r = in.read(buf)) != -1; ) {
                    out.write(buf, 0, r);
                }
                out.flush();
            }
            // ---------------------------------------------------------------------------------------------- verify
            assertThat(decrypted)
                    .hasSize(plain.length())
                    .hasSameBinaryContentAs(plain);
        }
        // ------------------------------------------------------------------------------------------------- channel
        {
            final var plain = Files.createTempFile(dir, null, null);
            {
                final var bytes = new byte[ThreadLocalRandom.current().nextInt(8192)];
                ThreadLocalRandom.current().nextBytes(bytes);
                Files.write(plain, bytes);
            }
            // --------------------------------------------------------------------------------------------- encrypt
            final var encrypted = Files.createTempFile(dir, null, null);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            try (var in = FileChannel.open(plain, StandardOpenOption.READ);
                 var out = FileChannel.open(encrypted, StandardOpenOption.WRITE)) {
                final var inbuf = ByteBuffer.allocate(ThreadLocalRandom.current().nextInt(8192) + 1);
                var outbuf = ByteBuffer.allocate(ThreadLocalRandom.current().nextInt(8192) + 1);
                while (in.read(inbuf) != -1) {
                    for (inbuf.flip(); ; ) {
                        try {
                            cipher.update(inbuf, outbuf);
                            break;
                        } catch (final ShortBufferException sbe) {
                            outbuf = ByteBuffer.allocate(outbuf.capacity() << 1);
                        }
                    }
                    inbuf.clear();
                    for (outbuf.flip(); outbuf.hasRemaining(); ) {
                        out.write(outbuf);
                    }
                    outbuf.clear();
                }
                for (inbuf.flip(); ; ) {
                    try {
                        cipher.doFinal(inbuf, outbuf);
                        break;
                    } catch (final ShortBufferException sbe) {
                        outbuf = ByteBuffer.allocate(outbuf.capacity() << 1);
                    }
                }
                for (outbuf.flip(); outbuf.hasRemaining(); ) {
                    out.write(outbuf);
                }
            }
            // --------------------------------------------------------------------------------------------- decrypt
            final var decrypted = Files.createTempFile(dir, null, null);
            cipher.init(Cipher.DECRYPT_MODE, key);
            try (var in = FileChannel.open(encrypted, StandardOpenOption.READ);
                 var out = FileChannel.open(decrypted, StandardOpenOption.WRITE)) {
                final var inbuf = ByteBuffer.allocate(ThreadLocalRandom.current().nextInt(8192) + 1);
                var outbuf = ByteBuffer.allocate(ThreadLocalRandom.current().nextInt(8192) + 1);
                while (in.read(inbuf) != -1) {
                    for (inbuf.flip(); ; ) {
                        try {
                            cipher.update(inbuf, outbuf);
                            break;
                        } catch (final ShortBufferException sbe) {
                            outbuf = ByteBuffer.allocate(outbuf.capacity() << 1);
                        }
                    }
                    inbuf.compact();
                    assert inbuf.position() == 0;
                    for (outbuf.flip(); outbuf.hasRemaining(); ) {
                        out.write(outbuf);
                    }
                    outbuf.clear();
                }
                assert inbuf.position() == 0;
                for (inbuf.flip(); ; ) {
                    try {
                        cipher.doFinal(inbuf, outbuf);
                        break;
                    } catch (final ShortBufferException sbe) {
                        outbuf = ByteBuffer.allocate(outbuf.capacity() << 1);
                    }
                }
                for (outbuf.flip(); outbuf.hasRemaining(); ) {
                    out.write(outbuf);
                }
            }
            // ---------------------------------------------------------------------------------------------- verify
            assertThat(decrypted)
                    .hasSize(Files.size(plain))
                    .hasSameBinaryContentAs(plain);
        }
    }
}
