package symmetric.aes;

import _javax.crypto._Cipher_TestUtils;
import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto._StreamCipher_TestUtils;
import symmetric._JCEProviderTest;
import symmetric._OFB_TestUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamBlockCipher;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class AES_OFB_Test
        extends AES__Test {

    @Nested
    class LowLevelApiTest {

        private static Stream<Arguments> getBitWidthAndKeySizeArgumentsStream_() {
            return _OFB_TestUtils.getBitWidthAndKeySizeArgumentsStream(
                    AES__Test::getKeySizeStream
            );
        }

        @DisplayName("encrypt/decrypt bytes")
        @MethodSource({"getBitWidthAndKeySizeArgumentsStream_"})
        @ParameterizedTest(name = "[{index}] bitWidth: {0}, keySize: {1}")
        void __(final int bitWidth, final int keySize) {
            final StreamBlockCipher cipher;
            try {
                cipher = new OFBBlockCipher(AESEngine.newInstance(), bitWidth);
            } catch (final IllegalArgumentException iae) {
                log.error("failed to create cipher instance for bitWidth: {}", bitWidth, iae);
                return;
            }
            final CipherParameters params;
            {
                final var key = _Random_TestUtils.newRandomBytes(keySize >> 3);
                final var iv = _Random_TestUtils.newRandomBytes(cipher.getBlockSize());
                params = new ParametersWithIV(new KeyParameter(key), iv);
            }
            final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(128));
            // -------------------------------------------------------------------------------------------------- encrypt
            final var encrypted = new byte[plain.length];
            {
                cipher.init(true, params);
                final var processed = cipher.processBytes(plain, 0, plain.length, encrypted, 0);
                assert processed == encrypted.length;
            }
            // ------------------------------------------------------------------------------------------------- decrypt
            final var decrypted = new byte[encrypted.length];
            {
                cipher.init(false, params);
                final var processed = cipher.processBytes(encrypted, 0, encrypted.length, decrypted, 0);
                assert processed == decrypted.length;
            }
            // -------------------------------------------------------------------------------------------------- verify
            assertThat(decrypted).isEqualTo(plain);
        }

        @DisplayName("encrypt/decrypt file")
        @MethodSource({"getBitWidthAndKeySizeArgumentsStream_"})
        @ParameterizedTest(name = "[{index}] bitWidth: {0}, keySize: {1}")
        void __(final int bitWidth, final int keySize, @TempDir final File dir) throws IOException {
            final StreamBlockCipher cipher;
            try {
                cipher = new OFBBlockCipher(AESEngine.newInstance(), bitWidth);
            } catch (final IllegalArgumentException iae) {
                log.error("failed to create cipher instance for bitWidth: {}", bitWidth, iae);
                return;
            }
            final CipherParameters params;
            {
                final var key = _Random_TestUtils.newRandomBytes(keySize >> 3);
                final var iv = _Random_TestUtils.newRandomBytes(cipher.getBlockSize());
                params = new ParametersWithIV(new KeyParameter(key), iv);
            }
            final var plain = _Random_TestUtils.createTempFileWithRandomBytesWritten(dir);
            // ------------------------------------------------------------------------------------------------- encrypt
            final var encrypted = File.createTempFile("tmp", null, dir);
            {
                cipher.init(true, params);
                try (final var out = new CipherOutputStream(new FileOutputStream(encrypted), cipher)) {
                    final var bytes = Files.copy(plain.toPath(), out);
                    // the encrypted ciphertext data to be the same size as the original plaintext dat
                    assert bytes == plain.length();
                    out.flush();
                }
                assertThat(encrypted).hasSize(plain.length());
            }
            // ------------------------------------------------------------------------------------------------- decrypt
            final var decrypted = File.createTempFile("tmp", null, dir);
            {
                cipher.init(false, params);
                try (final var in = new CipherInputStream(new FileInputStream(encrypted), cipher)) {
                    final var bytes = Files.copy(in, decrypted.toPath(), StandardCopyOption.REPLACE_EXISTING);
                    assert bytes == plain.length();
                }
                assertThat(decrypted).hasSize(encrypted.length());
            }
            // -------------------------------------------------------------------------------------------------- verify
            assertThat(decrypted).hasSameBinaryContentAs(plain);
        }

        private static Stream<Arguments> getCipherAndParamsArgumentsStream_() {
            return _OFB_TestUtils.getCipherAndParamsArgumentsStream(
                    AES__Test::getKeySizeStream,
                    AESEngine::newInstance
            );
        }

        @MethodSource({"getCipherAndParamsArgumentsStream_"})
        @ParameterizedTest
        void __(final StreamCipher cipher, final CipherParameters params) {
            _StreamCipher_TestUtils.__(cipher, params);
        }

        @MethodSource({"getCipherAndParamsArgumentsStream_"})
        @ParameterizedTest
        void __(final StreamBlockCipher cipher, final CipherParameters params, @TempDir final File dir)
                throws Exception {
            _StreamCipher_TestUtils.__(cipher, params, dir);
        }
    }

    @Nested
    class JCEProviderTest
            extends _JCEProviderTest {

        private static Stream<Arguments> getTransformationAndKeySizeArgumentsStream() {
            return Stream.of("NoPadding")
                    .map(p -> ALGORITHM + '/' + _OFB_TestUtils.MODE + '/' + p)
                    .flatMap(t -> getKeySizeStream().mapToObj(ks -> {
                        return Arguments.of(t, ks);
                    }));
        }

        @DisplayName("encrypt/decrypt bytes")
        @MethodSource({"getTransformationAndKeySizeArgumentsStream"})
        @ParameterizedTest(name = "[{index}] transformation: {0}, keySize: {1}")
        void __(final String transformation, final int keySize) throws Throwable {
            final Cipher cipher;
            try {
                cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
            } catch (final NoSuchAlgorithmException nsae) {
                log.error("failed to get cipher for '{}'", transformation, nsae);
                return;
            }
            final var key = new SecretKeySpec(_Random_TestUtils.newRandomBytes(keySize >> 3), ALGORITHM);
            final var params = new IvParameterSpec(_Random_TestUtils.newRandomBytes(BLOCK_BYTES));
            _Cipher_TestUtils.__(cipher, key, params, null);
        }

        @DisplayName("encrypt/decrypt file")
        @MethodSource({"getTransformationAndKeySizeArgumentsStream"})
        @ParameterizedTest(name = "[{index}] transformation: {0}, keySize: {1}, ")
        void __(final String transformation, final int keySize, @TempDir final Path dir) throws Throwable {
            final Cipher cipher;
            try {
                cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
            } catch (final NoSuchAlgorithmException nsae) {
                log.error("failed to get cipher for '{}'", transformation, nsae);
                return;
            }
            final var key = new SecretKeySpec(_Random_TestUtils.newRandomBytes(keySize >> 3), ALGORITHM);
            final var params = new IvParameterSpec(_Random_TestUtils.newRandomBytes(BLOCK_BYTES));
            _Cipher_TestUtils.__(cipher, key, params, null, dir);
        }

        private static Stream<Arguments> getTransformationWithBitWidthAndKeySizeArgumentsStream() {
            return _OFB_TestUtils.getBitWidthStream()
                    .mapToObj(_OFB_TestUtils::mode)
                    .flatMap(m -> {
                        return Stream.of("NoPadding")
                                .map(p -> ALGORITHM + '/' + m + '/' + p);
                    })
                    .flatMap(t -> getKeySizeStream().mapToObj(ks -> {
                        return Arguments.of(t, ks);
                    }));
        }

        @DisplayName("encrypt/decrypt bytes")
        @MethodSource({"getTransformationWithBitWidthAndKeySizeArgumentsStream"})
        @ParameterizedTest(name = "[{index}] {0} with {1}-bit key")
        void __bitWidth(final String transformation, final int keySize) throws Throwable {
            final Cipher cipher;
            try {
                cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
            } catch (final NoSuchAlgorithmException nsae) {
                log.error("failed to get cipher for '{}'", transformation, nsae);
                return;
            }
            final var key = new SecretKeySpec(_Random_TestUtils.newRandomBytes(keySize >> 3), ALGORITHM);
            final var params = new IvParameterSpec(_Random_TestUtils.newRandomBytes(BLOCK_BYTES));
            _Cipher_TestUtils.__(cipher, key, params, null);
        }

        @DisplayName("encrypt/decrypt file")
        @MethodSource({"getTransformationWithBitWidthAndKeySizeArgumentsStream"})
        @ParameterizedTest(name = "[{index}] {0} with {1}-bit key")
        void __bitWidth(final String transformation, final int keySize, @TempDir final Path dir) throws Throwable {
            final Cipher cipher;
            try {
                cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
            } catch (final NoSuchAlgorithmException nsae) {
                log.error("failed to get cipher for '{}'", transformation, nsae);
                return;
            }
            final var key = new SecretKeySpec(_Random_TestUtils.newRandomBytes(keySize >> 3), ALGORITHM);
            final var params = new IvParameterSpec(_Random_TestUtils.newRandomBytes(BLOCK_BYTES));
            _Cipher_TestUtils.__(cipher, key, params, null, dir);
        }
    }
}
