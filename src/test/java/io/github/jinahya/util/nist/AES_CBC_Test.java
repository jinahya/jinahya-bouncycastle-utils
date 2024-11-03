package io.github.jinahya.util.nist;

import _javax.crypto._Cipher_TestUtils;
import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto._BufferedBlockCipher_TestUtils;
import _org.bouncycastle.crypto.paddings._BlockCipherPadding_TestUtils;
import io.github.jinahya.util._CBC_TestUtils;
import io.github.jinahya.util._JCEProviderTest;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
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
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A class for testing {@link AESEngine} with {@link CBCBlockCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class AES_CBC_Test
        extends AES__Test {

    @DisplayName("Low-level API")
    @Nested
    class LowLevelApiTest {

        private static Stream<Arguments> getPaddingAndKeySizeArgumentsStream() {
            return _BlockCipherPadding_TestUtils.getPaddingAndKeySizeArgumentsStream(
                    AES__Test::getKeySizeStream
            );
        }

        @DisplayName("encrypt/decrypt bytes")
        @MethodSource({"getPaddingAndKeySizeArgumentsStream"})
        @ParameterizedTest(name = "[{index}] {0} with {1}-bit key")
        void __(final BlockCipherPadding padding, final int keySize) throws Exception {
            final var cipher = new PaddedBufferedBlockCipher(
                    CBCBlockCipher.newInstance(AESEngine.newInstance()),
                    padding
            );
            final CipherParameters params;
            {
                final var key = _Random_TestUtils.newRandomBytes(keySize >>> 3);
                // initialisation vector must be the same length as block size
                final var iv = _Random_TestUtils.newRandomBytes(cipher.getBlockSize());
                params = ThreadLocalRandom.current().nextBoolean()
                        ? new KeyParameter(key)
                        : new ParametersWithIV(new KeyParameter(key), iv);
            }
            final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
            // ------------------------------------------------------------------------------------------------- encrypt
            cipher.init(true, params);
            var encrypted = new byte[cipher.getOutputSize(plain.length)];
            {
                final var processed = cipher.processBytes(plain, 0, plain.length, encrypted, 0);
                final var finalized = cipher.doFinal(encrypted, processed);
                encrypted = Arrays.copyOf(encrypted, (processed + finalized));
                assertThat(encrypted).hasSizeGreaterThanOrEqualTo(plain.length);
            }
            // ------------------------------------------------------------------------------------------------- decrypt
            cipher.init(false, params);
            byte[] decrypted = new byte[cipher.getOutputSize(encrypted.length)];
            {
                final var processed = cipher.processBytes(encrypted, 0, encrypted.length, decrypted, 0);
                final var finalized = cipher.doFinal(decrypted, processed);
                decrypted = Arrays.copyOf(decrypted, (processed + finalized));
            }
            // -------------------------------------------------------------------------------------------------- verify
            assertThat(decrypted).isEqualTo(plain);
        }

        @DisplayName("encrypt/decrypt file")
        @MethodSource({"getPaddingAndKeySizeArgumentsStream"})
        @ParameterizedTest(name = "[{index}] {0} with {1}-bit key")
        void __(final BlockCipherPadding padding, final int keySize, @TempDir final File dir) throws IOException {
            final var cipher = new PaddedBufferedBlockCipher(
                    CBCBlockCipher.newInstance(AESEngine.newInstance()),
                    padding
            );
            final CipherParameters params;
            {
                final var key = _Random_TestUtils.newRandomBytes(keySize >>> 3);
                final var iv = _Random_TestUtils.newRandomBytes(cipher.getBlockSize());
                params = ThreadLocalRandom.current().nextBoolean()
                        ? new KeyParameter(key)
                        : new ParametersWithIV(new KeyParameter(key), iv);
            }
            final var plain = _Random_TestUtils.createTempFileWithRandomBytesWritten(dir);
            // ------------------------------------------------------------------------------------------------- encrypt
            final var encrypted = File.createTempFile("tmp", null, dir);
            {
                cipher.init(true, params);
                try (var out = new CipherOutputStream(new FileOutputStream(encrypted), cipher)) {
                    Files.copy(plain.toPath(), out);
                    out.flush();
                }
                assertThat(encrypted.length()).isGreaterThanOrEqualTo(plain.length());
            }
            // ------------------------------------------------------------------------------------------------- decrypt
            final var decrypted = File.createTempFile("tmp", null, dir);
            {
                cipher.init(false, params);
                try (var in = new CipherInputStream(new FileInputStream(encrypted), cipher)) {
                    Files.copy(in, decrypted.toPath(), StandardCopyOption.REPLACE_EXISTING);
                }
            }
            // -------------------------------------------------------------------------------------------------- verify
            assertThat(decrypted).hasSameBinaryContentAs(plain);
        }

        private static Stream<Arguments> getCipherAndParamsArgumentsStream() {
            return _CBC_TestUtils.getCipherAndParamsArgumentsStream(
                    AES__Test::getKeySizeStream,
                    AESEngine::newInstance
            );
        }

        @DisplayName("encrypt/decrypt bytes")
        @MethodSource({"getCipherAndParamsArgumentsStream"})
        @ParameterizedTest
        void __(final BufferedBlockCipher cipher, final CipherParameters params) throws Exception {
            _BufferedBlockCipher_TestUtils.__(cipher, params);
        }

        @DisplayName("encrypt/decrypt file")
        @MethodSource({"getCipherAndParamsArgumentsStream"})
        @ParameterizedTest
        void __(final BufferedBlockCipher cipher, final CipherParameters params, @TempDir final File dir)
                throws Exception {
            _BufferedBlockCipher_TestUtils.__(cipher, params, dir);
        }
    }

    @DisplayName("JCE Provider")
    @Nested
    class JCEProviderTest
            extends _JCEProviderTest {

        private static Stream<Arguments> getTransformationAndKeySizeArgumentsStream() {
            return Stream.of("PKCS5Padding")
                    .map(p -> ALGORITHM + '/' + _CBC_TestUtils.MODE + '/' + p)
                    .flatMap(t -> getKeySizeStream().mapToObj(ks -> Arguments.of(t, ks)));
        }

        @DisplayName("encrypt/decrypt bytes")
        @MethodSource({"getTransformationAndKeySizeArgumentsStream"})
        @ParameterizedTest(name = "[{index}] {0} with {1}-bit key")
        void __(final String transformation, final int keySize) throws Exception {
            final var cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
            final var key = new SecretKeySpec(_Random_TestUtils.newRandomBytes(keySize >> 3), ALGORITHM);
            final var params = new IvParameterSpec(_Random_TestUtils.newRandomBytes(BLOCK_BYTES));
            _Cipher_TestUtils.__(cipher, key, params, null);
        }

        @DisplayName("encrypt/decrypt file")
        @MethodSource({"getTransformationAndKeySizeArgumentsStream"})
        @ParameterizedTest(name = "[{index}] {0} with {1}-bit key")
        void __(final String transformation, final int keySize, @TempDir final Path dir) throws Exception {
            final var cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
            final var key = new SecretKeySpec(_Random_TestUtils.newRandomBytes(keySize >> 3), ALGORITHM);
            final var params = new IvParameterSpec(_Random_TestUtils.newRandomBytes(BLOCK_BYTES));
            _Cipher_TestUtils.__(cipher, key, params, null, dir);
        }
    }
}
