package symmetric.aes;

import _javax.crypto._Cipher_TestUtils;
import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto._BufferedBlockCipher_TestUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import symmetric._ECB_TestUtils;
import symmetric._JCEProviderTest;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Function;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
class AES_ECB_Test
        extends AES__Test {

    @DisplayName("Low-level API")
    @Nested
    class LowLevelApiTest {

        private static Stream<Arguments> getPaddingAndKeySizeArgumentsStream() {
            return _ECB_TestUtils.getPaddingAndKeySizeArgumentsStream(
                    AES__Test::getKeySizeStream
            );
        }

        @DisplayName("encrypt/decrypt bytes")
        @MethodSource({"getPaddingAndKeySizeArgumentsStream"})
        @ParameterizedTest(name = "[{index}] {0} with {1}-bit key")
        void __(final BlockCipherPadding padding, final int keySize) throws InvalidCipherTextException {
            final var cipher = new PaddedBufferedBlockCipher(AESEngine.newInstance(), padding);
            final var key = _Random_TestUtils.newRandomBytes(keySize >>> 3);
            final var params = new KeyParameter(key);
            final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
            // ------------------------------------------------------------------------------------------------- encrypt
            cipher.init(true, params);
            var encrypted = new byte[cipher.getOutputSize(plain.length)];
            {
                final var processed = cipher.processBytes(plain, 0, plain.length, encrypted, 0);
                final var finalized = cipher.doFinal(encrypted, processed);
                encrypted = Arrays.copyOf(encrypted, (processed + finalized));
            }
            // ------------------------------------------------------------------------------------------------- decrypt
            cipher.init(false, params);
            byte[] decrypted = new byte[cipher.getOutputSize(encrypted.length)];
            {
                final var processed = cipher.processBytes(encrypted, 0, encrypted.length, decrypted, 0);
                final var finalized = cipher.doFinal(decrypted, processed);
                decrypted = Arrays.copyOf(decrypted, (processed + finalized));
            }
            // ---------------------------------------------------------------------------------------------------- then
            assertThat(decrypted).isEqualTo(plain);
        }

        @DisplayName("encrypt/decrypt file")
        @MethodSource({"getPaddingAndKeySizeArgumentsStream"})
        @ParameterizedTest(name = "[{index}] {0} with {1}-bit key")
        void __(final BlockCipherPadding padding, final int keySize, @TempDir final Path dir) throws Exception {
            final var cipher = new PaddedBufferedBlockCipher(AESEngine.newInstance(), padding);
            final var key = _Random_TestUtils.newRandomBytes(keySize >>> 3);
            final var params = new KeyParameter(key);
            final var plain = Files.createTempFile(dir, null, null);
            {
                final var bytes = new byte[ThreadLocalRandom.current().nextInt(1024)];
                ThreadLocalRandom.current().nextBytes(bytes);
                Files.write(plain, bytes);
            }
            // ------------------------------------------------------------------------------------------------- encrypt
            cipher.init(true, params);
            final var encrypted = Files.createTempFile(dir, null, null);
            try (var out = new CipherOutputStream(new FileOutputStream(encrypted.toFile()), cipher)) {
                Files.copy(plain, out);
                out.flush();
            }
            // ------------------------------------------------------------------------------------------------- decrypt
            final var decrypted = Files.createTempFile(dir, null, null);
            cipher.init(false, params);
            try (var in = new CipherInputStream(new FileInputStream(encrypted.toFile()), cipher)) {
                Files.copy(in, decrypted, StandardCopyOption.REPLACE_EXISTING);
            }
            // -------------------------------------------------------------------------------------------------- verify
            assertThat(decrypted).hasSameBinaryContentAs(plain);
        }

        private static Stream<Arguments> getCipherAndParamsArgumentsStream() {
            return _ECB_TestUtils.getArgumentsStream(
                    AES__Test::getKeySizeStream,
                    AESEngine::newInstance
            );
        }

        @MethodSource({"getCipherAndParamsArgumentsStream"})
        @ParameterizedTest
        void __(final BufferedBlockCipher cipher, final CipherParameters params) throws Exception {
            _BufferedBlockCipher_TestUtils.__(cipher, params);
        }

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
            return getKeySizeStream().mapToObj(ks -> {
                return Stream.of("PKCS5Padding")
                        .map(p -> ALGORITHM + '/' + _ECB_TestUtils.MODE + '/' + p)
                        .map(t -> Arguments.of(t, ks));
            }).flatMap(Function.identity());
        }

        @DisplayName("encrypt/decrypt bytes")
        @MethodSource({"getTransformationAndKeySizeArgumentsStream"})
        @ParameterizedTest(name = "[{index}] {0} with {1}-bit key")
        void __(final String transformation, final int keySize) throws Throwable {
            final var cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
            final var key = new SecretKeySpec(_Random_TestUtils.newRandomBytes(keySize >> 3), ALGORITHM);
            _Cipher_TestUtils.__(cipher, key, null, null);
        }

        @DisplayName("encrypt/decrypt file")
        @MethodSource({"getTransformationAndKeySizeArgumentsStream"})
        @ParameterizedTest(name = "[{index}] {0} with {1}-bit key")
        void __(final String transformation, final int keySize, @TempDir final Path dir) throws Throwable {
            final var cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
            final var key = new SecretKeySpec(_Random_TestUtils.newRandomBytes(keySize >> 3), ALGORITHM);
            _Cipher_TestUtils.__(cipher, key, null, (byte[]) null, dir);
        }
    }
}
