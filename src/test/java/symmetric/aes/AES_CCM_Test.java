package symmetric.aes;

import _javax.crypto._Cipher_TestUtils;
import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto.modes._AEADCipher_TestUtils;
import symmetric._CCM_TestUtils;
import symmetric._JCEProviderTest;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
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
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class AES_CCM_Test
        extends AES__Test {

    @DisplayName("Low-level API")
    @Nested
    class LowLevelApiTest {

        private static Stream<Arguments> getKeySizeAndTagLengthArgumentsStream() {
            return _CCM_TestUtils.getKeySizeAndTagLengthArgumentsStream(
                    AES__Test::getKeySizeStream
            );
        }

        @DisplayName("encrypt/decrypt bytes")
        @MethodSource({"getKeySizeAndTagLengthArgumentsStream"})
        @ParameterizedTest(name = "[{index}] {0}-bit key with {1}-long tag length")
        void __(final int keySize, final int tagLength) throws InvalidCipherTextException {
            final var key = _Random_TestUtils.newRandomBytes(keySize >> 3);
            final var macSize = tagLength << 3;
            // nonce must have length from 7 to 13 octets
            final var nonce = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(7, 14));
            final var associatedText = ThreadLocalRandom.current().nextBoolean()
                    ? null
                    : _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
            final var cipher = CCMBlockCipher.newInstance(AESEngine.newInstance());
            final var params = new AEADParameters(new KeyParameter(key), macSize, nonce, associatedText);
            final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
            // ------------------------------------------------------------------------------------------------- encrypt
            cipher.init(true, params);
            final var encrypted = new byte[cipher.getOutputSize(plain.length)];
            {
                final var processed = cipher.processBytes(plain, 0, plain.length, encrypted, 0);
                if (associatedText != null) {
                    cipher.processAADBytes(associatedText, 0, associatedText.length);
                }
                final var finalized = cipher.doFinal(encrypted, processed);
                assert (processed + finalized) == encrypted.length;
            }
            final var encryptionMac = cipher.getMac();
            // ------------------------------------------------------------------------------------------------- decrypt
            cipher.init(false, params);
            final var decrypted = new byte[cipher.getOutputSize(encrypted.length)];
            {
                final var processed = cipher.processBytes(encrypted, 0, encrypted.length, decrypted, 0);
                if (associatedText != null) {
                    cipher.processAADBytes(associatedText, 0, associatedText.length);
                }
                final var finalized = cipher.doFinal(decrypted, processed);
                assert (processed + finalized) == decrypted.length;
            }
            final var decryptionMac = cipher.getMac();
            // -------------------------------------------------------------------------------------------------- verify
            assertThat(decrypted).isEqualTo(plain);
            assertThat(decryptionMac).isEqualTo(encryptionMac);
        }

        @DisplayName("encrypt/decrypt file")
        @MethodSource({"getKeySizeAndTagLengthArgumentsStream"})
        @ParameterizedTest(name = "[{index}] {0}-bit key with {1}-long tag length")
        void __(final int keySize, final int tagLength, @TempDir final File dir) throws IOException {
            final var key = _Random_TestUtils.newRandomBytes(keySize >> 3);
            final var macSize = tagLength << 3;
            final var nonce = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(7, 14));
            final var associatedText = ThreadLocalRandom.current().nextBoolean()
                    ? null
                    : _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
            final var cipher = CCMBlockCipher.newInstance(AESEngine.newInstance());
            final var params = new AEADParameters(new KeyParameter(key), macSize, nonce, associatedText);
            final var plain = File.createTempFile("tmp", null, dir);
            {
                final var bytes = new byte[ThreadLocalRandom.current().nextInt(1024)];
                ThreadLocalRandom.current().nextBytes(bytes);
                Files.write(plain.toPath(), bytes);
            }
            // ------------------------------------------------------------------------------------------------- encrypt
            final var encrypted = File.createTempFile("tmp", null, dir);
            {
                cipher.init(true, params);
                try (var out = new CipherOutputStream(new FileOutputStream(encrypted), cipher)) {
                    Files.copy(plain.toPath(), out);
                    out.flush();
                }
            }
            final var encryptionMac = cipher.getMac();
            // ------------------------------------------------------------------------------------------------- decrypt
            final var decrypted = File.createTempFile("tmp", null, dir);
            {
                cipher.init(false, params);
                try (var in = new CipherInputStream(new FileInputStream(encrypted), cipher)) {
                    Files.copy(in, decrypted.toPath(), StandardCopyOption.REPLACE_EXISTING);
                }
            }
            final var decryptionMac = cipher.getMac();
            // -------------------------------------------------------------------------------------------------- verify
            assertThat(decrypted).hasSameBinaryContentAs(plain);
            assertThat(decryptionMac).isEqualTo(encryptionMac);
        }

        private static Stream<Arguments> getCipherAndParamsArgumentsStream() {
            return _CCM_TestUtils.getCipherAndParamsArgumentsStream(
                    AES__Test::getKeySizeStream,
                    AESEngine::newInstance
            );
        }

        @DisplayName("encrypt/decrypt bytes")
        @MethodSource({"getCipherAndParamsArgumentsStream"})
        @ParameterizedTest
        void __(final AEADCipher cipher, final CipherParameters params) throws Exception {
            _AEADCipher_TestUtils.__(cipher, params);
        }

        @DisplayName("encrypt/decrypt file")
        @MethodSource({"getCipherAndParamsArgumentsStream"})
        @ParameterizedTest
        void __(final AEADCipher cipher, final CipherParameters params, @TempDir final File dir) throws Exception {
            _AEADCipher_TestUtils.__(cipher, params, dir);
        }
    }

    @DisplayName("JCE Provider")
    @Nested
    class JCEProviderTest
            extends _JCEProviderTest {

        private static Stream<Arguments> getTransformationAndKeySizeArgumentsStream() {
            return Stream.of("NoPadding")
                    .map(p -> ALGORITHM + '/' + _CCM_TestUtils.MODE + '/' + p)
                    .flatMap(t -> getKeySizeStream().mapToObj(ks -> Arguments.of(t, ks)));
        }

        @MethodSource({"getTransformationAndKeySizeArgumentsStream"})
        @ParameterizedTest(name = "[{index}] {0} with {1}-bit key")
        void __(final String transformation, final int keySize) throws Exception {
            final var cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
            final var key = new SecretKeySpec(_Random_TestUtils.newRandomBytes(keySize >> 3), ALGORITHM);
            final var params = new IvParameterSpec(_CCM_TestUtils.newBouncyCastleNonce());
            _Cipher_TestUtils.__(cipher, key, params, (byte[]) null);
        }

        @MethodSource({"getTransformationAndKeySizeArgumentsStream"})
        @ParameterizedTest(name = "[{index}] {0} with {1}-bit key")
        void __(final String transformation, final int keySize, @TempDir final Path dir) throws Exception {
            final var cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
            final var key = new SecretKeySpec(_Random_TestUtils.newRandomBytes(keySize >> 3), ALGORITHM);
            final var params = new IvParameterSpec(_CCM_TestUtils.newBouncyCastleNonce());
            _Cipher_TestUtils.__(cipher, key, params, (byte[]) null, dir);
        }
    }
}
