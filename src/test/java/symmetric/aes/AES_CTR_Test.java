package symmetric.aes;

import _javax.crypto._Cipher_TestUtils;
import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto._StreamCipher_TestUtils;
import symmetric._CTR_TestUtils;
import symmetric._JCEProviderTest;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Named;
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
import java.util.function.Function;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A class for testing {@link AESEngine} with {@link SICBlockCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class AES_CTR_Test
        extends AES__Test {

    @Nested
    class LowLevelApiTest {

        private static Stream<Arguments> getKeySizeArgumentsStream_() {
            return getKeySizeArgumentsStream();
        }

        @MethodSource({"getKeySizeArgumentsStream_"})
        @ParameterizedTest
        void __(final int keySize) {
            final var cipher = SICBlockCipher.newInstance(AESEngine.newInstance());
            final var key = _Random_TestUtils.newRandomBytes(keySize >> 3);
            final var iv = _Random_TestUtils.newRandomBytes(BLOCK_BYTES);
            final var params = new ParametersWithIV(new KeyParameter(key), iv);
            final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
            // ------------------------------------------------------------------------------------------------- encrypt
            final byte[] encrypted = new byte[plain.length];
            {
                cipher.init(true, params);
                final var processed = cipher.processBytes(plain, 0, plain.length, encrypted, 0);
                assertThat(processed).isEqualTo(encrypted.length);
            }
            // ------------------------------------------------------------------------------------------------- decrypt
            final byte[] decrypted = new byte[encrypted.length];
            {
                cipher.init(false, params);
                final var processed = cipher.processBytes(encrypted, 0, encrypted.length, decrypted, 0);
                assertThat(processed).isEqualTo(decrypted.length);
            }
            // ---------------------------------------------------------------------------------------------------- then
            assertThat(decrypted).isEqualTo(plain);
        }

        @MethodSource({"getKeySizeArgumentsStream_"})
        @ParameterizedTest
        void __(final int keySize, @TempDir final File dir) throws IOException {
            final var cipher = SICBlockCipher.newInstance(AESEngine.newInstance());
            final var key = _Random_TestUtils.newRandomBytes(keySize >> 3);
            final var iv = _Random_TestUtils.newRandomBytes(BLOCK_BYTES);
            final var params = new ParametersWithIV(new KeyParameter(key), iv);
            final var plain = _Random_TestUtils.createTempFileWithRandomBytesWritten(dir);
            // ------------------------------------------------------------------------------------------------- encrypt
            final var encrypted = File.createTempFile("tmp", null, dir);
            cipher.init(true, params);
            try (var out = new CipherOutputStream(new FileOutputStream(encrypted), cipher)) {
                final var bytes = Files.copy(plain.toPath(), out);
                assertThat(bytes).isEqualTo(plain.length());
                out.flush();
            }
            // ------------------------------------------------------------------------------------------------- decrypt
            final var decrypted = File.createTempFile("tmp", null, dir);
            cipher.init(false, params);
            try (var in = new CipherInputStream(new FileInputStream(encrypted), cipher)) {
                final var bytes = Files.copy(in, decrypted.toPath(), StandardCopyOption.REPLACE_EXISTING);
                assertThat(bytes).isEqualTo(encrypted.length());
            }
            // ---------------------------------------------------------------------------------------------------- then
            assertThat(decrypted).hasSameBinaryContentAs(plain);
        }

        private static Stream<Arguments> getCipherAndParamsArgumentsStream() {
            return _CTR_TestUtils.getCipherAndParamsArgumentsStream(
                    AES__Test::getKeySizeStream,
                    AESEngine::newInstance
            );
        }

        @MethodSource({"getCipherAndParamsArgumentsStream"})
        @ParameterizedTest
        void __(final StreamCipher cipher, final CipherParameters params) throws Exception {
            _StreamCipher_TestUtils.__(cipher, params);
        }

        @MethodSource({"getCipherAndParamsArgumentsStream"})
        @ParameterizedTest
        void __(final StreamCipher cipher, final CipherParameters params, @TempDir final File dir)
                throws Exception {
            _StreamCipher_TestUtils.__(cipher, params, dir);
        }
    }

    @Nested
    class JCEProviderTest
            extends _JCEProviderTest {

        private static Stream<Arguments> getKeySizeAndTransformationArgumentsStream() {
            return getKeySizeStream().mapToObj(ks -> {
                return Stream.of("NoPadding")
                        .map(p -> ALGORITHM + '/' + _CTR_TestUtils.MODE + '/' + p)
                        .map(t -> Arguments.of(
                                Named.of("keySize: " + ks, ks),
                                Named.of("transformation: " + t, t)
                        ));
            }).flatMap(Function.identity());
        }

        @MethodSource({"getKeySizeAndTransformationArgumentsStream"})
        @ParameterizedTest
        void __(final int keySize, final String transformation) throws Throwable {
            final var cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
            final var key = new SecretKeySpec(_Random_TestUtils.newRandomBytes(keySize >> 3), ALGORITHM);
            final var params = new IvParameterSpec(_Random_TestUtils.newRandomBytes(BLOCK_BYTES));
            _Cipher_TestUtils.__(cipher, key, params, (byte[]) null);
        }

        @MethodSource({"getKeySizeAndTransformationArgumentsStream"})
        @ParameterizedTest
        void __(final int keySize, final String transformation, @TempDir final Path dir) throws Throwable {
            final var cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
            final var key = new SecretKeySpec(_Random_TestUtils.newRandomBytes(keySize >> 3), ALGORITHM);
            final var params = new IvParameterSpec(_Random_TestUtils.newRandomBytes(BLOCK_BYTES));
            _Cipher_TestUtils.__(cipher, key, params, (byte[]) null, dir);
        }
    }
}
