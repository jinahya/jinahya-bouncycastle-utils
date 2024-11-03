package io.github.jinahya.util.nist;

import _javax.crypto._Cipher_TestUtils;
import _javax.security._Random_TestUtils;
import io.github.jinahya.util._GCM_TestUtils;
import io.github.jinahya.util._JCEProviderTest;
import io.github.jinahya.util.bouncycastle.crypto.modes._AEADCipher_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto.params.JinahyaKeyParametersUtils;
import io.github.jinahya.util.bouncycastle.crypto.params.JinahyaParametersWithIvUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Function;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class AES_GCM_Test
        extends AES__Test {

    @Nested
    class LowLevelAPI_Test {

        private static Stream<Arguments> getKeySizeArgumentsStream() {
            return getKeySizeStream()
                    .mapToObj(ks -> Arguments.of(Named.of("keySize: " + ks, ks)));
        }

        @MethodSource({"getKeySizeArgumentsStream"})
        @ParameterizedTest
        void __(final int keySize) throws Exception {
            final var key = JinahyaKeyParametersUtils.newRandomKey(null, keySize >> 3);
            // https://github.com/bcgit/bc-java/blob/99efbb53a33fbc4a159ac7ece4ec445198dd040b/core/src/main/java/org/bouncycastle/crypto/modes/GCMBlockCipher.java#L144
            final var macSize = ThreadLocalRandom.current().nextInt(32, 129) >> 3 << 3;
            // https://github.com/bcgit/bc-java/blob/99efbb53a33fbc4a159ac7ece4ec445198dd040b/core/src/main/java/org/bouncycastle/crypto/modes/GCMBlockCipher.java#L169
            final var nonce = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024) + 1);
            final var associatedText = ThreadLocalRandom.current().nextBoolean() ?
                    null : _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
            final var cipher = GCMBlockCipher.newInstance(AESEngine.newInstance());
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
            assertThat(decryptionMac).isEqualTo(encryptionMac);
            assertThat(decrypted).isEqualTo(plain);
        }

        @MethodSource({"getKeySizeArgumentsStream"})
        @ParameterizedTest
        void __(final int keySize, @TempDir final File dir) throws Exception {
            // ------------------------------------------------------------------------------------------------------- given
            final var key = JinahyaKeyParametersUtils.newRandomKey(null, keySize >> 3);
            // https://github.com/bcgit/bc-java/blob/99efbb53a33fbc4a159ac7ece4ec445198dd040b/core/src/main/java/org/bouncycastle/crypto/modes/GCMBlockCipher.java#L144
            final var macSize = ThreadLocalRandom.current().nextInt(32, 129) >> 3 << 3;
            // https://github.com/bcgit/bc-java/blob/99efbb53a33fbc4a159ac7ece4ec445198dd040b/core/src/main/java/org/bouncycastle/crypto/modes/GCMBlockCipher.java#L169
            final var nonce = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024) + 1);
            final var associatedText = ThreadLocalRandom.current().nextBoolean()
                    ? null
                    : _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
            final var cipher = GCMBlockCipher.newInstance(AESEngine.newInstance());
            final var params = new AEADParameters(new KeyParameter(key), macSize, nonce, associatedText);
            final var plain = _Random_TestUtils.createTempFileWithRandomBytesWritten(dir);
            // ----------------------------------------------------------------------------------------------------- encrypt
            final var encrypted = File.createTempFile("tmp", null, dir);
            cipher.init(true, params);
            try (var out = new CipherOutputStream(new FileOutputStream(encrypted), cipher)) {
                final var bytes = Files.copy(plain.toPath(), out);
                out.flush();
            }
            final var encryptionMac = cipher.getMac();
            // ----------------------------------------------------------------------------------------------------- decrypt
            final var decrypted = File.createTempFile("tmp", null, dir);
            cipher.init(false, params);
            try (var input = new CipherInputStream(new FileInputStream(encrypted), cipher)) {
                final var bytes = Files.copy(input, decrypted.toPath(), StandardCopyOption.REPLACE_EXISTING);
            }
            final var decryptionMac = cipher.getMac();
            // -------------------------------------------------------------------------------------------------------- then
            assertThat(decryptionMac).isEqualTo(encryptionMac);
            assertThat(decrypted).hasSameBinaryContentAs(plain);
        }

        private static Stream<Arguments> getCipherAndParamsArgumentsStream_() {
            return _GCM_TestUtils.getCipherAndParamsArgumentsStream(
                    AES__Test::getKeySizeStream,
                    AESEngine::newInstance
            );
        }

        @MethodSource({"getCipherAndParamsArgumentsStream_"})
        @ParameterizedTest
        void __(final AEADCipher cipher, final CipherParameters params) throws Exception {
            _AEADCipher_TestUtils.__(cipher, params);
        }

        @MethodSource({"getCipherAndParamsArgumentsStream_"})
        @ParameterizedTest
        void __(final AEADCipher cipher, final CipherParameters params, @TempDir final File dir) throws Exception {
            _AEADCipher_TestUtils.__(cipher, params, dir);
        }
    }

    @Nested
    class JCEProviderTest
            extends _JCEProviderTest {

        private static Stream<Arguments> getTransformationKeySizeAndTLenArgumentsStream() {
            return Stream.of("NoPadding")
                    .map(p -> ALGORITHM + '/' + _GCM_TestUtils.MODE + '/' + p)
                    .flatMap(t -> getKeySizeStream().mapToObj(ks -> {
                        return _GCM_TestUtils.getTLenStream().mapToObj(tl -> {
                            return Arguments.of(
                                    t,
                                    Named.of("keySize: " + ks, ks),
                                    Named.of("TLen: " + tl, tl)
                            );
                        });
                    })).flatMap(Function.identity());
        }

        @MethodSource({"getTransformationKeySizeAndTLenArgumentsStream"})
        @ParameterizedTest
        void __(final String transformation, final int keySize, final int tLen) throws Throwable {
            final var cipher = Cipher.getInstance(transformation);
            final var key = new SecretKeySpec(
                    JinahyaKeyParametersUtils.newRandomKey(null, keySize >> 3), ALGORITHM
            );
            _Random_TestUtils.getRandomBytesStream().forEach(p -> {
                final var iv = JinahyaParametersWithIvUtils.newRandomIv(null, BLOCK_BYTES);
                final var params = new GCMParameterSpec(tLen, iv);
                final var aad = ThreadLocalRandom.current().nextBoolean()
                        ? null
                        : _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
                try {
                    _Cipher_TestUtils.__(cipher, key, params, aad, p);
                } catch (final Exception e) {
                    throw new RuntimeException(e);
                }
            });
        }

        @MethodSource({"getTransformationKeySizeAndTLenArgumentsStream"})
        @ParameterizedTest
        void __(final String transformation, final int keySize, final int tLen, @TempDir final Path dir)
                throws Exception {
            final var cipher = Cipher.getInstance(transformation);
            final var key = new SecretKeySpec(
                    JinahyaKeyParametersUtils.newRandomKey(null, keySize >> 3), ALGORITHM
            );
            _Random_TestUtils.getRandomFileStream(dir).forEach(p -> {
                final var iv = JinahyaParametersWithIvUtils.newRandomIv(null, BLOCK_BYTES);
                final var params = new GCMParameterSpec(tLen, iv);
                final var aad = ThreadLocalRandom.current().nextBoolean()
                        ? null
                        : _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
                try {
                    _Cipher_TestUtils.__(cipher, key, params, aad, dir, p);
                } catch (final Exception e) {
                    throw new RuntimeException(e);
                }
            });
        }
    }
}
