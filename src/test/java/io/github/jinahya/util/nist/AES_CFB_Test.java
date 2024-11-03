package io.github.jinahya.util.nist;

import _javax.crypto._Cipher_TestUtils;
import _javax.security._Random_TestUtils;
import _org.bouncycastle.jce.provider._BouncyCastleProvider_TestUtils;
import io.github.jinahya.util._CFB_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto._StreamCipher_TestUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.CFBModeCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
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
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Function;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A class for testing {@link AESEngine} with {@link CFBModeCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class AES_CFB_Test
        extends AES__Test {

    @Nested
    class LowLevelApiTest {

        private static Stream<Arguments> getKeySizeAndBitWidthArgumentsStream_() {
            return _CFB_TestUtils.getKeySizeAndBitWidthArgumentsStream(
                    AES__Test::getKeySizeStream
            );
        }

        @MethodSource({"getKeySizeAndBitWidthArgumentsStream_"})
        @ParameterizedTest
        void __(final int keySize, final int bitWidth) {
            final CFBModeCipher cipher;
            try {
                cipher = CFBBlockCipher.newInstance(AESEngine.newInstance(), bitWidth);
            } catch (final Exception e) {
                log.error("failed to create cipher instance for bitWidth: {}", bitWidth, e);
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
                assertThat(processed).isEqualTo(encrypted.length);
            }
            // ------------------------------------------------------------------------------------------------- decrypt
            final var decrypted = new byte[encrypted.length];
            {
                cipher.init(false, params);
                final var processed = cipher.processBytes(encrypted, 0, encrypted.length, decrypted, 0);
                assertThat(processed).isEqualTo(decrypted.length);
            }
            // -------------------------------------------------------------------------------------------------- verify
            assertThat(decrypted).isEqualTo(plain);
        }

        @MethodSource({"getKeySizeAndBitWidthArgumentsStream_"})
        @ParameterizedTest
        void __(final int keySize, final int bitWidth, @TempDir final File dir) throws IOException {
            final CFBModeCipher cipher;
            try {
                cipher = CFBBlockCipher.newInstance(AESEngine.newInstance(), bitWidth);
            } catch (final Exception e) {
                log.error("failed to create cipher instance for bitWidth: {}", bitWidth, e);
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
            return _CFB_TestUtils.getCipherAndParamsArgumentsStream(
                    AES__Test::getKeySizeStream,
                    AESEngine::newInstance
            );
        }

        @MethodSource({"getCipherAndParamsArgumentsStream_"})
        @ParameterizedTest
        void __(final StreamCipher cipher, final CipherParameters params) throws Exception {
            _StreamCipher_TestUtils.__(cipher, params);
        }

        @MethodSource({"getCipherAndParamsArgumentsStream_"})
        @ParameterizedTest
        void __(final StreamCipher cipher, final CipherParameters params, @TempDir final File dir)
                throws Exception {
            _StreamCipher_TestUtils.__(cipher, params, dir);
        }
    }

    @Nested
    class JCEProviderTest {

        private static Stream<Arguments> getKeySizeAndTransformationArgumentsStream() {
            return getKeySizeStream().mapToObj(ks -> {
                return Stream.of("NoPadding")
                        .map(p -> ALGORITHM + '/' + _CFB_TestUtils.MODE + '/' + p)
                        .map(t -> Arguments.of(
                                Named.of("keySize: " + ks, ks),
                                Named.of("transformation: " + t, t)
                        ));
            }).flatMap(Function.identity());
        }

        @MethodSource({"getKeySizeAndTransformationArgumentsStream"})
        @ParameterizedTest
        void __(final int keySize, final String transformation) throws Throwable {
            _BouncyCastleProvider_TestUtils.callForBouncyCastleProvider(() -> {
                final Cipher cipher;
                try {
                    cipher = Cipher.getInstance(transformation);
                } catch (final NoSuchAlgorithmException nsae) {
                    log.error("failed to get cipher for '{}'", transformation, nsae);
                    return null;
                }
                final var key = new SecretKeySpec(_Random_TestUtils.newRandomBytes(keySize >> 3), ALGORITHM);
                final var params = new IvParameterSpec(_Random_TestUtils.newRandomBytes(BLOCK_BYTES));
                _Cipher_TestUtils.__(cipher, key, params);
                return null;
            });
        }

        @MethodSource({"getKeySizeAndTransformationArgumentsStream"})
        @ParameterizedTest
        void __(final int keySize, final String transformation, @TempDir final Path dir) throws Throwable {
            _BouncyCastleProvider_TestUtils.callForBouncyCastleProvider(() -> {
                final Cipher cipher;
                try {
                    cipher = Cipher.getInstance(transformation);
                } catch (final NoSuchAlgorithmException nsae) {
                    log.error("failed to get cipher for '{}'", transformation, nsae);
                    return null;
                }
                final var key = new SecretKeySpec(_Random_TestUtils.newRandomBytes(keySize >> 3), ALGORITHM);
                final var params = new IvParameterSpec(_Random_TestUtils.newRandomBytes(BLOCK_BYTES));
                _Cipher_TestUtils.__(cipher, key, params, dir);
                return null;
            });
        }

        // -------------------------------------------------------------------------------------------------------------
        private static Stream<Arguments> getKeySizeAndTransformationWithBitWidthArgumentsStream() {
            return getKeySizeStream().mapToObj(ks -> {
                return _CFB_TestUtils.getBitWidthStream().mapToObj(bw -> {
                    return Stream.of("NoPadding")
                            .map(p -> ALGORITHM + '/' + _CFB_TestUtils.MODE + bw + '/' + p)
                            .map(t -> Arguments.of(
                                    Named.of("keySize: " + ks, ks),
                                    Named.of("transformation: " + t, t)
                            ));
                }).flatMap(Function.identity());
            }).flatMap(Function.identity());
        }

        @MethodSource({"getKeySizeAndTransformationWithBitWidthArgumentsStream"})
        @ParameterizedTest
        void __bitWidth(final int keySize, final String transformation) throws Throwable {
            _BouncyCastleProvider_TestUtils.callForBouncyCastleProvider(() -> {
                final Cipher cipher;
                try {
                    cipher = Cipher.getInstance(transformation);
                } catch (final NoSuchAlgorithmException naae) {
                    log.error("failed to get cipher for '{}'", transformation);
                    return null;
                }
                final var key = new SecretKeySpec(_Random_TestUtils.newRandomBytes(keySize >> 3), ALGORITHM);
                final var params = new IvParameterSpec(_Random_TestUtils.newRandomBytes(BLOCK_BYTES));
                _Cipher_TestUtils.__(cipher, key, params);
                return null;
            });
        }

        @MethodSource({"getKeySizeAndTransformationWithBitWidthArgumentsStream"})
        @ParameterizedTest
        void __bitWidth(final int keySize, final String transformation, @TempDir final Path dir) throws Throwable {
            _BouncyCastleProvider_TestUtils.callForBouncyCastleProvider(() -> {
                final Cipher cipher;
                try {
                    cipher = Cipher.getInstance(transformation);
                } catch (final NoSuchAlgorithmException naae) {
                    log.error("failed to get cipher for '{}'", transformation);
                    return null;
                }
                final var key = new SecretKeySpec(_Random_TestUtils.newRandomBytes(keySize >> 3), ALGORITHM);
                final var params = new IvParameterSpec(_Random_TestUtils.newRandomBytes(BLOCK_BYTES));
                _Cipher_TestUtils.__(cipher, key, params, dir);
                return null;
            });
        }
    }
}
