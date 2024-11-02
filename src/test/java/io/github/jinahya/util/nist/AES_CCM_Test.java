package io.github.jinahya.util.nist;

import _javax.crypto._Cipher_TestUtils;
import _javax.security._Random_TestUtils;
import _org.bouncycastle.jce.provider._BouncyCastleProvider_TestUtils;
import io.github.jinahya.util._CCM_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto.modes._AEADCipher_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto.params._KeyParametersTestUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Function;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class AES_CCM_Test
        extends AES__Test {

    private static Stream<Arguments> getTagLengthStream() {
        return _CCM_TestUtils.getBouncyCastleTagLengthStream()
                .mapToObj(v -> Arguments.of(Named.of("tagLength: " + v, v)
                ));
    }

    @MethodSource({"getTagLengthStream"})
    @ParameterizedTest
    void __(final int tagLength) throws Exception {
        // ------------------------------------------------------------------------------------------------------- given
        final var key = _Random_TestUtils.newRandomBytes(16);
        final var macSize = tagLength << 3;
        final var nonce = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(7, 14));
        final var associatedText = ThreadLocalRandom.current().nextBoolean()
                ? null
                : _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
        final var cipher = CCMBlockCipher.newInstance(AESEngine.newInstance());
        final var params = new AEADParameters(new KeyParameter(key), macSize, nonce, associatedText);
        final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
        // ----------------------------------------------------------------------------------------------------- encrypt
        cipher.init(true, params);
        final var encrypted = new byte[cipher.getOutputSize(plain.length)];
        final byte[] encryptionMac;
        {
            final var processed = cipher.processBytes(plain, 0, plain.length, encrypted, 0);
            if (associatedText != null) {
                cipher.processAADBytes(associatedText, 0, associatedText.length);
            }
            final var finalized = cipher.doFinal(encrypted, processed);
            assert (processed + finalized) == encrypted.length;
            encryptionMac = cipher.getMac();
        }
        // ----------------------------------------------------------------------------------------------------- decrypt
        cipher.init(false, params);
        final byte[] decrypted = new byte[cipher.getOutputSize(encrypted.length)];
        final byte[] decryptionMac;
        {
            final var processed = cipher.processBytes(encrypted, 0, encrypted.length, decrypted, 0);
            if (associatedText != null) {
                cipher.processAADBytes(associatedText, 0, associatedText.length);
            }
            final var finalized = cipher.doFinal(decrypted, processed);
            assert (processed + finalized) == decrypted.length;
            decryptionMac = cipher.getMac();
        }
        // -------------------------------------------------------------------------------------------------------- then
        assertThat(decrypted).isEqualTo(plain);
        assertThat(decryptionMac).isEqualTo(encryptionMac);
    }

    @MethodSource({
            "getTagLengthStream"
    })
    @ParameterizedTest
    void __(final int tagLength, @TempDir final File dir) throws Exception {
        // ------------------------------------------------------------------------------------------------------- given
        final var key = _Random_TestUtils.newRandomBytes(16);
        final var macSize = tagLength << 3;
        final var nonce = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(7, 14));
        final var associatedText = ThreadLocalRandom.current().nextBoolean() ?
                null : _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
        final var cipher = CCMBlockCipher.newInstance(AESEngine.newInstance());
        final var params = new AEADParameters(new KeyParameter(key), macSize, nonce, associatedText);
        final var plain = File.createTempFile("tmp", null, dir);
        {
            final var bytes = new byte[ThreadLocalRandom.current().nextInt(1024)];
            ThreadLocalRandom.current().nextBytes(bytes);
            Files.write(plain.toPath(), bytes);
        }
        // ----------------------------------------------------------------------------------------------------- encrypt
        final var encrypted = File.createTempFile("tmp", null, dir);
        cipher.init(true, params);
        try (var target = new CipherOutputStream(new FileOutputStream(encrypted), cipher)) {
            Files.copy(plain.toPath(), target);
            target.flush();
        }
        final var encryptionMac = cipher.getMac();
        // ----------------------------------------------------------------------------------------------------- decrypt
        final var decrypted = File.createTempFile("tmp", null, dir);
        cipher.init(false, params);
        try (var source = new CipherInputStream(new FileInputStream(encrypted), cipher)) {
            Files.copy(source, decrypted.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }
        final var decryptionMac = cipher.getMac();
        // -------------------------------------------------------------------------------------------------------- then
        assertThat(decrypted).hasSameBinaryContentAs(plain);
        assertThat(decryptionMac).isEqualTo(encryptionMac);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private static Stream<Arguments> getCipherAndParamsArgumentsStream() {
        return _CCM_TestUtils.getCipherAndParamsArgumentsStream(
                AES__Test::getKeySizeStream,
                AESEngine::newInstance
        );
    }

    @MethodSource({"getCipherAndParamsArgumentsStream"})
    @ParameterizedTest
    void __(final AEADCipher cipher, final CipherParameters params) throws Exception {
        _AEADCipher_TestUtils.__(cipher, params);
    }

    @MethodSource({"getCipherAndParamsArgumentsStream"})
    @ParameterizedTest
    void __(final AEADCipher cipher, final CipherParameters params, @TempDir final File dir) throws Exception {
        _AEADCipher_TestUtils.__(cipher, params, dir);
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Nested
    class JCE_Test {

        private static Stream<Arguments> getKeySizeAndTransformationArgumentsStream() {
            return getKeySizeStream().mapToObj(ks -> {
                return Stream.of(
                                "NoPadding"
                        )
                        .map(p -> {
                            return ALGORITHM + '/' + _CCM_TestUtils.MODE + '/' + p;
                        })
                        .map(t -> {
                            return Arguments.of(
                                    Named.of("keySize: " + ks, ks),
                                    Named.of("transformation: " + t, t)
                            );
                        });
            }).flatMap(Function.identity());
        }

        @MethodSource({"getKeySizeAndTransformationArgumentsStream"})
        @ParameterizedTest
        void __(final int keySize, final String transformation) throws Throwable {
            _BouncyCastleProvider_TestUtils.callWithinBouncyCastleProvider(() -> {
                final var cipher = Cipher.getInstance(transformation);
                final var key = new SecretKeySpec(
                        _KeyParametersTestUtils.newRandomKey(null, keySize),
                        ALGORITHM
                );
                final var params = new IvParameterSpec(_CCM_TestUtils.newBouncyCastleNonce());
                _Cipher_TestUtils.__(cipher, key, params);
                return null;
            });
        }

        @MethodSource({"getKeySizeAndTransformationArgumentsStream"})
        @ParameterizedTest
        void __(final int keySize, final String transformation, @TempDir final Path dir) throws Throwable {
            _BouncyCastleProvider_TestUtils.callWithinBouncyCastleProvider(() -> {
                final var cipher = Cipher.getInstance(transformation);
                final var key = new SecretKeySpec(
                        _KeyParametersTestUtils.newRandomKey(null, keySize),
                        ALGORITHM
                );
                final var params = new IvParameterSpec(_CCM_TestUtils.newBouncyCastleNonce());
                _Cipher_TestUtils.__(cipher, key, params, dir);
                return null;
            });
        }
    }
}
