package io.github.jinahya.util.kisa;

import _javax.crypto._Cipher_TestUtils;
import _org.bouncycastle.crypto._BufferedBlockCipher_TestUtils;
import _org.bouncycastle.crypto.params._KeyParameters_TestUtils;
import _org.bouncycastle.jce.provider._BouncyCastleProvider_TestUtils;
import io.github.jinahya.util._ECB_TestUtils;
import io.github.jinahya.bouncycastle.jce.provider.BouncyCastleProviderUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.ARIAEngine;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.file.Path;
import java.security.spec.AlgorithmParameterSpec;
import java.util.function.Function;
import java.util.stream.Stream;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class ARIA_ECB_Test
        extends ARIA__Test {

    private static Stream<Arguments> getArgumentsStream() {
        return _ECB_TestUtils.getArgumentsStream(
                ARIA__Test::getKeySizeStream,
                ARIAEngine::new
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final BufferedBlockCipher cipher, final CipherParameters params) throws Exception {
        _BufferedBlockCipher_TestUtils.__(cipher, params);
    }

    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final BufferedBlockCipher cipher, final CipherParameters params, @TempDir final File dir)
            throws Exception {
        _BufferedBlockCipher_TestUtils.__(cipher, params, dir);
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Nested
    class JCE_Test {

        private static Stream<Arguments> getKeySizeAndTransformationArgumentsStream() {
            return getKeySizeStream().mapToObj(ks -> {
                return Stream.of(
                                "PKCS5Padding"
                        )
                        .map(p -> {
                            return ALGORITHM + '/' + _ECB_TestUtils.MODE + '/' + p;
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
            _BouncyCastleProvider_TestUtils.callForBouncyCastleProvider(() -> {
                final var cipher = Cipher.getInstance(transformation);
                final var key = new SecretKeySpec(
                        _KeyParameters_TestUtils.newRandomKey(null, keySize),
                        ALGORITHM
                );
                _Cipher_TestUtils.__(cipher, key, (AlgorithmParameterSpec) null, (byte[]) null);
                return null;
            });
        }

        @MethodSource({"getKeySizeAndTransformationArgumentsStream"})
        @ParameterizedTest
        void __(final int keySize, final String transformation, @TempDir final Path dir) throws Throwable {
            _BouncyCastleProvider_TestUtils.callForBouncyCastleProvider(() -> {
                BouncyCastleProviderUtils.addBouncyCastleProvider();
                final var cipher = Cipher.getInstance(transformation);
                final var key = new SecretKeySpec(
                        _KeyParameters_TestUtils.newRandomKey(null, keySize),
                        ALGORITHM
                );
                _Cipher_TestUtils.__(cipher, key, null, (byte[]) null, dir);
                return null;
            });
        }
    }
}
