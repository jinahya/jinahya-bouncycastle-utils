package io.github.jinahya.util.kisa;

import _javax.crypto._Cipher_TestUtils;
import _javax.security._Random_TestUtils;
import _org.bouncycastle.jce.provider._BouncyCastleProvider_TestUtils;
import io.github.jinahya.util._CFB_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto._StreamCipher_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto.params._KeyParametersTestUtils;
import io.github.jinahya.util.bouncycastle.jce.provider.JinahyaBouncyCastleProviderUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.SEEDEngine;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.util.function.Function;
import java.util.stream.IntStream;
import java.util.stream.Stream;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class SEED_CFB_Test
        extends SEED__Test {

    private static IntStream getKeySizeStream_() {
        return getKeySizeStream();
    }

    private static Stream<Arguments> getArgumentsStream() {
        return _CFB_TestUtils.getArgumentsStream(
                SEED__Test::getKeySizeStream,
                SEEDEngine::new
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final StreamCipher cipher, final CipherParameters params) throws Exception {
        _StreamCipher_TestUtils.__(cipher, params);
    }

    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final StreamCipher cipher, final CipherParameters params, @TempDir final File dir)
            throws Exception {
        _StreamCipher_TestUtils.__(cipher, params, dir);
    }

    // -----------------------------------------------------------------------------------------------------------------
    @DisplayName("SEED/CFB")
    @MethodSource({"getKeySizeStream_"})
    @ParameterizedTest
    void __(final int keySize) throws Throwable {
        _BouncyCastleProvider_TestUtils.callWithinBouncyCastleProvider(() -> {
            final var transformation = ALGORITHM + '/' + _CFB_TestUtils.MODE + "/PKCS5Padding";
            final Cipher cipher;
            try {
                cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
            } catch (final NoSuchAlgorithmException naae) {
                log.error("no such algorithm: {}", transformation);
                return null;
            }
            final var key = new SecretKeySpec(
                    _KeyParametersTestUtils.newRandomKey(null, keySize),
                    ALGORITHM
            );
            final var params = new IvParameterSpec(_Random_TestUtils.newRandomBytes(BLOCK_BYTES));
            _Cipher_TestUtils.__(cipher, key, params);
            return null;
        });
    }

    @DisplayName("CBC/CFB")
    @MethodSource({"getKeySizeStream_"})
    @ParameterizedTest
    void __(final int keySize, @TempDir final Path dir) throws Throwable {
        _BouncyCastleProvider_TestUtils.callWithinBouncyCastleProvider(() -> {
            final var transformation = ALGORITHM + '/' + _CFB_TestUtils.MODE + "/PKCS5Padding";
            final Cipher cipher;
            try {
                cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
            } catch (final NoSuchAlgorithmException naae) {
                log.error("no such algorithm: " + transformation);
                return null;
            }
            final var key = new SecretKeySpec(
                    _KeyParametersTestUtils.newRandomKey(null, keySize),
                    ALGORITHM
            );
            final var params = new IvParameterSpec(_Random_TestUtils.newRandomBytes(BLOCK_BYTES));
            _Cipher_TestUtils.__(cipher, key, params, dir);
            return null;
        });
    }

    // -----------------------------------------------------------------------------------------------------------------
    private static Stream<Arguments> getKeySizeAndBitWidthArgumentsStream() {
        return _CFB_TestUtils.getBitWidthStream().mapToObj(bw -> {
            return getKeySizeStream()
                    .mapToObj(ks -> Arguments.of(
                            Named.of(String.format("bitWidth(%1$d)", bw), bw),
                            Named.of(String.format("keySize(%1$d)", ks), ks)
                    ));
        }).flatMap(Function.identity());
    }

    @DisplayName("SEED/CFB<W>")
    @MethodSource({"getKeySizeAndBitWidthArgumentsStream"})
    @ParameterizedTest
    void __(final int bitWidth, final int keySize) throws Throwable {
        _BouncyCastleProvider_TestUtils.callWithinBouncyCastleProvider(() -> {
//            final var transformation = ALGORITHM + '/' + _CFB_TestUtils.mode(bitWidth) + "/PKCS5Padding";
            final var transformation = ALGORITHM + '/' + _CFB_TestUtils.mode(bitWidth);
            final Cipher cipher;
            try {
                cipher = Cipher.getInstance(
                        transformation,
                        JinahyaBouncyCastleProviderUtils.BOUNCY_CASTLE_PROVIDER_NAME
                );
            } catch (final NoSuchAlgorithmException naae) {
                log.error("no such algorithm: {}", transformation);
                return null;
            }
            final var key = new SecretKeySpec(
                    _KeyParametersTestUtils.newRandomKey(null, keySize),
                    ALGORITHM
            );
            final var params = new IvParameterSpec(_Random_TestUtils.newRandomBytes(BLOCK_BYTES));
            _Cipher_TestUtils.__(cipher, key, params);
            return null;
        });
    }

    @DisplayName("SEED/CFB<W>")
    @MethodSource({"getKeySizeAndBitWidthArgumentsStream"})
    @ParameterizedTest
    void __(final int bitWidth, final int keySize, @TempDir final Path dir) throws Throwable {
        _BouncyCastleProvider_TestUtils.callWithinBouncyCastleProvider(() -> {
//            final var transformation = ALGORITHM + '/' + _CFB_TestUtils.mode(bitWidth) + "/PKCS5Padding";
            final var transformation = ALGORITHM + '/' + _CFB_TestUtils.mode(bitWidth);
            final Cipher cipher;
            try {
                cipher = Cipher.getInstance(
                        transformation,
                        JinahyaBouncyCastleProviderUtils.BOUNCY_CASTLE_PROVIDER_NAME
                );
            } catch (final NoSuchAlgorithmException naae) {
                log.error("no such algorithm: {}", transformation);
                return null;
            }
            final var key = new SecretKeySpec(
                    _KeyParametersTestUtils.newRandomKey(null, keySize),
                    ALGORITHM
            );
            final var params = new IvParameterSpec(_Random_TestUtils.newRandomBytes(BLOCK_BYTES));
            _Cipher_TestUtils.__(cipher, key, params, dir);
            return null;
        });
    }
}
