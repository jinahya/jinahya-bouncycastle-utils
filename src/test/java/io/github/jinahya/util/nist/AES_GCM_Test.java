package io.github.jinahya.util.nist;

import io.github.jinahya.util._GCM_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto._AEADBlockCipher_TestUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class AES_GCM_Test
        extends AES__Test {

    private static Stream<Arguments> getArgumentsStream() {
        return _GCM_TestUtils.getArgumentsStream(
                AES__Test::getKeySizeStream,
                AESEngine::newInstance
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Disabled
    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final AEADBlockCipher cipher, final CipherParameters params) throws Exception {
        _AEADBlockCipher_TestUtils.__(cipher, params);
    }

//    @MethodSource({"getArgumentsStream"})
//    @ParameterizedTest
//    void __(final StreamBlockCipher cipher, final CipherParameters params, @TempDir final File dir)
//            throws Exception {
//        _StreamCipher_TestUtils.__(cipher, params, dir);
//    }

//    // -----------------------------------------------------------------------------------------------------------------
//    private static IntStream getKeySizeStream_() {
//        return getKeySizeStream();
//    }
//
//    @DisplayName("AES/OFB/NoPadding")
//    @MethodSource({"getKeySizeStream_"})
//    @ParameterizedTest
//    void __(final int keySize) throws Throwable {
//        _BouncyCastleProvider_TestUtils.callWithinBouncyCastleProvider(() -> {
//            final var transformation = ALGORITHM + '/' + _OFB_TestUtils.MODE + "/NoPadding";
//            final Cipher cipher;
//            try {
//                cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
//            } catch (final NoSuchAlgorithmException nsae) {
//                log.error("no such algorithm: {}", transformation, nsae);
//                return null;
//            }
//            final var key = new SecretKeySpec(
//                    _KeyParametersTestUtils.newRandomKey(null, keySize),
//                    ALGORITHM
//            );
//            final var params = new IvParameterSpec(_Random_TestUtils.newRandomBytes(BLOCK_BYTES));
//            _Cipher_TestUtils.__(cipher, key, params);
//            return null;
//        });
//    }
//
//    @DisplayName("AES/OFB/NoPadding")
//    @MethodSource({"getKeySizeStream_"})
//    @ParameterizedTest
//    void __(final int keySize, @TempDir final Path dir) throws Throwable {
//        _BouncyCastleProvider_TestUtils.callWithinBouncyCastleProvider(() -> {
//            final var transformation = ALGORITHM + '/' + _OFB_TestUtils.MODE + "/NoPadding";
//            final Cipher cipher;
//            try {
//                cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
//            } catch (final NoSuchAlgorithmException nsae) {
//                log.error("no such algorithm: " + transformation, nsae);
//                return null;
//            }
//            final var key = new SecretKeySpec(
//                    _KeyParametersTestUtils.newRandomKey(null, keySize),
//                    ALGORITHM
//            );
//            final var params = new IvParameterSpec(_Random_TestUtils.newRandomBytes(BLOCK_BYTES));
//            _Cipher_TestUtils.__(cipher, key, params, dir);
//            return null;
//        });
//    }
//
//    // -----------------------------------------------------------------------------------------------------------------
//    private static Stream<Arguments> getBitWidthAndKeySizeArgumentsStream() {
//        return _OFB_TestUtils.getBitWidthStream().mapToObj(bw -> {
//            return getKeySizeStream()
//                    .mapToObj(ks -> Arguments.of(
//                            Named.of(String.format("bitWidth(%1$d)", bw), bw),
//                            Named.of(String.format("keySize(%1$d)", ks), ks)
//                    ));
//        }).flatMap(Function.identity());
//    }
//
//    @DisplayName("AES/OFB<W>")
//    @MethodSource({"getBitWidthAndKeySizeArgumentsStream"})
//    @ParameterizedTest
//    void __(final int bitWidth, final int keySize) throws Throwable {
//        _BouncyCastleProvider_TestUtils.callWithinBouncyCastleProvider(() -> {
//            final var transformation = ALGORITHM + '/' + _OFB_TestUtils.mode(bitWidth) + "/NoPadding";
//            final Cipher cipher;
//            try {
//                cipher = Cipher.getInstance(
//                        transformation,
//                        JinahyaBouncyCastleProviderUtils.BOUNCY_CASTLE_PROVIDER_NAME
//                );
//            } catch (final NoSuchAlgorithmException naae) {
//                log.error("failed to get cipher for '{}'", transformation);
//                return null;
//            }
//            final var key = new SecretKeySpec(
//                    _KeyParametersTestUtils.newRandomKey(null, keySize),
//                    ALGORITHM
//            );
//            final var params = new IvParameterSpec(_Random_TestUtils.newRandomBytes(BLOCK_BYTES));
//            _Cipher_TestUtils.__(cipher, key, params);
//            return null;
//        });
//    }
//
//    @DisplayName("AES/OFB<W>")
//    @MethodSource({"getBitWidthAndKeySizeArgumentsStream"})
//    @ParameterizedTest
//    void __(final int bitWidth, final int keySize, @TempDir final Path dir) throws Throwable {
//        _BouncyCastleProvider_TestUtils.callWithinBouncyCastleProvider(() -> {
//            final var transformation = ALGORITHM + '/' + _OFB_TestUtils.mode(bitWidth) + "/NoPadding";
//            final Cipher cipher;
//            try {
//                cipher = Cipher.getInstance(
//                        transformation,
//                        JinahyaBouncyCastleProviderUtils.BOUNCY_CASTLE_PROVIDER_NAME
//                );
//            } catch (final NoSuchAlgorithmException naae) {
//                log.error("failed to get cipher for '{}'", transformation);
//                return null;
//            }
//            final var key = new SecretKeySpec(
//                    _KeyParametersTestUtils.newRandomKey(null, keySize),
//                    ALGORITHM
//            );
//            final var params = new IvParameterSpec(_Random_TestUtils.newRandomBytes(BLOCK_BYTES));
//            _Cipher_TestUtils.__(cipher, key, params, dir);
//            return null;
//        });
//    }
}
