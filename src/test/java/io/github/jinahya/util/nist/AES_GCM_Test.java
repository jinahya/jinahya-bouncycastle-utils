package io.github.jinahya.util.nist;

import _javax.security._Random_TestUtils;
import io.github.jinahya.util._GCM_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto.modes._AEADCipher_TestUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class AES_GCM_Test
        extends AES__Test {

    @Test
    void __() throws Exception {
        // ------------------------------------------------------------------------------------------------------- given
        final var key = _Random_TestUtils.newRandomBytes(16);
        final var macSize = ThreadLocalRandom.current().nextInt(32, 129) >> 3 << 3;
        final var nonce = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024) + 1);
        final var associatedText = ThreadLocalRandom.current().nextBoolean() ?
                null : _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
        final var cipher = GCMBlockCipher.newInstance(AESEngine.newInstance());
        final var params = new AEADParameters(new KeyParameter(key), macSize, nonce, associatedText);
        final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
        // ----------------------------------------------------------------------------------------------------- encrypt
        cipher.init(true, params);
        final var encrypted = new byte[cipher.getOutputSize(plain.length)];
        final byte[] encryptionMac;
        {
            final var processed = cipher.processBytes(plain, 0, plain.length, encrypted, 0);
//            if (associatedText != null) {
//                cipher.processAADBytes(associatedText, 0, associatedText.length);
//            }
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
//            if (associatedText != null) {
//                cipher.processAADBytes(associatedText, 0, associatedText.length);
//            }
            final var finalized = cipher.doFinal(decrypted, processed);
            assert (processed + finalized) == decrypted.length;
            decryptionMac = cipher.getMac();
        }
        // -------------------------------------------------------------------------------------------------------- then
        Assertions.assertArrayEquals(plain, decrypted);
        Assertions.assertArrayEquals(encryptionMac, decryptionMac);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private static Stream<Arguments> getArgumentsStream() {
        return _GCM_TestUtils.getArgumentsStream(
                AES__Test::getKeySizeStream,
                AESEngine::newInstance
        );
    }

    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final AEADCipher cipher, final CipherParameters params) throws Exception {
        _AEADCipher_TestUtils.__(cipher, params);
    }

    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final AEADCipher cipher, final CipherParameters params, @TempDir final File dir) throws Exception {
        _AEADCipher_TestUtils.__(cipher, params, dir);
    }

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
