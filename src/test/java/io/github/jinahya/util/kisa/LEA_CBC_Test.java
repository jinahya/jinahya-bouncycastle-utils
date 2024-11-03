package io.github.jinahya.util.kisa;

import _javax.crypto._Cipher_TestUtils;
import _javax.security._Random_TestUtils;
import _org.bouncycastle.jce.provider._BouncyCastleProvider_TestUtils;
import io.github.jinahya.util._CBC_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto._BufferedBlockCipher_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto.paddings._BlockCipherPaddingTestUtils;
import io.github.jinahya.util.bouncycastle.crypto.params.JinahyaKeyParametersUtils;
import io.github.jinahya.util.bouncycastle.crypto.params.JinahyaParametersWithIvUtils;
import io.github.jinahya.util.bouncycastle.crypto.params._KeyParametersTestUtils;
import io.github.jinahya.util.bouncycastle.jce.provider.JinahyaBouncyCastleProviderUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.LEAEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.file.Path;
import java.security.Security;
import java.util.stream.Stream;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class LEA_CBC_Test
        extends LEA__Test {

    private static Stream<Arguments> getArgumentsStream() {
        return _BlockCipherPaddingTestUtils.getBlockCipherPaddingStream().flatMap(p -> {
            return getKeySizeStream().mapToObj(ks -> {
                final var engine = new LEAEngine();
                final var cipher = new PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(engine), p);
                final var params = JinahyaParametersWithIvUtils.newRandomInstanceFor(
                        JinahyaKeyParametersUtils.newRandomInstance(null, ks >> 3),
                        null,
                        cipher.getUnderlyingCipher()
                );
                return Arguments.of(
                        cipher,
                        params
                );
            });
        });
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
    @Disabled("https://github.com/bcgit/bc-java/issues/1880")
    @DisplayName("LEA/CBC/PKCS5Padding")
    @ValueSource(ints = {
            128,
            192,
            256
    })
    @ParameterizedTest
    void __(final int keySize) throws Throwable {
        _BouncyCastleProvider_TestUtils.callForBouncyCastleProvider(() -> {
            Security.addProvider(new BouncyCastleProvider());
            final var transformation = ALGORITHM + '/' + _CBC_TestUtils.MODE + "/PKCS5Padding";
            final var cipher = Cipher.getInstance(
                    transformation,
                    JinahyaBouncyCastleProviderUtils.BOUNCY_CASTLE_PROVIDER_NAME
            );
            final var key = new SecretKeySpec(
                    _KeyParametersTestUtils.newRandomKey(null, keySize),
                    ALGORITHM
            );
            final var params = new IvParameterSpec(_Random_TestUtils.newRandomBytes(BLOCK_BYTES));
            _Cipher_TestUtils.__(cipher, key, params, (byte[]) null);
            return null;
        });
    }

    @Disabled("https://github.com/bcgit/bc-java/issues/1880")
    @DisplayName("LEA/CBC/PKCS5Padding")
    @ValueSource(ints = {
            128,
            192,
            256
    })
    @ParameterizedTest
    void __(final int keySize, @TempDir final Path dir) throws Throwable {
        _BouncyCastleProvider_TestUtils.callForBouncyCastleProvider(() -> {
            final var transformation = ALGORITHM + '/' + _CBC_TestUtils.MODE + "/PKCS5Padding";
            final var cipher = Cipher.getInstance(
                    transformation,
                    JinahyaBouncyCastleProviderUtils.BOUNCY_CASTLE_PROVIDER_NAME
            );
            final var key = new SecretKeySpec(
                    _KeyParametersTestUtils.newRandomKey(null, keySize),
                    ALGORITHM
            );
            final var params = new IvParameterSpec(_Random_TestUtils.newRandomBytes(BLOCK_BYTES));
            _Cipher_TestUtils.__(cipher, key, params, (byte[]) null, dir);
            return null;
        });
    }
}
