package symmetric.seed;

import _javax.crypto._Cipher_TestUtils;
import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto._StreamCipher_TestUtils;
import _org.bouncycastle.crypto.params._KeyParameters_TestUtils;
import _org.bouncycastle.jce.provider._BouncyCastleProvider_TestUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.SEEDEngine;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import symmetric._CTR_TestUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.util.stream.IntStream;
import java.util.stream.Stream;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class SEED_CTR_Test
        extends SEED__Test {

    private static Stream<Arguments> getArgumentsStream() {
        return _CTR_TestUtils.getCipherAndParamsArgumentsStream(
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
    private static IntStream getKeySizeStream_() {
        return getKeySizeStream();
    }

    @DisplayName("SEED/CTR/NoPadding")
    @MethodSource({"getKeySizeStream_"})
    @ParameterizedTest
    void __(final int keySize) throws Throwable {
        _BouncyCastleProvider_TestUtils.callForBouncyCastleProvider(() -> {
            final var transformation = ALGORITHM + '/' + _CTR_TestUtils.MODE + "/NoPadding";
            final Cipher cipher;
            try {
                cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
            } catch (final NoSuchAlgorithmException nsae) {
                throw new RuntimeException("failed to get cipher for " + transformation, nsae);
            }
            final var key = new SecretKeySpec(
                    _KeyParameters_TestUtils.newRandomKey(null, keySize),
                    ALGORITHM
            );
            final var params = new IvParameterSpec(_Random_TestUtils.newRandomBytes(BLOCK_BYTES));
            _Cipher_TestUtils.__(cipher, key, params, (byte[]) null);
            return null;
        });
    }

    @DisplayName("SEED/CTR/NoPadding")
    @MethodSource({"getKeySizeStream_"})
    @ParameterizedTest
    void __(final int keySize, @TempDir final Path dir) throws Throwable {
        _BouncyCastleProvider_TestUtils.callForBouncyCastleProvider(() -> {
            final var transformation = ALGORITHM + '/' + _CTR_TestUtils.MODE + "/NoPadding";
            final Cipher cipher;
            try {
                cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
            } catch (final NoSuchAlgorithmException nsae) {
                throw new RuntimeException("failed to get cipher for " + transformation, nsae);
            }
            final var key = new SecretKeySpec(
                    _KeyParameters_TestUtils.newRandomKey(null, keySize),
                    ALGORITHM
            );
            final var params = new IvParameterSpec(_Random_TestUtils.newRandomBytes(BLOCK_BYTES));
            _Cipher_TestUtils.__(cipher, key, params, (byte[]) null, dir);
            return null;
        });
    }
}
