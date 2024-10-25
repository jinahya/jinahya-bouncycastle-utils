package io.github.jinahya.util.kisa;

import _javax.security._Random_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto._BlockCipher_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto._CipherParameters_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto._StreamCipher_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto.params._KeyParametersTestUtils;
import io.github.jinahya.util.bouncycastle.crypto.params._ParametersWithIVTestUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.LEAEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.util.stream.Stream;

@Disabled
@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class LEA_CCM_Test
        extends LEA__Test {

    private static Stream<Arguments> getArgumentsStream() {
        return getKeySizeStream().mapToObj(ks -> {
            final var engine = new LEAEngine();
            final var blockSize = engine.getBlockSize();
            final var blockSizeInBits = blockSize << 3;
            final var cipher = CCMBlockCipher.newInstance(engine);
            final var key = _KeyParametersTestUtils.newRandomKey(null, ks);
            final var iv = _ParametersWithIVTestUtils.newRandomIv(null, blockSizeInBits);
            final var aad = _Random_TestUtils.newRandomBytes(blockSize);
            final var params = new AEADParameters(new KeyParameter(key), 128, iv, aad);
            return Arguments.of(
                    Named.of(_BlockCipher_TestUtils.cipherName(engine), cipher),
                    Named.of(_CipherParameters_TestUtils.paramsName(params), params)
            );
        });
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
}
