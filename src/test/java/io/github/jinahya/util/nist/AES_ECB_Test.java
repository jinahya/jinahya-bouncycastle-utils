package io.github.jinahya.util.nist;

import io.github.jinahya.util._ECB_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto._BufferedBlockCipherTestUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.util.stream.Stream;

@Slf4j
class AES_ECB_Test
        extends AES__Test {

    private static Stream<Arguments> getArgumentsStream() {
        return _ECB_TestUtils.getArgumentsStream(AES__Test::getKeySizeStream, AESEngine::newInstance);
    }

    // -----------------------------------------------------------------------------------------------------------------
    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final BufferedBlockCipher cipher, final CipherParameters params) throws Exception {
        _BufferedBlockCipherTestUtils.__(cipher, params);
    }

    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final BufferedBlockCipher cipher, final CipherParameters params, @TempDir final File dir)
            throws Exception {
        _BufferedBlockCipherTestUtils.__(cipher, params, dir);
    }
}
