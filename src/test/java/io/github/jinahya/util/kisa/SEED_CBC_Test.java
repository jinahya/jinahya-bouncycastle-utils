package io.github.jinahya.util.kisa;

import io.github.jinahya.util._CBC_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto._BufferedBlockCipher_TestUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.SEEDEngine;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.util.stream.Stream;

@Slf4j
class SEED_CBC_Test
        extends SEED__Test {

    private static Stream<Arguments> getArgumentsStream() {
        return _CBC_TestUtils.getArgumentsStream(
                SEED__Test::getKeySizeStream,
                SEEDEngine::new
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final PaddedBufferedBlockCipher cipher, final CipherParameters params) throws Exception {
        _BufferedBlockCipher_TestUtils.__(cipher, params);
    }

    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final PaddedBufferedBlockCipher cipher, final CipherParameters params, @TempDir final File dir)
            throws Exception {
        _BufferedBlockCipher_TestUtils.__(cipher, params, dir);
    }
}
