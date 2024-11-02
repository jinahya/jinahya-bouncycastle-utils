package io.github.jinahya.util.kisa;

import io.github.jinahya.util._CFB_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto._StreamCipher_TestUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.LEAEngine;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.util.stream.IntStream;
import java.util.stream.Stream;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class LEA_CFB_Test
        extends LEA__Test {

    private static IntStream getBlockSizeStream() {
        return IntStream.of(
                1,
                8,
                64,
                128
        );
    }

    private static Stream<Arguments> getArgumentsStream() {
        return _CFB_TestUtils.getCipherAndParamsArgumentsStream(
                ARIA__Test::getKeySizeStream,
                LEAEngine::new
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
    void __(final StreamCipher cipher, final CipherParameters params, @TempDir final File dir) throws Exception {
        _StreamCipher_TestUtils.__(cipher, params, dir);
    }
}
