package symmetric.aria;

import _org.bouncycastle.crypto._StreamCipher_TestUtils;
import symmetric._CTR_TestUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.ARIAEngine;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.util.stream.Stream;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class ARIA_CTR_Test
        extends ARIA__Test {

    private static Stream<Arguments> getCipherAndParamsArgumentsStream_() {
        return _CTR_TestUtils.getCipherAndParamsArgumentsStream(
                ARIA__Test::getKeySizeStream,
                ARIAEngine::new
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    @MethodSource({"getCipherAndParamsArgumentsStream_"})
    @ParameterizedTest
    void __(final StreamCipher cipher, final CipherParameters params) throws Exception {
        _StreamCipher_TestUtils.__(cipher, params);
    }

    @MethodSource({"getCipherAndParamsArgumentsStream_"})
    @ParameterizedTest
    void __(final StreamCipher cipher, final CipherParameters params, @TempDir final File dir)
            throws Exception {
        _StreamCipher_TestUtils.__(cipher, params, dir);
    }
}
