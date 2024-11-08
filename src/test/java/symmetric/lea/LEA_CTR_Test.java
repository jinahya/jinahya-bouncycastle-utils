package symmetric.lea;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto._StreamCipher_TestUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.LEAEngine;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.util.stream.Stream;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class LEA_CTR_Test
        extends LEA__Test {

    private static Stream<Arguments> getArgumentsStream() {
        return getKeySizeStream().mapToObj(ks -> {
            final var engine = new LEAEngine();
            final var cipher = SICBlockCipher.newInstance(engine);
            final var key = _Random_TestUtils.newRandomBytes(ks >> 3);
            final var iv = _Random_TestUtils.newRandomBytes(cipher.getBlockSize());
            final var params = new ParametersWithIV(
                    new KeyParameter(key),
                    iv
            );
            return Arguments.of(
                    cipher,
                    params
            );
        });
    }

    // -----------------------------------------------------------------------------------------------------------------
    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final StreamCipher cipher, final CipherParameters params) {
        _StreamCipher_TestUtils.__(cipher, params);
    }

    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final StreamCipher cipher, final CipherParameters params, @TempDir final File dir) throws Exception {
        _StreamCipher_TestUtils.__(cipher, params, dir);
    }
}
