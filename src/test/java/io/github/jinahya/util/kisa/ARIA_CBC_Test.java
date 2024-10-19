package io.github.jinahya.util.kisa;

import io.github.jinahya.util._TestUtils;
import io.github.jinahya.util.bouncycastle.crypto.JinahyaCipherParametersUtils;
import io.github.jinahya.util.bouncycastle.crypto._BufferedBlockCipherTestUtils;
import io.github.jinahya.util.bouncycastle.crypto._CipherParametersTestUtils;
import io.github.jinahya.util.bouncycastle.crypto.padding._BlockCipherPaddingTestUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.ARIAEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.util.stream.Stream;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class ARIA_CBC_Test
        extends ARIA__Test {

    private static Stream<Arguments> getArgumentsStream() {
        return _BlockCipherPaddingTestUtils.getBlockCipherPaddingStream().flatMap(p -> {
            return getKeySizeStream().mapToObj(ks -> {
                final var engine = new ARIAEngine();
                final var cipher = new PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(engine), p);
                final var params = JinahyaCipherParametersUtils.newRandomParametersWithIV(null, ks, cipher);
                return Arguments.of(
                        Named.of(_TestUtils.cipherName(cipher, p), cipher),
                        Named.of(_CipherParametersTestUtils.paramsName(params), params)
                );
            });
        });
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
