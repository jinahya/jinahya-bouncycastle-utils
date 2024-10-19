package io.github.jinahya.util.kisa;

import io.github.jinahya.util._TestUtils;
import io.github.jinahya.util.bouncycastle.crypto.JinahyaCipherParametersUtils;
import io.github.jinahya.util.bouncycastle.crypto._BufferedBlockCipherTestUtils;
import io.github.jinahya.util.bouncycastle.crypto.padding._BlockCipherPaddingTestUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.SEEDEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.util.function.Function;
import java.util.stream.Stream;

@Slf4j
class SEED_CBC_Test
        extends SEED__Test {

    private static Stream<Arguments> getargumentsstream() {
        return getKeySizeStream().mapToObj(ks -> {
            return _BlockCipherPaddingTestUtils.getBlockCipherPaddingStream().map(p -> {
                final var engine = new SEEDEngine();
                final var cipher = new PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(engine), p);
                final var params = JinahyaCipherParametersUtils.newRandomParametersWithIV(null, ks, cipher);
                return Arguments.of(
                        Named.of(_TestUtils.cipherName(cipher, p), cipher),
                        Named.of(_TestUtils.paramsName(params), params)
                );
            });
        }).flatMap(Function.identity());
    }

    @MethodSource({"getargumentsstream"})
    @ParameterizedTest
    void __(final PaddedBufferedBlockCipher cipher, final CipherParameters params) throws Exception {
        _BufferedBlockCipherTestUtils.__(cipher, params);
    }

    @MethodSource({"getargumentsstream"})
    @ParameterizedTest
    void __(final PaddedBufferedBlockCipher cipher, final CipherParameters params, @TempDir final File dir)
            throws Exception {
        _BufferedBlockCipherTestUtils.__(cipher, params, dir);
    }
}
