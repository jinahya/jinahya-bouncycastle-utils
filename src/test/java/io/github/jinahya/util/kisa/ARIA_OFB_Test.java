package io.github.jinahya.util.kisa;

import io.github.jinahya.util._TestUtils;
import io.github.jinahya.util.bouncycastle.crypto.JinahyaCipherParametersUtils;
import io.github.jinahya.util.bouncycastle.crypto._StreamCipherTestUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamBlockCipher;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.ARIAEngine;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.IntStream;
import java.util.stream.Stream;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class ARIA_OFB_Test
        extends ARIA__Test {

    private static IntStream getBlockSizeStream() {
        return IntStream.of(
                1,
                8,
                64,
                128
        );
    }

    private static Stream<Arguments> getArgumentsStream() {
        return getKeySizeStream().mapToObj(ks -> getBlockSizeStream().mapToObj(bs -> {
            final var engine = new ARIAEngine();
            final OFBBlockCipher cipher;
            try {
                cipher = new OFBBlockCipher(engine, bs);
            } catch (final Exception e) {
                log.error("failed to create with blockSize of {}", bs, e);
                return null;
            }
            final var params = JinahyaCipherParametersUtils.newRandomParametersWithIV(null, ks, cipher);
            return Arguments.of(
                    Named.of(_TestUtils.cipherName(cipher), cipher),
                    Named.of(_TestUtils.paramsName(params), params)
            );
        }).filter(Objects::nonNull)).flatMap(Function.identity());
    }

    // -----------------------------------------------------------------------------------------------------------------
    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final StreamCipher cipher, final CipherParameters params) throws Exception {
        _StreamCipherTestUtils.__(cipher, params);
    }

    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final StreamBlockCipher cipher, final CipherParameters params, @TempDir final File dir)
            throws Exception {
        _StreamCipherTestUtils.__(cipher, params, dir);
    }
}
