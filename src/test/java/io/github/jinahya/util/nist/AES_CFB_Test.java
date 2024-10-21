package io.github.jinahya.util.nist;

import _org.junit.jupiter.params.provider._Arguments_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto._StreamCipherTestUtils;
import io.github.jinahya.util.bouncycastle.crypto.params._ParametersWithIVTestUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.util.Objects;
import java.util.stream.IntStream;
import java.util.stream.Stream;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class AES_CFB_Test
        extends AES__Test {

    private static IntStream getCFBBlockSizeStream() {
        return IntStream.of(
                1,
                8,
                64,
                128
        );
    }

    private static Stream<Arguments> getArgumentsStream() {
        return getCFBBlockSizeStream().mapToObj(bs -> {
            final var engine = AESEngine.newInstance();
            try {
                return CFBBlockCipher.newInstance(engine, bs);
            } catch (final Exception e) {
                log.error("failed to create a new cipher for CFB-blockSize: {}", bs);
                return null;
            }
        }).filter(Objects::nonNull).flatMap(c -> getKeySizeStream().mapToObj(ks -> {
            final var params = _ParametersWithIVTestUtils.newRandomInstanceOfParametersWithIV(null, ks, c);
            return _Arguments_TestUtils.argumentsOf(c, params);
        }));
    }

    // -----------------------------------------------------------------------------------------------------------------
    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final StreamCipher cipher, final CipherParameters params) throws Exception {
        _StreamCipherTestUtils.__(cipher, params);
    }

    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final StreamCipher cipher, final CipherParameters params, @TempDir final File dir)
            throws Exception {
        _StreamCipherTestUtils.__(cipher, params, dir);
    }
}
