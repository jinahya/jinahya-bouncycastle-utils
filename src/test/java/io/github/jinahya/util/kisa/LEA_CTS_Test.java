package io.github.jinahya.util.kisa;

import io.github.jinahya.util._RandomTestUtils;
import io.github.jinahya.util.bouncycastle.crypto.JinahyaCipherParametersUtils;
import io.github.jinahya.util.bouncycastle.crypto._BufferedBlockCipherTestUtils;
import io.github.jinahya.util.bouncycastle.crypto._CipherParametersTestUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.LEAEngine;
import org.bouncycastle.crypto.modes.CTSBlockCipher;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class LEA_CTS_Test
        extends LEA__Test {

    private static Stream<Arguments> getArgumentsStream() {
        return getKeySizeStream().mapToObj(ks -> {
            final var engine = new LEAEngine();
            final var cipher = new CTSBlockCipher(engine);
            final var params = JinahyaCipherParametersUtils.newRandomKeyParameter(null, ks);
            return Arguments.of(
                    Named.of(_BufferedBlockCipherTestUtils.cipherName(cipher), cipher),
                    Named.of(_CipherParametersTestUtils.paramsName(params), params)
            );
        });
    }

    // -----------------------------------------------------------------------------------------------------------------
    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final BufferedBlockCipher cipher, final CipherParameters params) throws Exception {
        final var plain = new byte[ThreadLocalRandom.current().nextInt(16) + cipher.getBlockSize()];
        ThreadLocalRandom.current().nextBytes(plain);
        _BufferedBlockCipherTestUtils.__(cipher, params, plain);
    }

    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final BufferedBlockCipher cipher, final CipherParameters params, @TempDir final File dir)
            throws Exception {
        final var plain = File.createTempFile("tmp", null, dir);
        _RandomTestUtils.writeRandomBytesWhile(plain, f -> f.length() < cipher.getBlockSize());
        _BufferedBlockCipherTestUtils.__(cipher, params, dir, plain);
    }
}
