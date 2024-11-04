package io.github.jinahya.util.kisa;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto._BufferedBlockCipher_TestUtils;
import _org.bouncycastle.crypto._CipherParameters_TestUtils;
import _org.bouncycastle.crypto.params._KeyParameters_TestUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.ARIAEngine;
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
class ARIA_CTS_Test
        extends ARIA__Test {

    private static Stream<Arguments> getArgumentsStream() {
        return getKeySizeStream().mapToObj(ks -> {
            final var engine = new ARIAEngine();
            final var cipher = new CTSBlockCipher(engine);
            final var params = _KeyParameters_TestUtils.newRandomInstanceOfKeyParameter(null, ks);
            return Arguments.of(
                    Named.of(_BufferedBlockCipher_TestUtils.cipherName(cipher), cipher),
                    Named.of(_CipherParameters_TestUtils.paramsName(params), params)
            );
        });
    }

    // -----------------------------------------------------------------------------------------------------------------
    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final BufferedBlockCipher cipher, final CipherParameters params) throws Exception {
        final var plain = new byte[ThreadLocalRandom.current().nextInt(16) + cipher.getBlockSize()];
        ThreadLocalRandom.current().nextBytes(plain);
        _BufferedBlockCipher_TestUtils.__(cipher, params, plain);
    }

    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final BufferedBlockCipher cipher, final CipherParameters params, @TempDir final File dir)
            throws Exception {
        final var plain = File.createTempFile("tmp", null, dir);
        _Random_TestUtils.writeRandomBytesWhile(plain, f -> f.length() < cipher.getBlockSize());
        _BufferedBlockCipher_TestUtils.__(cipher, params, dir, plain);
    }
}
