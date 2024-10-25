package io.github.jinahya.util.nist;

import io.github.jinahya.util._OFB_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto._StreamCipher_TestUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamBlockCipher;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.Cipher;
import java.io.File;
import java.security.Security;
import java.util.Objects;
import java.util.stream.Stream;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class AES_OFB_Test
        extends AES__Test {

    private static Stream<Arguments> getArgumentsStream() {
        return _OFB_TestUtils.getArgumentsStream(
                AES__Test::getKeySizeStream,
                AESEngine::newInstance
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
    void __(final StreamBlockCipher cipher, final CipherParameters params, @TempDir final File dir)
            throws Exception {
        _StreamCipher_TestUtils.__(cipher, params, dir);
    }

    @Test
    void __() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        _OFB_TestUtils.getBitWidthStream()
                .peek(bbs -> {
                    log.debug("bitBlockSize: {}", bbs);
                })
                .mapToObj(bbs -> "AES/CFB" + bbs + "/NoPadding").map(t -> {
                    try {
                        return Cipher.getInstance(t, "BC");
                    } catch (final Exception e) {
                        log.error("failed to get cipher instance for {}", t, e);
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .forEach(c -> {
                });
    }

    @Test
    void __def() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        final var cipher = Cipher.getInstance("AES/CFB/NoPadding");
    }
}
