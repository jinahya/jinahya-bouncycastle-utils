package io.github.jinahya.bouncycastle.util.kisa;

import io.github.jinahya.bouncycastle.util._LogUtils;
import io.github.jinahya.bouncycastle.util._RandomTestUtils;
import io.github.jinahya.bouncycastle.util._TestUtils;
import io.github.jinahya.util.bouncycastle.crypto.JinahyaBufferedBlockCipherUtils;
import io.github.jinahya.util.bouncycastle.crypto.JinahyaCipherParametersUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
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
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.MessageDigest;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

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
                    Named.of(_TestUtils.cipherName(cipher), cipher),
                    Named.of(_TestUtils.keyName(params), params)
            );
        });
    }

    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final BufferedBlockCipher cipher, final CipherParameters params) throws Exception {
        // ------------------------------------------------------------------------------------------------------- plain
        final var plain = new byte[ThreadLocalRandom.current().nextInt(16) + cipher.getBlockSize()];
        ThreadLocalRandom.current().nextBytes(plain);
        // ----------------------------------------------------------------------------------------------------- encrypt
        cipher.init(true, params);
        final var encrypted = JinahyaBufferedBlockCipherUtils.processBytesAndDoFinal(cipher, plain);
        // ----------------------------------------------------------------------------------------------------- decrypt
        cipher.init(false, params);
        final var decrypted = JinahyaBufferedBlockCipherUtils.processBytesAndDoFinal(cipher, encrypted);
        // -------------------------------------------------------------------------------------------------------- then
        _LogUtils.log(plain, encrypted, decrypted);
        assertThat(decrypted).isEqualTo(plain);
    }

    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final BufferedBlockCipher cipher, final CipherParameters params, @TempDir final File dir)
            throws Exception {
        // -------------------------------------------------------------------------------------------------------- plain
        final var plain = File.createTempFile("tmp", null, dir);
        _RandomTestUtils.writeRandomBytesWhile(plain, f -> f.length() < cipher.getBlockSize());
        // ----------------------------------------------------------------------------------------------------- encrypt
        cipher.init(true, params);
        final var encrypted = File.createTempFile("tmp", null, dir);
        try (var source = new FileInputStream(plain);
             var target = new FileOutputStream(encrypted)) {
            JinahyaBufferedBlockCipherUtils.processAllBytesAndDoFinal(cipher, source, target, 1);
            target.flush();
        }
        // ----------------------------------------------------------------------------------------------------- decrypt
        cipher.init(false, params);
        final var decrypted = File.createTempFile("tmp", null, dir);
        try (var source = new FileInputStream(encrypted);
             var target = new FileOutputStream(decrypted)) {
            JinahyaBufferedBlockCipherUtils.processAllBytesAndDoFinal(cipher, source, target, 1);
            target.flush();
        }
        // -------------------------------------------------------------------------------------------------------- then
        _LogUtils.log(plain, encrypted, decrypted);
        assertThat(decrypted).hasSize(plain.length());
        for (var algorithm : new String[]{"SHA-1", "SHA-256"}) {
            final var digest = MessageDigest.getInstance(algorithm);
            assertThat(decrypted).hasDigest(digest, DigestUtils.digest(digest, plain));
        }
    }
}
