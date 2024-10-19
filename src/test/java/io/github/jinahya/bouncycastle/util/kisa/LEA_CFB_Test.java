package io.github.jinahya.bouncycastle.util.kisa;

import io.github.jinahya.bouncycastle.util._LogUtils;
import io.github.jinahya.bouncycastle.util._RandomTestUtils;
import io.github.jinahya.util.bouncycastle.crypto.JinahyaStreamCipherUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamBlockCipher;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.LEAEngine;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.CFBModeCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.MessageDigest;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class LEA_CFB_Test
        extends LEA__Test {

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
            final var engine = new LEAEngine();
            final CFBModeCipher cipher;
            try {
                cipher = CFBBlockCipher.newInstance(engine, bs);
            } catch (final Exception e) {
                log.error("failed to create with blockSize of {}", bs, e);
                return null;
            }
            final CipherParameters params;
            final var key = _RandomTestUtils.newRandomBytes(ks >> 3);
            final var iv = _RandomTestUtils.newRandomBytes(ks >> 3);
            params = new ParametersWithIV(new KeyParameter(key), iv);
            final String name1 = String.format("%1$s/%2$d", cipher.getAlgorithmName(), ks);
            final String name2 = String.format("key: (%1$d) %2$02x ...", key.length, key[0]);
            return Arguments.of(
                    Named.of(name1, cipher),
                    Named.of(name2, params)
            );
        }).filter(Objects::nonNull)).flatMap(s -> s);
    }

    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final StreamCipher cipher, final CipherParameters params) throws Exception {
        // ------------------------------------------------------------------------------------------------------- plain
        final byte[] plain = _RandomTestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(16));
        // ----------------------------------------------------------------------------------------------------- encrypt
        cipher.init(true, params);
        final byte[] encrypted = JinahyaStreamCipherUtils.processAllBytes(cipher, plain, 1);
        // ----------------------------------------------------------------------------------------------------- decrypt
        cipher.init(false, params);
        final byte[] decrypted = JinahyaStreamCipherUtils.processAllBytes(cipher, encrypted, 1);
        // -------------------------------------------------------------------------------------------------------- then
        _LogUtils.log(plain, encrypted, decrypted);
        assertThat(decrypted).isEqualTo(plain);
    }

    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final StreamBlockCipher cipher, final CipherParameters params, @TempDir final File dir)
            throws Exception {
        // ------------------------------------------------------------------------------------------------------- plain
        final var plain = _RandomTestUtils.writeRandomBytes(File.createTempFile("tmp", null, dir));
        // ----------------------------------------------------------------------------------------------------- encrypt
        cipher.init(true, params);
        final var encrypted = File.createTempFile("tmp", null, dir);
        try (var source = new FileInputStream(plain);
             var target = new FileOutputStream(encrypted)) {
            JinahyaStreamCipherUtils.processAllBytes(cipher, source, target, 1);
            target.flush();
        }
        // ----------------------------------------------------------------------------------------------------- decrypt
        cipher.init(false, params);
        final var decrypted = File.createTempFile("tmp", null, dir);
        try (var source = new FileInputStream(encrypted);
             var target = new FileOutputStream(decrypted)) {
            JinahyaStreamCipherUtils.processAllBytes(cipher, source, target, 1);
            target.flush();
        }
        // -------------------------------------------------------------------------------------------------------- then
        assertThat(decrypted).hasSize(plain.length());
        for (var algorithm : new String[]{"SHA-1", "SHA-256"}) {
            final var digest = MessageDigest.getInstance(algorithm);
            assertThat(decrypted).hasDigest(digest, DigestUtils.digest(digest, plain));
        }
    }
}
