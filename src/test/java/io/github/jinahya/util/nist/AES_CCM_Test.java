package io.github.jinahya.util.nist;

import _javax.security._Random_TestUtils;
import io.github.jinahya.util._CCM_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto.modes.JinahyaAEADCipherUtils;
import io.github.jinahya.util.bouncycastle.crypto.modes._AEADCipher_TestUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class AES_CCM_Test
        extends AES__Test {

    private static IntStream getTagLengthStream() {
        return _CCM_TestUtils.getBouncyCastleTagLengthStream();
    }

    @MethodSource({
            "getTagLengthStream"
    })
    @ParameterizedTest
    void __(final int tagLength) throws Exception {
        // ------------------------------------------------------------------------------------------------------- given
        final var key = _Random_TestUtils.newRandomBytes(16);
        final var macSize = tagLength << 3;
        final var nonce = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(7, 14));
        final var associatedText = ThreadLocalRandom.current().nextBoolean() ?
                null : _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
        final var cipher = CCMBlockCipher.newInstance(AESEngine.newInstance());
        final var params = new AEADParameters(new KeyParameter(key), macSize, nonce, associatedText);
        final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
        // ----------------------------------------------------------------------------------------------------- encrypt
        cipher.init(true, params);
        final var encrypted = new byte[cipher.getOutputSize(plain.length)];
        final byte[] encryptionMac;
        {
            final var processed = cipher.processBytes(plain, 0, plain.length, encrypted, 0);
            if (associatedText != null) {
                cipher.processAADBytes(associatedText, 0, associatedText.length);
            }
            final var finalized = cipher.doFinal(encrypted, processed);
            assert (processed + finalized) == encrypted.length;
            encryptionMac = cipher.getMac();
        }
        // ----------------------------------------------------------------------------------------------------- decrypt
        cipher.init(false, params);
        final byte[] decrypted = new byte[cipher.getOutputSize(encrypted.length)];
        final byte[] decryptionMac;
        {
            final var processed = cipher.processBytes(encrypted, 0, encrypted.length, decrypted, 0);
            if (associatedText != null) {
                cipher.processAADBytes(associatedText, 0, associatedText.length);
            }
            final var finalized = cipher.doFinal(decrypted, processed);
            assert (processed + finalized) == decrypted.length;
            decryptionMac = cipher.getMac();
        }
        // -------------------------------------------------------------------------------------------------------- then
        assertThat(decrypted).isEqualTo(plain);
        assertThat(decryptionMac).isEqualTo(encryptionMac);
    }

    @MethodSource({
            "getTagLengthStream"
    })
    void __(final int tagLength, @TempDir final File dir) throws Exception {
        // ------------------------------------------------------------------------------------------------------- given
        final var key = _Random_TestUtils.newRandomBytes(16);
        final var macSize = tagLength << 3;
        final var nonce = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(7, 14));
        final var associatedText = ThreadLocalRandom.current().nextBoolean() ?
                null : _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
        final var cipher = CCMBlockCipher.newInstance(AESEngine.newInstance());
        final var params = new AEADParameters(new KeyParameter(key), macSize, nonce, associatedText);
        final var plain = _Random_TestUtils.createTempFileWithRandomBytesWritten(dir);
        // ----------------------------------------------------------------------------------------------------- encrypt
        final var encrypted = File.createTempFile("tmp", null, dir);
        try (var source = new FileInputStream(plain);
             var target = new FileOutputStream(encrypted)) {
            cipher.init(true, params);
            JinahyaAEADCipherUtils.processAllBytesAndDoFinal(
                    cipher,
                    source,
                    target,
                    ThreadLocalRandom.current().nextInt(1, 8192)
            );
            target.flush();
        }
        final var encryptionMac = cipher.getMac();
        // ----------------------------------------------------------------------------------------------------- decrypt
        final var decrypted = File.createTempFile("tmp", null, dir);
        try (var source = new FileInputStream(encrypted);
             var target = new FileOutputStream(decrypted)) {
            cipher.init(false, params);
            JinahyaAEADCipherUtils.processAllBytesAndDoFinal(
                    cipher,
                    source,
                    target,
                    ThreadLocalRandom.current().nextInt(1, 8192)
            );
            target.flush();
        }
        final var decryptionMac = cipher.getMac();
        // -------------------------------------------------------------------------------------------------------- then
        assertThat(decrypted).hasSameBinaryContentAs(plain);
        assertThat(decryptionMac).isEqualTo(encryptionMac);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private static Stream<Arguments> getArgumentsStream() {
        return _CCM_TestUtils.getArgumentsStream(
                AES__Test::getKeySizeStream,
                AESEngine::newInstance
        );
    }

    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final AEADCipher cipher, final CipherParameters params) throws Exception {
        _AEADCipher_TestUtils.__(cipher, params);
    }

    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final AEADCipher cipher, final CipherParameters params, @TempDir final File dir) throws Exception {
        _AEADCipher_TestUtils.__(cipher, params, dir);
    }
}
