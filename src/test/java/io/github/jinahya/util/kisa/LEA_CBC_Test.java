package io.github.jinahya.util.kisa;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto._BufferedBlockCipher_TestUtils;
import _org.bouncycastle.crypto.paddings._BlockCipherPadding_TestUtils;
import io.github.jinahya.util._CBC_TestUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.LEAEngine;
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class LEA_CBC_Test
        extends LEA__Test {

    @DisplayName("Low-level API")
    @Nested
    class LowLevelApiTest {

        private static Stream<Arguments> getPaddingAndKeySizeArgumentsStream() {
            return _BlockCipherPadding_TestUtils.getPaddingAndKeySizeArgumentsStream(
                    LEA__Test::getKeySizeStream
            );
        }

        @DisplayName("encrypt/decrypt bytes")
        @MethodSource({"getPaddingAndKeySizeArgumentsStream"})
        @ParameterizedTest(name = "[{index}] {0} with {1}-bit key")
        void __(final BlockCipherPadding padding, final int keySize) throws Exception {
            final var cipher = new PaddedBufferedBlockCipher(
                    CBCBlockCipher.newInstance(new LEAEngine()),
                    padding
            );
            final CipherParameters params;
            {
                final var key = _Random_TestUtils.newRandomBytes(keySize >>> 3);
                // initialisation vector must be the same length as block size
                final var iv = _Random_TestUtils.newRandomBytes(cipher.getBlockSize());
                params = ThreadLocalRandom.current().nextBoolean()
                        ? new KeyParameter(key)
                        : new ParametersWithIV(new KeyParameter(key), iv);
            }
            final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
            // ------------------------------------------------------------------------------------------------- encrypt
            cipher.init(true, params);
            var encrypted = new byte[cipher.getOutputSize(plain.length)];
            {
                final var processed = cipher.processBytes(plain, 0, plain.length, encrypted, 0);
                final var finalized = cipher.doFinal(encrypted, processed);
                encrypted = Arrays.copyOf(encrypted, (processed + finalized));
                assertThat(encrypted).hasSizeGreaterThanOrEqualTo(plain.length);
            }
            // ------------------------------------------------------------------------------------------------- decrypt
            cipher.init(false, params);
            byte[] decrypted = new byte[cipher.getOutputSize(encrypted.length)];
            {
                final var processed = cipher.processBytes(encrypted, 0, encrypted.length, decrypted, 0);
                final var finalized = cipher.doFinal(decrypted, processed);
                decrypted = Arrays.copyOf(decrypted, (processed + finalized));
            }
            // -------------------------------------------------------------------------------------------------- verify
            assertThat(decrypted).isEqualTo(plain);
        }

        @DisplayName("encrypt/decrypt file")
        @MethodSource({"getPaddingAndKeySizeArgumentsStream"})
        @ParameterizedTest(name = "[{index}] {0} with {1}-bit key")
        void __(final BlockCipherPadding padding, final int keySize, @TempDir final File dir) throws Exception {
            // --------------------------------------------------------------------------------------------------- given
            final var cipher = new PaddedBufferedBlockCipher(
                    CBCBlockCipher.newInstance(new LEAEngine()),
                    padding
            );
            final CipherParameters params;
            {
                final var key = _Random_TestUtils.newRandomBytes(keySize >>> 3);
                final var iv = _Random_TestUtils.newRandomBytes(cipher.getBlockSize());
                params = ThreadLocalRandom.current().nextBoolean()
                        ? new KeyParameter(key)
                        : new ParametersWithIV(new KeyParameter(key), iv);
            }
            final var plain = _Random_TestUtils.createTempFileWithRandomBytesWritten(dir);
            // ------------------------------------------------------------------------------------------------- encrypt
            final var encrypted = File.createTempFile("tmp", null, dir);
            {
                cipher.init(true, params);
                try (var out = new CipherOutputStream(new FileOutputStream(encrypted), cipher)) {
                    final var bytes = Files.copy(plain.toPath(), out);
                    out.flush();
                }
            }
            // ------------------------------------------------------------------------------------------------- decrypt
            final var decrypted = File.createTempFile("tmp", null, dir);
            {
                cipher.init(false, params);
                try (var in = new CipherInputStream(new FileInputStream(encrypted), cipher)) {
                    final var bytes = Files.copy(in, decrypted.toPath(), StandardCopyOption.REPLACE_EXISTING);
                }
            }
            // -------------------------------------------------------------------------------------------------- verify
            assertThat(decrypted).hasSameBinaryContentAs(plain);
        }

        private static Stream<Arguments> getCipherAndParamsArgumentsStream() {
            return _CBC_TestUtils.getCipherAndParamsArgumentsStream(
                    LEAEngine::new, LEA__Test::getKeySizeStream
            );
        }

        // -----------------------------------------------------------------------------------------------------------------
        @DisplayName("encrypt/decrypt bytes")
        @MethodSource({"getCipherAndParamsArgumentsStream"})
        @ParameterizedTest
        void __(final PaddedBufferedBlockCipher cipher, final CipherParameters params) throws Exception {
            _BufferedBlockCipher_TestUtils.__(cipher, params);
        }

        @DisplayName("encrypt/decrypt file")
        @MethodSource({"getCipherAndParamsArgumentsStream"})
        @ParameterizedTest
        void __(final PaddedBufferedBlockCipher cipher, final CipherParameters params, @TempDir final File dir)
                throws Exception {
            _BufferedBlockCipher_TestUtils.__(cipher, params, dir);
        }
    }
}
