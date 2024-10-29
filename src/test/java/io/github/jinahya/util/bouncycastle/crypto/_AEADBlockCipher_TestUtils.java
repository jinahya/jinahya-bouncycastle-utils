package io.github.jinahya.util.bouncycastle.crypto;

import _javax.security._Random_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto.modes.JinahyaAEADCipherUtils;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.modes.AEADBlockCipher;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.Objects;

import static org.assertj.core.api.Assertions.assertThat;

public final class _AEADBlockCipher_TestUtils {

    public static String cipherName(final StreamCipher cipher) {
        return Objects.requireNonNull(cipher, "cipher is null").getAlgorithmName();
    }

//    public static String cipherName(final StreamCipher cipher, final BlockCipherPadding padding) {
//        return _BlockCipherTestUtils.cipherName(
//                Objects.requireNonNull(cipher, "cipher is null").getUnderlyingCipher(),
//                padding
//        );
//    }

    // -----------------------------------------------------------------------------------------------------------------
    private static void __(final AEADBlockCipher cipher, final CipherParameters params, final byte[] plain)
            throws Exception {
        // ----------------------------------------------------------------------------------------------------- encrypt
        cipher.init(true, params);
        final var encrypted = JinahyaAEADCipherUtils.processBytesAndDoFinal(cipher, plain);
        // ----------------------------------------------------------------------------------------------------- decrypt
        cipher.init(false, params);
        final var decrypted = JinahyaAEADCipherUtils.processBytesAndDoFinal(cipher, encrypted);
        // -------------------------------------------------------------------------------------------------------- then
        assertThat(decrypted).isEqualTo(plain);
    }

    public static void __(final AEADBlockCipher cipher, final CipherParameters params) throws Exception {
        _Random_TestUtils.getRandomBytesStream().forEach(b -> {
            try {
                __(cipher, params, b);
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    // -----------------------------------------------------------------------------------------------------------------
    private static void __(final StreamCipher cipher, final CipherParameters params, final File dir,
                           final File plain)
            throws Exception {
        // ----------------------------------------------------------------------------------------------------- encrypt
        cipher.init(true, params);
        final var encrypted = File.createTempFile("tmp", null, dir);
        try (var source = new FileInputStream(plain);
             var target = new FileOutputStream(encrypted)) {
            JinahyaStreamCipherUtils.processAllBytes(cipher, source, target, new byte[1]);
            target.flush();
        }
        // ----------------------------------------------------------------------------------------------------- decrypt
        cipher.init(false, params);
        final var decrypted = File.createTempFile("tmp", null, dir);
        try (var source = new FileInputStream(encrypted);
             var target = new FileOutputStream(decrypted)) {
            JinahyaStreamCipherUtils.processAllBytes(cipher, source, target, new byte[1]);
            target.flush();
        }
        // -------------------------------------------------------------------------------------------------------- then
//        _LogUtils.log(plain, encrypted, decrypted);
        assertThat(decrypted).hasSize(plain.length());
        for (var algorithm : new String[]{"SHA-1", "SHA-256"}) {
            final var digest = MessageDigest.getInstance(algorithm);
            assertThat(decrypted).hasDigest(digest, DigestUtils.digest(digest, plain));
        }
    }

    public static void __(final StreamCipher cipher, final CipherParameters params, final File dir) throws IOException {
        _Random_TestUtils.getRandomFileStream(dir).forEach(f -> {
            try {
                __(cipher, params, dir, f);
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _AEADBlockCipher_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
