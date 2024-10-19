package io.github.jinahya.util.bouncycastle.crypto;

import io.github.jinahya.util._LogUtils;
import io.github.jinahya.util._RandomTestUtils;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;

import static org.assertj.core.api.Assertions.assertThat;

public final class _StreamCipherTestUtils {

    private static void __(final StreamCipher cipher, final CipherParameters params, final byte[] plain) {
        // ----------------------------------------------------------------------------------------------------- encrypt
        cipher.init(true, params);
        final var encrypted = JinahyaStreamCipherUtils.processBytes(cipher, plain);
        // ----------------------------------------------------------------------------------------------------- decrypt
        cipher.init(false, params);
        final var decrypted = JinahyaStreamCipherUtils.processBytes(cipher, encrypted);
        // -------------------------------------------------------------------------------------------------------- then
        _LogUtils.log(plain, encrypted, decrypted);
        assertThat(decrypted).isEqualTo(plain);
    }

    public static void __(final StreamCipher cipher, final CipherParameters params) throws Exception {
        _RandomTestUtils.getRandomBytesStream().forEach(b -> {
            __(cipher, params, b);
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
        _LogUtils.log(plain, encrypted, decrypted);
        assertThat(decrypted).hasSize(plain.length());
        for (var algorithm : new String[]{"SHA-1", "SHA-256"}) {
            final var digest = MessageDigest.getInstance(algorithm);
            assertThat(decrypted).hasDigest(digest, DigestUtils.digest(digest, plain));
        }
    }

    public static void __(final StreamCipher cipher, final CipherParameters params, final File dir) throws IOException {
        _RandomTestUtils.getRandomFileStream(dir).forEach(f -> {
            try {
                __(cipher, params, dir, f);
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _StreamCipherTestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
