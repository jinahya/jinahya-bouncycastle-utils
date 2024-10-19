package io.github.jinahya.bouncycastle.util;

import io.github.jinahya.util.bouncycastle.crypto.JinahyaBufferedBlockCipherUtils;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.MessageDigest;
import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThat;

public final class _BufferedBlockCipherTestUtils {

    private static void __(final BufferedBlockCipher cipher, final CipherParameters params, final byte[] plain)
            throws Exception {
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

    public static void __(final BufferedBlockCipher cipher, final CipherParameters params) throws Exception {
        __(cipher, params, new byte[0]); // empty
        __(cipher, params, new byte[1]); // zero
        __(cipher, params, _RandomTestUtils.newRandomBytes(1));
        __(cipher, params, _RandomTestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(16)));
    }

    private static void __(final BufferedBlockCipher cipher, final CipherParameters params, final File dir,
                           final File plain)
            throws Exception {
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

    public static void __(final BufferedBlockCipher cipher, final CipherParameters params, final File dir)
            throws Exception {
        __(cipher, params, dir, File.createTempFile("tmp", null, dir));
        __(cipher, params, dir, _RandomTestUtils.writeRandomBytes(File.createTempFile("tmp", null, dir)));
    }

    private _BufferedBlockCipherTestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
