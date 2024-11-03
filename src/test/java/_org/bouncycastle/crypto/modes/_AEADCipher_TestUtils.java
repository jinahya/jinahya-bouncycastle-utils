package _org.bouncycastle.crypto.modes;

import _javax.security._Random_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto.modes.JinahyaAEADCipherUtils;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.modes.AEADCipher;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.MessageDigest;
import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThat;

public final class _AEADCipher_TestUtils {

    // -----------------------------------------------------------------------------------------------------------------
    private static void __(final AEADCipher cipher, final CipherParameters params, final byte[] plain)
            throws Exception {
        // ----------------------------------------------------------------------------------------------------- encrypt
        cipher.init(true, params);
        final var encrypted = JinahyaAEADCipherUtils.processBytesAndDoFinal(cipher, plain);
        final var encryptionMac = cipher.getMac();
        // ----------------------------------------------------------------------------------------------------- decrypt
        cipher.init(false, params);
        final var decrypted = JinahyaAEADCipherUtils.processBytesAndDoFinal(cipher, encrypted);
        final var decryptionMac = cipher.getMac();
        // -------------------------------------------------------------------------------------------------------- then
        assertThat(decrypted).isEqualTo(plain);
        assertThat(decryptionMac).isEqualTo(encryptionMac);
    }

    public static void __(final AEADCipher cipher, final CipherParameters params) throws Exception {
        final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
        __(cipher, params, plain);
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static void __(final AEADCipher cipher, final CipherParameters params, final File dir)
            throws Exception {
        final var plain = _Random_TestUtils.createTempFileWithRandomBytesWritten(dir);
        // ----------------------------------------------------------------------------------------------------- encrypt
        cipher.init(true, params);
        final var encrypted = File.createTempFile("tmp", null, dir);
        try (var source = new FileInputStream(plain);
             var target = new FileOutputStream(encrypted)) {
            JinahyaAEADCipherUtils.processAllBytesAndDoFinal(
                    cipher,
                    source,
                    target,
                    new byte[ThreadLocalRandom.current().nextInt(1024) + 1]
            );
            target.flush();
        }
        // ----------------------------------------------------------------------------------------------------- decrypt
        cipher.init(false, params);
        final var decrypted = File.createTempFile("tmp", null, dir);
        try (var source = new FileInputStream(encrypted);
             var target = new FileOutputStream(decrypted)) {
            JinahyaAEADCipherUtils.processAllBytesAndDoFinal(
                    cipher,
                    source,
                    target,
                    new byte[ThreadLocalRandom.current().nextInt(1024) + 1]
            );
            target.flush();
        }
        // -------------------------------------------------------------------------------------------------------- then
        assertThat(decrypted).hasSize(plain.length());
        for (var algorithm : new String[]{"SHA-1", "SHA-256"}) {
            final var digest = MessageDigest.getInstance(algorithm);
            assertThat(decrypted).hasDigest(digest, DigestUtils.digest(digest, plain));
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _AEADCipher_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
