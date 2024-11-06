package _org.bouncycastle.crypto.modes;

import _javax.security._Random_TestUtils;
import io.github.jinahya.bouncycastle.crypto.modes.JinahyaAEADCipherCrypto;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.modes.AEADCipher;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThat;

public final class _AEADCipher_TestUtils {

    // -----------------------------------------------------------------------------------------------------------------
    private static void __(final AEADCipher cipher, final CipherParameters params, final byte[] plain)
            throws Exception {
        final var crypto = new JinahyaAEADCipherCrypto(cipher, params);
        // ----------------------------------------------------------------------------------------------------- encrypt
//        cipher.init(true, params);
//        final var encrypted = JinahyaAEADCipherUtils.processBytesAndDoFinal(cipher, plain);
        final var encrypted = crypto.encrypt(plain);
        final var encryptionMac = cipher.getMac();
        // ----------------------------------------------------------------------------------------------------- decrypt
//        cipher.init(false, params);
//        final var decrypted = JinahyaAEADCipherUtils.processBytesAndDoFinal(cipher, encrypted);
        final var decrypted = crypto.decrypt(encrypted);
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
        final var crypto = new JinahyaAEADCipherCrypto(cipher, params);
        final var plain = _Random_TestUtils.createTempFileWithRandomBytesWritten(dir);
        // ----------------------------------------------------------------------------------------------------- encrypt
//        cipher.init(true, params);
        final var encrypted = File.createTempFile("tmp", null, dir);
        try (var in = new FileInputStream(plain);
             var out = new FileOutputStream(encrypted)) {
//            JinahyaAEADCipherUtils.processAllBytesAndDoFinal(
//                    cipher,
//                    in,
//                    out,
//                    new byte[ThreadLocalRandom.current().nextInt(1024) + 1]
//            );
            crypto.encrypt(in, out, new byte[ThreadLocalRandom.current().nextInt(1024) + 1]);
            out.flush();
        }
        // ----------------------------------------------------------------------------------------------------- decrypt
//        cipher.init(false, params);
        final var decrypted = File.createTempFile("tmp", null, dir);
        try (var in = new FileInputStream(encrypted);
             var out = new FileOutputStream(decrypted)) {
//            JinahyaAEADCipherUtils.processAllBytesAndDoFinal(
//                    cipher,
//                    in,
//                    out,
//                    new byte[ThreadLocalRandom.current().nextInt(1024) + 1]
//            );
            crypto.decrypt(in, out, new byte[ThreadLocalRandom.current().nextInt(1024) + 1]);
            out.flush();
        }
        // -------------------------------------------------------------------------------------------------------- then
        assertThat(decrypted)
                .hasSize(plain.length())
                .hasSameBinaryContentAs(plain);
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static String cipherName(final AEADCipher cipher) {
        return cipher.getAlgorithmName();
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _AEADCipher_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
