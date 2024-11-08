package _org.bouncycastle.crypto;

import _javax.security._Random_TestUtils;
import io.github.jinahya.bouncycastle.crypto.JinahyaStreamCipherCrypto;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThat;

public final class _StreamCipher_TestUtils {

    public static String cipherName(final StreamCipher cipher) {
        Objects.requireNonNull(cipher, "cipher is null");
        return String.format("%1$s", cipher.getAlgorithmName());
    }

    // -----------------------------------------------------------------------------------------------------------------
    private static void __(final StreamCipher cipher, final CipherParameters params, final byte[] plain) {
        final var crypto = new JinahyaStreamCipherCrypto(cipher, params);
        // ----------------------------------------------------------------------------------------------------- encrypt
//        cipher.init(true, params);
//        final var encrypted = JinahyaStreamCipherUtils.processBytes(cipher, plain);
//        final var encrypted = StreamCipherUtils.encrypt(cipher, params, plain);
        final var encrypted = crypto.encrypt(plain);
        // ----------------------------------------------------------------------------------------------------- decrypt
//        cipher.init(false, params);
//        final var decrypted = JinahyaStreamCipherUtils.processBytes(cipher, encrypted);
//        final var decrypted = StreamCipherUtils.decrypt(cipher, params, encrypted);
        final var decrypted = crypto.decrypt(encrypted);
        // ------------------------------------------------------------------------------------------------------ verify
        assertThat(decrypted).isEqualTo(plain);
    }

    public static void __(final StreamCipher cipher, final CipherParameters params) {
        _Random_TestUtils.getRandomBytesStream().forEach(b -> {
            __(cipher, params, b);
        });
    }

    // -----------------------------------------------------------------------------------------------------------------
    private static void __(final StreamCipher cipher, final CipherParameters params, final File dir,
                           final File plain)
            throws Exception {
        final var crypto = new JinahyaStreamCipherCrypto(cipher, params);
        // ----------------------------------------------------------------------------------------------------- encrypt
//        cipher.init(true, params);
        final var encrypted = File.createTempFile("tmp", null, dir);
        try (var in = new FileInputStream(plain);
             var out = new FileOutputStream(encrypted)) {
//            final var bytes = StreamCipherUtils.processAllBytes(cipher, in, out, new byte[1]);
            final var bytes = crypto.encrypt(in, out, new byte[ThreadLocalRandom.current().nextInt(1024) + 1]);
            out.flush();
        }
        // ----------------------------------------------------------------------------------------------------- decrypt
//        cipher.init(false, params);
        final var decrypted = File.createTempFile("tmp", null, dir);
        try (var in = new FileInputStream(encrypted);
             var out = new FileOutputStream(decrypted)) {
//            final var bytes = StreamCipherUtils.processAllBytes(cipher, in, out, new byte[1]);
            final var bytes = crypto.decrypt(in, out, new byte[ThreadLocalRandom.current().nextInt(1024) + 1]);
            out.flush();
        }
        // ------------------------------------------------------------------------------------------------------ verify
        assertThat(decrypted).hasSize(plain.length());
        assertThat(decrypted).hasSameBinaryContentAs(plain);
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
    private _StreamCipher_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
