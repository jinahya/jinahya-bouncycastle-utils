package io.github.jinahya.util.bouncycastle.crypto;

import io.github.jinahya.util.bouncycastle.crypto.params._KeyParametersTestUtils;
import io.github.jinahya.util.bouncycastle.crypto.params._ParametersWithIVTestUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.io.File;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Objects;

@Slf4j
public final class _BlockCipherTestUtils {

    // -----------------------------------------------------------------------------------------------------------------
    static String cipherName(final BlockCipher cipher, final int keySize) {
        return String.format("%1$s/%2$d", cipher.getAlgorithmName(), keySize);
    }

    public static String cipherName(final BlockCipher cipher) {
        return cipherName(cipher, cipher.getBlockSize());
    }

    public static String cipherName(final BlockCipher cipher, final BlockCipherPadding padding) {
        return String.format("%1$s/%2$s", cipher.getAlgorithmName(), padding.getPaddingName());
    }

    static String keyName(final byte[] key) {
        return String.format("%1$d 0x%2$02X", key.length << 3, key[0]);
    }

    public static String paramsName(final CipherParameters parameters) {
        Objects.requireNonNull(parameters, "parameters is null");
        if (parameters instanceof KeyParameter p) {
            return _KeyParametersTestUtils.paramsName(p);
        }
        if (parameters instanceof ParametersWithIV p) {
            return _ParametersWithIVTestUtils.paramsName(p);
        }
        throw new RuntimeException("failed to get key from " + parameters);
    }

    // -----------------------------------------------------------------------------------------------------------------
    static void log(final String name, final byte[] bytes) {
        log.debug("{}: {}, {}", name, bytes.length, Base64.getEncoder().encodeToString(bytes));
    }

    static void log(final byte[] plain, final byte[] encrypted, final byte[] decrypted) {
        log("   plain", plain);
        log("encrypted", encrypted);
        log("decrypted", decrypted);
    }

    static void log(final String name, final File file)
            throws NoSuchAlgorithmException, IOException {
        final var digest = MessageDigest.getInstance("SHA-1");
        log.debug("{}: {}, {}", name, file.length(), Base64.getEncoder()
                .encodeToString(DigestUtils.digest(digest, file)));
    }

    static void log(final File plain, final File encrypted, final File decrypted)
            throws NoSuchAlgorithmException, IOException {
        log("   plain", plain);
        log("encrypted", encrypted);
        log("decrypted", decrypted);
    }

    private _BlockCipherTestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
