package io.github.jinahya.util;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;

import java.io.File;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@Slf4j
public final class _LogUtils {

    static void log(final String name, final byte[] bytes) {
        log.debug(
                "{}: {}, {}",
                name,
                String.format("%1$10d", bytes.length),
                Base64.getEncoder().encodeToString(bytes)
        );
    }

    public static void log(final byte[] plain, final byte[] encrypted, final byte[] decrypted) {
        log("    plain", plain);
        log("encrypted", encrypted);
        log("decrypted", decrypted);
    }

    static void log(final String name, final File file)
            throws NoSuchAlgorithmException, IOException {
        final var digest = MessageDigest.getInstance("SHA-1");
        log.debug(
                "{}: {}, {}",
                name,
                String.format("%1$10d", file.length()),
                Base64.getEncoder().encodeToString(DigestUtils.digest(digest, file))
        );
    }

    public static void log(final File plain, final File encrypted, final File decrypted)
            throws NoSuchAlgorithmException, IOException {
        log("    plain", plain);
        log("encrypted", encrypted);
        log("decrypted", decrypted);
    }

    private _LogUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
