package _javax.security;

import org.apache.commons.codec.digest.DigestUtils;

import java.io.File;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import static org.assertj.core.api.Assertions.assertThat;

public final class _MessageDigest_TestUtils {

    public static void __(final File plain, final File decrypted) throws NoSuchAlgorithmException, IOException {
        for (var algorithm : Security.getAlgorithms("MessageDigest")) {
            final var digest = MessageDigest.getInstance(algorithm);
            assertThat(decrypted).hasDigest(digest, DigestUtils.digest(digest, plain));
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _MessageDigest_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
