package io.github.jinahya.util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Predicate;
import java.util.stream.Stream;

public final class _RandomTestUtils {

    static SecureRandom newSecureRandom() {
        try {
            return SecureRandom.getInstanceStrong();
        } catch (final NoSuchAlgorithmException nsae) {
            throw new RuntimeException("failed to get a strong secure random instance", nsae);
        }
    }

    public static byte[] newRandomBytes(final int length) {
        final var bytes = new byte[length];
        newSecureRandom().nextBytes(bytes);
        return bytes;
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static <T extends File> T writeRandomBytesWhile(final T file, final Predicate<? super T> tester)
            throws IOException {
        Objects.requireNonNull(file, "file is null");
        Objects.requireNonNull(tester, "tester is null");
        do {
            try (var stream = new FileOutputStream(file, true)) {
                stream.write(newRandomBytes(ThreadLocalRandom.current().nextInt(1024)));
                stream.flush();
            }
        } while (tester.test(file));
        return file;
    }

    public static <T extends File> T writeRandomBytes(final T file) throws IOException {
        return writeRandomBytesWhile(file, f -> false);
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static Stream<byte[]> getRandomBytesStream() {
        return Stream.of(
                new byte[0],
                new byte[1],
                newRandomBytes(1),
                newRandomBytes(ThreadLocalRandom.current().nextInt(16))
        );
    }

    public static Stream<File> getRandomFileStream(final File dir) throws IOException {
        return Stream.of(
                File.createTempFile("tmp", null, dir),
                writeRandomBytes(File.createTempFile("tmp", null, dir))
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _RandomTestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
