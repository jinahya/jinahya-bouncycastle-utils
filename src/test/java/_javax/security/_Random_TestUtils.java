package _javax.security;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Predicate;
import java.util.stream.Stream;

public final class _Random_TestUtils {

    private static SecureRandom random = null;

    static SecureRandom random() {
        if (random == null) {
            try {
                random = SecureRandom.getInstanceStrong();
            } catch (final NoSuchAlgorithmException nsae) {
                throw new RuntimeException("failed to get a strong secure random instance", nsae);
            }
        }
        return random;
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static byte[] newRandomBytes(final int length) {
        if (length < 0) {
            throw new IllegalArgumentException("negative length: " + length);
        }
        final var bytes = new byte[length];
        random().nextBytes(bytes);
        return bytes;
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static <T extends File> T writeRandomBytesWhile(final T file, final Predicate<? super T> tester)
            throws IOException {
        Objects.requireNonNull(file, "file is null");
        Objects.requireNonNull(tester, "tester is null");
        do {
            try (var stream = new FileOutputStream(file, true)) {
                stream.write(newRandomBytes(ThreadLocalRandom.current().nextInt(8192)));
                stream.flush();
            }
        } while (tester.test(file));
        return file;
    }

    public static <T extends File> T writeRandomBytes(final T file) throws IOException {
        return writeRandomBytesWhile(file, f -> false);
    }

    public static Path createTempFileWithRandomBytesWritten(final Path dir) throws IOException {
        final var file = Files.createTempFile(dir, null, null);
        writeRandomBytes(file.toFile());
        return file;
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
    private _Random_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
