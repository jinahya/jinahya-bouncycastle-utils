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

    // -----------------------------------------------------------------------------------------------------------------
    public static Path writeRandomBytes(final Path file) throws IOException {
        return Files.write(
                file,
                newRandomBytes(ThreadLocalRandom.current().nextInt(8192))
        );
    }

    public static File writeRandomBytes(final File file) throws IOException {
        return writeRandomBytes(file.toPath()).toFile();
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static Path createTempFileWithRandomBytesWritten(final Path dir) throws IOException {
        return writeRandomBytes(
                Files.createTempFile(dir, null, null)
        );
    }

    public static File createTempFileWithRandomBytesWritten(final File dir) throws IOException {
        return createTempFileWithRandomBytesWritten(dir.toPath()).toFile();
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static Stream<byte[]> getRandomBytesStream() {
        return Stream.of(
                new byte[0], // empty
                new byte[1], // single zero
                newRandomBytes(1), // single random
                newRandomBytes(ThreadLocalRandom.current().nextInt(8192)) // random
        );
    }

    public static Stream<Path> getRandomFileStream(final Path dir) throws IOException {
        return Stream.of(
                Files.createTempFile(dir, null, null), // empty
                createTempFileWithRandomBytesWritten(dir) // random
        );
    }

    public static Stream<File> getRandomFileStream(final File dir) throws IOException {
        return getRandomFileStream(dir.toPath()).map(Path::toFile);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _Random_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
