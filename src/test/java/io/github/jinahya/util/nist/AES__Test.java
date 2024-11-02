package io.github.jinahya.util.nist;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

import java.util.stream.IntStream;
import java.util.stream.Stream;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
abstract class AES__Test {

    static final String ALGORITHM = "AES";

    static final int BLOCK_SIZE = 128;

    static final int BLOCK_BYTES = BLOCK_SIZE >> 3;

    static IntStream getKeySizeStream() {
        return IntStream.of(
                128,
                196,
                256
        );
    }

    static Stream<Arguments> getKeySizeArgumentsStream() {
        return getKeySizeStream().mapToObj(ks -> {
            return Arguments.of(
                    Named.of("keySize: " + ks, ks)
            );
        });
    }

    static IntStream getKeyBytesStream() {
        return getKeySizeStream().map(ks -> ks >> 3);
    }

    static Stream<Arguments> getKeyBytesArgumentsStream() {
        return getKeyBytesStream().mapToObj(ks -> {
            return Arguments.of(
                    Named.of("keyBytes: " + ks, ks)
            );
        });
    }
}
