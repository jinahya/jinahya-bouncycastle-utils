package io.github.jinahya.util.kisa;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.stream.IntStream;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
abstract class ARIA__Test {

    static final String ALGORITHM = "ARIA";

    static final int BLOCK_SIZE = 128;

    static final int BLOCK_BYTES = BLOCK_SIZE >> 3;

    static IntStream getKeySizeStream() {
        return IntStream.of(
                128,
                192,
                256
        );
    }

    static IntStream getKeyBytesStream() {
        return getKeySizeStream().map(ks -> ks >> 3);
    }
}
