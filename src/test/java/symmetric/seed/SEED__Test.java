package symmetric.seed;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.stream.IntStream;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
abstract class SEED__Test {

    static final String ALGORITHM = "SEED";

    public static final int BLOCK_SIZE = 128;

    public static final int BLOCK_BYTES = BLOCK_SIZE >> 3;

    static IntStream getKeySizeStream() {
        return IntStream.of(
                128
        );
    }

    static IntStream getKeyBytestream() {
        return getKeySizeStream().map(ks -> ks >> 3);
    }
}
