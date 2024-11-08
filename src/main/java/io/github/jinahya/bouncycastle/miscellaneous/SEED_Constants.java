package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.stream.IntStream;

final class SEED_Constants {

    public static final String ALGORITHM = "SEED";

    public static final int BLOCK_SIZE = 128;

    public static final int BLOCK_BYTES = BLOCK_SIZE >> 3;

    static IntStream getKeySizeStream() {
        return IntStream.of(128)
                .peek(ks -> {
                    assert ks % (BLOCK_SIZE >> 3) == 0;
                });
    }

    static IntStream getKeyBytesStream() {
        return getKeySizeStream().map(ks -> ks >> 3);
    }

    private SEED_Constants() {
        throw new AssertionError("instantiation is not allowed");
    }
}
