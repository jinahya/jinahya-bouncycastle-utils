package io.github.jinahya.util.bouncycastle.crypto;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.function.Function;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class JinahyaCipherParametersUtilsTest {

    private static IntStream getKeySizeStream() {
        return IntStream.of(
                128,
                192,
                256
        );
    }

    private static IntStream getBlockSizeStream() {
        return IntStream.of(
                128
        );
    }

    private static Stream<Arguments> getKeySizeAndBlockSizeArgumentsStream() {
        return getKeySizeStream().mapToObj(ks -> {
            return getBlockSizeStream().mapToObj(bs -> Arguments.of(ks, bs));
        }).flatMap(Function.identity());
    }

    // -----------------------------------------------------------------------------------------------------------------
    @MethodSource({
            "getKeySizeStream"
    })
    @ParameterizedTest
    void newKey__(final int keySize) {
        final var key = JinahyaCipherParametersUtils.newRandomKey(null, keySize);
        assertThat(key).isNotNull().hasSize(keySize >> 3);
    }

    @MethodSource({
            "getBlockSizeStream"
    })
    @ParameterizedTest
    void newIv__(final int blockSize) {
        final var iv = JinahyaCipherParametersUtils.newRandomIv(null, blockSize);
        assertThat(iv).isNotNull().hasSize(blockSize >> 3);
    }

    // -----------------------------------------------------------------------------------------------------------------
    @MethodSource({
            "getKeySizeStream"
    })
    @ParameterizedTest
    void newKeyParameter__(final int keySize) {
        final var params = JinahyaCipherParametersUtils.newRandomKeyParameter(null, keySize);
        final var key = JinahyaCipherParametersUtils.getKey(params);
        assertThat(key).isNotNull().hasSize(keySize >> 3);
    }

    @MethodSource({
            "getKeySizeAndBlockSizeArgumentsStream"
    })
    @ParameterizedTest
    void newParametersWithIV__(final int keySize, final int blockSize) {
        final var params = JinahyaCipherParametersUtils.newRandomParametersWithIV(null, keySize, blockSize);
        final var key = JinahyaCipherParametersUtils.getKey(params);
        final var iv = JinahyaCipherParametersUtils.getIV(params);
        assertThat(key).isNotNull().hasSize(keySize >> 3);
        assertThat(iv).isNotNull().hasSize(128 >> 3);
    }
}