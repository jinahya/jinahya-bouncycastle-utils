package io.github.jinahya.util;

import _org.bouncycastle.crypto.params._ParametersWithIV_TestUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

import java.util.Objects;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.IntStream;
import java.util.stream.Stream;

@Slf4j
public final class _CFB_TestUtils {

    public static final String MODE = "CFB";

    public static IntStream getBitWidthStream() {
        return IntStream.of(
                1,
                8,
                64,
                128
        );
    }

    public static String mode(final int bitWidth) {
        return MODE + bitWidth;
    }

    public static Stream<Arguments> getKeySizeAndBitWidthArgumentsStream(
            final Supplier<? extends IntStream> keySizeStreamSupplier) {
        return keySizeStreamSupplier.get().mapToObj(ks -> {
            return getBitWidthStream().mapToObj(bw -> {
                return Arguments.of(
                        Named.named("keySize: " + ks, ks),
                        Named.named("bitWidth: " + bw, bw)
                );
            });
        }).flatMap(Function.identity());
    }

    public static Stream<Arguments> getCipherAndParamsArgumentsStream(
            final Supplier<? extends IntStream> keySizeStreamSupplier,
            final Supplier<? extends BlockCipher> cipherSupplier) {
        return getBitWidthStream()
                .mapToObj(bw -> {
                    final var engine = cipherSupplier.get();
                    try {
                        return CFBBlockCipher.newInstance(engine, bw);
                    } catch (final Exception e) {
                        log.error("failed to create cipher for bitWidth: {}", bw, e);
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .flatMap(c -> keySizeStreamSupplier.get().mapToObj(ks -> {
                    final var params = _ParametersWithIV_TestUtils.newRandomInstanceOfParametersWithIV(null, ks, c);
                    return Arguments.of(
                            Named.of(_TestUtils.cipherName(c), c),
                            Named.of("params: " + params, params)
                    );
                }));
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _CFB_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
