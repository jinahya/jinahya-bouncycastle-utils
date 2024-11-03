package io.github.jinahya.util;

import _org.junit.jupiter.params.provider._Arguments_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto.params.JinahyaKeyParametersUtils;
import io.github.jinahya.util.bouncycastle.crypto.params.JinahyaParametersWithIvUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

import java.util.Objects;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.IntStream;
import java.util.stream.Stream;

@Slf4j
public final class _OFB_TestUtils {

    public static final String MODE = "OFB";

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

//    public static Stream<Arguments> getBitWidthAndKeySizeArgumentsStream(
//            final Supplier<? extends IntStream> keySizeStreamSupplier) {
//        return keySizeStreamSupplier.get().mapToObj(ks -> {
//            return getBitWidthStream().mapToObj(bw -> {
//                return Arguments.of(
//                        Named.named("keySize: " + ks, ks),
//                        Named.named("bitWidth: " + bw, bw)
//                );
//            });
//        }).flatMap(Function.identity());
//    }

    public static Stream<Arguments> getBitWidthAndKeySizeArgumentsStream(
            final Supplier<? extends IntStream> keyStreamSupplier) {
        return getBitWidthStream().mapToObj(bw -> {
            return keyStreamSupplier.get().mapToObj(ks -> {
                return Arguments.of(bw, ks);
            });
        }).flatMap(Function.identity());
    }

    public static Stream<Arguments> getCipherAndParamsArgumentsStream(
            final Supplier<? extends IntStream> keyStreamSupplier,
            final Supplier<? extends BlockCipher> cipherSupplier) {
        return getBitWidthStream().mapToObj(bs -> {
                    final var engine = cipherSupplier.get();
                    try {
                        return new OFBBlockCipher(engine, bs);
                    } catch (final Exception e) {
                        log.error("failed to create CFBBlockCipher with cipher({}) and bit width: {}", engine, bs, e);
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .flatMap(c -> keyStreamSupplier.get().mapToObj(ks -> {
                    final var params = JinahyaParametersWithIvUtils.newRandomInstanceFor(
                            JinahyaKeyParametersUtils.newRandomInstance(null, ks >> 3),
                            null,
                            c.getUnderlyingCipher()
                    );
                    return _Arguments_TestUtils.argumentsOf(c, params);
                }));
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _OFB_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
