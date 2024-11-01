package io.github.jinahya.util;

import io.github.jinahya.util.bouncycastle.crypto.params._KeyParametersTestUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

import java.util.Objects;
import java.util.function.Supplier;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static io.github.jinahya.util.bouncycastle.crypto.paddings._BlockCipherPaddingTestUtils.getBlockCipherPaddingStream;

@Slf4j
public final class _ECB_TestUtils {

    public static final String MODE = "ECB";

    public static Stream<Arguments> getArgumentsStream(final Supplier<? extends IntStream> keySizeStreamSupplier,
                                                       final Supplier<? extends BlockCipher> cipherSupplier) {
        Objects.requireNonNull(keySizeStreamSupplier, "keySizeStreamSupplier is null");
        Objects.requireNonNull(cipherSupplier, "cipherSupplier is null");
        return getBlockCipherPaddingStream().flatMap(p -> keySizeStreamSupplier.get().mapToObj(ks -> {
            final var cipher = new PaddedBufferedBlockCipher(cipherSupplier.get(), p);
            final var params = _KeyParametersTestUtils.newRandomInstanceOfKeyParameter(null, ks);
            return Arguments.of(
                    Named.of(_TestUtils.cipherName(cipher, p), cipher),
                    Named.of(_TestUtils.paramsName(params), params)
            );
        }));
    }

    private _ECB_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
