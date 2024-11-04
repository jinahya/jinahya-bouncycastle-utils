package io.github.jinahya.util;

import io.github.jinahya.util.bouncycastle.crypto.params.JinahyaKeyParametersUtils;
import io.github.jinahya.util.bouncycastle.crypto.params.JinahyaParametersWithIvUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.junit.jupiter.params.provider.Arguments;

import java.util.function.Supplier;
import java.util.stream.IntStream;
import java.util.stream.Stream;

@Slf4j
public final class _CTR_TestUtils {

    public static final String MODE = "CTR";

    public static Stream<Arguments> getCipherAndParamsArgumentsStream(
            final Supplier<? extends IntStream> keyStreamSupplier,
            final Supplier<? extends BlockCipher> cipherSupplier) {
        return keyStreamSupplier.get().mapToObj(ks -> {
            final var engine = cipherSupplier.get();
            final var cipher = SICBlockCipher.newInstance(engine);
            final var params = JinahyaParametersWithIvUtils.newRandomInstanceFor(
                    JinahyaKeyParametersUtils.newRandomInstance(null, ks >> 3),
                    null,
                    cipher.getUnderlyingCipher()
            );
            return Arguments.of(
                    cipher,
                    params
            );
        });
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _CTR_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
