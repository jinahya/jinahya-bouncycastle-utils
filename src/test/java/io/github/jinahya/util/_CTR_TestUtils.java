package io.github.jinahya.util;

import io.github.jinahya.util.bouncycastle.crypto._CipherParameters_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto._StreamCipher_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto.params._ParametersWithIVTestUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.junit.jupiter.api.Named;
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
            final var params = _ParametersWithIVTestUtils.newRandomInstanceOfParametersWithIV(null, ks, cipher);
            return Arguments.of(
                    Named.of(_StreamCipher_TestUtils.cipherName(cipher), cipher),
                    Named.of(_CipherParameters_TestUtils.paramsName(params), params)
            );
        });
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _CTR_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
