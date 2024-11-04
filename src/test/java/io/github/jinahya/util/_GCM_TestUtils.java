package io.github.jinahya.util;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto.modes._AEADBlockCipher_TestUtils;
import _org.bouncycastle.crypto.params._AEADParameters_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto.params.JinahyaKeyParametersUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Supplier;
import java.util.stream.IntStream;
import java.util.stream.Stream;

@Slf4j
public final class _GCM_TestUtils {

    public static Stream<Arguments> getCipherAndParamsArgumentsStream(
            final Supplier<? extends IntStream> keySizeStreamSupplier,
            final Supplier<? extends BlockCipher> cipherSupplier) {
        Objects.requireNonNull(keySizeStreamSupplier, "keySizeStreamSupplier is null");
        Objects.requireNonNull(cipherSupplier, "cipherSupplier is null");
        return keySizeStreamSupplier.get().mapToObj(ks -> {
            final var cipher = GCMBlockCipher.newInstance(cipherSupplier.get());
            final var key = JinahyaKeyParametersUtils.newRandomKey(null, ks >> 3);
            final var macSize = ThreadLocalRandom.current().nextInt(12, 17) << 3; // [96...128]
            final var nonce = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024) + 1);
            final var associatedText = ThreadLocalRandom.current().nextBoolean()
                    ? null
                    : _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
            final var params = new AEADParameters(
                    new KeyParameter(key),
                    macSize,
                    nonce,
                    associatedText
            );
            return Arguments.of(
                    Named.of(_AEADBlockCipher_TestUtils.cipherName(cipher), cipher),
                    Named.of(_AEADParameters_TestUtils.paramsName(params), params)
            );
        });
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static final String MODE = "GCM";

    public static IntStream getTLenStream() {
        return IntStream.of(
                128, 120, 112, 104, 96,
                64, 32 // for certain applications
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _GCM_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
