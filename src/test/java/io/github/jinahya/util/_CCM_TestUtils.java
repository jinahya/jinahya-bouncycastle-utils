package io.github.jinahya.util;

import _javax.security._Random_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto.params._KeyParametersTestUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.IntStream;
import java.util.stream.Stream;

@Slf4j
public final class _CCM_TestUtils {

    public static final String MODE = "CCM";

    public static IntStream getBouncyCastleTagLengthStream() {
        return IntStream.of(
                // https://github.com/bcgit/bc-java/blob/240a79848179a65747333c3ba697e687033cfa88/core/src/main/java/org/bouncycastle/crypto/modes/CCMBlockCipher.java#L462
                // tag length in octets must be one of {4,6,8,10,12,14,16}
                4, 6, 8, 10, 12, 14, 16
        );
    }

    public static byte[] newBouncyCastleNonce() {
        // once must have length from 7 to 13 octets
        return _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(7, 14));
    }

    public static Stream<Arguments> getCipherAndParamsArgumentsStream(
            final Supplier<? extends IntStream> keySizeStreamSupplier,
            final Supplier<? extends BlockCipher> cipherSupplier) {
        Objects.requireNonNull(keySizeStreamSupplier, "keySizeStreamSupplier is null");
        Objects.requireNonNull(cipherSupplier, "cipherSupplier is null");
        return keySizeStreamSupplier.get()
                .mapToObj(ks -> getBouncyCastleTagLengthStream().map(tl -> tl << 3).mapToObj(ms -> {
                    final var cipher = CCMBlockCipher.newInstance(cipherSupplier.get());
                    final var key = _KeyParametersTestUtils.newRandomKey(null, ks);
                    final var nonce = newBouncyCastleNonce();
                    final var associatedText = ThreadLocalRandom.current().nextBoolean()
                            ? null
                            : _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
                    final var params = new AEADParameters(
                            new KeyParameter(key),
                            ms,
                            nonce,
                            associatedText
                    );
                    return Arguments.of(
                            Named.of(_TestUtils.cipherName(cipher.getUnderlyingCipher()), cipher),
                            Named.of(_TestUtils.paramsName(params), params)
                    );
                })).flatMap(Function.identity());
    }

    // > The GCM specification states that tLen may only have the values {128, 120, 112, 104, 96},
    // or {64, 32} for certain applications. Other values can be specified for this class,
    // but not all CSP implementations will support them.
    public static IntStream getTLenStream() {
        return IntStream.of(
                128, 120, 112, 104, 96,
                64, 32
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _CCM_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
