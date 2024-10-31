package io.github.jinahya.util;

import _javax.security._Random_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto.params._KeyParametersTestUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.params.provider.Arguments;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Supplier;
import java.util.stream.IntStream;
import java.util.stream.Stream;

@Slf4j
public final class _GCM_TestUtils {

    public static final String MODE = "GCM";

    public static IntStream getTLenStream() {
        return IntStream.of(
                128, 120, 112, 104, 96,
                64, 32 // for certain applications
        );
    }

    private static final Set<byte[]> keys = new HashSet<>();

    private static final Set<byte[]> nonces = new HashSet<>();

    private static byte[] key(final int keySize) {
        byte[] key;
        do {
            key = _KeyParametersTestUtils.newRandomKey(null, keySize);
        } while (keys.contains(key));
        return key;
    }

    private static byte[] nonce() {
        byte[] nonce;
        do {
            nonce = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024) + 1);
        } while (nonces.contains(nonce));
        return nonce;
    }

    public static Stream<Arguments> getArgumentsStream(final Supplier<? extends IntStream> keySizeStreamSupplier,
                                                       final Supplier<? extends BlockCipher> cipherSupplier) {
        Objects.requireNonNull(keySizeStreamSupplier, "keySizeStreamSupplier is null");
        Objects.requireNonNull(cipherSupplier, "cipherSupplier is null");
        return keySizeStreamSupplier.get().mapToObj(ks -> {
            final var cipher = GCMBlockCipher.newInstance(cipherSupplier.get());
//            final var key = _KeyParametersTestUtils.newRandomKey(null, ks);
            final var key = key(ks);
            final var macSize = ThreadLocalRandom.current().nextInt(12, 17) << 3; // [96...128]
//            final var nonce = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024) + 1);
            final var nonce = nonce();
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
//                    Named.of(_TestUtils.cipherName(cipher), cipher),
//                    Named.of(_TestUtils.paramsName(params), params)
                    cipher,
                    params
            );
        });
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _GCM_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
