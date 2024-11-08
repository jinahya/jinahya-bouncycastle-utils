package symmetric;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto._CipherParameters_TestUtils;
import _org.bouncycastle.crypto.paddings._PaddedBufferedBlockCipher_TestUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Supplier;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static _org.bouncycastle.crypto.paddings._BlockCipherPadding_TestUtils.getBlockCipherPaddingStream;

@Slf4j
public final class _CBC_TestUtils {

    public static Stream<Arguments> getCipherAndParamsArgumentsStream(
            final Supplier<? extends BlockCipher> cipherSupplier,
            final Supplier<? extends IntStream> keySizeStreamSupplier) {
        Objects.requireNonNull(keySizeStreamSupplier, "keySizeStreamSupplier is null");
        Objects.requireNonNull(cipherSupplier, "cipherSupplier is null");
        return getBlockCipherPaddingStream()
                .flatMap(p -> keySizeStreamSupplier.get().mapToObj(ks -> {
                    final var cipher = new PaddedBufferedBlockCipher(
                            CBCBlockCipher.newInstance(cipherSupplier.get()),
                            p
                    );
                    final var key = _Random_TestUtils.newRandomBytes(ks >> 3);
                    final var iv = _Random_TestUtils.newRandomBytes(cipher.getBlockSize());
                    final var params = ThreadLocalRandom.current().nextBoolean()
                            ? new KeyParameter(key)
                            : new ParametersWithIV(new KeyParameter(key), iv);
                    return Arguments.of(
                            Named.of(_PaddedBufferedBlockCipher_TestUtils.cipherName(cipher), cipher),
                            Named.of(_CipherParameters_TestUtils.paramsName(params), params)
                    );
                }));
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static final String MODE = "CBC";

    // -----------------------------------------------------------------------------------------------------------------
    private _CBC_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
