package _org.bouncycastle.crypto.paddings;

import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.ISO10126d2Padding;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.TBCPadding;
import org.bouncycastle.crypto.paddings.X923Padding;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

import java.util.Objects;
import java.util.function.Supplier;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public final class _BlockCipherPadding_TestUtils {

    /**
     * .
     *
     * @return .
     * @see <a
     * href="https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/">org.bouncycastle.crypto.paddings.BlockCipherPadding</a>
     */
    public static Stream<BlockCipherPadding> getBlockCipherPaddingStream() {
        return Stream.of(
                new ISO10126d2Padding(),
                new ISO7816d4Padding(),
                new PKCS7Padding(),
                new TBCPadding(),
                new X923Padding()
//                ,
//                new ZeroBytePadding() // https://github.com/bcgit/bc-java/issues/1871
        );
    }

    public static Stream<Arguments> getPaddingAndKeySizeArgumentsStream(
            final Supplier<? extends IntStream> keySizeStreamSupplier) {
        return getBlockCipherPaddingStream()
                .flatMap(p -> keySizeStreamSupplier.get().mapToObj(ks -> Arguments.of(
                        Named.of(p.getPaddingName(), p),
                        ks
                )));
    }

    public static String paddingName(final BlockCipherPadding padding) {
        Objects.requireNonNull(padding, "padding is null");
        return padding.getPaddingName();
    }

    private _BlockCipherPadding_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
