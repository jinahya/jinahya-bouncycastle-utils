package io.github.jinahya.bouncycastle.util;

import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.ISO10126d2Padding;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.TBCPadding;
import org.bouncycastle.crypto.paddings.X923Padding;

import java.util.stream.Stream;

public final class _BouncyCastleTestUtils {

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

    private _BouncyCastleTestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
