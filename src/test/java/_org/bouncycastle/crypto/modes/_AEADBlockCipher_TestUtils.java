package _org.bouncycastle.crypto.modes;

import _org.bouncycastle.crypto._BlockCipher_TestUtils;
import org.bouncycastle.crypto.modes.AEADBlockCipher;

public final class _AEADBlockCipher_TestUtils {

    public static String cipherName(final AEADBlockCipher cipher) {
        return cipher.getAlgorithmName() +
                '/' +
                _BlockCipher_TestUtils.cipherName(cipher.getUnderlyingCipher());
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _AEADBlockCipher_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
