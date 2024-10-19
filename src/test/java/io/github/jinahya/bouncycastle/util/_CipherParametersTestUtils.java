package io.github.jinahya.bouncycastle.util;

import io.github.jinahya.util.bouncycastle.crypto.JinahyaCipherParametersUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;

import java.util.function.Function;

@Slf4j
final class _CipherParametersTestUtils {

    @Deprecated
    static CipherParameters newKeyParameter(final int keySize) {
        return JinahyaCipherParametersUtils.newRandomKeyParameter(null, keySize);
    }

    static <R> R newKeyParameter(final int keysize, final Function<? super CipherParameters, ? extends R> mapper) {
        return mapper.apply(newKeyParameter(keysize));
    }

    @Deprecated
    static CipherParameters newParametersWithIV(final int keySize, final int blockSize) {
        return JinahyaCipherParametersUtils.newRandomParametersWithIV(null, keySize, blockSize);
    }

    static <R> R newParametersWithIV(final int keysize, final int blocksize,
                                     final Function<? super CipherParameters, ? extends R> mapper) {
        return mapper.apply(newParametersWithIV(keysize, blocksize));
    }

    @Deprecated
    static CipherParameters newParametersWithIV(final int keysize, final BufferedBlockCipher cipher) {
        return newParametersWithIV(keysize, cipher.getBlockSize());
    }

    static <R> R newParametersWithIV(final int keysize, final BufferedBlockCipher cipher,
                                     final Function<? super CipherParameters, ? extends R> mapper) {
        return mapper.apply(newParametersWithIV(keysize, cipher));
    }

    private _CipherParametersTestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
