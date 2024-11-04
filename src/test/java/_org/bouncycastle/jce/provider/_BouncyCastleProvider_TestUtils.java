package _org.bouncycastle.jce.provider;

import io.github.jinahya.util.bouncycastle.jce.provider.JinahyaBouncyCastleProviderUtils;

import java.util.Objects;
import java.util.concurrent.Callable;

public final class _BouncyCastleProvider_TestUtils {

    public static <R> R callForBouncyCastleProvider(final Callable<? extends R> callable) throws Exception {
        Objects.requireNonNull(callable, "callable is null");
        JinahyaBouncyCastleProviderUtils.addBouncyCastleProvider();
        try {
            return callable.call();
        } finally {
            JinahyaBouncyCastleProviderUtils.removeBouncyCastleProvider();
        }
    }

    private _BouncyCastleProvider_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
