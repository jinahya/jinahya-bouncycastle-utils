package _org.bouncycastle.jce.provider;

import io.github.jinahya.util.bouncycastle.jce.provider.JinahyaBouncyCastleProviderUtils;

import java.util.Objects;
import java.util.concurrent.Callable;

public final class _BouncyCastleProvider_TestUtils {

    public static <R> R callWithinBouncyCastleProvider(final Callable<? extends R> callable) {
        Objects.requireNonNull(callable, "callable is null");
        JinahyaBouncyCastleProviderUtils.addBouncyCastleProvider();
        try {
            return callable.call();
        } catch (final Throwable e) {
            throw new RuntimeException("failed to call " + callable, e);
        } finally {
            JinahyaBouncyCastleProviderUtils.removeBouncyCastleProvider();
        }
    }

    private _BouncyCastleProvider_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
