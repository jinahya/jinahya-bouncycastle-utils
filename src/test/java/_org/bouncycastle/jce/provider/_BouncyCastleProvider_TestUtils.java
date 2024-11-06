package _org.bouncycastle.jce.provider;

import io.github.jinahya.bouncycastle.jce.provider.BouncyCastleProviderUtils;

import java.util.Objects;
import java.util.concurrent.Callable;

public final class _BouncyCastleProvider_TestUtils {

    public static <R> R callForBouncyCastleProvider(final Callable<? extends R> callable) throws Exception {
        Objects.requireNonNull(callable, "callable is null");
        BouncyCastleProviderUtils.addBouncyCastleProvider();
        try {
            return callable.call();
        } finally {
            BouncyCastleProviderUtils.removeBouncyCastleProvider();
        }
    }

    private _BouncyCastleProvider_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
