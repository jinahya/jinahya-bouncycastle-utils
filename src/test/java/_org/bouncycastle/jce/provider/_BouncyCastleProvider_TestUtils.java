package _org.bouncycastle.jce.provider;

import io.github.jinahya.util.bouncycastle.jce.provider.JinahyaBouncyCastleProviderUtils;
import io.vavr.CheckedFunction0;

import java.util.Objects;
import java.util.concurrent.Callable;

public final class _BouncyCastleProvider_TestUtils {

    public static <R> R applyWithinBouncyCastleProvider(final CheckedFunction0<? extends R> function) {
        Objects.requireNonNull(function, "function is null");
        JinahyaBouncyCastleProviderUtils.addBouncyCastleProvider();
        try {
            return function.apply();
        } catch (final Throwable e) {
            throw new RuntimeException("failed to apply " + function, e);
        } finally {
            JinahyaBouncyCastleProviderUtils.removeBouncyCastleProvider();
        }
    }

    public static void runWithinBouncyCastleProvider(final Runnable runnable) {
        Objects.requireNonNull(runnable, "runnable is null");
        JinahyaBouncyCastleProviderUtils.addBouncyCastleProvider();
        try {
            runnable.run();
        } catch (final Throwable e) {
            throw new RuntimeException("failed to apply " + runnable, e);
        } finally {
            JinahyaBouncyCastleProviderUtils.removeBouncyCastleProvider();
        }
    }

    public static <R> R callWithinBouncyCastleProvider(final Callable<? extends R> callable) {
        Objects.requireNonNull(callable, "callable is null");
        JinahyaBouncyCastleProviderUtils.addBouncyCastleProvider();
        try {
            return callable.call();
        } catch (final Throwable e) {
            throw new RuntimeException("failed to apply " + callable, e);
        } finally {
            JinahyaBouncyCastleProviderUtils.removeBouncyCastleProvider();
        }
    }

    private _BouncyCastleProvider_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
