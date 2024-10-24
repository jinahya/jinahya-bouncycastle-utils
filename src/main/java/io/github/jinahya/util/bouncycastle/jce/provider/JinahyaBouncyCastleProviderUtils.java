package io.github.jinahya.util.bouncycastle.jce.provider;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;
import java.util.concurrent.atomic.AtomicReference;

public final class JinahyaBouncyCastleProviderUtils {

    private static final String BOUNCY_CASTLE_PROVIDER_CLASS_NAME =
            "org.bouncycastle.jce.provider.BouncyCastleProvider";

    private static final AtomicReference<Provider> provider = new AtomicReference<>();

    /**
     * Returns a new instance of {@value #BOUNCY_CASTLE_PROVIDER_CLASS_NAME}.
     *
     * @return a new instance of {@value #BOUNCY_CASTLE_PROVIDER_CLASS_NAME}.
     */
    // when the bouncycastle is a runtime-scoped dependency.
    public static Provider getBouncyCastleProvider() {
        return provider.accumulateAndGet(null, (current, given) -> {
            if (current != null) {
                return current;
            }
            try {
                return (Provider) Class.forName(BOUNCY_CASTLE_PROVIDER_CLASS_NAME).getConstructor().newInstance();
            } catch (final ReflectiveOperationException roe) {
                throw new RuntimeException("failed to get BC provider", roe);
            }
        });
    }

    private static boolean added = false;

    public static void addBouncyCastleProvider() {
        synchronized (JinahyaBouncyCastleProviderUtils.class) {
            if (added) {
                return;
            }
            Security.addProvider(getBouncyCastleProvider());
            added = true;
        }
    }

    public static void removeBouncyCastleProvider() {
        synchronized (JinahyaBouncyCastleProviderUtils.class) {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
            added = false;
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaBouncyCastleProviderUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
